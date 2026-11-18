using System.Buffers.Binary;
using System.Text;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Operations;

namespace SplitVpn.Service.Tests;

/// <summary>«VPN поверх SSH»: туннель поднимает процесс движка, служба владеет маршрутами, DNS и защитой.</summary>
public sealed partial class CoordinatorTests
{
    // Номер адаптера в поддельном снимке сети: 0 - туннель RAS, 2 - AnyConnect.
    private const int SshSlot = 1;
    private const string SshKeyText = "ключ-устройства-для-теста";
    private static readonly uint SshServer = Ipv4.Parse("192.0.2.10");

    private static string SshHostKeyText()
    {
        var name = Encoding.ASCII.GetBytes("ssh-ed25519");
        var blob = new byte[4 + name.Length + 4 + 32];
        BinaryPrimitives.WriteUInt32BigEndian(blob, (uint)name.Length);
        name.CopyTo(blob, 4);
        BinaryPrimitives.WriteUInt32BigEndian(blob.AsSpan(4 + name.Length), 32);
        return "ssh-ed25519 " + Convert.ToBase64String(blob);
    }

    private readonly ConnectionProfile _ssh = new()
    {
        Name = "США",
        Server = "192.0.2.10:2222",
        Protocol = VpnProtocol.SshVpn,
        AuthMethod = AuthMethod.SshKey,
        UserName = "tunnel",
        Role = ProfileRole.Primary,
        SshVpn = new SshVpnSettings { HostKey = SshHostKeyText() },
    };

    private AppSettings SshSettings() => new() { Profiles = [_ssh], DefaultTarget = RouteTarget.Tunnel(_ssh.Id) };

    private async Task<Coordinator> StartWithSshAsync(AppSettings? settings = null, bool withKey = true)
    {
        new ServiceStores(_world.Paths).SaveSettings(settings ?? SshSettings());
        if (withKey)
        {
            _world.Secrets.Save(_ssh.Id, SshKeyText, SecretKind.SshPrivateKey);
        }

        return await StartAsync();
    }

    /// <summary>Движок запущен и создал адаптер: туннель поднят, проверка связи прошла.</summary>
    private async Task<FakeSshTunnelSession> RaiseSshAsync(Coordinator coordinator)
    {
        await ConnectAsync(coordinator);
        var session = _world.SshTunnel.Last!;
        _world.Inventory.AddTunnel(SshSlot);
        session.Emit(new SshTunnelReady(FakeInventory.TunnelLuid(SshSlot)));
        await CompleteDialAsync(coordinator);
        return session;
    }

    private static async Task WaitAsync(Coordinator coordinator, Func<bool> condition)
    {
        for (var i = 0; i < 400 && !condition(); i++)
        {
            await CompleteDialAsync(coordinator);
            await Task.Delay(5);
        }

        Assert.True(condition());
    }

    private IEnumerable<FilterSpec> EngineFilters() =>
        _world.Wfp.Groups.GetValueOrDefault(FilterGroup.Runtime, [])
            .Where(f => f.Conditions.OfType<AppIdCondition>().Any(a => a.ExecutablePath == _world.SshTunnel.EnginePath));

    [Fact]
    public async Task StaleSettingsRevisionRejectsBothSaveCommands()
    {
        var coordinator = await StartWithSshAsync();
        var settings = SshSettings();
        var revision = SettingsSerializer.Revision(settings with { Profiles = [] });
        var requests = new Core.Ipc.IpcRequest[]
        {
            new Core.Ipc.SaveSettingsRequest(settings, revision),
            new Core.Ipc.SaveConnectionRequest(settings, _ssh.Id, null, null, ExpectedRevision: revision),
        };
        foreach (var request in requests)
        {
            var response = await coordinator.HandleRequestAsync(request, CancellationToken.None);
            Assert.Equal(Core.Ipc.IpcErrorCodes.Busy, response.ErrorCode);
        }
    }

    [Fact]
    public async Task Ssh_KeyValidationRejectsConcurrentProfileEdit()
    {
        var coordinator = await StartWithSshAsync();
        var previous = coordinator.Settings;
        var keyGate = _world.SshTunnel.ReadKeyGate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        var pending = coordinator.SubmitAsync(new Core.Ipc.SaveConnectionRequest(previous, _ssh.Id, null, null,
            SshPrivateKey: SshKeyFile(), ExpectedRevision: SettingsSerializer.Revision(previous)), TestContext.Current.CancellationToken);
        var renamed = previous with { Profiles = [_ssh with { Name = "Новое имя" }] };
        Assert.True((await coordinator.HandleRequestAsync(new Core.Ipc.SaveSettingsRequest(renamed), CancellationToken.None)).Ok);
        keyGate.SetResult(true);
        await WaitAsync(coordinator, () => pending.IsCompleted);
        Assert.Equal(Core.Ipc.IpcErrorCodes.Busy, (await pending).ErrorCode);
        Assert.Equal("Новое имя", coordinator.Settings.Profile(_ssh.Id)!.Name);
        Assert.Equal(SshKeyText, _world.Secrets.SshKeys[_ssh.Id]);
    }

    [Fact]
    public async Task Ssh_StalePathCannotPostponeNewHealthCheck()
    {
        var coordinator = await StartWithSshAsync();
        await RaiseSshAsync(coordinator);
        var link = coordinator.Facts.Tunnels[_ssh.Id].Ssh!;
        link.HealthRunning = true;
        link.PathGeneration++;
        link.NextHealthAt = _world.Time.GetUtcNow();
        await coordinator.OnSshHealthAsync(_ssh.Id, link.Generation, true, CancellationToken.None, link.PathGeneration - 1);
        Assert.False(link.HealthRunning);
        Assert.Equal(_world.Time.GetUtcNow(), link.NextHealthAt);
        var token = link.Probes.Token;
        await coordinator.ShutdownSshTunnels();
        Assert.True(token.IsCancellationRequested);
    }

    [Fact]
    public async Task Ssh_WaitsForOldAdapterOnceBeforeStartingEngine()
    {
        var coordinator = await StartWithSshAsync();
        var released = new TaskCompletionSource();
        _world.SshTunnel.InterfacePreparation = released.Task;
        await ConnectAsync(coordinator);
        await TickAsync(coordinator);
        Assert.Equal(1, _world.SshTunnel.PreparationCalls);
        Assert.Empty(_world.SshTunnel.Sessions);

        released.SetResult();
        await TickAsync(coordinator);
        Assert.Equal(1, _world.SshTunnel.PreparationCalls);
        Assert.Single(_world.SshTunnel.Sessions);
    }

    [Fact]
    public async Task Ssh_Connect_StartsEngineWithKeyAndPinnedServer_WithoutRas()
    {
        var coordinator = await StartWithSshAsync();

        await ConnectAsync(coordinator);

        var session = Assert.Single(_world.SshTunnel.Sessions);
        Assert.Equal(SshServer, session.Parameters.Server);
        Assert.Equal(2222, session.Parameters.Port);
        Assert.Equal("tunnel", session.Parameters.User);
        Assert.Equal(_ssh.SshVpn.HostKey, session.Parameters.HostKey.Text);
        Assert.Equal("SplitVpn SSH " + _ssh.Id.ToString("N")[..8], session.Parameters.InterfaceName);
        Assert.Equal(SshKeyText, session.PrivateKey);
        // Не RAS: ни дозвона, ни записи телефонной книги.
        Assert.Equal(0, _world.Ras.Dials);
        Assert.Null(_world.Ras.SavedProfile);

        // Адаптера ещё нет: туннель не поднят, но маршрут до сервера через основной адаптер уже стоит,
        // а движку открыт только этот адрес.
        var tunnel = coordinator.Facts.Tunnels[_ssh.Id];
        Assert.False(tunnel.IsUp);
        Assert.Contains(_ssh.Name, coordinator.BuildStatus().Progress!.Stage, StringComparison.Ordinal);
        Assert.Contains(new Ipv4Cidr(SshServer, 32), _world.Routes.On(FakeWorld.WiFiLuid));
        Assert.Equal(SshServer, Assert.Single(EngineFilters().SelectMany(f => f.Conditions).OfType<RemoteAddressNotV4>()).Address);
    }

    [Fact]
    public async Task Ssh_AdapterReady_RaisesTunnel_VerifiesByDnsOverTcp_AndRoutesIntoIt()
    {
        var coordinator = await StartWithSshAsync();

        await RaiseSshAsync(coordinator);

        var tunnel = coordinator.Facts.Tunnels[_ssh.Id];
        Assert.True(tunnel.IsUp);
        Assert.True(tunnel.Verified);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
        Assert.NotEmpty(_world.Routes.On(FakeInventory.TunnelLuid(SshSlot)));

        // Проверка шла запросом DNS через интерфейс туннеля, а посредник ходит к DNS туннеля только по TCP.
        Assert.True(_world.SshTunnel.Probes > 0);
        Assert.Equal(tunnel.Adapter!.InterfaceIndex, _world.SshTunnel.LastProbe!.Value.InterfaceIndex);
        Assert.True(_world.Proxy.Configuration.Tunnel!.TcpOnly);

        // Запросы DNS идут на служебные адреса туннеля, движок подменяет их настоящими серверами. Маршрут на
        // служебные адреса стоит в адаптере туннеля, даже когда настоящие адреса DNS направлены в другое место.
        var dns = SplitVpn.Core.SshTunnel.SshTunnelDefaults.DnsAddress(0);
        Assert.Equal(Ipv4.Format(dns), _world.SshTunnel.LastProbe!.Value.Servers[0].Address.ToString());
        Assert.Equal(53, _world.SshTunnel.LastProbe!.Value.Servers[0].Port);
        Assert.Contains(new Ipv4Cidr(dns, 32), _world.Routes.On(FakeInventory.TunnelLuid(SshSlot)));
        Assert.Equal([Ipv4.Parse("1.1.1.1"), Ipv4.Parse("8.8.8.8")], _world.SshTunnel.Last!.Parameters.DnsServers);

        // В туннеле нет UDP, движок по-прежнему ограничен своим сервером.
        var runtime = _world.Wfp.Groups[FilterGroup.Runtime];
        Assert.Contains(runtime, f => f.Action == FilterAction.Block && f.Conditions.Contains(new ProtocolCondition(FilterPlanBuilder.ProtocolUdp))
            && f.Conditions.Contains(new LocalInterfaceCondition(FakeInventory.TunnelLuid(SshSlot), NotEqual: false)));
        Assert.Equal(5, EngineFilters().Count());
    }

    [Fact]
    public async Task Ssh_VerifyFails_StopsEngine_ThenRetriesWithNewProcess()
    {
        var coordinator = await StartWithSshAsync();
        _world.SshTunnel.Alive = false;

        var session = await RaiseSshAsync(coordinator);
        for (var i = 0; i < 6 && !session.Disposed; i++)
        {
            _world.Time.Advance(TimeSpan.FromSeconds(3));
            await TickAsync(coordinator);
        }

        // Неудачная проверка рвёт сеанс через общий разрыв: процесс завершён, туннель не числится поднятым.
        var tunnel = coordinator.Facts.Tunnels[_ssh.Id];
        Assert.True(session.Disposed);
        Assert.False(tunnel.IsUp);
        Assert.Null(tunnel.Ssh);
        Assert.Equal(ErrorCategory.NoInternetInTunnel, tunnel.LastErrorCategory);

        _world.Inventory.RemoveTunnel(SshSlot);
        _world.SshTunnel.Alive = true;
        _world.Time.Advance(TimeSpan.FromMinutes(2));
        await TickAsync(coordinator);

        Assert.Equal(2, _world.SshTunnel.Sessions.Count);
    }

    [Fact]
    public async Task Ssh_EngineExit_DropsTunnel_AndRestartsAfterPause()
    {
        var coordinator = await StartWithSshAsync();
        var session = await RaiseSshAsync(coordinator);

        _world.Inventory.RemoveTunnel(SshSlot);
        session.ExitSource.TrySetResult();
        session.Emit(new SshTunnelExited(1, null));
        await CompleteDialAsync(coordinator);

        var tunnel = coordinator.Facts.Tunnels[_ssh.Id];
        Assert.False(tunnel.IsUp);
        Assert.Empty(_world.Routes.On(FakeInventory.TunnelLuid(SshSlot)));
        Assert.Equal(ErrorCategory.None, tunnel.BlockingError);
        Assert.Contains("туннель оборвался", tunnel.LastErrorText, StringComparison.Ordinal);
        // Пока туннель лежит, его трафик не уходит напрямую: защита при обрыве.
        Assert.NotEqual(ConnectionState.Connected, coordinator.DeriveState());

        _world.Time.Advance(TimeSpan.FromMinutes(2));
        await TickAsync(coordinator);

        Assert.Equal(2, _world.SshTunnel.Sessions.Count);
    }

    [Theory]
    [InlineData("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain", "не принял ключ")]
    [InlineData("ssh: handshake failed: ssh: no common algorithm for host key", "алгоритм")]
    [InlineData("ssh: handshake failed: host key mismatch, server send ssh-ed25519 AAAA", "другой ключ")]
    public async Task Ssh_AuthOrHostKeyFailure_StopsRetries(string line, string expected)
    {
        var coordinator = await StartWithSshAsync();
        await ConnectAsync(coordinator);
        var session = _world.SshTunnel.Last!;

        session.Emit(new SshTunnelLog(line));
        session.ExitSource.TrySetResult();
        session.Emit(new SshTunnelExited(1, null));
        await CompleteDialAsync(coordinator);

        var tunnel = coordinator.Facts.Tunnels[_ssh.Id];
        Assert.Equal(ErrorCategory.Authentication, tunnel.BlockingError);
        Assert.Contains(expected, tunnel.LastErrorText, StringComparison.Ordinal);

        // Повторов нет: частые попытки с неверным ключом сервер может принять за подбор.
        _world.Time.Advance(TimeSpan.FromMinutes(30));
        await TickAsync(coordinator);
        Assert.Single(_world.SshTunnel.Sessions);
    }

    [Fact]
    public async Task Ssh_WithoutKey_DoesNotStartEngine_AndAsksForKey()
    {
        var coordinator = await StartWithSshAsync(withKey: false);

        await ConnectAsync(coordinator);

        var tunnel = coordinator.Facts.Tunnels[_ssh.Id];
        Assert.Empty(_world.SshTunnel.Sessions);
        Assert.Equal(ErrorCategory.Authentication, tunnel.BlockingError);
        Assert.Contains("ключ SSH", tunnel.LastErrorText, StringComparison.Ordinal);
        Assert.Equal(0, _world.Ras.Dials);
    }

    [Fact]
    public async Task Ssh_MissingEngine_BlocksWithoutAppFilters()
    {
        _world.SshTunnel.EnginePath = null;
        var coordinator = await StartWithSshAsync();

        await ConnectAsync(coordinator);

        Assert.Empty(_world.SshTunnel.Sessions);
        Assert.Contains("переустановите", coordinator.Facts.Tunnels[_ssh.Id].LastErrorText, StringComparison.Ordinal);
        Assert.DoesNotContain(_world.Wfp.Groups[FilterGroup.Runtime], f => f.Name.StartsWith("Движок SSH", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Ssh_HealthCheck_TwoFailuresRestartEngine_OneFailureDoesNot()
    {
        var coordinator = await StartWithSshAsync();
        var session = await RaiseSshAsync(coordinator);
        var link = coordinator.Facts.Tunnels[_ssh.Id].Ssh!;

        // Связь есть: контроль проходит, туннель не трогается.
        var before = _world.SshTunnel.Probes;
        _world.Time.Advance(Coordinator.SshHealthInterval + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);
        await WaitAsync(coordinator, () => _world.SshTunnel.Probes > before && !link.HealthRunning);
        Assert.False(session.Disposed);

        // Сервер перестал отвечать: первая неудача только назначает повтор.
        _world.SshTunnel.Alive = false;
        _world.Time.Advance(Coordinator.SshHealthInterval + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);
        await WaitAsync(coordinator, () => link.HealthFailures == 1 && !link.HealthRunning);
        Assert.False(session.Disposed);
        Assert.True(coordinator.Facts.Tunnels[_ssh.Id].Verified);

        // Вторая подряд - движок перезапускается.
        _world.Time.Advance(Coordinator.SshHealthRetry + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);
        await WaitAsync(coordinator, () => session.Disposed);
        Assert.False(coordinator.Facts.Tunnels[_ssh.Id].IsUp);
        Assert.Contains("соединение с сервером SSH потеряно", coordinator.Facts.Tunnels[_ssh.Id].LastErrorText, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(null)]
    public async Task Ssh_DnsTimeoutPreservesTransportUnlessLossIsConfirmed(bool? transport)
    {
        var coordinator = await StartWithSshAsync();
        var session = await RaiseSshAsync(coordinator);
        session.EstablishedTransport = transport;
        var link = coordinator.Facts.Tunnels[_ssh.Id].Ssh!;
        for (var i = 0; i < Coordinator.SshHealthFailureLimit; i++)
            await coordinator.OnSshHealthAsync(_ssh.Id, link.Generation, false, CancellationToken.None);

        Assert.False(session.Disposed);
        Assert.True(coordinator.Facts.Tunnels[_ssh.Id].Verified);
    }

    [Fact]
    public async Task Ssh_Disconnect_StopsEngine()
    {
        var coordinator = await StartWithSshAsync();
        var session = await RaiseSshAsync(coordinator);

        await coordinator.HandleRequestAsync(new SplitVpn.Core.Ipc.DisconnectRequest(KeepProtection: true), CancellationToken.None);
        await CompleteDialAsync(coordinator);

        Assert.True(session.Disposed);
        Assert.Null(coordinator.Facts.Tunnels.GetValueOrDefault(_ssh.Id)?.Ssh);
    }

    [Fact]
    public async Task Ssh_ProfileSwitchedOff_StopsEngine()
    {
        var coordinator = await StartWithSshAsync();
        var session = await RaiseSshAsync(coordinator);

        var off = new AppSettings { Profiles = [_ssh with { Role = ProfileRole.Off }], DefaultTarget = RouteTarget.Direct };
        Assert.True((await coordinator.HandleRequestAsync(new SplitVpn.Core.Ipc.SaveSettingsRequest(off), CancellationToken.None)).Ok);
        await CompleteDialAsync(coordinator);

        // Выключенное подключение не оставляет работающий движок без хозяина.
        Assert.True(session.Disposed);
        Assert.False(coordinator.Facts.Tunnels.ContainsKey(_ssh.Id));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Ssh_UnusableAdapter_RestartsEngineAfterTimeout(bool disappeared)
    {
        var coordinator = await StartWithSshAsync();
        var session = await RaiseSshAsync(coordinator);

        // Адаптер исчез, процесс движка жив: короткое время служба ждёт, что адаптер вернётся.
        session.EstablishedTransport = true;
        if (disappeared) _world.Inventory.RemoveTunnel(SshSlot);
        else _world.Inventory.TunnelHasAddress = false;
        await coordinator.ReconcileAsync(CancellationToken.None);
        Assert.NotEqual(ConnectionState.Connected, coordinator.DeriveState());
        Assert.NotEqual(ConnectionState.Connected, Assert.Single(coordinator.BuildStatus().Tunnels).State);
        await TickAsync(coordinator);
        Assert.False(session.Disposed);

        _world.Time.Advance(Coordinator.AdapterMissingTimeout + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);
        await WaitAsync(coordinator, () => session.Disposed);
        Assert.False(coordinator.Facts.Tunnels[_ssh.Id].IsUp);
        Assert.Contains("адаптер туннеля не найден", coordinator.Facts.Tunnels[_ssh.Id].LastErrorText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Ssh_StuckOldProfileKeepsNewEngineOffSharedAddress()
    {
        var coordinator = await StartWithSshAsync();
        var old = await RaiseSshAsync(coordinator);
        old.ExitOnDispose = false;
        await coordinator.HandleRequestAsync(new Core.Ipc.DisconnectRequest(KeepProtection: false), CancellationToken.None);
        var next = _ssh with { Id = Guid.NewGuid(), Name = "Следующий профиль" };
        _world.Secrets.Save(next.Id, SshKeyText, SecretKind.SshPrivateKey);
        var settings = coordinator.Settings with { Profiles = [next], DefaultTarget = RouteTarget.Tunnel(next.Id) };
        var saved = await coordinator.HandleRequestAsync(new Core.Ipc.SaveSettingsRequest(settings), CancellationToken.None);
        Assert.True(saved.Ok, saved.ErrorMessage);
        await ConnectAsync(coordinator);
        _world.Time.Advance(Coordinator.SshEngineExitWait + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);
        Assert.Single(_world.SshTunnel.Sessions);
        Assert.Contains(_ssh.Name, coordinator.Facts.Tunnels[next.Id].LastErrorText, StringComparison.Ordinal);
        Assert.Equal(ErrorCategory.Other, coordinator.Facts.Tunnels[next.Id].BlockingError);
        old.ExitSource.SetResult();
        await WaitAsync(coordinator, () => _world.SshTunnel.Sessions.Count == 2);
    }

    [Fact]
    public async Task Ssh_NewEngineWaitsForPreviousProcessToExit()
    {
        var coordinator = await StartWithSshAsync();
        var session = await RaiseSshAsync(coordinator);
        session.ExitOnDispose = false;

        _world.Inventory.RemoveTunnel(SshSlot);
        session.Emit(new SshTunnelExited(null, "сбой"));
        await CompleteDialAsync(coordinator);
        _world.Time.Advance(TimeSpan.FromMinutes(1));
        await TickAsync(coordinator);

        // Имя адаптера общее: пока прежний процесс не вышел, новый не запускается.
        Assert.Single(_world.SshTunnel.Sessions);

        session.ExitSource.TrySetResult();
        _world.Time.Advance(TimeSpan.FromMinutes(2));
        await TickAsync(coordinator);
        await WaitAsync(coordinator, () => _world.SshTunnel.Sessions.Count == 2);
    }

    [Fact]
    public async Task Ssh_RetryUsesNextResolvedAddressInConfigAndFirewall()
    {
        const string host = "ssh.example.org";
        var next = Ipv4.Parse("192.0.2.11");
        _world.Resolver.Answers[host] = [SshServer, next];
        var coordinator = await StartWithSshAsync(SshSettings() with { Profiles = [_ssh with { Server = host }] });
        await ConnectAsync(coordinator);
        await WaitAsync(coordinator, () => _world.SshTunnel.Last is not null);
        var session = _world.SshTunnel.Last!;
        Assert.Equal(SshServer, session.Parameters.Server);
        session.ExitSource.TrySetResult();
        session.Emit(new SshTunnelExited(1, null));
        await CompleteDialAsync(coordinator);
        _world.Time.Advance(TimeSpan.FromMinutes(2));
        await TickAsync(coordinator);
        await WaitAsync(coordinator, () => _world.SshTunnel.Sessions.Count == 2);
        Assert.Equal(next, _world.SshTunnel.Last!.Parameters.Server);
        Assert.Equal(next, Assert.Single(EngineFilters().SelectMany(f => f.Conditions).OfType<RemoteAddressNotV4>()).Address);
    }

    [Fact]
    public async Task Ssh_DebugLinesDoNotFillTheCommandQueue()
    {
        var coordinator = await StartWithSshAsync();
        await ConnectAsync(coordinator);
        var session = _world.SshTunnel.Last!;
        var pending = coordinator.QueuedCount;
        for (var i = 0; i < 1000; i++)
        {
            session.Emit(new SshTunnelLog("DEBUG[0001] outbound connection"));
        }

        Assert.Equal(pending, coordinator.QueuedCount);
    }

    [Fact]
    public async Task Ssh_EngineRejectingKey_PreservesStoredKey()
    {
        var coordinator = await StartWithSshAsync();
        _world.SshTunnel.KeyReadable = false;
        var result = await coordinator.HandleRequestAsync(new SplitVpn.Core.Ipc.SaveConnectionRequest(
            coordinator.Settings, _ssh.Id, null, null, null, SshKeyFile()), CancellationToken.None);
        Assert.False(result.Ok);
        Assert.Equal(SshKeyText, _world.Secrets.SshKeys[_ssh.Id]);
    }

    [Fact]
    public async Task Ssh_ServiceShutdown_StopsEngine()
    {
        var coordinator = await StartWithSshAsync();
        var session = await RaiseSshAsync(coordinator);

        await coordinator.ShutdownSshTunnels();

        Assert.True(session.Disposed);
        Assert.False(coordinator.Facts.Tunnels[_ssh.Id].IsUp);
    }

    [Fact]
    public async Task Ssh_WorksNextToAnyConnect_EachWithOwnProcessAndFilters()
    {
        _world.Resolver.Answers[Gateway] = [GatewayAddress];
        var coordinator = await StartWithSshAsync(SshSettings() with { Profiles = [_ssh, _anyConnect] });
        _world.Secrets.Delete(_anyConnect.Id);

        var session = await RaiseSshAsync(coordinator);

        // AnyConnect ждёт входа пользователя и движок SSH не трогает; движку SSH закрыт сервер шлюза.
        Assert.True(coordinator.Facts.Tunnels[_ssh.Id].IsUp);
        Assert.False(session.Disposed);
        Assert.Equal(SshServer, Assert.Single(EngineFilters().SelectMany(f => f.Conditions).OfType<RemoteAddressNotV4>()).Address);
        Assert.Contains(_world.Wfp.Groups[FilterGroup.Runtime], f => f.Name.StartsWith("AnyConnect-сервер", StringComparison.Ordinal));
    }

    /// <summary>Контейнер закрытого ключа OpenSSH со случайным содержимым: настоящих ключей в тестах нет.</summary>
    private static string SshKeyFile(string cipher = "none")
    {
        using var stream = new MemoryStream();
        void Field(byte[] value)
        {
            Span<byte> length = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(length, (uint)value.Length);
            stream.Write(length);
            stream.Write(value);
        }

        stream.Write("openssh-key-v1\0"u8);
        Field(Encoding.ASCII.GetBytes(cipher));
        Field("none"u8.ToArray());
        Field([]);
        stream.Write([0, 0, 0, 1]);
        Field(System.Security.Cryptography.RandomNumberGenerator.GetBytes(51));
        var privatePart = System.Security.Cryptography.RandomNumberGenerator.GetBytes(136);
        privatePart.AsSpan(0, 4).CopyTo(privatePart.AsSpan(4));
        Field(privatePart);
        return "-----BEGIN OPENSSH " + "PRIVATE KEY-----\n" + Convert.ToBase64String(stream.ToArray(), Base64FormattingOptions.InsertLineBreaks)
            + "\n-----END OPENSSH " + "PRIVATE KEY-----\n";
    }

    [Fact]
    public async Task Ssh_SaveConnection_StoresKeySeparately_AndRestartsRunningEngine()
    {
        var coordinator = await StartWithSshAsync();
        var session = await RaiseSshAsync(coordinator);
        var key = SshKeyFile();

        var response = await coordinator.HandleRequestAsync(
            new SplitVpn.Core.Ipc.SaveConnectionRequest(coordinator.Settings, _ssh.Id, null, null, null, key), CancellationToken.None);
        await CompleteDialAsync(coordinator);

        Assert.True(response.Ok);
        // Ключ лежит в своём хранилище, а не среди паролей и ключей IPsec.
        Assert.Equal(key, _world.Secrets.SshKeys[_ssh.Id]);
        Assert.False(_world.Secrets.Saved.ContainsKey(_ssh.Id));
        Assert.False(_world.Secrets.Keys.ContainsKey(_ssh.Id));
        // Новый ключ действует только после перезапуска движка.
        Assert.True(session.Disposed);
        // Запрос с ключом в журнале и отладочном выводе печатается без него.
        Assert.DoesNotContain("PRIVATE", new SplitVpn.Core.Ipc.SaveConnectionRequest(coordinator.Settings, _ssh.Id, null, null, null, key).ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("aes256-ctr", "защищён паролем")]
    [InlineData(null, "не похож на закрытый ключ")]
    public async Task Ssh_SaveConnection_RejectsUnusableKey_AndKeepsStoredOne(string? cipher, string expected)
    {
        var coordinator = await StartWithSshAsync();
        var key = cipher is null ? "ssh-ed25519 AAAA" : SshKeyFile(cipher);

        var response = await coordinator.HandleRequestAsync(
            new SplitVpn.Core.Ipc.SaveConnectionRequest(coordinator.Settings, _ssh.Id, null, null, null, key), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Contains(expected, response.ErrorMessage, StringComparison.Ordinal);
        Assert.Equal(SshKeyText, _world.Secrets.SshKeys[_ssh.Id]);
    }

    [Fact]
    public async Task Ssh_SaveConnection_KeyForOtherProtocolIsRefused()
    {
        var coordinator = await StartAsync();

        var response = await coordinator.HandleRequestAsync(
            new SplitVpn.Core.Ipc.SaveConnectionRequest(coordinator.Settings, _profile.Id, null, null, null, SshKeyFile()), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Empty(_world.Secrets.SshKeys);
    }

    [Fact]
    public async Task Ssh_ProfileRemovedOrRetyped_DeletesStoredKey_ButServerChangeKeepsIt()
    {
        var coordinator = await StartWithSshAsync();

        // Смена адреса сервера ключ не трогает: он принадлежит устройству.
        var moved = _ssh with { Server = "192.0.2.20:22" };
        Assert.True((await coordinator.HandleRequestAsync(new SplitVpn.Core.Ipc.SaveSettingsRequest(SshSettings() with { Profiles = [moved] }), CancellationToken.None)).Ok);
        Assert.True(_world.Secrets.SshKeys.ContainsKey(_ssh.Id));

        // Подключение удалено: ключ в хранилище не остаётся.
        Assert.True((await coordinator.HandleRequestAsync(new SplitVpn.Core.Ipc.SaveSettingsRequest(new AppSettings()), CancellationToken.None)).Ok);
        Assert.False(_world.Secrets.SshKeys.ContainsKey(_ssh.Id));
    }
}
