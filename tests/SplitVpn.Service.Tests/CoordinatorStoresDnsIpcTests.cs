using System.IO.Pipes;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.OpenConnect;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Service.Ipc;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Operations;
using Xunit.Sdk;

namespace SplitVpn.Service.Tests;

/// <summary>Круг 3 код-ревью: хранилища, DNS, канал управления (M2, M7, M8, M11, M19, M22).</summary>
public sealed partial class CoordinatorTests
{
    /// <summary>M2: повреждённый файл состояния не снимает защиту молча — служба стартует с сохранённой защитой.</summary>
    [Fact]
    public async Task CorruptStateFile_KeepsProtection()
    {
        File.WriteAllText(_world.Paths.State, "{ повреждено");

        var coordinator = await StartAsync();

        Assert.Equal(Intent.Protected, coordinator.State.Intent);
        Assert.True(coordinator.BuildStatus().ProtectionActive);
        Assert.Contains(FilterGroup.Base, _world.Wfp.Groups.Keys);
        Assert.Equal(0, _world.Ras.Dials);
        Assert.NotEmpty(Directory.GetFiles(Path.GetDirectoryName(_world.Paths.State)!, Path.GetFileName(_world.Paths.State) + ".corrupt-*"));
    }

    /// <summary>
    /// M2: «защита сохранена» после повреждения сразу пишется на диск. Иначе при сервере, заданном адресом, без
    /// автоподключения и без действий пользователя следующий запуск не нашёл бы файла и стартовал бы с «Отключено».
    /// </summary>
    [Fact]
    public void CorruptStateFile_ProtectionSurvivesNextRestart()
    {
        File.WriteAllText(_world.Paths.State, "{ повреждено");

        Assert.Equal(Intent.Protected, new ServiceStores(_world.Paths).LoadState().Intent);

        Assert.True(File.Exists(_world.Paths.State));
        Assert.Equal(Intent.Protected, new ServiceStores(_world.Paths).LoadState().Intent);
        Assert.Single(Directory.GetFiles(Path.GetDirectoryName(_world.Paths.State)!, Path.GetFileName(_world.Paths.State) + ".corrupt-*"));
    }

    /// <summary>M2: без файла состояния (первый запуск) намерение по-прежнему «Отключено».</summary>
    [Fact]
    public void MissingStateFile_IntentIsOff()
    {
        Assert.Equal(Intent.Off, new ServiceStores(_world.Paths).LoadState().Intent);
    }

    /// <summary>
    /// M7: посредник больше не занимает [::1]:53, а на адаптере остался наш ::1 прежнего запуска (копия хранит
    /// исходный пустой IPv6-список) — он снимается.
    /// </summary>
    [Fact]
    public async Task StaleOwnIpv6Loopback_IsRemovedWithoutListener()
    {
        new DnsBackupStore(_world.Paths.DnsBackup).Upsert(new InterfaceDnsBackup(FakeWorld.WiFiGuid, "", "", "", 0, DateTimeOffset.UnixEpoch));
        _world.Dns.NameServers[FakeWorld.WiFiGuid] = "127.0.0.1";
        _world.Dns.NameServersV6[FakeWorld.WiFiGuid] = "::1";
        _world.Dns.Ipv6Loopback = false;

        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        Assert.Equal("", _world.Dns.NameServersV6[FakeWorld.WiFiGuid]);
        Assert.Equal("127.0.0.1", _world.Dns.NameServers[FakeWorld.WiFiGuid]);
    }

    /// <summary>M7: собственный ::1 пользователя (он и есть исходный в копии) без слушателя на [::1]:53 не трогается.</summary>
    [Fact]
    public async Task UserIpv6Loopback_IsKeptWithoutListener()
    {
        _world.Dns.NameServers[FakeWorld.WiFiGuid] = "192.168.1.1";
        _world.Dns.NameServersV6[FakeWorld.WiFiGuid] = "::1";
        _world.Dns.Ipv6Loopback = false;

        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        _world.Time.Advance(Coordinator.FullReconcileInterval);
        await TickAsync(coordinator);

        Assert.Equal("127.0.0.1", _world.Dns.NameServers[FakeWorld.WiFiGuid]);
        Assert.Equal("::1", _world.Dns.NameServersV6[FakeWorld.WiFiGuid]);
    }

    /// <summary>
    /// Клиент отключился (истёк срок ожидания интерфейса), пока его команда ждала очередь: команда, меняющая
    /// состояние, всё равно выполняется. Иначе при занятой очереди терялись бы «Восстановить сеть» и отключение.
    /// </summary>
    [Fact]
    public async Task ClientGoneWhileCommandQueued_CommandStillRuns()
    {
        using (var self = WindowsIdentity.GetCurrent(TokenAccessLevels.Query))
        {
            if (!IpcServer.IsAllowedCaller(self))
            {
                throw SkipException.ForSkip("Канал управления принимает команды только от администратора интерактивного сеанса.");
            }
        }

        var coordinator = new Coordinator(_world.Dependencies());
        using var stopping = new CancellationTokenSource();
        var run = Task.Run(() => coordinator.RunAsync(stopping.Token), CancellationToken.None);
        var logger = new DisconnectLogger();
        var name = "SplitVpn.Test." + Guid.NewGuid().ToString("N");
        var server = new IpcServer(coordinator, logger) { PipeName = name, Security = () => null, Precheck = _ => true };
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        try
        {
            await WaitQueueAsync(coordinator);
            await server.StartAsync(TestContext.Current.CancellationToken);
            await coordinator.EnqueueAsync("Test:Blocked", async () =>
            {
                entered.TrySetResult();
                await gate.Task;
            });
            await entered.Task.WaitAsync(QueueWait, TestContext.Current.CancellationToken);

            var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(5000, TestContext.Current.CancellationToken);
            await using (var client = new IpcClient(pipe))
            {
                using var leave = new CancellationTokenSource();
                var send = client.SendAsync(new DisconnectRequest(KeepProtection: true), leave.Token);
                for (var i = 0; i < 500 && coordinator.QueuedCount == 0; i++)
                {
                    await Task.Delay(10, TestContext.Current.CancellationToken);
                }

                Assert.Equal(1, coordinator.QueuedCount);
                await leave.CancelAsync();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => send);
            }

            await logger.Disconnected.Task.WaitAsync(QueueWait, TestContext.Current.CancellationToken);
            gate.TrySetResult();
            await WaitQueueAsync(coordinator);

            Assert.NotEqual(Intent.Off, coordinator.State.Intent);
            Assert.NotEqual(Intent.Off, new ServiceStores(_world.Paths).LoadState().Intent);
        }
        finally
        {
            gate.TrySetResult();
            await server.StopAsync(CancellationToken.None);
            await StopAsync(stopping, run);
        }
    }

    /// <summary>M11: в список поиска адаптера не попадают зоны верхнего уровня, однословные и публичные суффиксы шлюза.</summary>
    [Fact]
    public async Task AnyConnect_PublicSuffixes_StayOutOfSearchList()
    {
        _world.Dns.SearchLists[FakeWorld.WiFiGuid] = "corp.example";
        var coordinator = await StartWithAnyConnectAsync();
        await ConnectAsync(coordinator);
        var session = _world.AnyConnect.Last!;
        var request = Guid.NewGuid();
        session.Emit(new SsoOpenEvent(request, "https://" + Gateway + "/+CSCOE+/saml/sp/login", Gateway));
        await CompleteDialAsync(coordinator);
        session.Emit(new SsoResultEvent(request, true, null));
        _world.Inventory.AddTunnel(AnyConnectSlot);
        session.Emit(new EstablishedEvent(FakeInventory.TunnelLuid(AnyConnectSlot), "SplitVpn AC",
            GatewaySession() with { SplitDns = ["ru", "com.ru", "CO.UK", "local", "corp.com.ru.", "office.example.org"] }));
        await CompleteDialAsync(coordinator);

        Assert.Equal("corp.example,corp.com.ru,office.example.org", _world.Dns.SearchLists[FakeWorld.WiFiGuid]);
        // DNS шлюза разрешает только корпоративные имена: публичная зона увела бы к нему все сайты в ней.
        Assert.DoesNotContain(_world.Proxy.Configuration.DomainRoutes, d => d.Suffix is "com.ru" or "co.uk" or "ru");
        Assert.Contains(_world.Proxy.Configuration.DomainRoutes, d => d.Suffix == "corp.com.ru");
    }

    /// <summary>При сбое до или после удаления настройки, пароль и ключ IPsec остаются прежними.</summary>
    [Theory]
    [InlineData(SecretKind.Password, false)]
    [InlineData(SecretKind.Password, true)]
    [InlineData(SecretKind.PreSharedKey, true)]
    public async Task SecretDeleteFailure_KeepsSettingsAndCredentials(SecretKind failingKind, bool deleteBeforeThrowing)
    {
        var l2tp = _profile with { Protocol = VpnProtocol.L2tpIpsec, Server = "203.0.113.10" };
        SaveSettings(Settings() with { Profiles = [l2tp] });
        _world.Secrets.Save(l2tp.Id, "psk", SecretKind.PreSharedKey);
        var coordinator = new Coordinator(_world.Dependencies() with
        {
            Secrets = new FailingDeleteSecrets(_world.Secrets, failingKind, deleteBeforeThrowing),
        });
        await coordinator.StartupAsync(CancellationToken.None);
        await CompleteDialAsync(coordinator);
        var moved = l2tp with { Server = "198.51.100.99" };

        var response = await coordinator.HandleRequestAsync(new SaveSettingsRequest(Settings() with { Profiles = [moved] }), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Contains("не удалось удалить", response.ErrorMessage, StringComparison.Ordinal);
        Assert.Equal(l2tp.Server, Assert.Single(coordinator.Settings.Profiles).Server);
        Assert.Equal(l2tp.Server, Assert.Single(new ServiceStores(_world.Paths).LoadSettings(out _).Profiles).Server);
        Assert.Equal("secret", new string(_world.Secrets.TryLoad(l2tp.Id)!));
        Assert.Equal("psk", new string(_world.Secrets.TryLoad(l2tp.Id, SecretKind.PreSharedKey)!));
    }

    /// <summary>
    /// M19: файл настроек не записался (занят, диск заполнен) - удалённые перед записью пароль и ключ IPsec
    /// возвращаются, профиль остаётся прежним и в файле, и в памяти, а клиент получает понятную причину.
    /// </summary>
    [Fact]
    public async Task SettingsWriteFailure_RestoresDeletedSecrets()
    {
        var l2tp = _profile with { Protocol = VpnProtocol.L2tpIpsec, Server = "203.0.113.10" };
        SaveSettings(Settings() with { Profiles = [l2tp] });
        _world.Secrets.Save(l2tp.Id, "psk", SecretKind.PreSharedKey);
        var coordinator = await StartAsync();
        var moved = l2tp with { Server = "198.51.100.99" };

        IpcResponse response;
        using (new FileStream(_world.Paths.Settings, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            response = await coordinator.HandleRequestAsync(new SaveSettingsRequest(Settings() with { Profiles = [moved] }), CancellationToken.None);
        }

        Assert.False(response.Ok);
        Assert.Contains("файл настроек", response.ErrorMessage, StringComparison.Ordinal);
        Assert.Equal(l2tp.Server, Assert.Single(coordinator.Settings.Profiles).Server);
        Assert.Equal(l2tp.Server, Assert.Single(new ServiceStores(_world.Paths).LoadSettings(out _).Profiles).Server);
        Assert.Equal("secret", new string(_world.Secrets.TryLoad(l2tp.Id)!));
        Assert.Equal("psk", new string(_world.Secrets.TryLoad(l2tp.Id, SecretKind.PreSharedKey)!));
        Assert.DoesNotContain(_world.Journal.Since(0), e => e.Text.StartsWith("Сохранённый пароль", StringComparison.Ordinal));

        // Файл освободился: то же сохранение проходит, и пароль с ключом прежнего сервера к новому не переходят.
        var retried = await coordinator.HandleRequestAsync(new SaveSettingsRequest(Settings() with { Profiles = [moved] }), CancellationToken.None);

        Assert.True(retried.Ok, retried.ErrorMessage);
        Assert.Equal(moved.Server, Assert.Single(new ServiceStores(_world.Paths).LoadSettings(out _).Profiles).Server);
        Assert.False(_world.Secrets.Contains(l2tp.Id));
        Assert.False(_world.Secrets.Contains(l2tp.Id, SecretKind.PreSharedKey));
        Assert.Contains(_world.Journal.Since(0), e => e.Text.StartsWith("Сохранённый пароль", StringComparison.Ordinal));
    }

    /// <summary>M19: при успешном сохранении пароль, привязанный к прежнему серверу, удаляется, а файл и память совпадают.</summary>
    [Fact]
    public async Task ServerChange_DeletesPasswordAndSavesSettings()
    {
        var coordinator = await StartAsync();
        var moved = _profile with { Server = "198.51.100.99:4443" };

        var response = await coordinator.HandleRequestAsync(new SaveSettingsRequest(Settings() with { Profiles = [moved] }), CancellationToken.None);

        Assert.True(response.Ok, response.ErrorMessage);
        Assert.Equal(moved.Server, Assert.Single(coordinator.Settings.Profiles).Server);
        Assert.Equal(moved.Server, Assert.Single(new ServiceStores(_world.Paths).LoadSettings(out _).Profiles).Server);
        Assert.False(_world.Secrets.Contains(_profile.Id));
    }

    /// <summary>M22: отчёт маскирует и прежнее название подключения, оставшееся в старых записях журнала.</summary>
    [Fact]
    public async Task ExportReport_MasksFormerProfileName()
    {
        var coordinator = await StartAsync();
        coordinator.Journal("Сведения", $"Соединение «{_profile.Name}» установлено.");
        var renamed = _profile with { Name = "Резерв-7" };
        Assert.True((await coordinator.HandleRequestAsync(new SaveSettingsRequest(Settings() with { Profiles = [renamed] }), CancellationToken.None)).Ok);

        var plain = (await coordinator.HandleRequestAsync(new ExportReportRequest(MaskPersonalData: false), CancellationToken.None)).ResultAs<string>()!;
        var masked = (await coordinator.HandleRequestAsync(new ExportReportRequest(MaskPersonalData: true), CancellationToken.None)).ResultAs<string>()!;

        Assert.Contains("Нидерланды", plain, StringComparison.Ordinal);
        Assert.DoesNotContain("Нидерланды", masked, StringComparison.Ordinal);
        Assert.DoesNotContain("Резерв-7", masked, StringComparison.Ordinal);
    }

    private sealed class FailingDeleteSecrets(FakeSecrets inner, SecretKind failingKind, bool deleteBeforeThrowing) : ISecretOps
    {
        public char[]? TryLoad(Guid profileId, SecretKind kind = SecretKind.Password) => inner.TryLoad(profileId, kind);

        public void Save(Guid profileId, ReadOnlySpan<char> password, SecretKind kind = SecretKind.Password) => inner.Save(profileId, password, kind);

        public void Delete(Guid profileId, SecretKind kind = SecretKind.Password)
        {
            if (kind != failingKind || deleteBeforeThrowing)
            {
                inner.Delete(profileId, kind);
            }

            if (kind == failingKind)
            {
                throw new IOException("не удалось завершить удаление секрета");
            }
        }

        public bool Contains(Guid profileId, SecretKind kind = SecretKind.Password) => inner.Contains(profileId, kind);

        public bool IsStored(Guid profileId, SecretKind kind = SecretKind.Password) => inner.IsStored(profileId, kind);
    }

    /// <summary>Журнал канала управления: ждёт записи об отключении клиента.</summary>
    private sealed class DisconnectLogger : ILogger<IpcServer>
    {
        public TaskCompletionSource Disconnected { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (formatter(state, exception).Contains("Клиент IPC отключился", StringComparison.Ordinal))
            {
                Disconnected.TrySetResult();
            }
        }
    }
}
