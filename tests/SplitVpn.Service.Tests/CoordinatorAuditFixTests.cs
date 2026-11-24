using Microsoft.Extensions.Logging.Abstractions;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.OpenConnect;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Service.Ipc;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Operations;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Tests;

/// <summary>Исправления аудита в зоне координатора: маршрут проверки интернета, срок команд, ключ IPsec, задачи без наблюдателя.</summary>
public sealed partial class CoordinatorTests
{
    /// <summary>
    /// Адрес веб-проверки интернета Windows, который политика отдала лежащему дополнительному туннелю: проба NCSI от
    /// svchost.exe разрешена планом фильтров (вес правил для доменов перебивает «Туннель недоступен») и получает
    /// маршрут /32 через основной адаптер, пока туннель-владелец лежит. Иначе Windows помечала бы сеть «без интернета»
    /// и сбрасывала Wi-Fi. Чужой программе адрес не открыт; поднялся туннель - маршрут снимается.
    /// </summary>
    [Fact]
    public async Task ConnectivityCheckAddress_OfDownSecondaryTunnel_PermittedForNcsiWithRouteViaPrimary()
    {
        var address = Ipv4.Parse("23.215.0.136");
        var second = SecondProfile();
        SaveSettings(Settings() with
        {
            Profiles = [_profile, second],
            Rules = [new UserRuleSetting { Cidr = "23.215.0.0/24", Target = RouteTarget.Tunnel(second.Id) }],
        });
        _world.Ras.ResultsByEntry[Coordinator.EntryNameFor(second)] = new Queue<RasDialResult>([new RasDialResult(false, null, 809, "Нет ответа")]);
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.True(coordinator.Facts.Tunnels[_profile.Id].IsUp);
        Assert.False(coordinator.Facts.Tunnels[second.Id].IsUp);

        var pin = coordinator.ObservePinnedAsync(new PinnedRouteNotice(Coordinator.ConnectivityCheckWebHost, Coordinator.ConnectivityCheckWebHost,
            RouteTarget.Direct, [address], TimeSpan.FromHours(1), coordinator.ConnectivityPinContext), CancellationToken.None);
        await coordinator.DrainAsync();
        Assert.True(await pin);

        Assert.True(coordinator.Facts.RevocationPins.ContainsKey(address));
        Assert.Equal(second.Id, coordinator.Facts.Policy!.Classify(address).Tunnel);
        var route = new Ipv4Cidr(address, 32);
        Assert.Contains(_world.Routes.Current, r => r.Destination == route && r.InterfaceLuid == FakeWorld.WiFiLuid);

        // План фильтров: проба NCSI (svchost.exe, TCP/80, основной адаптер) разрешена весом выше «Туннель недоступен»;
        // чужая программа на тот же адрес и порт блокируется.
        var installed = Enum.GetValues<FilterGroup>().SelectMany(g => _world.Wfp.Group(g)).ToList();
        Assert.Contains(installed, f => f.Action == FilterAction.Block && f.Weight == FilterPlanBuilder.WeightUserBlock
            && f.Name.StartsWith("Туннель недоступен", StringComparison.Ordinal));
        var ncsi = Assert.Single(_world.Wfp.Group(FilterGroup.Dynamic), f => f.Name.StartsWith("Проверка интернета Windows", StringComparison.Ordinal));
        Assert.Equal(FilterAction.Permit, ncsi.Action);
        Assert.Equal(FilterPlanBuilder.WeightDomain, ncsi.Weight);
        Assert.Contains(new AppIdCondition(FilterPlanBuilder.SvchostExecutablePath), ncsi.Conditions);
        Assert.Contains(new RemotePortCondition(80), ncsi.Conditions);
        Assert.Contains(new LocalInterfaceCondition(FakeWorld.WiFiLuid, NotEqual: false), ncsi.Conditions);

        // Туннель-владелец поднялся: «застрявший» маршрут через основной адаптер снимается.
        coordinator.Facts.Tunnels[second.Id].NextDialAt = _world.Time.GetUtcNow();
        for (var i = 0; i < 10 && !coordinator.Facts.Tunnels[second.Id].IsUp; i++)
        {
            _world.Time.Advance(TimeSpan.FromSeconds(2));
            await TickAsync(coordinator);
        }

        await TickAsync(coordinator);

        Assert.True(coordinator.Facts.Tunnels[second.Id].IsUp);
        Assert.True(coordinator.Facts.RevocationPins.ContainsKey(address));
        Assert.DoesNotContain(_world.Routes.Current, r => r.Destination == route && r.InterfaceLuid == FakeWorld.WiFiLuid);
    }

    /// <summary>
    /// R-SVC-4: хост останавливает канал управления раньше координатора. Остановка канала посреди долгой сверки
    /// «Отключить» снимает только ожидание клиента: команда доходит до конца под сроком жизни координатора, и ложного
    /// «неполного применения» нет.
    /// </summary>
    [Fact]
    public async Task IpcStop_DuringLongDisconnect_DoesNotMarkPartialApply()
    {
        var coordinator = new Coordinator(_world.Dependencies());
        using var stopping = new CancellationTokenSource();
        var run = Task.Run(() => coordinator.RunAsync(stopping.Token), CancellationToken.None);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        try
        {
            await WaitQueueAsync(coordinator);
            var connected = await coordinator.SubmitAsync(new ConnectRequest(null, null), TestContext.Current.CancellationToken);
            Assert.True(connected.Ok, connected.ErrorMessage);
            for (var i = 0; i < 500 && !_world.Ras.Connected; i++)
            {
                await Task.Delay(10, TestContext.Current.CancellationToken);
            }

            Assert.True(_world.Ras.Connected);
            await WaitQueueAsync(coordinator);
            await WaitQueueAsync(coordinator);

            _world.Ras.HangUpHook = async token =>
            {
                entered.TrySetResult();
                await release.Task.WaitAsync(token);
            };
            var server = new IpcServer(coordinator, NullLogger<IpcServer>.Instance);
            using var ipc = new CancellationTokenSource();
            var command = server.SubmitAsync(new DisconnectRequest(KeepProtection: false), ipc.Token);
            await entered.Task.WaitAsync(QueueWait, TestContext.Current.CancellationToken);

            await ipc.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => command);
            release.TrySetResult();
            await WaitQueueAsync(coordinator);

            Assert.Null(coordinator.Facts.PartialError);
            Assert.Equal(Intent.Off, coordinator.State.Intent);
            Assert.False(_world.Ras.Connected);
        }
        finally
        {
            release.TrySetResult();
            _world.Ras.HangUpHook = null;
            await StopAsync(stopping, run);
        }
    }

    /// <summary>R-SVC-6: ключ IPsec записан, а прежняя запись телефонной книги не удалилась — блокировка дозвона всё равно снята.</summary>
    [Fact]
    public async Task PreSharedKey_DeleteEntryFailure_StillClearsBlockingError()
    {
        SaveSettings(Settings() with { Profiles = [_profile with { Protocol = VpnProtocol.L2tpIpsec }] });
        _world.Secrets.Save(_profile.Id, "old-key", SecretKind.PreSharedKey);
        _world.Ras.Results.Enqueue(new RasDialResult(false, null, 789, "Ошибка согласования IPsec"));
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        tunnel.BlockingError = ErrorCategory.Authentication;
        tunnel.NextDialAt = _world.Time.GetUtcNow().AddHours(1);
        _world.Ras.DeleteEntryFailure = new IOException("телефонная книга занята");

        var response = await coordinator.HandleRequestAsync(new SetPreSharedKeyRequest(_profile.Id, "new-key"), CancellationToken.None);
        await CompleteDialAsync(coordinator);

        Assert.True(response.Ok, response.ErrorMessage);
        Assert.Equal("new-key", _world.Secrets.Keys[_profile.Id]);
        Assert.Equal(ErrorCategory.None, tunnel.BlockingError);
        Assert.True(tunnel.NextDialAt <= _world.Time.GetUtcNow());
        Assert.Null(coordinator.Facts.PartialError);
    }

    /// <summary>R-SVC-6: ключ IPsec не записался — понятная ошибка клиенту, без «неполного применения» и без разрыва.</summary>
    [Fact]
    public async Task PreSharedKey_SaveFailure_IsClientErrorWithoutPartialApply()
    {
        SaveSettings(Settings() with { Profiles = [_profile with { Protocol = VpnProtocol.L2tpIpsec }] });
        _world.Secrets.Save(_profile.Id, "old-key", SecretKind.PreSharedKey);
        var coordinator = new Coordinator(_world.Dependencies());
        using var stopping = new CancellationTokenSource();
        var run = Task.Run(() => coordinator.RunAsync(stopping.Token), CancellationToken.None);
        try
        {
            await WaitQueueAsync(coordinator);
            var hangUps = _world.Ras.HangUps;
            _world.Secrets.FailSave = true;

            var response = await coordinator.SubmitAsync(new SetPreSharedKeyRequest(_profile.Id, "new-key"), TestContext.Current.CancellationToken);
            await WaitQueueAsync(coordinator);

            Assert.False(response.Ok);
            Assert.Equal(IpcErrorCodes.Failed, response.ErrorCode);
            Assert.Contains("ключ IPsec", response.ErrorMessage, StringComparison.Ordinal);
            Assert.Equal("old-key", _world.Secrets.Keys[_profile.Id]);
            Assert.Equal(hangUps, _world.Ras.HangUps);
            Assert.Null(coordinator.Facts.PartialError);
        }
        finally
        {
            _world.Secrets.FailSave = false;
            await StopAsync(stopping, run);
        }
    }

    /// <summary>
    /// R-SVC-9: неожиданное исключение разрешения узла шлюза (ArgumentException на имени, присланном шлюзом) не теряется
    /// в задаче без наблюдателя: помощник сразу получает ответ «не разрешилось», а не ждёт его до своего срока.
    /// </summary>
    [Fact]
    public async Task AnyConnect_ResolverThrowsUnexpectedly_HelperGetsEmptyReply()
    {
        const string host = "node2.example.org";
        _world.Resolver.Failures[host] = new ArgumentException("недопустимое имя узла");
        var coordinator = await StartWithAnyConnectAsync();
        await ConnectAsync(coordinator);
        var session = _world.AnyConnect.Last!;

        session.Emit(new ResolveHostEvent(host));
        await CompleteUntilAsync(coordinator, () => session.Commands.OfType<ResolveReplyCommand>().Any());

        var reply = Assert.Single(session.Commands.OfType<ResolveReplyCommand>());
        Assert.Equal(host, reply.Host);
        Assert.Null(reply.Address);
        Assert.Empty(reply.Addresses ?? []);
    }

    /// <summary>
    /// R-SVC-9: неожиданное исключение при разрешении одного узла проверки отзыва не обрывает закрепление остальных:
    /// узел просто считается не разрешившимся.
    /// </summary>
    [Fact]
    public async Task RevocationResolve_UnexpectedException_DoesNotBreakOtherHosts()
    {
        const string broken = "crl.broken.example";
        _world.Probes.ServerCertificate = ServerCertificate(_world.Time.GetUtcNow().AddDays(6))
            with { RevocationUrls = ["http://" + RevocationHost + "/112.crl", "http://" + broken + "/1.crl"] };
        _world.Resolver.Answers[RevocationHost] = [RevocationAddress];
        _world.Resolver.Failures[broken] = new ArgumentException("недопустимое имя узла");
        _world.Ras.Results.Enqueue(Failed(ConnectionErrorGuide.RevocationOffline));

        var coordinator = await StartAsync();
        await ConnectAfterCertificateProbeAsync(coordinator, _profile);

        Assert.False(coordinator.Facts.Tunnels[_profile.Id].IsUp);
        Assert.True(coordinator.Facts.RevocationPins.ContainsKey(RevocationAddress));
        Assert.Null(coordinator.Facts.PartialError);
    }
}
