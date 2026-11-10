using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.OpenConnect;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;

namespace SplitVpn.Service.Tests;

/// <summary>Исправления кругов код-ревью в зоне AnyConnect: жизненный цикл помощника, вход, копии сертификатов.</summary>
public sealed partial class CoordinatorTests
{
    private static readonly uint GatewayPrivateHost = Ipv4.Parse("10.1.2.3");
    private static readonly string ClientCertificate = new('B', 40);

    private async Task DropAsync(Coordinator coordinator, FakeAnyConnectSession session)
    {
        _world.Inventory.RemoveTunnel(AnyConnectSlot);
        session.Emit(new TerminatedEvent(TerminationKind.NetworkError, "связь потеряна"));
        await CompleteDialAsync(coordinator);
    }

    /// <summary>Работы, которые ставят в очередь продолжения задач (выход помощника, таймеры), приходят с задержкой.</summary>
    private static async Task CompleteUntilAsync(Coordinator coordinator, Func<bool> condition)
    {
        for (var i = 0; i < 200 && !condition(); i++)
        {
            await CompleteDialAsync(coordinator);
            if (!condition())
            {
                await Task.Delay(10, TestContext.Current.CancellationToken);
            }
        }
    }

    /// <summary>
    /// Состояние, записанное сборкой с запоминанием сетей прошлого сеанса (поле gatewaySessions), читается без ошибки,
    /// а запомненные сети и имена ничего не блокируют: без сеанса шлюза частная сеть локальная, имена — по общим правилам.
    /// </summary>
    [Fact]
    public async Task AnyConnect_StateWithRememberedGatewaySessions_LoadsAndBlocksNothing()
    {
        Directory.CreateDirectory(_world.Paths.Root);
        File.WriteAllText(_world.Paths.State, $$"""
            {
              "intent": "Connected",
              "gatewaySessions": [
                { "profileId": "{{_anyConnect.Id}}", "gateway": "{{Gateway}}", "networks": ["10.0.0.0/8"], "dnsNames": ["office.example.org"] }
              ]
            }
            """);

        var coordinator = await StartWithAnyConnectAsync();
        await TickAsync(coordinator);

        Assert.Equal(Intent.Connected, coordinator.State.Intent);
        Assert.Empty(Directory.GetFiles(_world.Paths.Root, "state.json.corrupt-*"));
        Assert.Equal(Decision.Local, coordinator.Facts.Policy!.Classify(GatewayPrivateHost).Decision);
        Assert.DoesNotContain(_world.Proxy.Configuration.DomainRoutes, d => d.Suffix == "office.example.org");
        Assert.Equal(SignInKind.Required, AnyConnectStatus(coordinator).SignIn?.Kind);
    }

    /// <summary>
    /// Остановка службы ждёт и помощников, отпущенных раньше (обрыв, срок подъёма, смена настроек), пока они прощаются
    /// со шлюзом: иначе выход службы закрыл бы Job и убил их посреди BYE.
    /// </summary>
    [Fact]
    public async Task AnyConnect_ServiceShutdown_WaitsForReleasedHelperStillExiting()
    {
        var coordinator = await StartWithAnyConnectAsync();
        var session = await EstablishAsync(coordinator);
        await DropAsync(coordinator, session);
        Assert.Null(coordinator.Facts.Tunnels[_anyConnect.Id].AnyConnect);

        var exited = coordinator.ShutdownAnyConnect();

        Assert.False(exited.IsCompleted);
        session.ExitSource.SetResult();
        await exited.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// С16: служба помнит сертификаты, отданные помощнику (копия в хранилище SYSTEM), и после перезапуска: сертификат,
    /// снятый с подключения, пока служба была остановлена, удаляется на первой сверке.
    /// </summary>
    [Fact]
    public async Task AnyConnect_CertificateCopy_IsRemovedAfterRestartWhenNoLongerSelected()
    {
        var withCertificate = _anyConnect with { AnyConnect = new AnyConnectSettings { ClientCertificateThumbprint = ClientCertificate } };
        var first = await StartWithAnyConnectAsync(Settings() with { Profiles = [_profile, withCertificate] });
        await ConnectAsync(first);
        Assert.Equal([ClientCertificate], new ServiceStores(_world.Paths).LoadState().AnyConnectCertificateCopies!);
        Assert.Empty(_world.AnyConnect.RemovedCopies);

        SaveSettings(Settings() with { Profiles = [_profile, _anyConnect] });
        var restarted = await StartAsync();
        await TickAsync(restarted);

        Assert.Equal([ClientCertificate], _world.AnyConnect.RemovedCopies);
        Assert.Empty(new ServiceStores(_world.Paths).LoadState().AnyConnectCertificateCopies!);
    }

    /// <summary>С16: сертификат, который служба помощнику не отдавала, в хранилище SYSTEM не трогается.</summary>
    [Fact]
    public async Task AnyConnect_CertificateNeverGivenToHelper_IsNotTouched()
    {
        new ServiceStores(_world.Paths).SaveState(new ServiceStateFile { Intent = Intent.Connected, AnyConnectCertificateCopies = [] });
        var withCertificate = _anyConnect with { AnyConnect = new AnyConnectSettings { ClientCertificateThumbprint = ClientCertificate } };
        var coordinator = await StartWithAnyConnectAsync(Settings() with { Profiles = [_profile, withCertificate] });
        await TickAsync(coordinator);

        var saved = await coordinator.HandleRequestAsync(new SaveSettingsRequest(Settings() with { Profiles = [_profile, _anyConnect] }), CancellationToken.None);
        await TickAsync(coordinator);

        Assert.True(saved.Ok, saved.ErrorMessage);

        Assert.Empty(_world.AnyConnect.RemovedCopies);
    }

    /// <summary>С12: новый помощник профиля не запускается, пока прежний не вышел и не освободил адаптер Wintun.</summary>
    [Fact]
    public async Task AnyConnect_NewHelperWaitsForPreviousHelperExit()
    {
        var coordinator = await StartWithAnyConnectAsync();
        var session = await EstablishAsync(coordinator);
        await DropAsync(coordinator, session);

        await coordinator.HandleRequestAsync(new BeginSignInRequest(_anyConnect.Id), CancellationToken.None);
        await CompleteDialAsync(coordinator);
        Assert.Single(_world.AnyConnect.Sessions);

        session.ExitSource.SetResult();
        await CompleteUntilAsync(coordinator, () => _world.AnyConnect.Sessions.Count == 2);

        Assert.Equal(2, _world.AnyConnect.Sessions.Count);
    }

    /// <summary>С12: прежний помощник завис и не выходит — ожидание ограничено, новый запускается после срока.</summary>
    [Fact]
    public async Task AnyConnect_HungPreviousHelper_DoesNotBlockNewSignInForever()
    {
        var coordinator = await StartWithAnyConnectAsync();
        var session = await EstablishAsync(coordinator);
        await DropAsync(coordinator, session);
        await coordinator.HandleRequestAsync(new BeginSignInRequest(_anyConnect.Id), CancellationToken.None);
        await CompleteDialAsync(coordinator);
        Assert.Single(_world.AnyConnect.Sessions);

        _world.Time.Advance(Coordinator.HelperExitWait + TimeSpan.FromSeconds(1));
        await CompleteUntilAsync(coordinator, () => _world.AnyConnect.Sessions.Count == 2);

        Assert.Equal(2, _world.AnyConnect.Sessions.Count);
    }

    /// <summary>С13: помощник не поднял сеанс в срок и не ждёт пользователя — он останавливается, туннель ждёт нового входа.</summary>
    [Fact]
    public async Task AnyConnect_HelperStuckBeforeEstablished_IsStoppedAfterDeadline()
    {
        var coordinator = await StartWithAnyConnectAsync();
        await ConnectAsync(coordinator);
        var session = _world.AnyConnect.Last!;

        _world.Time.Advance(Coordinator.AnyConnectEstablishDeadline + TimeSpan.FromSeconds(1));
        await CompleteUntilAsync(coordinator, () => session.Disposed);

        Assert.True(session.Disposed);
        Assert.Contains(session.Commands, c => c is StopCommand);
        Assert.Null(coordinator.Facts.Tunnels[_anyConnect.Id].AnyConnect);
        var status = AnyConnectStatus(coordinator);
        Assert.Equal(SignInKind.Required, status.SignIn?.Kind);
        Assert.Contains("не ответил", status.ErrorText, StringComparison.Ordinal);
        Assert.Single(_world.AnyConnect.Sessions);
    }

    /// <summary>С13: пока пользователь проходит вход в окне, срок не идёт; после ответа он начинается заново.</summary>
    [Fact]
    public async Task AnyConnect_DeadlineWaitsForInteractiveSignIn()
    {
        var coordinator = await StartWithAnyConnectAsync();
        await ConnectAsync(coordinator);
        var session = _world.AnyConnect.Last!;
        var request = Guid.NewGuid();
        session.Emit(new SsoOpenEvent(request, "https://" + Gateway + "/saml", Gateway));
        await CompleteDialAsync(coordinator);

        _world.Time.Advance(TimeSpan.FromMinutes(4));
        await CompleteDialAsync(coordinator);
        Assert.False(session.Disposed);

        session.Emit(new SsoResultEvent(request, true, null));
        await CompleteDialAsync(coordinator);
        _world.Time.Advance(Coordinator.AnyConnectEstablishDeadline - TimeSpan.FromSeconds(10));
        await CompleteDialAsync(coordinator);
        Assert.False(session.Disposed);

        _world.Time.Advance(TimeSpan.FromSeconds(11));
        await CompleteUntilAsync(coordinator, () => session.Disposed);
        Assert.True(session.Disposed);
    }

    /// <summary>М10: отключённый пользователем туннель не показывает «Требуется вход» ни в строке, ни в предупреждениях.</summary>
    [Fact]
    public async Task AnyConnect_PausedTunnel_DoesNotAskForSignIn()
    {
        var coordinator = await StartWithAnyConnectAsync();
        var session = await EstablishAsync(coordinator);
        await DropAsync(coordinator, session);
        Assert.Equal(SignInKind.Required, AnyConnectStatus(coordinator).SignIn?.Kind);

        await coordinator.HandleRequestAsync(new SetTunnelPausedRequest(_anyConnect.Id, true), CancellationToken.None);
        await CompleteDialAsync(coordinator);

        Assert.Null(AnyConnectStatus(coordinator).SignIn);
        Assert.DoesNotContain(coordinator.BuildStatus().Warnings, w => w.Code == "sign-in-required");
    }

    /// <summary>М13: помощник получает все адреса узла шлюза, а не только первый.</summary>
    [Fact]
    public async Task AnyConnect_ResolveReply_CarriesAllGatewayAddresses()
    {
        var second = Ipv4.Parse("198.51.100.11");
        _world.Resolver.Answers["node2.example.org"] = [Ipv4.Parse("198.51.100.20"), second];
        var coordinator = await StartWithAnyConnectAsync();
        await ConnectAsync(coordinator);
        var session = _world.AnyConnect.Last!;

        session.Emit(new ResolveHostEvent("node2.example.org"));
        await CompleteDialAsync(coordinator);

        var reply = Assert.Single(session.Commands.OfType<ResolveReplyCommand>());
        Assert.Equal("198.51.100.20", reply.Address);
        Assert.Equal(["198.51.100.20", "198.51.100.11"], reply.Addresses!);
        Assert.Contains(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(second, 32) && r.InterfaceLuid == FakeWorld.WiFiLuid);
    }

    /// <summary>Узлы шлюза, заданные IP-адресами, считаются в пределе узлов наравне с именами.</summary>
    [Fact]
    public async Task AnyConnect_LiteralGatewayNodes_AreLimited()
    {
        var coordinator = await StartWithAnyConnectAsync();
        await ConnectAsync(coordinator);
        var session = _world.AnyConnect.Last!;

        for (var i = 0; i < 12; i++)
        {
            session.Emit(new ResolveHostEvent(Ipv4.Format(Ipv4.Parse("203.0.113.10") + (uint)i)));
            await CompleteDialAsync(coordinator);
        }

        var replies = session.Commands.OfType<ResolveReplyCommand>().ToList();
        Assert.Equal(12, replies.Count);
        Assert.Equal(8, replies.Count(r => r.Address is not null));
        Assert.DoesNotContain(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(Ipv4.Parse("203.0.113.21"), 32));
        Assert.Contains(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(Ipv4.Parse("203.0.113.17"), 32));
    }

    /// <summary>
    /// Выход из Windows: интерфейс опорного туннеля RAS уже убран, а соединение ещё числится. Остановка AnyConnect
    /// берёт свежий снимок сети и не ставит маршруты на исчезнувший интерфейс.
    /// </summary>
    [Fact]
    public async Task AnyConnect_ShutdownAfterRasInterfaceVanished_DoesNotRouteToIt()
    {
        var coordinator = await StartWithAnyConnectAsync();
        await EstablishAsync(coordinator);
        Assert.NotEmpty(_world.Routes.On(FakeWorld.TunnelLuid));
        _world.Inventory.RemoveTunnel(0);

        _ = coordinator.ShutdownAnyConnect();

        Assert.Empty(_world.Routes.On(FakeWorld.TunnelLuid));
        Assert.Null(coordinator.Facts.Tunnels[_profile.Id].Adapter);
    }
}
