using System.Net;
using System.Net.Http.Headers;
using System.Text;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Core.Update;
using SplitVpn.Service.Coordination;

namespace SplitVpn.Service.Tests;

/// <summary>Поиск ошибок 2026-11-09, круг 3: маршрут по умолчанию, DNS нового адаптера, дозвон, запуск службы.</summary>
public sealed partial class CoordinatorTests
{
    private static readonly Ipv4Cidr LowerHalf = Ipv4Cidr.Parse("0.0.0.0/1");

    /// <summary>
    /// «Остальной интернет» напрямую, а Windows по умолчанию выбрала другой адаптер (лучшая метрика): прямой трафик
    /// уводится парой /1 через основной, иначе защита («Прямой путь») блокировала бы его весь.
    /// </summary>
    [Fact]
    public async Task DirectDefault_PrimaryNotWindowsDefault_GetsHalfRoutesThroughPrimary()
    {
        SaveSettings(Settings() with { DefaultTarget = RouteTarget.Direct });
        _world.Inventory.RadminDefaultRouteMetric = 20;
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        Assert.Contains(_world.Routes.Current, r => r.Destination == LowerHalf && r.InterfaceLuid == FakeWorld.WiFiLuid);

        // Wi-Fi снова маршрут Windows по умолчанию: своя пара /1 не нужна.
        _world.Inventory.RadminDefaultRouteMetric = 9257;
        _world.Time.Advance(Coordinator.FullReconcileInterval);
        await TickAsync(coordinator);

        Assert.DoesNotContain(_world.Routes.Current, r => r.Destination == LowerHalf && r.InterfaceLuid == FakeWorld.WiFiLuid);
    }

    /// <summary>
    /// Подъём по очереди: первое подключение отключили через меню сети Windows, второе оборвалось. Второе
    /// поднимается снова: отключённого вручную служба сама не поднимет, и ждать его нечего.
    /// </summary>
    [Fact]
    public async Task SequentialDial_ExternallyDisconnectedPredecessor_DoesNotHoldQueue()
    {
        var second = SecondProfile();
        // «Остальной интернет» несёт второе: отключение первого вручную не снимает намерение «подключено».
        SaveSettings(Settings() with { Profiles = [_profile, second], SequentialDial = true, DefaultTarget = RouteTarget.Tunnel(second.Id) });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        // Повторное «Подключить» при поднятых туннелях сбрасывает признак завершённого дозвона.
        await ConnectAsync(coordinator);

        _world.TerminationReason = 631;
        _world.TerminationEntry = Coordinator.EntryNameFor(_profile);
        _world.Ras.Drop(Coordinator.EntryNameFor(_profile));
        await TickAsync(coordinator);
        Assert.True(coordinator.Facts.Tunnels[_profile.Id].ExternallyDisconnected);
        var dials = _world.Ras.Dials;

        _world.Ras.Drop(Coordinator.EntryNameFor(second));
        await TickAsync(coordinator);
        _world.Time.Advance(TimeSpan.FromMinutes(2));
        await TickAsync(coordinator);
        await CompleteDialAsync(coordinator);

        Assert.True(_world.Ras.Dials > dials, Dump(coordinator));
    }

    /// <summary>Имя сервера не находится: подключение не висит молча в «Подключении», ошибка видна и записана в журнал.</summary>
    [Fact]
    public async Task UnresolvableServerName_ShowsError()
    {
        const string host = "vpn.mistyped.example";
        _world.Resolver.Answers[host] = [];
        SaveSettings(Settings() with { Profiles = [_profile with { Server = host }] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        Assert.Equal(ErrorCategory.NameResolution, tunnel.LastErrorCategory);
        Assert.Contains(host, coordinator.BuildStatus().ErrorText, StringComparison.Ordinal);
        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains(host, StringComparison.Ordinal));

        // Имя нашлось: ошибка снимается.
        _world.Resolver.Answers[host] = [FakeWorld.Server];
        _world.Time.Advance(TimeSpan.FromSeconds(15));
        await TickAsync(coordinator);
        await CompleteDialAsync(coordinator);
        Assert.NotEqual(ErrorCategory.NameResolution, coordinator.Facts.Tunnels[_profile.Id].LastErrorCategory);
    }

    /// <summary>Ключ IPsec сохранён, но сейчас не расшифровывается: это не «ключа нет», подключение не блокируется.</summary>
    [Fact]
    public async Task UnreadablePresharedKey_IsRetriedInsteadOfBlocking()
    {
        var l2tp = _profile with { Protocol = VpnProtocol.L2tpIpsec, Server = "203.0.113.10", AuthMethod = AuthMethod.EapMsChapV2 };
        SaveSettings(Settings() with { Profiles = [l2tp] });
        _world.Secrets.Keys[l2tp.Id] = "psk";
        _world.Secrets.Unreadable.Add(l2tp.Id);
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var tunnel = coordinator.Facts.Tunnels[l2tp.Id];
        Assert.Equal(ErrorCategory.None, tunnel.BlockingError);
        Assert.Contains("не читается", tunnel.LastErrorText, StringComparison.Ordinal);
    }

    /// <summary>Сбой подготовки записи L2TP с сертификатом компьютера для IPsec - ошибка сертификата, не пароля.</summary>
    [Fact]
    public async Task IpsecMachineCertificatePrepareFailure_IsCertificateError()
    {
        var l2tp = _profile with
        {
            Protocol = VpnProtocol.L2tpIpsec, Server = "203.0.113.10", AuthMethod = AuthMethod.EapMsChapV2,
            IpsecAuthentication = IpsecAuthentication.MachineCertificate,
        };
        SaveSettings(Settings() with { Profiles = [l2tp] });
        _world.Ras.SaveEntryFailure = new InvalidOperationException("Нет подходящего клиентского сертификата");
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var tunnel = coordinator.Facts.Tunnels[l2tp.Id];
        Assert.Equal(ErrorCategory.Certificate, tunnel.BlockingError);
        Assert.Equal(ErrorCategory.Certificate, tunnel.LastErrorCategory);
        Assert.Null(tunnel.LastErrorCode);
    }

    /// <summary>
    /// Под одним именем два узла SSTP с сертификатами разных издателей: адреса проверки отзыва берутся у обоих,
    /// потому что узел, на который попадёт RAS, неизвестен.
    /// </summary>
    [Fact]
    public async Task MultiNodeServer_RevocationHostsOfAllNodesAreKnown()
    {
        const string host = "vpn.example.org";
        var nodeA = Ipv4.Parse("203.0.113.31");
        var nodeB = Ipv4.Parse("203.0.113.32");
        _world.Resolver.Answers[host] = [nodeA, nodeB];
        ServerCertificateFacts Node(string thumbprint, string revocation) => new()
        {
            Subject = host, Issuer = "Let's Encrypt", Names = [host], NameMatches = true,
            NotBefore = _world.Time.GetUtcNow().AddDays(-7), NotAfter = _world.Time.GetUtcNow().AddDays(60), Thumbprint = thumbprint,
            RevocationUrls = ["http://" + revocation + "/1.crl"], RevocationHosts = [revocation],
        };
        _world.Probes.CertificatesByAddress[nodeA] = Node("AA", "r10.c.lencr.org");
        _world.Probes.CertificatesByAddress[nodeB] = Node("BB", "r11.c.lencr.org");
        SaveSettings(Settings() with { Profiles = [_profile with { Server = host }] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        for (var i = 0; i < 200 && coordinator.Facts.Tunnels[_profile.Id].RevocationHosts.Count < 2; i++)
        {
            await Task.Delay(10, TestContext.Current.CancellationToken);
            await CompleteDialAsync(coordinator);
        }

        var hosts = coordinator.Facts.Tunnels[_profile.Id].RevocationHosts;
        Assert.Contains("r10.c.lencr.org", hosts);
        Assert.Contains("r11.c.lencr.org", hosts);
    }

    /// <summary>
    /// При запуске службы файл активной RU-базы был занят (антивирус): база перечитывается через минуту, а не ждёт
    /// плановой проверки через дни. Сбой не мешает остальным шагам запуска.
    /// </summary>
    [Fact]
    public async Task GeoListLockedAtStartup_IsReloadedLater()
    {
        var first = await StartAsync();
        await ConnectAsync(first);
        Assert.True((await first.HandleRequestAsync(new GeoImportRequest(GeoContent(3)), CancellationToken.None)).Ok);
        var russian = Ipv4.Parse("77.88.0.1");
        Assert.Equal(DecisionSource.Geo, first.Facts.Policy!.Classify(russian).Source);

        var locks = Directory.EnumerateFiles(Path.Combine(_world.Paths.Geo, "revisions"), "*", SearchOption.AllDirectories)
            .Select(f => new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.None)).ToList();
        Coordinator restarted;
        try
        {
            restarted = await StartAsync();
            Assert.NotEqual(DecisionSource.Geo, restarted.Facts.Policy!.Classify(russian).Source);
        }
        finally
        {
            locks.ForEach(l => l.Dispose());
        }

        _world.Time.Advance(TimeSpan.FromMinutes(2));
        await TickAsync(restarted);
        await TickAsync(restarted);

        Assert.Equal(DecisionSource.Geo, restarted.Facts.Policy!.Classify(russian).Source);
    }

    /// <summary>«Отключить, сохранить защиту»: своё RAS-соединение, о котором служба не знает, тоже разрывается.</summary>
    [Fact]
    public async Task Protected_HangsUpUntrackedOwnConnection()
    {
        var coordinator = await StartAsync();
        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: true), CancellationToken.None);
        // Соединение осталось от дозвона, результат которого служба потеряла.
        _world.Ras.SaveEntry(Coordinator.EntryNameFor(_profile), _profile, []);
        await _world.Ras.DialAsync(Coordinator.EntryNameFor(_profile), "user", "secret".AsMemory(), null, CancellationToken.None);
        Assert.True(_world.Ras.Connected);

        coordinator.Facts.ReconcilePending = true;
        await TickAsync(coordinator);

        Assert.False(_world.Ras.Connected);
    }

    /// <summary>
    /// Найденное обновление не скачалось (обрыв), а следующая проверка получила «список не изменился» (304):
    /// загрузка всё равно продолжается, а не стоит до выхода следующей версии.
    /// </summary>
    [Fact]
    public async Task Tick_NotModified_ResumesInterruptedDownload()
    {
        var manifest = Manifest(expires: "2026-10-30T00:00:00+00:00");
        var packageFails = true;
        var notModified = 0;
        var source = new UpdateSource(manifest);
        source.Override = r =>
        {
            var url = r.RequestUri!.AbsoluteUri;
            if (url.EndsWith(".msi", StringComparison.Ordinal) && packageFails)
            {
                return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
            }

            if (!url.EndsWith(".json", StringComparison.Ordinal))
            {
                return null;
            }

            notModified += r.Headers.IfNoneMatch.Count > 0 ? 1 : 0;
            var response = r.Headers.IfNoneMatch.Count > 0
                ? new HttpResponseMessage(HttpStatusCode.NotModified)
                : new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(Encoding.UTF8.GetBytes(manifest)) };
            response.Headers.ETag = new EntityTagHeaderValue("\"m1\"");
            return response;
        };
        var coordinator = await UpdatingAsync(source);
        await TickAsync(coordinator);
        await PumpAsync(coordinator);
        Assert.Equal(UpdatePhase.Available, Status(coordinator).Phase);

        packageFails = false;
        _world.Time.Advance(TimeSpan.FromHours(3));
        await TickAsync(coordinator);
        await PumpAsync(coordinator);

        Assert.Equal(1, notModified);
        Assert.Equal(UpdatePhase.Ready, Status(coordinator).Phase);
    }

    /// <summary>Предложенная версия уже работает (её поставили вручную): после запуска службы предложение снято.</summary>
    [Fact]
    public async Task Startup_OfferedVersionAlreadyRunning_IsForgotten()
    {
        new UpdateStore(_world.Paths.Update).SaveState(new UpdateState
        {
            Phase = UpdatePhase.Ready,
            AvailableVersion = "0.8.0",
            PackageFileName = "SplitVpn-0.8.0.msi",
            PackageSha256 = PackageHash,
            PackageSize = Package.Length,
        });

        var coordinator = await StartAsync();

        Assert.Equal(UpdatePhase.Idle, Status(coordinator).Phase);
        Assert.DoesNotContain(coordinator.BuildStatus().Warnings, w => w.Code == "update-ready");
    }

    /// <summary>
    /// Служба перезапустилась, пока шла установка (откат запускает прежнюю службу): итог msiexec снова
    /// отслеживается, и отмена пользователем не превращается через 15 минут в «не установилось».
    /// </summary>
    [Fact]
    public async Task Startup_DuringInstall_WatchesInstallerAgain()
    {
        new UpdateStore(_world.Paths.Update).SaveState(new UpdateState
        {
            Phase = UpdatePhase.Installing,
            AvailableVersion = "0.9.0",
            InstallVersion = "0.9.0",
            PackageFileName = "SplitVpn-0.9.0.msi",
            PackageSha256 = PackageHash,
            PackageSize = Package.Length,
            InstallStartedUtc = _world.Time.GetUtcNow(),
            InstallerProcessId = 4242,
        });
        _world.ProcessExitCodes[4242] = 1602;

        var coordinator = await StartAsync();
        for (var i = 0; i < 200 && Status(coordinator).Phase == UpdatePhase.Installing; i++)
        {
            await coordinator.DrainAsync();
            await Task.Delay(5, TestContext.Current.CancellationToken);
        }

        Assert.Contains(4242, _world.WatchedProcesses);
        Assert.NotEqual(UpdatePhase.Installing, Status(coordinator).Phase);
    }

    /// <summary>Адаптер с DNS, заданным вручную, стал основным впервые: разрешение DNS службы для него есть сразу.</summary>
    [Fact]
    public async Task NewPrimaryWithStaticDns_ServiceDnsPermittedFromFirstApply()
    {
        new ServiceStores(_world.Paths).SaveState(new ServiceStateFile { Intent = Intent.Protected });
        _world.Inventory.WiFiDnsServers = [Ipv4.Parse("77.88.8.8")];
        _world.Dns.NameServers[FakeWorld.WiFiGuid] = "77.88.8.8";
        var coordinator = new Coordinator(_world.Dependencies());

        await coordinator.StartupAsync(CancellationToken.None);

        Assert.Contains(_world.Wfp.Groups[FilterGroup.Runtime], f => f.Name == "DNS службы 77.88.8.8");
    }
}
