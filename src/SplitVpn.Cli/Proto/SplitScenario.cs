using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.Ras;
using SplitVpn.Windows.Wfp;

namespace SplitVpn.Cli.Proto;

/// <summary>
/// S3. Полное разделение с общесистемной защитой в динамической сессии WFP: при завершении процесса
/// фильтры исчезают сами; маршруты и RAS снимаются в finally.
/// </summary>
internal static class SplitScenario
{
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(6);

    public static async Task<int> RunAsync(CliArgs args)
    {
        var report = new ScenarioReport("s3-split");
        var profile = ProtoContext.LoadProfile();
        var password = ProtoContext.LoadPassword();
        var state = new SplitState();
        try
        {
            await PrepareAsync(report, args, profile, state);
            using var preexisting = await OpenPreexistingConnectionAsync(report);
            using var engine = WfpEngine.Open(dynamicSession: true);
            WfpOps.EnsureProviderAndSubLayer(engine, WfpIdentity.Prototype, persistent: false);
            ApplyGroups(report, engine, state, tunnelLuid: null, "до туннеля");
            await ProbePreexistingAsync(report, preexisting);
            using var pktmon = new PktmonProbe();
            StartPktmon(report, pktmon);
            await ProbeProtectedWithoutTunnelAsync(report, state, "до туннеля");
            CheckPktmon(report, pktmon, state, "до туннеля");

            if (!await ConnectTunnelAsync(report, engine, state, profile, password))
            {
                return await report.SaveAsync(args, Secrets(profile));
            }

            await ProbeConnectedAsync(report, state);
            await ProbeReapplyDuringDownloadAsync(report, engine, state);
            CheckPktmon(report, pktmon, state, "в подключённом состоянии");

            await SimulateOutageAsync(report, engine, state, pktmon, args.IntOption("--outage-seconds", 30));
            if (await ConnectTunnelAsync(report, engine, state, profile, password))
            {
                var recovered = await ProtoNet.TcpAsync(ProtoNet.ForeignTargets[0], 443, null, ProbeTimeout);
                report.Check("После повторного подключения иностранный адрес снова доступен", recovered.Outcome == ProbeOutcome.Connected, Describe(recovered));
            }
        }
        catch (Exception ex)
        {
            report.Fail("Сценарий прерван", ex);
        }
        finally
        {
            Array.Clear(password);
            await CleanupAsync(report, state);
        }

        return await report.SaveAsync(args, Secrets(profile));
    }

    private static async Task PrepareAsync(ScenarioReport report, CliArgs args, ProtoProfile profile, SplitState state)
    {
        var snapshot = NetInventory.Capture();
        state.Primary = ProtoNet.PrimaryAdapter(snapshot);
        state.Radmin = snapshot.Adapters.FirstOrDefault(a => a.IsUp && a.Luid != state.Primary.Luid && a.DefaultGateway is not null);
        report.Measure("primary", new { state.Primary.Name, gateway = Ipv4.Format(state.Primary.DefaultGateway!.Value), dns = state.Primary.DnsServers.Select(Ipv4.Format) });

        state.ServiceDns = state.Primary.DnsServers.ToList();
        state.OnLink = snapshot.Adapters.Where(a => a.IsUp).SelectMany(a => a.OnLinkPrefixes).Where(p => p.PrefixLength >= PolicyCompiler.MinOnLinkPrefix).Distinct().ToList();
        state.Server = ServerAddress.Parse(profile.Server);
        state.ServerAddresses = await BootstrapResolver.ResolveAsync(state.Server.Host, state.ServiceDns, state.Primary.InterfaceIndex, CancellationToken.None);
        report.Check("Начальное разрешение имени сервера через исходный DNS", state.ServerAddresses.Count > 0, string.Join(", ", state.ServerAddresses.Select(Ipv4.Format)));

        state.Policy = PolicyCompiler.Compile(new PolicyInput
        {
            Geo = ProtoNet.LoadGeo(ProtoContext.GeoPath(args)),
            ServerAddresses = state.ServerAddresses,
            ServiceDnsAddresses = state.ServiceDns,
            OnLinePrefixes = state.OnLink,
        });

        // Сначала /32 сервера, затем RU-блоки: поведение совпадает с маршрутом по умолчанию.
        var routes = state.ServerAddresses.Select(a => new RouteKey(new Ipv4Cidr(a, 32), state.Primary.DefaultGateway.Value, state.Primary.Luid))
            .Concat(state.Policy.DirectRouteCidrs.Select(c => new RouteKey(c, state.Primary.DefaultGateway.Value, state.Primary.Luid)))
            .ToList();
        var result = RouteOps.Reconcile(routes);
        report.Measure("directRoutesSeconds", Math.Round(result.Elapsed.TotalSeconds, 1));
        report.Check("Маршруты /32 сервера и RU применены", result.Failed == 0, $"добавлено {result.Added}, ошибок {result.Failed}");
    }

    /// <summary>В прототипе один туннель: его идентификатор фиксирован.</summary>
    internal static readonly Guid PrototypeTunnelId = new("11111111-1111-1111-1111-111111111111");

    private static void ApplyGroups(ScenarioReport report, WfpEngine engine, SplitState state, ulong? tunnelLuid, string stage)
    {
        var inputs = new ProtectionInputs
        {
            Policy = state.Policy!,
            PrimaryLuid = state.Primary!.Luid,
            Tunnels = [new TunnelInput { Id = PrototypeTunnelId, Name = "прототип", Luid = tunnelLuid, ServerAddresses = state.Policy!.ServerAddresses, ServerPort = state.Server.Port, ServesDefault = true }],
            Intent = Intent.Connected,
            OutageMode = OutageMode.BlockVpnTraffic,
            ServiceDnsAddresses = state.ServiceDns,
            ServiceExecutablePath = Environment.ProcessPath!,
            OnLinkPrefixes = state.OnLink,
        };

        var stopwatch = Stopwatch.StartNew();
        engine.InTransaction(e =>
        {
            WfpOps.DeleteFilters(e, state.RuntimeIds);
            state.RuntimeIds = [.. WfpOps.AddFilters(e, WfpIdentity.Prototype, FilterPlanBuilder.BuildRuntime(inputs), persistent: false)];
            if (state.BaseIds.Count == 0)
            {
                state.BaseIds = [.. WfpOps.AddFilters(e, WfpIdentity.Prototype, FilterPlanBuilder.BuildBase(inputs), persistent: false)];
                state.DirectIds = [.. WfpOps.AddFilters(e, WfpIdentity.Prototype, FilterPlanBuilder.BuildDirect(inputs), persistent: false, indexed: true)];
            }
        });
        report.Measure("wfpApplySeconds " + stage, Math.Round(stopwatch.Elapsed.TotalSeconds, 2));
        report.Measure("wfpFilters " + stage, new { baseCount = state.BaseIds.Count, direct = state.DirectIds.Count, runtime = state.RuntimeIds.Count });
    }

    private static async Task<bool> ConnectTunnelAsync(ScenarioReport report, WfpEngine engine, SplitState state, ProtoProfile profile, char[] password)
    {
        RasPhonebook.Save(ProtoContext.Phonebook, new RasEntrySpec(ProtoContext.EntryName, profile.Server));
        var handle = await RasScenario.DialAndDescribeAsync(report, profile, password);
        if (handle is null)
        {
            return false;
        }

        state.Connection = handle;
        state.Tunnel = RasScenario.FindTunnel(RasClient.GetProjection(handle.Value).ClientAddress);
        if (state.Tunnel is null)
        {
            return false;
        }

        ApplyGroups(report, engine, state, state.Tunnel.Luid, "туннель");
        var halves = new[] { Ipv4Cidr.Parse("0.0.0.0/1"), Ipv4Cidr.Parse("128.0.0.0/1") }
            .Select(c => new RouteKey(c, 0, state.Tunnel.Luid));
        var codes = halves.Select(RouteOps.Add).ToList();
        return report.Check("Маршруты 0.0.0.0/1 и 128.0.0.0/1 через туннель", codes.All(c => c == 0), string.Join(", ", codes));
    }

    private static async Task<TcpClient?> OpenPreexistingConnectionAsync(ScenarioReport report)
    {
        var client = new TcpClient();
        try
        {
            using var cts = new CancellationTokenSource(ProbeTimeout);
            await client.ConnectAsync(Ipv4.ToAddress(ProtoNet.ForeignTargets[0]), 443, cts.Token);
            report.Note("Открыто соединение к иностранному адресу до применения фильтров.");
            return client;
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            report.Note("Не удалось открыть соединение до фильтров: " + ex.Message);
            client.Dispose();
            return null;
        }
    }

    private static async Task ProbePreexistingAsync(ScenarioReport report, TcpClient? client)
    {
        if (client is null)
        {
            return;
        }

        var stream = client.GetStream();
        var failed = false;
        try
        {
            using var cts = new CancellationTokenSource(ProbeTimeout);
            await stream.WriteAsync(new byte[] { 0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00 }, cts.Token);
            var buffer = new byte[64];
            var read = await stream.ReadAsync(buffer, cts.Token);
            failed = read == 0;
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException)
        {
            failed = true;
        }

        report.Check("Соединение, открытое до фильтров, прекращает обмен (переавторизация)", failed, failed ? "обмен прерван" : "данные прошли");
    }

    private static async Task ProbeProtectedWithoutTunnelAsync(ScenarioReport report, SplitState state, string stage)
    {
        var russian = await ProtoNet.TcpAsync(ProtoNet.RussianTargets[0], 443, null, ProbeTimeout);
        report.Check($"RU-адрес доступен напрямую ({stage})", russian.Outcome == ProbeOutcome.Connected, Describe(russian));
        var foreign = await ProtoNet.TcpAsync(ProtoNet.ForeignTargets[0], 443, null, ProbeTimeout);
        report.Check($"Иностранный адрес заблокирован ({stage})", foreign.Outcome is ProbeOutcome.Blocked or ProbeOutcome.Timeout, Describe(foreign));
        // Датаграмму, отброшенную WFP, sendto не отвергает: результат проверяется счётчиками pktmon стадии.
        _ = await ProtoNet.UdpSendAsync(ProtoNet.ForeignTargets[1], 443, null);
        report.Note($"UDP 443 к {Ipv4.Format(ProtoNet.ForeignTargets[1])} отправлен ({stage}) — проверка по pktmon.");
        var server = await ProtoNet.TcpAsync(state.ServerAddresses[0], state.Server.Port, null, ProbeTimeout);
        report.Check($"Транспорт к SSTP-серверу разрешён ({stage})", server.Outcome == ProbeOutcome.Connected, Describe(server));
    }

    private static async Task ProbeConnectedAsync(ScenarioReport report, SplitState state)
    {
        var primaryAddress = state.Primary!.Addresses[0];
        var vpnAddress = state.Tunnel!.Addresses[0];
        var random = new Random(3);
        var direct = ProtoNet.VerifyRoutes(ProtoNet.SampleRanges(state.Policy!.DirectRanges, 1000, random), state.Primary.Luid);
        report.Check("GetBestRoute2: RU → основной адаптер", direct.Matched == direct.Total, $"{direct.Matched}/{direct.Total} {string.Join("; ", direct.Examples)}");
        var foreignRoutes = ProtoNet.VerifyRoutes(ProtoNet.SampleForeign(state.Policy, 1000, random), state.Tunnel.Luid);
        report.Check("GetBestRoute2: иностранные → туннель", foreignRoutes.Matched == foreignRoutes.Total, $"{foreignRoutes.Matched}/{foreignRoutes.Total} {string.Join("; ", foreignRoutes.Examples)}");

        foreach (var target in ProtoNet.ForeignTargets)
        {
            var probe = await ProtoNet.TcpAsync(target, 443, null, ProbeTimeout);
            report.Check($"TCP {Ipv4.Format(target)}:443 через туннель", probe.Outcome == ProbeOutcome.Connected && probe.LocalAddress == Ipv4.Format(vpnAddress), Describe(probe));
            var bypass = await ProtoNet.TcpAsync(target, 443, primaryAddress, ProbeTimeout);
            report.Check($"Обход через Wi-Fi к {Ipv4.Format(target)} заблокирован", bypass.Outcome is ProbeOutcome.Blocked or ProbeOutcome.Timeout, Describe(bypass));
        }

        foreach (var target in ProtoNet.RussianTargets)
        {
            var probe = await ProtoNet.TcpAsync(target, 443, null, ProbeTimeout);
            report.Check($"TCP {Ipv4.Format(target)}:443 напрямую", probe.Outcome == ProbeOutcome.Connected && probe.LocalAddress == Ipv4.Format(primaryAddress), Describe(probe));
        }

        await ProbeOtherInterfaceAsync(report, state);
        await ProbeUdpIcmpDnsAsync(report, state, primaryAddress);
    }

    private static async Task ProbeOtherInterfaceAsync(ScenarioReport report, SplitState state)
    {
        if (state.Radmin is not { Addresses.Count: > 0 } other)
        {
            report.Note("Второго интерфейса с маршрутом по умолчанию нет — проверка обхода через него пропущена.");
            return;
        }

        var viaOther = await ProtoNet.TcpAsync(ProtoNet.RussianTargets[0], 443, other.Addresses[0], ProbeTimeout);
        report.Check($"RU через «{other.Name}» заблокирован (только основной адаптер)", viaOther.Outcome is ProbeOutcome.Blocked or ProbeOutcome.Timeout, Describe(viaOther));
    }

    private static async Task ProbeUdpIcmpDnsAsync(ScenarioReport report, SplitState state, uint primaryAddress)
    {
        var udpTunnel = await ProtoNet.UdpSendAsync(ProtoNet.ForeignTargets[0], 443, null);
        report.Check("UDP 443 к иностранному адресу через туннель", udpTunnel.Outcome == ProbeOutcome.Connected, Describe(udpTunnel));
        _ = await ProtoNet.UdpSendAsync(ProtoNet.ForeignTargets[0], 443, primaryAddress);
        report.Note("UDP 443 в обход через Wi-Fi отправлен — проверка по pktmon.");

        using var ping = new Ping();
        var reply = await ping.SendPingAsync(Ipv4.ToAddress(ProtoNet.ForeignTargets[0]), 3000);
        report.Check("ICMP к иностранному адресу через туннель", reply.Status == IPStatus.Success, reply.Status.ToString());

        var guarded = await BootstrapResolver.ResolveAsync("ya.ru", [Ipv4.Parse("77.88.8.8")], state.Primary!.InterfaceIndex, CancellationToken.None);
        report.Check("DNS к RU-резолверу через Wi-Fi заблокирован стражем (ответа нет)", guarded.Count == 0, guarded.Count == 0 ? "ответа нет" : string.Join(", ", guarded.Select(Ipv4.Format)));

        var tunnelDns = await BootstrapResolver.ResolveAsync("ya.ru", [ProtoNet.ForeignTargets[0]], state.Tunnel!.InterfaceIndex, CancellationToken.None);
        report.Check("DNS через туннель (IP_UNICAST_IF) работает", tunnelDns.Count > 0, string.Join(", ", tunnelDns.Select(Ipv4.Format)));
    }

    private static async Task ProbeReapplyDuringDownloadAsync(ScenarioReport report, WfpEngine engine, SplitState state)
    {
        var resolved = await BootstrapResolver.ResolveAsync("speed.cloudflare.com", [ProtoNet.ForeignTargets[0]], state.Tunnel!.InterfaceIndex, CancellationToken.None);
        if (resolved.Count == 0)
        {
            report.Check("Загрузка через туннель пережила переприменение фильтров", false, "не удалось разрешить speed.cloudflare.com через туннель");
            return;
        }

        var target = resolved[0];
        using var handler = new SocketsHttpHandler
        {
            ConnectCallback = async (context, token) =>
            {
                var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                await socket.ConnectAsync(Ipv4.ToAddress(target), 443, token);
                return new NetworkStream(socket, ownsSocket: true);
            },
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(60) };
        var download = Task.Run(async () =>
        {
            using var response = await client.GetAsync(new Uri("https://speed.cloudflare.com/__down?bytes=30000000"), HttpCompletionOption.ResponseHeadersRead);
            await using var stream = await response.Content.ReadAsStreamAsync();
            var buffer = new byte[81920];
            long total = 0;
            int read;
            while ((read = await stream.ReadAsync(buffer)) > 0)
            {
                total += read;
            }

            return total;
        });

        await Task.Delay(TimeSpan.FromSeconds(2));
        ApplyGroups(report, engine, state, state.Tunnel!.Luid, "переприменение во время загрузки");
        try
        {
            var bytes = await download;
            report.Check("Загрузка через туннель пережила переприменение фильтров", bytes > 1_000_000, $"{bytes} байт");
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or TaskCanceledException)
        {
            report.Check("Загрузка через туннель пережила переприменение фильтров", false, ex.Message);
        }
    }

    private static void StartPktmon(ScenarioReport report, PktmonProbe pktmon)
    {
        pktmon.Start(ProtoNet.ForeignTargets);
        report.Note("pktmon: счётчики пакетов к иностранным тестовым адресам запущены.");
    }

    private static void CheckPktmon(ScenarioReport report, PktmonProbe pktmon, SplitState state, string stage)
    {
        var groups = pktmon.Snapshot();
        report.Measure("pktmon " + stage, groups);
        var physical = groups.Where(g => string.Equals(g.Group, state.Primary!.Description, StringComparison.OrdinalIgnoreCase)).ToList();
        var outbound = physical.Sum(g => g.OutboundFlowPackets);
        var drops = physical.Sum(g => g.OutboundDrops);
        report.Check($"pktmon: 0 исходящих пакетов к иностранным адресам на «{state.Primary!.Description}» ({stage})", outbound == 0, $"исходящих потоков {outbound}, отброшено стеком {drops}");
        PktmonProbe.Reset();
    }
    private static async Task SimulateOutageAsync(ScenarioReport report, WfpEngine engine, SplitState state, PktmonProbe pktmon, int seconds)
    {
        report.Note($"Обрыв: разрываем туннель на {seconds} с.");
        await RasClient.HangUpAsync(state.Connection!.Value, CancellationToken.None);
        state.Connection = null;
        var halvesLeft = RouteOps.ListMarked().Count(r => r.Destination.PrefixLength == 1);
        var anyHalf = NetInventory.ReadRoutesV4().Count(r => r.Destination.PrefixLength == 1 && r.InterfaceLuid == state.Tunnel!.Luid);
        report.Check("Маршруты /1 исчезли вместе с интерфейсом", anyHalf == 0, $"помеченных /1: {halvesLeft}, на туннеле: {anyHalf}");
        ApplyGroups(report, engine, state, tunnelLuid: null, "обрыв");

        var deadline = DateTime.UtcNow.AddSeconds(seconds);
        await ProbeProtectedWithoutTunnelAsync(report, state, "обрыв");
        while (DateTime.UtcNow < deadline)
        {
            _ = await ProtoNet.TcpAsync(ProtoNet.ForeignTargets[1], 443, null, TimeSpan.FromSeconds(2));
            await Task.Delay(TimeSpan.FromSeconds(2));
        }

        CheckPktmon(report, pktmon, state, "при обрыве");
    }

    private static async Task CleanupAsync(ScenarioReport report, SplitState state)
    {
        if (state.Connection is { } connection)
        {
            await RasClient.HangUpAsync(connection, CancellationToken.None);
        }

        var routes = RouteOps.RemoveAllMarked();
        report.Measure("cleanupRoutesRemoved", routes.Removed);
        report.Note("Динамическая сессия WFP закрыта — фильтры прототипа удалены.");
    }

    private static string Describe(ProbeResult probe) =>
        $"{probe.Outcome}{(probe.LocalAddress is null ? "" : " с " + probe.LocalAddress)} за {probe.Milliseconds:F0} мс{(probe.Error is null ? "" : " (" + probe.Error + ")")}";

    private static string?[] Secrets(ProtoProfile profile) => [profile.UserName, profile.Server];

    private sealed class SplitState
    {
        public AdapterCandidate? Primary { get; set; }

        public AdapterCandidate? Radmin { get; set; }

        public AdapterCandidate? Tunnel { get; set; }

        public ServerAddress Server { get; set; }

        public IReadOnlyList<uint> ServerAddresses { get; set; } = [];

        public List<uint> ServiceDns { get; set; } = [];

        public List<Ipv4Cidr> OnLink { get; set; } = [];

        public CompiledPolicy? Policy { get; set; }

        public RasConnectionHandle? Connection { get; set; }

        public List<ulong> BaseIds { get; set; } = [];

        public List<ulong> DirectIds { get; set; } = [];

        public List<ulong> RuntimeIds { get; set; } = [];
    }
}
