using System.Net;
using System.Net.Sockets;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Net;
using SplitVpn.Windows.Diagnostics;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Cli.Proto;

/// <summary>S4. DNS-посредник от SYSTEM: порт 53 при ICS, loopback на основном адаптере, upstream через туннель.</summary>
internal static class DnsScenario
{
    public static async Task<int> RunAsync(CliArgs args)
    {
        var report = new ScenarioReport("s4-dns");
        var profile = ProtoContext.LoadProfile();
        var password = ProtoContext.LoadPassword();
        var primary = ProtoNet.PrimaryAdapter(NetInventory.Capture());
        var store = new DnsBackupStore(ProtoContext.DnsBackupPath);
        RasConnectionHandle? connection = null;
        DnsProxyServer? proxy = null;
        try
        {
            report.Measure("sharedAccess", SystemMetrics.ServiceStatus("SharedAccess"));
            proxy = StartProxy(report);
            if (proxy is null)
            {
                return await report.SaveAsync(args, [profile.UserName, profile.Server]);
            }

            RasPhonebook.Save(ProtoContext.Phonebook, new RasEntrySpec(ProtoContext.EntryName, profile.Server));
            connection = await RasScenario.DialAndDescribeAsync(report, profile, password);
            var tunnel = connection is null ? null : RasScenario.FindTunnel(RasClient.GetProjection(connection.Value).ClientAddress);
            if (tunnel is null)
            {
                return await report.SaveAsync(args, [profile.UserName, profile.Server]);
            }

            report.Check("Маршруты /1 через туннель", ProtoNet.AddHalfRoutes(tunnel.Luid).All(code => code == 0), "для upstream через IP_UNICAST_IF");
            var vpnDns = NetInventory.ReadDnsServersFromRegistry(tunnel.InterfaceGuid);
            await CheckUpstreamsAsync(report, tunnel, vpnDns);
            proxy.Configuration = new DnsProxyConfiguration
            {
                Mode = DnsProxyMode.Online,
                Tunnel = new DnsRoute(vpnDns.Select(s => new IPEndPoint(Ipv4.ToAddress(s), 53)).ToList(), tunnel.InterfaceIndex),
            };

            await CheckSystemResolverAsync(report, primary, tunnel, store, proxy);
            connection = await CheckPppDnsVariantsAsync(report, profile, password, connection!.Value, tunnel, proxy);
            await CheckSharedAccessRestartAsync(report, proxy);
        }
        catch (Exception ex)
        {
            report.Fail("Сценарий прерван", ex);
        }
        finally
        {
            Array.Clear(password);
            RestoreDns(report, primary, store);
            RouteOps.RemoveAllMarked();
            if (connection is { } handle)
            {
                await RasClient.HangUpAsync(handle, CancellationToken.None);
            }

            if (proxy is not null)
            {
                await proxy.DisposeAsync();
            }
        }

        return await report.SaveAsync(args, [profile.UserName, profile.Server]);
    }

    private static DnsProxyServer? StartProxy(ScenarioReport report)
    {
        foreach (var address in new[] { IPAddress.Loopback, IPAddress.IPv6Loopback })
        {
            var proxy = new DnsProxyServer(address, new DnsCache(TimeProvider.System));
            try
            {
                proxy.Start();
                report.Check($"Bind UDP {address}:53 (SO_EXCLUSIVEADDRUSE) при работающем ICS", true, "успешно");
                report.Measure("proxyAddress", address.ToString());
                return proxy;
            }
            catch (SocketException ex)
            {
                report.Check($"Bind UDP {address}:53 (SO_EXCLUSIVEADDRUSE) при работающем ICS", false, ex.SocketErrorCode.ToString());
                proxy.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
        }

        return null;
    }

    private static async Task CheckUpstreamsAsync(ScenarioReport report, AdapterCandidate tunnel, IReadOnlyList<uint> vpnDns)
    {
        foreach (var upstream in vpnDns.Concat([ProtoNet.ForeignTargets[0], Ipv4.Parse("77.88.8.8")]))
        {
            var addresses = await BootstrapResolver.ResolveAsync("example.com", [upstream], tunnel.InterfaceIndex, CancellationToken.None);
            report.Check($"Upstream {Ipv4.Format(upstream)} через туннель (IP_UNICAST_IF)", addresses.Count > 0, string.Join(", ", addresses.Select(Ipv4.Format)));
        }
    }

    private static async Task CheckSystemResolverAsync(ScenarioReport report, AdapterCandidate primary, AdapterCandidate tunnel, DnsBackupStore store, DnsProxyServer proxy)
    {
        var before = InterfaceDnsOps.Read(primary.InterfaceGuid, ipv6: false);
        report.Measure("primaryDnsBefore", new { before.NameServer, before.ProfileNameServer, before.DohServerProperties, dhcp = primary.DnsServers.Select(Ipv4.Format) });
        var backup = InterfaceDnsOps.Capture(primary.InterfaceGuid, store.Load().GetValueOrDefault(primary.InterfaceGuid), DateTimeOffset.UtcNow);
        store.Upsert(backup);
        InterfaceDnsOps.ApplyLoopback(primary.InterfaceGuid);
        InterfaceDnsOps.ApplyLoopback(tunnel.InterfaceGuid);
        InterfaceDnsOps.FlushResolverCache();

        var queriesBefore = proxy.Stats.Queries;
        var name = $"t{Random.Shared.Next(100000, 999999)}.example.com";
        var system = await TryResolveAsync("ya.ru");
        _ = await TryResolveAsync(name);
        report.Check("Системный резолвер отвечает через посредник", system.Length > 0, string.Join(", ", system.Select(a => a.ToString())));
        report.Check("Запросы системного резолвера пришли в посредник", proxy.Stats.Queries > queriesBefore, $"запросов: {proxy.Stats.Queries - queriesBefore}");
        report.Measure("proxyStats", proxy.Stats);

        var loopbackCaptured = InterfaceDnsOps.Capture(primary.InterfaceGuid, backup, DateTimeOffset.UtcNow);
        report.Check("Loopback не сохраняется как исходный DNS", loopbackCaptured.NameServerV4 == backup.NameServerV4, $"«{loopbackCaptured.NameServerV4}»");
    }

    /// <summary>
    /// Вариант (a): loopback ставится на PPP-интерфейс после подключения. Вариант (b): в записи RAS задан
    /// DNS 127.0.0.1 (RASEO_SpecificNameServers) — тогда RAS сам не выдаёт системе DNS сервера.
    /// </summary>
    private static async Task<RasConnectionHandle?> CheckPppDnsVariantsAsync(ScenarioReport report, ProtoProfile profile, char[] password, RasConnectionHandle current, AdapterCandidate tunnel, DnsProxyServer proxy)
    {
        var variantA = InterfaceDnsOps.Read(tunnel.InterfaceGuid, ipv6: false);
        report.Measure("pppDnsVariantA", new { variantA.NameServer, registry = NetInventory.ReadDnsServersFromRegistry(tunnel.InterfaceGuid).Select(Ipv4.Format) });
        InterfaceDnsOps.SetNameServer(tunnel.InterfaceGuid, "", ipv6: false);
        await RasClient.HangUpAsync(current, CancellationToken.None);

        RasPhonebook.Save(ProtoContext.Phonebook, new RasEntrySpec(ProtoContext.EntryName, profile.Server, DnsServer: Ipv4.Parse("127.0.0.1")));
        var handle = await RasScenario.DialAndDescribeAsync(report, profile, password);
        var newTunnel = handle is null ? null : RasScenario.FindTunnel(RasClient.GetProjection(handle.Value).ClientAddress);
        if (newTunnel is null)
        {
            return handle;
        }

        ProtoNet.AddHalfRoutes(newTunnel.Luid);
        proxy.Configuration = proxy.Configuration with { Tunnel = proxy.Configuration.Tunnel! with { InterfaceIndex = newTunnel.InterfaceIndex } };
        var dns = NetInventory.ReadDnsServersFromRegistry(newTunnel.InterfaceGuid);
        report.Check("Вариант (b): DNS PPP-интерфейса = 127.0.0.1 из записи RAS", dns.Count > 0 && dns.All(d => d == Ipv4.Parse("127.0.0.1")), string.Join(", ", dns.Select(Ipv4.Format)));
        InterfaceDnsOps.FlushResolverCache();
        var resolved = await TryResolveAsync("mail.ru");
        report.Check("Вариант (b): системный резолвер работает через посредник", resolved.Length > 0, string.Join(", ", resolved.Select(a => a.ToString())));
        return handle;
    }
    private static async Task CheckSharedAccessRestartAsync(ScenarioReport report, DnsProxyServer proxy)
    {
        if (SystemMetrics.ServiceStatus("SharedAccess").State != "SERVICE_RUNNING")
        {
            report.Note("ICS не запущена — проверка очерёдности bind пропущена.");
            return;
        }

        RunSc("stop SharedAccess");
        await WaitForStateAsync("SharedAccess", "SERVICE_STOPPED");
        RunSc("start SharedAccess");
        var running = await WaitForStateAsync("SharedAccess", "SERVICE_RUNNING");
        report.Check("ICS запускается, когда наш сокет уже занял 127.0.0.1:53", running, SystemMetrics.ServiceStatus("SharedAccess").State);
        var resolved = await TryResolveAsync("ya.ru");
        report.Check("Посредник продолжает отвечать после перезапуска ICS", resolved.Length > 0, $"статистика {proxy.Stats}");
    }

    private static void RunSc(string arguments)
    {
        using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("sc.exe", arguments) { CreateNoWindow = true, UseShellExecute = false });
        process?.WaitForExit(30_000);
    }

    private static async Task<bool> WaitForStateAsync(string service, string state)
    {
        for (var i = 0; i < 60; i++)
        {
            if (SystemMetrics.ServiceStatus(service).State == state)
            {
                return true;
            }

            await Task.Delay(500);
        }

        return false;
    }
    private static void RestoreDns(ScenarioReport report, AdapterCandidate primary, DnsBackupStore store)
    {
        try
        {
            var outcome = InterfaceDnsOps.Restore(primary.InterfaceGuid, store.Load().GetValueOrDefault(primary.InterfaceGuid));
            store.Remove(primary.InterfaceGuid);
            InterfaceDnsOps.FlushResolverCache();
            var after = InterfaceDnsOps.Read(primary.InterfaceGuid, ipv6: false);
            report.Check("DNS основного адаптера возвращён", !InterfaceDnsOps.IsLoopback(after.NameServer), $"{outcome}; NameServer «{after.NameServer}», DHCP {string.Join(", ", NetInventory.ReadDnsServersFromRegistry(primary.InterfaceGuid).Select(Ipv4.Format))}");
        }
        catch (Exception ex)
        {
            report.Fail("Возврат DNS", ex);
        }
    }

    private static async Task<IPAddress[]> TryResolveAsync(string name)
    {
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(8));
            return await Dns.GetHostAddressesAsync(name, AddressFamily.InterNetwork, cts.Token);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            return [];
        }
    }
}
