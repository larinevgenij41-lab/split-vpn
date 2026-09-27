using System.Diagnostics;
using System.Globalization;
using System.Net;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Windows.Dns;

// Синтетические воспроизводимые входы; сокеты не открываются, настройки ПК не меняются.
var tunnel = Guid.Parse("aaaaaaaa-0000-0000-0000-000000000001");
var input = new PolicyInput
{
    DefaultTarget = RouteTarget.Tunnel(tunnel),
    GeoTarget = RouteTarget.Direct,
    Geo = RangeSet.From(Enumerable.Range(0, 10_000).Select(i => new Ipv4Range(0x20000000u + ((uint)i * 32768), 0x20001FFFu + ((uint)i * 32768)))),
    BypassTarget = RouteTarget.Tunnel(tunnel),
    Bypass = RangeSet.From(Enumerable.Range(0, 20_000).Select(i => new Ipv4Range(0x20001000u + ((uint)i * 16384), 0x200017FFu + ((uint)i * 16384)))),
    OnLinePrefixes = [Ipv4Cidr.Parse("192.168.1.0/24")],
    ServerAddresses = [Ipv4.Parse("5.1.2.3")],
    ServiceDnsAddresses = [Ipv4.Parse("192.168.1.1")],
    TunnelHosts = [new TunnelHost(tunnel, Ipv4.Parse("10.1.0.1"))],
};
Measure("policy-10k-20k", 100, () => GC.KeepAlive(PolicyCompiler.Compile(input)));

var protection = new ProtectionInputs
{
    Policy = PolicyCompiler.Compile(input), PrimaryLuid = 8,
    Tunnels = [new TunnelInput { Id = tunnel, Luid = 56, ServesDefault = true }],
};
Console.WriteLine($"filter-specs: Direct={FilterPlanBuilder.BuildDirect(protection).Count}; Runtime={FilterPlanBuilder.BuildRuntime(protection).Count}");
Measure("filter-plan-10k-20k", 100, () =>
{
    GC.KeepAlive(FilterPlanBuilder.BuildDirect(protection));
    GC.KeepAlive(FilterPlanBuilder.BuildRuntime(protection));
});

foreach (var ruleCount in new[] { 0, 20, 200 })
{
    var cache = new DnsCache(TimeProvider.System);
    await using var proxy = new DnsProxyServer(IPAddress.Loopback, cache);
    var query = DnsMessage.BuildQuery(1, "host.corp.example", DnsMessage.TypeA);
    DnsMessage.TryReadQuestion(query, out var question);
    cache.Put(question, "", DnsMessage.BuildAddressResponse(query, [0x0A000001u], 3600));
    proxy.Configuration = new DnsProxyConfiguration
    {
        Mode = DnsProxyMode.Offline,
        Local = new DnsRoute([], null),
        LocalSuffixes = ["lan", "local"],
        DomainRoutes = Enumerable.Range(0, ruleCount)
            .Select(i => new DomainRoute(i == ruleCount - 1 ? "corp.example" : $"domain{i}.example", RouteTarget.Tunnel(tunnel), null, PinAddresses: false))
            .ToArray(),
    };
    Measure($"cached-dns-{ruleCount}-rules", 20_000, () =>
    {
        var response = proxy.HandleAsync(query, CancellationToken.None).GetAwaiter().GetResult();
        if (response is null || DnsMessage.GetRcode(response) != 0)
        {
            throw new InvalidOperationException("DNS benchmark did not return a cached answer.");
        }
    });
}

static void Measure(string name, int iterations, Action action)
{
    for (var i = 0; i < 200; i++)
    {
        action();
    }

    var samples = new List<(double Microseconds, long Bytes)>();
    for (var sample = 0; sample < 5; sample++)
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        var allocated = GC.GetAllocatedBytesForCurrentThread();
        var start = Stopwatch.GetTimestamp();
        for (var i = 0; i < iterations; i++)
        {
            action();
        }

        var elapsed = Stopwatch.GetElapsedTime(start);
        samples.Add((elapsed.TotalMicroseconds / iterations, (GC.GetAllocatedBytesForCurrentThread() - allocated) / iterations));
    }

    var median = samples.OrderBy(s => s.Microseconds).ElementAt(samples.Count / 2);
    Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"{name}: {median.Microseconds:F3} us/op; {median.Bytes} B/op"));
}
