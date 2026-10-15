using System.Diagnostics;
using System.Globalization;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;

// Только вычисления в памяти: служба, сокеты и нативные сетевые API не запускаются.
Console.WriteLine($"Runtime: {Environment.Version}; CPU count: {Environment.ProcessorCount}");
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
var protection = new ProtectionInputs
{
    Policy = PolicyCompiler.Compile(input), PrimaryLuid = 8,
    Tunnels = [new TunnelInput { Id = tunnel, Luid = 56, ServesDefault = true }],
};
// Историческое выражение из Coordinator.FilterFingerprint в e7de6f0 для сравнения.
Func<IReadOnlyList<FilterSpec>, string> fingerprint = LegacyFingerprint;
var direct = FilterPlanBuilder.BuildDirect(protection);
Console.WriteLine($"Direct specs: {direct.Count}; fingerprint chars: {fingerprint(direct).Length}");
Measure("compile-policy-10k-20k", 30, () => GC.KeepAlive(PolicyCompiler.Compile(input)));
Measure("build-direct-plan", 30, () => GC.KeepAlive(FilterPlanBuilder.BuildDirect(protection)));
Measure("legacy-direct-fingerprint", 30, () => GC.KeepAlive(fingerprint(direct)));
Measure("legacy-compile-all-plans-and-fingerprints", 20, () =>
{
    var current = protection with { Policy = PolicyCompiler.Compile(input) };
    GC.KeepAlive(fingerprint(FilterPlanBuilder.BuildBase(current)));
    GC.KeepAlive(fingerprint(FilterPlanBuilder.BuildRuntime(current)));
    GC.KeepAlive(fingerprint(FilterPlanBuilder.BuildDynamic(current)));
    GC.KeepAlive(fingerprint(FilterPlanBuilder.BuildDirect(current)));
});

foreach (var count in new[] { 0, 100, 1_000, 10_000 })
{
    var pins = Enumerable.Range(0, count).Select(i => new PinnedHost(0x08000000u + (uint)i, RouteTarget.Tunnel(tunnel))).ToArray();
    var first = input with { PinnedHosts = pins };
    var second = input with { PinnedHosts = [.. pins, new PinnedHost(0x09000000u, RouteTarget.Direct)] };
    var policyCache = new PolicyCompilationCache();
    var planCache = new FilterPlanCache();
    var previous = planCache.Build(protection with { Policy = policyCache.Compile(first) });
    var toggle = false;
    if (count == 1_000)
    {
        Measure("legacy-policy-plan-update-1000-pins", 20, () =>
        {
            toggle = !toggle;
            var current = protection with { Policy = PolicyCompiler.Compile(toggle ? second : first) };
            GC.KeepAlive(fingerprint(FilterPlanBuilder.BuildBase(current)));
            GC.KeepAlive(fingerprint(FilterPlanBuilder.BuildRuntime(current)));
            GC.KeepAlive(fingerprint(FilterPlanBuilder.BuildDynamic(current)));
            GC.KeepAlive(fingerprint(FilterPlanBuilder.BuildDirect(current)));
        });
    }

    Measure($"cached-policy-plan-update-{count}-pins", 100, () =>
    {
        toggle = !toggle;
        var plans = planCache.Build(protection with { Policy = policyCache.Compile(toggle ? second : first) });
        if (!ReferenceEquals(plans[FilterGroup.Direct], previous[FilterGroup.Direct]))
        {
            throw new InvalidOperationException("Pin update rebuilt the address plan.");
        }

        foreach (var (group, specs) in plans)
        {
            GC.KeepAlive(ReferenceEquals(specs, previous[group]) || specs.SequenceEqual(previous[group], FilterSpecComparer.Instance));
        }

        previous = plans;
    });
}

foreach (var count in new[] { 100, 1_000, 10_000 })
{
    var pins = Enumerable.Range(0, count).Select(i => new PinnedHost(0x08000000u + (uint)i, RouteTarget.Tunnel(tunnel))).ToArray();
    var current = protection with { Policy = PolicyCompiler.Compile(input with { PinnedHosts = pins }) };
    var specs = FilterPlanBuilder.BuildDynamic(current);
    // Каждый V4 spec ставится на двух ALE-слоях, см. WfpOps.LayersOf.
    Console.WriteLine($"pins={count}; Dynamic specs={specs.Count}; native filters={specs.Count * 2}");
    Measure($"legacy-dynamic-plan-and-fingerprint-{count}", 50, () => GC.KeepAlive(fingerprint(FilterPlanBuilder.BuildDynamic(current))));
}

foreach (var count in new[] { 100, 1_000, 10_000 })
{
    var cache = new DnsCache(TimeProvider.System);
    for (var i = 0; i < count; i++)
    {
        var query = DnsMessage.BuildQuery(1, $"host{i}.example", DnsMessage.TypeA);
        DnsMessage.TryReadQuestion(query, out var question);
        cache.Put(question, "previous-path", DnsMessage.BuildAddressResponse(query, [0x08080808u], 3600));
    }

    var hitQuery = DnsMessage.BuildQuery(1, $"host{count - 1}.example", DnsMessage.TypeA);
    DnsMessage.TryReadQuestion(hitQuery, out var hit);
    DnsMessage.TryReadQuestion(DnsMessage.BuildQuery(1, "missing.example", DnsMessage.TypeA), out var miss);
    if (cache.TryGetAnyPath(hit, 1) is null || cache.TryGetAnyPath(miss, 1) is not null)
    {
        throw new InvalidOperationException("Invalid cache benchmark setup.");
    }

    Measure($"cache-context-hit-{count}", 5_000, () => GC.KeepAlive(cache.TryGet(hit, "previous-path", 1, offline: true)));
    Measure($"cache-any-path-hit-{count}", 5_000, () => GC.KeepAlive(cache.TryGetAnyPath(hit, 1)));
    Measure($"cache-any-path-miss-{count}", 5_000, () => GC.KeepAlive(cache.TryGetAnyPath(miss, 1)));
}

static string LegacyFingerprint(IReadOnlyList<FilterSpec> specs) =>
    string.Join("\n", specs.Select(s => $"{s.Weight}|{s.Action}|{s.Family}|{s.Name}|{string.Join("&", s.Conditions)}"));

static void Measure(string name, int iterations, Action action)
{
    for (var i = 0; i < 20; i++)
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

        samples.Add((Stopwatch.GetElapsedTime(start).TotalMicroseconds / iterations,
            (GC.GetAllocatedBytesForCurrentThread() - allocated) / iterations));
    }

    var median = samples.OrderBy(s => s.Microseconds).ElementAt(samples.Count / 2);
    Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"{name}: {median.Microseconds:F3} us/op; {median.Bytes} B/op"));
}
