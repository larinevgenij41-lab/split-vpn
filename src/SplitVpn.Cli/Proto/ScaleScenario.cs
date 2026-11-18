using System.Diagnostics;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Windows.Diagnostics;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.Wfp;

namespace SplitVpn.Cli.Proto;

/// <summary>
/// S1. Масштаб: RU-маршруты через шлюз основного адаптера и разрешения Direct в динамической сессии WFP.
/// Блокирующих фильтров нет — трафик системы не затрагивается.
/// </summary>
internal static class ScaleScenario
{
    private const int LatencySamples = 500;

    public static async Task<int> RunAsync(CliArgs args)
    {
        var report = new ScenarioReport("s1-scale");
        try
        {
            var snapshot = NetInventory.Capture();
            var primary = ProtoNet.PrimaryAdapter(snapshot);
            var geo = ProtoNet.LoadGeo(ProtoContext.GeoPath(args));
            var policy = PolicyCompiler.Compile(new PolicyInput { Geo = geo, OnLinePrefixes = primary.OnLinkPrefixes });
            report.Measure("primaryAdapter", primary.Name);
            report.Measure("directRanges", policy.DirectRanges.Count);
            report.Measure("directRouteCidrs", policy.DirectRouteCidrs.Count);

            MeasureRoutes(report, policy, primary);
            await MeasureWfpAsync(report, policy, indexed: false);
            await MeasureWfpAsync(report, policy, indexed: true);
        }
        catch (Exception ex)
        {
            report.Fail("Сценарий прерван", ex);
        }
        finally
        {
            var leftover = RouteOps.RemoveAllMarked();
            report.Measure("cleanupRoutesRemoved", leftover.Removed);
        }

        return await report.SaveAsync(args, []);
    }

    private static void MeasureRoutes(ScenarioReport report, CompiledPolicy policy, AdapterCandidate primary)
    {
        var poolBefore = SystemMetrics.KernelNonpagedBytes();
        var desired = policy.DirectRouteCidrs.Select(c => new RouteKey(c, primary.DefaultGateway!.Value, primary.Luid)).ToList();

        var add = RouteOps.Reconcile(desired);
        report.Measure("routesAddSeconds", Math.Round(add.Elapsed.TotalSeconds, 2));
        report.Check("Все RU-маршруты добавлены", add.Failed == 0 && add.Added == desired.Count, $"добавлено {add.Added} из {desired.Count}, ошибок {add.Failed} {string.Join("; ", add.Errors)}");
        report.Measure("nonpagedPoolDeltaMb", Math.Round((SystemMetrics.KernelNonpagedBytes() - (double)poolBefore) / 1_048_576, 1));

        var random = new Random(1);
        var stopwatch = Stopwatch.StartNew();
        var direct = ProtoNet.VerifyRoutes(ProtoNet.SampleRanges(policy.DirectRanges, 1000, random), primary.Luid);
        report.Measure("routeVerifySeconds", Math.Round(stopwatch.Elapsed.TotalSeconds, 2));
        report.Check("GetBestRoute2: RU → основной адаптер", direct.Matched == direct.Total, $"{direct.Matched}/{direct.Total} {string.Join("; ", direct.Examples)}");
        var marked = RouteOps.ListMarked().Count;
        report.Check("Помеченных маршрутов столько же, сколько желаемых", marked == desired.Count, $"{marked}");

        var remove = RouteOps.RemoveAllMarked();
        report.Measure("routesRemoveSeconds", Math.Round(remove.Elapsed.TotalSeconds, 2));
        report.Check("Все RU-маршруты удалены", remove.Failed == 0 && RouteOps.ListMarked().Count == 0, $"удалено {remove.Removed}");
    }

    private static async Task MeasureWfpAsync(ScenarioReport report, CompiledPolicy policy, bool indexed)
    {
        var suffix = indexed ? "Indexed" : "Plain";
        var baseline = await ProtoNet.LoopbackConnectLatencyAsync(LatencySamples);
        var bfeBefore = SystemMetrics.ServicePrivateBytes("BFE");
        var filters = FilterPlanBuilder.BuildDirect(new ProtectionInputs { Policy = policy });

        using (var engine = WfpEngine.Open(dynamicSession: true))
        {
            WfpOps.EnsureProviderAndSubLayer(engine, WfpIdentity.Prototype, persistent: false);
            var stopwatch = Stopwatch.StartNew();
            IReadOnlyList<ulong> ids = [];
            engine.InTransaction(e => ids = WfpOps.AddFilters(e, WfpIdentity.Prototype, filters, persistent: false, indexed));
            report.Measure("wfpCommitSeconds" + suffix, Math.Round(stopwatch.Elapsed.TotalSeconds, 2));
            report.Check("Фильтры Direct добавлены " + suffix, ids.Count == filters.Count * 2, $"{ids.Count}");
            report.Measure("bfePrivateDeltaMb" + suffix, Math.Round((SystemMetrics.ServicePrivateBytes("BFE") - (double)bfeBefore) / 1_048_576, 1));

            var loaded = await ProtoNet.LoopbackConnectLatencyAsync(LatencySamples);
            report.Measure("connectP50Ms" + suffix, new { without = Math.Round(ProtoNet.Percentile(baseline, 0.5), 3), with = Math.Round(ProtoNet.Percentile(loaded, 0.5), 3) });
            report.Measure("connectP95Ms" + suffix, new { without = Math.Round(ProtoNet.Percentile(baseline, 0.95), 3), with = Math.Round(ProtoNet.Percentile(loaded, 0.95), 3) });

            stopwatch.Restart();
            engine.InTransaction(e => WfpOps.DeleteFilters(e, ids));
            report.Measure("wfpDeleteSeconds" + suffix, Math.Round(stopwatch.Elapsed.TotalSeconds, 2));
        }

        using var check = WfpEngine.Open(dynamicSession: true);
        report.Check("Динамическая сессия не оставила объектов " + suffix, WfpOps.ListFilters(check, WfpIdentity.Prototype).Count == 0, "фильтров прототипа после закрытия сессии");
    }
}
