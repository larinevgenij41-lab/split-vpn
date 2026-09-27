using System.Diagnostics;
using Microsoft.Win32;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.Recovery;
using SplitVpn.Windows.Wfp;

namespace SplitVpn.Cli.Proto;

/// <summary>
/// S5. Жизненный цикл объектов WFP без влияния на трафик: блокирующие фильтры получают условие,
/// которое не совпадает ни с одним пакетом (протокол 255, порт 1).
/// </summary>
internal static class PersistScenario
{
    private const string PersistentKey = @"SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy\Persistent";

    public static async Task<int> ApplyAsync(CliArgs args)
    {
        var report = new ScenarioReport("s5-apply");
        try
        {
            var snapshot = NetInventory.Capture();
            var primary = ProtoNet.PrimaryAdapter(snapshot);
            var policy = PolicyCompiler.Compile(new PolicyInput { Geo = ProtoNet.LoadGeo(ProtoContext.GeoPath(args)), OnLinePrefixes = primary.OnLinkPrefixes });
            var inputs = new ProtectionInputs { Policy = policy, PrimaryLuid = primary.Luid, ServiceExecutablePath = Environment.ProcessPath!, ServiceDnsAddresses = primary.DnsServers };
            report.Measure("bfePersistentKeyValuesBefore", PersistentValueCount());

            using var engine = WfpEngine.Open(dynamicSession: false);
            WfpOps.EnsureProviderAndSubLayer(engine, WfpIdentity.Prototype, persistent: true);
            var stopwatch = Stopwatch.StartNew();
            var counts = new Dictionary<string, int>();
            engine.InTransaction(e =>
            {
                counts["persistentBase"] = WfpOps.AddFilters(e, WfpIdentity.Prototype, Neutralize(FilterPlanBuilder.BuildBase(inputs)), persistent: true).Count;
                counts["staticRuntime"] = WfpOps.AddFilters(e, WfpIdentity.Prototype, Neutralize(FilterPlanBuilder.BuildRuntime(inputs)), persistent: false).Count;
                counts["staticDirect"] = WfpOps.AddFilters(e, WfpIdentity.Prototype, FilterPlanBuilder.BuildDirect(inputs), persistent: false).Count;
            });
            report.Measure("applySeconds", Math.Round(stopwatch.Elapsed.TotalSeconds, 2));
            report.Measure("filters", counts);
            report.Measure("bfePersistentKeyValuesAfter", PersistentValueCount());
            report.Note("Процесс завершается без удаления: проверка — «proto s5-check».");
        }
        catch (Exception ex)
        {
            report.Fail("Применение", ex);
        }

        return await report.SaveAsync(args, []);
    }

    public static async Task<int> CheckAsync(CliArgs args)
    {
        var report = new ScenarioReport("s5-check");
        try
        {
            using (var engine = WfpEngine.Open(dynamicSession: false))
            {
                var filters = WfpOps.ListFilters(engine, WfpIdentity.Prototype);
                report.Measure("filtersFound", new { total = filters.Count, persistent = filters.Count(f => f.Persistent) });
                report.Check("Persistent и static фильтры пережили завершение процесса", filters.Count > 0 && filters.Any(f => f.Persistent) && filters.Any(f => !f.Persistent), $"{filters.Count}");
            }

            var recovery = await NetworkRecovery.RunAsync(new RecoveryOptions { Phonebooks = [ProtoContext.Phonebook], WfpIdentities = [WfpIdentity.Prototype], DnsBackupPath = ProtoContext.DnsBackupPath }, CancellationToken.None);
            report.Measure("recovery", recovery);
            using var after = WfpEngine.Open(dynamicSession: true);
            var left = WfpOps.ListFilters(after, WfpIdentity.Prototype).Count;
            report.Check("recover удалил все объекты прототипа", left == 0 && recovery.Success, $"осталось {left}; ошибки: {string.Join("; ", recovery.Errors)}");
            report.Measure("bfePersistentKeyValuesAfterRecover", PersistentValueCount());
        }
        catch (Exception ex)
        {
            report.Fail("Проверка", ex);
        }

        return await report.SaveAsync(args, []);
    }

    private static List<FilterSpec> Neutralize(IReadOnlyList<FilterSpec> specs)
    {
        return specs.Select(s => s.Action == FilterAction.Block
            ? s with { Conditions = [.. s.Conditions.Where(c => c is not ProtocolCondition and not RemotePortCondition), new ProtocolCondition(255), new RemotePortCondition(1)] }
            : s).ToList();
    }

    private static int PersistentValueCount()
    {
        using var key = Registry.LocalMachine.OpenSubKey(PersistentKey);
        if (key is null)
        {
            return -1;
        }

        return key.ValueCount + key.GetSubKeyNames().Sum(name =>
        {
            using var child = key.OpenSubKey(name);
            return child?.ValueCount ?? 0;
        });
    }
}
