using System.Security.Principal;
using System.Text.Json;
using SplitVpn.Core.Net;
using SplitVpn.Core.Settings;
using SplitVpn.Windows.Native;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.Wfp;

namespace SplitVpn.Cli;

internal static class InspectCommand
{
    public static Task<int> RunAsync(CliArgs args)
    {
        var elevated = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        Console.WriteLine(Text.Inv($"Повышенные права: {(elevated ? "да" : "нет")}"));

        var snapshot = NetInventory.Capture();
        PrintAdapters(snapshot);
        PrintDefaultRoutes(snapshot);

        var primary = PrimaryAdapterSelector.Select(snapshot.Adapters, pinned: null, allowFallback: false);
        Console.WriteLine();
        Console.WriteLine(Text.Inv($"Основной адаптер (Auto): {primary.Adapter?.Name ?? "нет"} — {primary.Status}"));
        foreach (var (adapter, prefix) in PrimaryAdapterSelector.PublicOnLinkConflicts(snapshot.Adapters))
        {
            Console.WriteLine(Text.Inv($"Конфликт: интерфейс «{adapter.Name}» держит публичную сеть {prefix}; при защите она блокируется, если не включён локальный доступ."));
        }

        var wfp = TryCaptureWfp();
        var jsonPath = args.Option("--json");
        if (jsonPath is not null)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(jsonPath))!);
            File.WriteAllText(jsonPath, JsonSerializer.Serialize(new { elevated, snapshot, primary, wfp }, JsonDefaults.Options));
            Console.WriteLine("Отчёт записан: " + jsonPath);
        }

        return Task.FromResult(0);
    }

    private static void PrintAdapters(NetSnapshot snapshot)
    {
        Console.WriteLine();
        Console.WriteLine("Интерфейсы в состоянии Up с адресами IPv4:");
        foreach (var a in snapshot.Adapters.Where(a => a.IsUp && a.Addresses.Count > 0).OrderBy(a => a.InterfaceIndex))
        {
            var gateway = a.DefaultGateway is { } g ? Ipv4.Format(g) : "—";
            var onLink = string.Join(", ", a.OnLinkPrefixes);
            var dns = string.Join(", ", a.DnsServers.Select(Ipv4.Format));
            Console.WriteLine(Text.Inv($"  [{a.InterfaceIndex,3}] {a.Name} ({a.TypeName}, {(a.IsHardware ? "аппаратный" : "виртуальный")}) шлюз {gateway}, метрика {a.DefaultRouteMetric?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "—"}; on-link: {onLink}; DNS: {dns}"));
        }
    }

    private static void PrintDefaultRoutes(NetSnapshot snapshot)
    {
        Console.WriteLine();
        Console.WriteLine(Text.Inv($"Маршрутов IPv4: {snapshot.RoutesV4.Count}; маршруты по умолчанию и /1:"));
        foreach (var route in snapshot.RoutesV4.Where(r => r.Destination.PrefixLength <= 1))
        {
            var name = snapshot.Adapters.FirstOrDefault(a => a.Luid == route.InterfaceLuid)?.Name ?? route.InterfaceIndex.ToString(System.Globalization.CultureInfo.InvariantCulture);
            Console.WriteLine(Text.Inv($"  {route.Destination} → {Ipv4.Format(route.NextHop)} через «{name}», метрика маршрута {route.RouteMetric}"));
        }
    }

    private static WfpInventory? TryCaptureWfp()
    {
        Console.WriteLine();
        try
        {
            var wfp = WfpInspector.Capture();
            Console.WriteLine(Text.Inv($"WFP: провайдеров {wfp.Providers.Count}, sublayer {wfp.SubLayers.Count}, фильтров {wfp.TotalFilters}"));
            foreach (var s in wfp.SubLayers.Where(s => s.FilterCount > 0).OrderByDescending(s => s.Weight))
            {
                var warning = s.HardPermitCount > 0 ? Text.Inv($" — жёстких разрешений на ALE: {s.HardPermitCount}") : "";
                Console.WriteLine(Text.Inv($"  вес {s.Weight,5}: {s.Name} — фильтров {s.FilterCount}{warning}"));
            }

            foreach (var p in wfp.Providers.Where(p => p.Persistent || p.ServiceName is not null))
            {
                Console.WriteLine(Text.Inv($"  провайдер {p.Name}: служба {p.ServiceName ?? "—"}, persistent {p.Persistent}, disabled {p.Disabled}"));
            }

            return wfp;
        }
        catch (NativeCallException ex)
        {
            Console.WriteLine("WFP: перечисление недоступно — " + ex.Message);
            return null;
        }
    }
}
