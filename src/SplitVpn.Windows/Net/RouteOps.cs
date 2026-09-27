using SplitVpn.Core.Net;
using SplitVpn.Windows.Native;
using Windows.Win32;
using Windows.Win32.NetworkManagement.IpHelper;
using Windows.Win32.Networking.WinSock;

namespace SplitVpn.Windows.Net;

public readonly record struct RouteKey(Ipv4Cidr Destination, uint NextHop, ulong InterfaceLuid);

public sealed record RouteApplyResult(int Added, int Removed, int Failed, TimeSpan Elapsed, IReadOnlyList<string> Errors);

public sealed record BestRoute(ulong InterfaceLuid, uint NextHop, Ipv4Cidr Destination, uint SourceAddress);

/// <summary>
/// Маршруты приложения помечаются характерной метрикой: так их находит и recover без журнала.
/// </summary>
public static unsafe class RouteOps
{
    public const uint MarkerMetric = 3917;

    private const uint ErrorObjectAlreadyExists = 5010;
    private const uint ErrorNotFound = 1168;
    private const int MaxReportedErrors = 20;

    public static IReadOnlyList<RouteKey> ListMarked()
    {
        return NetInventory.ReadRoutesV4()
            .Where(r => r.RouteMetric == MarkerMetric)
            .Select(r => new RouteKey(r.Destination, r.NextHop, r.InterfaceLuid))
            .ToList();
    }

    /// <summary>Приводит помеченные маршруты к желаемому набору: сначала добавляет, затем удаляет лишние.</summary>
    public static RouteApplyResult Reconcile(IReadOnlyCollection<RouteKey> desired)
    {
        ArgumentNullException.ThrowIfNull(desired);
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var existing = ListMarked().ToHashSet();
        var wanted = desired.ToHashSet();
        var errors = new List<string>();
        var added = 0;
        var removed = 0;
        var failed = 0;

        foreach (var route in wanted.Where(r => !existing.Contains(r)))
        {
            // Такой же маршрут с другой метрикой уже есть (например, /32 к серверу, который добавляет RAS):
            // трафик идёт как нужно, но это не наш маршрут — не считать добавленным при каждой сверке.
            var code = (uint)PInvoke.CreateIpForwardEntry2(ToRow(route));
            if (code != ErrorObjectAlreadyExists)
            {
                Count(code, "добавление", route, ref added, ref failed, errors);
            }
        }

        foreach (var route in existing.Where(r => !wanted.Contains(r)))
        {
            Count(Delete(route), "удаление", route, ref removed, ref failed, errors);
        }

        return new RouteApplyResult(added, removed, failed, stopwatch.Elapsed, errors);
    }

    public static RouteApplyResult RemoveAllMarked() => Reconcile([]);

    public static uint Add(RouteKey route)
    {
        var row = ToRow(route);
        var code = (uint)PInvoke.CreateIpForwardEntry2(row);
        return code == ErrorObjectAlreadyExists ? 0 : code;
    }

    public static uint Delete(RouteKey route)
    {
        var row = ToRow(route);
        var code = (uint)PInvoke.DeleteIpForwardEntry2(row);
        return code == ErrorNotFound ? 0 : code;
    }

    public static BestRoute? FindBestRoute(uint destination)
    {
        var target = SockAddr(destination);
        var code = PInvoke.GetBestRoute2(null, 0, null, target, 0, out var row, out var source);
        if (code != 0)
        {
            return null;
        }

        return new BestRoute(
            row.InterfaceLuid.Value,
            NetInventory.ToHostOrder(row.NextHop.Ipv4.sin_addr.S_un.S_addr),
            new Ipv4Cidr(NetInventory.ToHostOrder(row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr), row.DestinationPrefix.PrefixLength),
            NetInventory.ToHostOrder(source.Ipv4.sin_addr.S_un.S_addr));
    }

    private static MIB_IPFORWARD_ROW2 ToRow(RouteKey route)
    {
        MIB_IPFORWARD_ROW2 row;
        PInvoke.InitializeIpForwardEntry(&row);
        row.InterfaceLuid.Value = route.InterfaceLuid;
        row.DestinationPrefix.Prefix = SockAddr(route.Destination.Network);
        row.DestinationPrefix.PrefixLength = (byte)route.Destination.PrefixLength;
        row.NextHop = SockAddr(route.NextHop);
        row.Metric = MarkerMetric;
        row.Protocol = NL_ROUTE_PROTOCOL.MIB_IPPROTO_NETMGMT;
        return row;
    }

    private static SOCKADDR_INET SockAddr(uint address)
    {
        var value = default(SOCKADDR_INET);
        value.si_family = ADDRESS_FAMILY.AF_INET;
        value.Ipv4.sin_family = ADDRESS_FAMILY.AF_INET;
        value.Ipv4.sin_addr.S_un.S_addr = NetInventory.ToNetworkOrder(address);
        return value;
    }

    private static void Count(uint code, string operation, RouteKey route, ref int succeeded, ref int failed, List<string> errors)
    {
        if (code == 0)
        {
            succeeded++;
            return;
        }

        failed++;
        if (errors.Count < MaxReportedErrors)
        {
            errors.Add($"{operation} {route.Destination} через {Ipv4.Format(route.NextHop)} (LUID {route.InterfaceLuid}): {NativeCallException.Describe(code)}");
        }
    }
}
