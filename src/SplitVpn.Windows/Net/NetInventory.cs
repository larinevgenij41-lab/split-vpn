using System.Net;
using Microsoft.Win32;
using SplitVpn.Core.Net;
using SplitVpn.Windows.Native;
using Windows.Win32;
using Windows.Win32.NetworkManagement.IpHelper;
using Windows.Win32.NetworkManagement.Ndis;
using Windows.Win32.Networking.WinSock;

namespace SplitVpn.Windows.Net;

public sealed record RouteEntry(Ipv4Cidr Destination, uint NextHop, ulong InterfaceLuid, uint InterfaceIndex, uint RouteMetric, uint Protocol);

public sealed record NetSnapshot(IReadOnlyList<AdapterCandidate> Adapters, IReadOnlyList<RouteEntry> RoutesV4);

/// <summary>Снимок интерфейсов и таблицы маршрутов IPv4 через IP Helper.</summary>
public static unsafe class NetInventory
{
    private const string InterfacesKey = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\";

    public static NetSnapshot Capture()
    {
        var routes = ReadRoutesV4();
        var addresses = ReadUnicastV4();
        var metrics = ReadInterfaceMetrics();
        var adapters = ReadInterfaces()
            .Select(row => BuildCandidate(row, routes, addresses, metrics))
            .ToList();
        return new NetSnapshot(adapters, routes);
    }

    public static IReadOnlyList<RouteEntry> ReadRoutesV4()
    {
        var error = PInvoke.GetIpForwardTable2(ADDRESS_FAMILY.AF_INET, out var table);
        NativeCallException.ThrowIfFailed((uint)error, "GetIpForwardTable2");
        try
        {
            var result = new List<RouteEntry>((int)table->NumEntries);
            foreach (ref readonly var row in table->Table.AsSpan((int)table->NumEntries))
            {
                result.Add(new RouteEntry(
                    new Ipv4Cidr(ToHostOrder(row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr), row.DestinationPrefix.PrefixLength),
                    ToHostOrder(row.NextHop.Ipv4.sin_addr.S_un.S_addr),
                    row.InterfaceLuid.Value,
                    row.InterfaceIndex,
                    row.Metric,
                    (uint)row.Protocol));
            }

            return result;
        }
        finally
        {
            PInvoke.FreeMibTable(table);
        }
    }

    /// <summary>Сетевой порядок байтов (как в sockaddr) → число «старший октет первым».</summary>
    internal static uint ToHostOrder(uint networkOrder) => (uint)IPAddress.NetworkToHostOrder(unchecked((int)networkOrder));

    internal static uint ToNetworkOrder(uint hostOrder) => (uint)IPAddress.HostToNetworkOrder(unchecked((int)hostOrder));

    public static IReadOnlyList<uint> ReadDnsServersFromRegistry(Guid interfaceGuid)
    {
        using var key = Registry.LocalMachine.OpenSubKey(InterfacesKey + interfaceGuid.ToString("B"));
        var configured = key?.GetValue("NameServer") as string;
        var dhcp = key?.GetValue("DhcpNameServer") as string;
        var text = string.IsNullOrWhiteSpace(configured) ? dhcp : configured;
        return (text ?? "")
            .Split([' ', ','], StringSplitOptions.RemoveEmptyEntries)
            .Select(s => Ipv4.TryParse(s, out var v) ? (uint?)v : null)
            .OfType<uint>()
            .ToList();
    }

    private static List<MIB_IF_ROW2> ReadInterfaces()
    {
        var error = PInvoke.GetIfTable2(out var table);
        NativeCallException.ThrowIfFailed((uint)error, "GetIfTable2");
        try
        {
            return table->Table.AsSpan((int)table->NumEntries).ToArray().ToList();
        }
        finally
        {
            PInvoke.FreeMibTable(table);
        }
    }

    private static Dictionary<ulong, List<(uint Address, int PrefixLength)>> ReadUnicastV4()
    {
        var error = PInvoke.GetUnicastIpAddressTable(ADDRESS_FAMILY.AF_INET, out var table);
        NativeCallException.ThrowIfFailed((uint)error, "GetUnicastIpAddressTable");
        try
        {
            var result = new Dictionary<ulong, List<(uint, int)>>();
            foreach (ref readonly var row in table->Table.AsSpan((int)table->NumEntries))
            {
                if (!result.TryGetValue(row.InterfaceLuid.Value, out var list))
                {
                    result[row.InterfaceLuid.Value] = list = [];
                }

                list.Add((ToHostOrder(row.Address.Ipv4.sin_addr.S_un.S_addr), row.OnLinkPrefixLength));
            }

            return result;
        }
        finally
        {
            PInvoke.FreeMibTable(table);
        }
    }

    private static Dictionary<ulong, uint> ReadInterfaceMetrics()
    {
        var result = new Dictionary<ulong, uint>();
        foreach (var row in ReadInterfaces())
        {
            var ipRow = new MIB_IPINTERFACE_ROW { Family = ADDRESS_FAMILY.AF_INET, InterfaceLuid = row.InterfaceLuid };
            if (PInvoke.GetIpInterfaceEntry(ref ipRow) == 0)
            {
                result[row.InterfaceLuid.Value] = ipRow.Metric;
            }
        }

        return result;
    }

    private static AdapterCandidate BuildCandidate(
        MIB_IF_ROW2 row,
        IReadOnlyList<RouteEntry> routes,
        Dictionary<ulong, List<(uint Address, int PrefixLength)>> addresses,
        Dictionary<ulong, uint> metrics)
    {
        var luid = row.InterfaceLuid.Value;
        var defaultRoute = routes
            .Where(r => r.InterfaceLuid == luid && r.Destination.PrefixLength == 0)
            .OrderBy(r => r.RouteMetric)
            .FirstOrDefault();
        var interfaceMetric = metrics.GetValueOrDefault(luid);
        var own = addresses.GetValueOrDefault(luid) ?? [];

        return new AdapterCandidate
        {
            InterfaceGuid = row.InterfaceGuid,
            Luid = luid,
            InterfaceIndex = row.InterfaceIndex,
            Name = row.Alias.AsReadOnlySpan().SliceAtNull().ToString(),
            Description = row.Description.AsReadOnlySpan().SliceAtNull().ToString(),
            IfType = row.Type,
            IsHardware = row.InterfaceAndOperStatusFlags.HardwareInterface,
            IsUp = row.OperStatus == IF_OPER_STATUS.IfOperStatusUp,
            DefaultGateway = defaultRoute?.NextHop,
            DefaultRouteMetric = defaultRoute is null ? null : defaultRoute.RouteMetric + interfaceMetric,
            OnLinkPrefixes = own
                .Where(a => a.PrefixLength is > 0 and < 32)
                .Select(a => new Ipv4Cidr(a.Address & Ipv4Cidr.MaskOf(a.PrefixLength), a.PrefixLength))
                .Distinct()
                .ToList(),
            Addresses = own.Select(a => a.Address).ToList(),
            DnsServers = ReadDnsServersFromRegistry(row.InterfaceGuid),
        };
    }
}
