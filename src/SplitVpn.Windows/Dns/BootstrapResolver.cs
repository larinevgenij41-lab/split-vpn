using System.Net;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Net;

namespace SplitVpn.Windows.Dns;

/// <summary>Начальное разрешение имени SSTP-сервера через исходный DNS основного адаптера, мимо системного резолвера.</summary>
public static class BootstrapResolver
{
    public static async Task<IReadOnlyList<uint>> ResolveAsync(
        string host,
        IReadOnlyList<uint> dnsServers,
        uint? interfaceIndex,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(dnsServers);
        if (Ipv4.TryParse(host, out var literal))
        {
            return [literal];
        }

        var query = DnsMessage.BuildQuery((ushort)Random.Shared.Next(0, 65536), host, DnsMessage.TypeA);
        var servers = dnsServers.Select(s => new IPEndPoint(Ipv4.ToAddress(s), 53)).ToList();
        var response = await DnsForwarder.ForwardAsync(query, servers, interfaceIndex, TimeSpan.FromSeconds(3), cancellationToken);
        return response is null ? [] : DnsMessage.ReadAddresses(response).Distinct().ToList();
    }
}
