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

        // Имя на национальном алфавите (vpn.пример.рф) один раз переводится в Punycode: так оно уходит в запрос,
        // так записан владелец A-записи в ответе, и так его чаще пишут в hosts. Сравнение с исходной записью
        // по-русски не находило ни одного адреса. Имя, которое в IDNA не переводится, не разрешается.
        if (!DnsMessage.TryGetAsciiName(host, out var name) || name.Length == 0)
        {
            return [];
        }

        // Имя закреплено в hosts: RAS при дозвоне возьмёт этот адрес, а не ответ DNS.
        if (HostsFile.Lookup(name) is { Count: > 0 } fromHosts)
        {
            return fromHosts;
        }

        var query = DnsMessage.BuildQuery((ushort)Random.Shared.Next(0, 65536), name, DnsMessage.TypeA);
        var servers = dnsServers.Select(s => new IPEndPoint(Ipv4.ToAddress(s), 53)).ToList();
        var response = await DnsForwarder.ForwardAsync(query, servers, interfaceIndex, TimeSpan.FromSeconds(3), cancellationToken);
        return response is null ? [] : DnsMessage.ReadAddresses(response, name).Distinct().ToList();
    }
}
