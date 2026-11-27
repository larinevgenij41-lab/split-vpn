using System.Net;
using Microsoft.Extensions.Time.Testing;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Policy;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Мост DNS-посредник → координатор (<see cref="CoordinatorRouteSink"/>) передаёт частичное принятие: без своего
/// ObservePartialAsync мост молча откатился бы к реализации интерфейса по умолчанию - «всё или ничего», и ответ с одним
/// конфликтующим адресом уходил бы клиенту отказом целиком.
/// </summary>
public sealed partial class CoordinatorTests
{
    [Fact]
    public async Task RouteSinkBridge_PartialAcceptance_EndToEnd()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var coordinator = await WithLingerRulesAsync();
        var other = LingerAddress + 1;
        // Адрес уже закреплён за другим правилом и другой целью: в ответе second.example он конфликтует.
        Assert.True(await PinAsync(coordinator, "first.example", vpn, TimeSpan.FromHours(1), LingerAddress));

        await using var upstream = new DnsPinTrimTests.TrimUpstream
        {
            Respond = query => DnsMessage.BuildAddressResponse(query, [LingerAddress, other], 300),
        };
        await using var proxy = new DnsProxyServer(IPAddress.Loopback, new DnsCache(new FakeTimeProvider(DateTimeOffset.UnixEpoch)))
        {
            RouteSink = new CoordinatorRouteSink(coordinator),
            Configuration = new DnsProxyConfiguration
            {
                Mode = DnsProxyMode.DirectAllowed,
                Direct = new DnsRoute([upstream.EndPoint], null),
                DomainRoutes = [new DomainRoute("second.example", RouteTarget.Direct, new DnsRoute([upstream.EndPoint], null))],
            },
        };

        var handle = proxy.HandleAsync(DnsMessage.BuildQuery(11, "www.second.example", DnsMessage.TypeA), CancellationToken.None);
        // Закрепление применяет очередь актора: она прокручивается, пока посредник ждёт ответа.
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        while (!handle.IsCompleted)
        {
            await coordinator.DrainAsync();
            await Task.Delay(5, timeout.Token);
        }

        var reply = (await handle)!;
        await coordinator.DrainAsync();

        Assert.Equal(0, DnsMessage.GetRcode(reply));
        Assert.Equal([other], DnsMessage.ReadAddresses(reply, "www.second.example"));
        Assert.Equal(vpn, coordinator.Facts.Pinned[LingerAddress].Target);
        Assert.Equal(RouteTarget.Direct, coordinator.Facts.Pinned[other].Target);
    }
}
