using System.Net;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests
{
    [Fact]
    public async Task ConnectivityCheck_RefusedOldResponseDoesNotOccupyNewPathsPinCapacity()
    {
        var coordinator = await StartProtectedForConnectivityCheckAsync();
        var oldContext = coordinator.ConnectivityPinContext;
        var cache = new DnsCache(_world.Time);
        await using var proxy = new DnsProxyServer(IPAddress.Loopback, cache);
        proxy.Configuration = _world.Proxy.Configuration;
        var route = proxy.Configuration.DomainRoutes.Single(r => r.Suffix == Coordinator.ConnectivityCheckWebHost).Route!;
        var query = DnsMessage.BuildQuery(0x1234, Coordinator.ConnectivityCheckWebHost, DnsMessage.TypeA);
        Assert.True(DnsMessage.TryReadQuestion(query, out var question));
        var addresses = Enumerable.Range(1, 4).Select(i => Ipv4.Parse($"23.215.0.{i}")).ToArray();
        cache.Put(question, route.InterfaceIndex + ":" + string.Join(",", route.Servers),
            DnsMessage.BuildAddressResponse(query, addresses, 300), DnsMessage.ReadQueryFlags(query));

        proxy.RouteSink = new PathChangingSink(coordinator, async () =>
        {
            // AnnounceAsync уже проверил старую конфигурацию, но ещё не записал закрепление.
            Assert.True((await coordinator.HandleRequestAsync(new SaveSettingsRequest(coordinator.Settings with
            {
                LocalDnsServer = "9.9.9.9",
            }), CancellationToken.None)).Ok);
            proxy.Configuration = _world.Proxy.Configuration;
        });

        var response = await proxy.HandleAsync(query, CancellationToken.None);
        Assert.NotNull(response);
        Assert.Equal(2, DnsMessage.GetRcode(response));
        Assert.NotEqual(oldContext, coordinator.ConnectivityPinContext);

        // Старый ответ клиенту не выдан: его адреса не должны занять лимит нового пути.
        Assert.True(await ObserveConnectivityCheckAsync(coordinator, [Ipv4.Parse("23.215.0.136")]));
        Assert.Equal("Проверка интернета Windows 23.215.0.136:80", Assert.Single(ConnectivityFilters()).Name);
    }

    private sealed class PathChangingSink(Coordinator coordinator, Func<Task> changePath) : IPinnedRouteSink
    {
        public async ValueTask<bool> ObserveAsync(PinnedRouteNotice notice, CancellationToken cancellationToken)
        {
            await changePath();
            var pending = coordinator.ObservePinnedAsync(notice, cancellationToken);
            await coordinator.DrainAsync();
            return await pending;
        }

        public ValueTask<bool> CompleteAsync(PinnedRouteNotice notice, bool accepted) =>
            coordinator.CompletePinnedAsync(notice, accepted);
    }
}
