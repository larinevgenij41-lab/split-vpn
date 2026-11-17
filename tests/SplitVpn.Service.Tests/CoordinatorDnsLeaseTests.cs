using System.Net;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DomainDns_OnlyIssuedAnswerSurvivesNextApply(bool cancelAfterApply)
    {
        SaveSettings(Settings() with
        {
            DomainRules = [new DomainRuleSetting { Suffix = "cdn.example", Target = RouteTarget.Direct }],
        });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var address = Ipv4.Parse("93.184.216.34");
        var cache = new DnsCache(_world.Time);
        await using var proxy = new DnsProxyServer(IPAddress.Loopback, cache);
        proxy.Configuration = _world.Proxy.Configuration;
        var route = proxy.Configuration.DomainRoutes.Single(r => r.Suffix == "cdn.example").Route!;
        var query = DnsMessage.BuildQuery(0x1234, "cdn.example", DnsMessage.TypeA);
        Assert.True(DnsMessage.TryReadQuestion(query, out var question));
        cache.Put(question, route.InterfaceIndex + ":" + string.Join(",", route.Servers),
            DnsMessage.BuildAddressResponse(query, [address], 300), DnsMessage.ReadQueryFlags(query));
        proxy.RouteSink = new LeaseChangingSink(coordinator,
            () => cancelAfterApply ? throw new OperationCanceledException() : Task.CompletedTask, afterApply: true);

        if (cancelAfterApply)
        {
            await Assert.ThrowsAsync<OperationCanceledException>(() => proxy.HandleAsync(query, CancellationToken.None));
        }
        else
        {
            Assert.Equal(0, DnsMessage.GetRcode((await proxy.HandleAsync(query, CancellationToken.None))!));
        }

        await TickAsync(coordinator);
        Assert.Equal(!cancelAfterApply, coordinator.Facts.Pinned.ContainsKey(address));
        Assert.Equal(!cancelAfterApply, _world.Routes.Current.Any(r => r.Destination == new Ipv4Cidr(address, 32)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DomainDns_RefusedOldAnswerDoesNotBlockCurrentRule(bool changeAfterApply)
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        SaveSettings(Settings() with
        {
            DomainRules =
            [
                new DomainRuleSetting { Suffix = "cdn.example", Target = RouteTarget.Direct },
                new DomainRuleSetting { Suffix = "secure.example", Target = vpn },
            ],
        });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var address = Ipv4.Parse("93.184.216.34");
        var cache = new DnsCache(_world.Time);
        await using var proxy = new DnsProxyServer(IPAddress.Loopback, cache);
        proxy.Configuration = _world.Proxy.Configuration;
        var route = proxy.Configuration.DomainRoutes.Single(r => r.Suffix == "cdn.example").Route!;
        var query = DnsMessage.BuildQuery(0x1234, "cdn.example", DnsMessage.TypeA);
        Assert.True(DnsMessage.TryReadQuestion(query, out var question));
        cache.Put(question, route.InterfaceIndex + ":" + string.Join(",", route.Servers),
            DnsMessage.BuildAddressResponse(query, [address], 300), DnsMessage.ReadQueryFlags(query));
        proxy.RouteSink = new LeaseChangingSink(coordinator, async () =>
        {
            Assert.True((await coordinator.HandleRequestAsync(new SaveSettingsRequest(coordinator.Settings with
            {
                LocalDnsServer = "9.9.9.9",
            }), CancellationToken.None)).Ok);
            proxy.Configuration = _world.Proxy.Configuration;
        }, changeAfterApply);

        var response = await proxy.HandleAsync(query, CancellationToken.None);
        Assert.NotNull(response);
        Assert.Equal(2, DnsMessage.GetRcode(response));
        Assert.DoesNotContain(address, coordinator.Facts.Pinned.Keys);
        Assert.DoesNotContain(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(address, 32));

        var current = coordinator.ObservePinnedAsync(new PinnedRouteNotice("secure.example", "secure.example",
            vpn, [address], TimeSpan.FromMinutes(5)), CancellationToken.None);
        await coordinator.DrainAsync();
        Assert.True(await current);
        Assert.Equal(vpn, coordinator.Facts.Pinned[address].Target);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DomainDns_CancelledRefreshPreservesEarlierLeaseAndItsTtl(bool commitEarlierFirst)
    {
        SaveSettings(Settings() with
        {
            DomainRules = [new DomainRuleSetting { Suffix = "cdn.example", Target = RouteTarget.Direct }],
        });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var address = Ipv4.Parse("93.184.216.34");
        var first = new PinnedRouteNotice("cdn.example", "cdn.example", RouteTarget.Direct,
            [address], TimeSpan.FromMinutes(1)) { LeaseId = Guid.NewGuid() };
        var refresh = first with { LeaseId = Guid.NewGuid(), Ttl = TimeSpan.FromHours(1) };
        Assert.True(await ApplyDnsLeaseAsync(coordinator, first));
        if (commitEarlierFirst) { Assert.True(await FinishDnsLeaseAsync(coordinator, first, true)); }
        // Повторный ответ использует уже применённый маршрут без новой работы в очереди актора.
        var refreshing = coordinator.ObservePinnedAsync(refresh, CancellationToken.None);
        Assert.True(refreshing.IsCompletedSuccessfully);
        Assert.True(await refreshing);
        Assert.False(await FinishDnsLeaseAsync(coordinator, refresh, false));
        if (!commitEarlierFirst) { Assert.True(await FinishDnsLeaseAsync(coordinator, first, true)); }
        Assert.Contains(address, coordinator.Facts.Pinned.Keys);
        _world.Time.Advance(TimeSpan.FromMinutes(2));
        await TickAsync(coordinator);
        Assert.DoesNotContain(address, coordinator.Facts.Pinned.Keys);
    }

    [Fact]
    public async Task DomainDns_CommitRechecksConfigurationAndDoesNotKeepStaleLease()
    {
        SaveSettings(Settings() with
        {
            DomainRules = [new DomainRuleSetting { Suffix = "cdn.example", Target = RouteTarget.Direct }],
        });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var current = true;
        var address = Ipv4.Parse("93.184.216.34");
        var notice = new PinnedRouteNotice("cdn.example", "cdn.example", RouteTarget.Direct,
            [address], TimeSpan.FromMinutes(5)) { LeaseId = Guid.NewGuid(), IsCurrent = () => current };
        Assert.True(await ApplyDnsLeaseAsync(coordinator, notice));
        current = false;
        Assert.False(await FinishDnsLeaseAsync(coordinator, notice, true));
        Assert.DoesNotContain(address, coordinator.Facts.Pinned.Keys);
    }

    private static async Task<bool> ApplyDnsLeaseAsync(Coordinator coordinator, PinnedRouteNotice notice)
    {
        var pending = coordinator.ObservePinnedAsync(notice, CancellationToken.None);
        await coordinator.DrainAsync();
        return await pending;
    }

    private static async ValueTask<bool> FinishDnsLeaseAsync(Coordinator coordinator, PinnedRouteNotice notice, bool accepted)
    {
        var pending = coordinator.CompletePinnedAsync(notice, accepted);
        await coordinator.DrainAsync();
        return await pending;
    }

    private sealed class LeaseChangingSink(Coordinator coordinator, Func<Task> change, bool afterApply) : IPinnedRouteSink
    {
        public async ValueTask<bool> ObserveAsync(PinnedRouteNotice notice, CancellationToken cancellationToken)
        {
            if (!afterApply) { await change(); }
            var accepted = await ApplyDnsLeaseAsync(coordinator, notice);
            if (afterApply) { await change(); }
            return accepted;
        }

        public ValueTask<bool> CompleteAsync(PinnedRouteNotice notice, bool accepted) =>
            FinishDnsLeaseAsync(coordinator, notice, accepted);
    }
}
