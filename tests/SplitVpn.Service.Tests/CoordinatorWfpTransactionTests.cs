using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Windows.Operations;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests
{
    [Fact]
    public async Task WfpGroupFailure_PreservesWholePreviousPolicyUntilAtomicRetry()
    {
        var second = SecondProfile();
        var subnet = "13.107.0.0/16";
        var host = Ipv4.Parse("13.107.1.1");
        SaveSettings(Settings() with
        {
            Profiles = [_profile, second],
            Rules = [new UserRuleSetting { Cidr = subnet, Target = RouteTarget.Tunnel(second.Id) }],
        });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var previous = _world.Wfp.Groups.ToDictionary(g => g.Key, g => g.Value);
        var fingerprints = coordinator.Facts.AppliedFilters.ToDictionary(g => g.Key, g => g.Value);
        var transactions = _world.Wfp.Transactions;
        var replacements = _world.Wfp.Replacements;
        _world.Wfp.FailOnGroup = FilterGroup.Direct;

        await coordinator.HandleRequestAsync(new SaveSettingsRequest(coordinator.Settings with
        {
            Rules = [new UserRuleSetting { Cidr = subnet, Target = RouteTarget.Direct }],
            LocalAccess = false,
        }), CancellationToken.None);

        Assert.Equal(ConnectionState.PartiallyApplied, coordinator.DeriveState());
        Assert.Equal(transactions, _world.Wfp.Transactions);
        Assert.Equal(replacements, _world.Wfp.Replacements);
        foreach (var (group, specs) in previous)
        {
            Assert.Same(specs, _world.Wfp.Groups[group]);
            Assert.Equal(fingerprints[group], coordinator.Facts.AppliedFilters[group]);
        }

        // Пока commit не состоялся, целиком действует прежняя политика B, включая её запрет A/Direct.
        Assert.Equal(FilterAction.Block, RoutingAction(host, FakeWorld.WiFiLuid));
        Assert.Equal(FilterAction.Block, RoutingAction(host, FakeInventory.TunnelLuid(0)));
        Assert.Equal(FilterAction.Permit, RoutingAction(host, FakeInventory.TunnelLuid(1)));
        Assert.Contains(_world.Routes.Current, r => r.Destination == Ipv4Cidr.Parse(subnet)
            && r.InterfaceLuid == FakeInventory.TunnelLuid(1));

        await coordinator.ReconcileAsync(CancellationToken.None);

        Assert.Equal(transactions + 1, _world.Wfp.Transactions);
        Assert.Equal([FilterGroup.Base, FilterGroup.Runtime, FilterGroup.Direct], _world.Wfp.LastReplacedGroups);
        Assert.Equal(FilterAction.Permit, RoutingAction(host, FakeWorld.WiFiLuid));
        Assert.Equal(FilterAction.Block, RoutingAction(host, FakeInventory.TunnelLuid(1)));
        Assert.Contains(_world.Routes.Current, r => r.Destination == Ipv4Cidr.Parse(subnet)
            && r.InterfaceLuid == FakeWorld.WiFiLuid);

        await coordinator.ReconcileAsync(CancellationToken.None);
        Assert.Equal(transactions + 1, _world.Wfp.Transactions);
    }

    [Fact]
    public void DirectDifference_UpdatesInterfaceGuardWhenPrimaryChanges()
    {
        var spec = new FilterSpec("Прямой путь 13.107.0.0/16", FilterGroup.Direct, FilterFamily.V4,
            FilterPlanBuilder.WeightRouteGuard, FilterAction.Block,
            [new RemoteRangeV4(1, 2), new LocalInterfaceCondition(8, NotEqual: true)]);
        var changed = spec with { Conditions = [new RemoteRangeV4(1, 2), new LocalInterfaceCondition(9, NotEqual: true)] };

        Assert.NotEqual(SystemWfpOps.InstalledName(FilterGroup.Direct, spec), SystemWfpOps.InstalledName(FilterGroup.Direct, changed));
        Assert.Equal(SystemWfpOps.InstalledName(FilterGroup.Direct, spec), SystemWfpOps.InstalledName(FilterGroup.Direct, spec with { }));
    }
}
