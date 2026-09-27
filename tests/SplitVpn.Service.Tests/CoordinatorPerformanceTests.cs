using SplitVpn.Core.Protection;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests
{
    [Fact]
    public async Task NewDomainPin_ReusesAddressPolicyAndDirectPlan()
    {
        var coordinator = await WithSharedDomainRulesAsync();
        var previous = coordinator.Facts.Policy!;
        var directPlan = coordinator.Facts.AppliedFilters[FilterGroup.Direct].Specs;
        await PinSharedAddressAsync(coordinator, "first.example", TimeSpan.FromHours(1));
        Assert.Same(previous.DirectRouteCidrs, coordinator.Facts.Policy!.DirectRouteCidrs);
        Assert.Same(directPlan, coordinator.Facts.AppliedFilters[FilterGroup.Direct].Specs);
        Assert.Equal([FilterGroup.Dynamic], _world.Wfp.LastReplacedGroups);
    }
}
