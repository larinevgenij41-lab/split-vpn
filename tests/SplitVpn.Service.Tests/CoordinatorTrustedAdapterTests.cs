using SplitVpn.Core.Net;
using SplitVpn.Core.Protection;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests
{
    private static readonly uint RadminPeer = Ipv4.Parse("26.1.2.3");

    [Fact]
    public async Task RadminVpn_IsTrustedByDescription_AndNotReportedAsConflict()
    {
        _world.Inventory.RadminDescription = "Famatech Radmin VPN Ethernet Adapter";
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        Assert.Contains(coordinator.Facts.AppliedFilters[FilterGroup.Runtime].Specs, f => f.Name == "Доверенный адаптер «Radmin VPN»");
        Assert.Empty(coordinator.Facts.Conflicts);
    }

    [Fact]
    public async Task RadminVpn_WithoutDescription_StaysUntrusted()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        Assert.DoesNotContain(coordinator.Facts.AppliedFilters[FilterGroup.Runtime].Specs, f => f.Name.StartsWith("Доверенный адаптер", StringComparison.Ordinal));
        Assert.NotEmpty(coordinator.Facts.Conflicts);
    }

    [Fact]
    public async Task RadminVpn_LosingAddress_KeepsItsNetworkLocal()
    {
        _world.Inventory.RadminDescription = "Famatech Radmin VPN Ethernet Adapter";
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.True(coordinator.Facts.Policy!.LocalRanges.Contains(RadminPeer));

        _world.Inventory.RadminHasAddress = false;
        await TickAsync(coordinator);

        Assert.True(coordinator.Facts.Policy!.LocalRanges.Contains(RadminPeer));
        Assert.Contains(coordinator.Facts.AppliedFilters[FilterGroup.Runtime].Specs, f => f.Name == "Доверенный адаптер «Radmin VPN»");
    }
}
