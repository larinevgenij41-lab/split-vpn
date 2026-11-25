using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
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

        // Итерация 12: публичная сеть недоверенного адаптера не локальна - она идёт по правилам (здесь в туннель), а
        // локальным остаётся только его маршрутизатор. Предупреждение говорит, как доверять адаптеру.
        Assert.False(coordinator.Facts.Policy!.LocalRanges.Contains(RadminPeer));
        Assert.Equal(Decision.Local, coordinator.Facts.Policy.Classify(Ipv4.Parse("26.0.0.1")).Decision);
        var warning = Assert.Single(coordinator.BuildStatus().Warnings, w => w.Code == "public-onlink");
        Assert.Contains("Доверенные адаптеры", warning.Text, StringComparison.Ordinal);
        Assert.Contains("26.0.0.0/8", warning.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TrustedAdapterByGuid_KeepsItsPublicNetworkLocal()
    {
        var radmin = Guid.NewGuid();
        _world.Inventory.RadminGuid = radmin;
        SaveSettings(Settings() with { TrustedAdapters = [radmin] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        Assert.True(coordinator.Facts.Policy!.LocalRanges.Contains(RadminPeer));
        var trusted = Assert.Single(coordinator.Facts.AppliedFilters[FilterGroup.Runtime].Specs, f => f.Name == "Доверенный адаптер «Radmin VPN»");
        Assert.Contains(trusted.Conditions, c => c is RemoteRangesV4 r && r.Contains(RadminPeer) && !r.Contains(Ipv4.Parse("1.1.1.1")));
        Assert.DoesNotContain(coordinator.BuildStatus().Warnings, w => w.Code == "public-onlink");
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
