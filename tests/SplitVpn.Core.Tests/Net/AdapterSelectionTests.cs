using SplitVpn.Core.Net;

namespace SplitVpn.Core.Tests.Net;

public class AdapterSelectionTests
{
    private static readonly AdapterCandidate WiFi = new()
    {
        InterfaceGuid = Guid.NewGuid(),
        Name = "Беспроводная сеть",
        IfType = 71,
        IsHardware = true,
        IsUp = true,
        InterfaceIndex = 8,
        DefaultGateway = Ipv4.Parse("192.168.1.1"),
        DefaultRouteMetric = 35,
        OnLinkPrefixes = [Ipv4Cidr.Parse("192.168.1.0/24")],
    };

    private static readonly AdapterCandidate Radmin = new()
    {
        InterfaceGuid = Guid.NewGuid(),
        Name = "Radmin VPN",
        IfType = 6,
        IsHardware = false,
        IsUp = true,
        InterfaceIndex = 19,
        DefaultGateway = Ipv4.Parse("26.0.0.1"),
        DefaultRouteMetric = 9257,
        OnLinkPrefixes = [Ipv4Cidr.Parse("26.0.0.0/8")],
    };

    private static readonly AdapterCandidate VEthernet = new()
    {
        InterfaceGuid = Guid.NewGuid(),
        Name = "vEthernet (Default Switch)",
        IsUp = true,
        OnLinkPrefixes = [Ipv4Cidr.Parse("172.29.128.0/20")],
    };

    private static readonly AdapterCandidate Ethernet = new()
    {
        InterfaceGuid = Guid.NewGuid(),
        Name = "Ethernet",
        IfType = 6,
        IsHardware = true,
        IsUp = true,
        InterfaceIndex = 3,
        DefaultGateway = Ipv4.Parse("192.168.0.1"),
        DefaultRouteMetric = 35,
    };

    [Fact]
    public void Auto_NeverPicksOverlayAdapter_EvenIfReportedAsHardware()
    {
        var radminAsHardware = Radmin with { IsHardware = true, DefaultRouteMetric = 1, Description = "Famatech Radmin VPN Ethernet Adapter" };

        Assert.True(radminAsHardware.IsOverlay);
        Assert.Equal(PrimaryAdapterStatus.NoneAvailable, PrimaryAdapterSelector.Select([radminAsHardware], pinned: null, allowFallback: false).Status);
        Assert.Equal(WiFi, PrimaryAdapterSelector.Select([radminAsHardware, WiFi], pinned: null, allowFallback: false).Adapter);
    }

    [Theory]
    [InlineData("Famatech Radmin VPN Ethernet Adapter", true)]
    [InlineData("LogMeIn Hamachi Virtual Ethernet Adapter", true)]
    [InlineData("ZeroTier Virtual Port", true)]
    [InlineData("Tailscale Tunnel", true)]
    [InlineData("Intel(R) Wi-Fi 6 AX201 160MHz", false)]
    [InlineData("", false)]
    public void OverlayAdapters_AreRecognizedByDescription(string description, bool expected) =>
        Assert.Equal(expected, OverlayAdapters.IsKnown(description));

    [Fact]
    public void Auto_PicksHardwareAdapterWithDefaultRoute_IgnoringVirtualVpn()
    {
        var result = PrimaryAdapterSelector.Select([Radmin, VEthernet, WiFi], pinned: null, allowFallback: false);

        Assert.Equal(PrimaryAdapterStatus.Selected, result.Status);
        Assert.Equal(WiFi, result.Adapter);
    }

    [Fact]
    public void Auto_EqualMetrics_AreOrderedByInterfaceIndex()
    {
        var result = PrimaryAdapterSelector.Select([WiFi, Ethernet], pinned: null, allowFallback: false);

        Assert.Equal(Ethernet, result.Adapter);
    }

    [Fact]
    public void Pinned_Missing_WithoutFallback_ReturnsNoAdapter()
    {
        var result = PrimaryAdapterSelector.Select([WiFi], pinned: Ethernet.InterfaceGuid, allowFallback: false);

        Assert.Null(result.Adapter);
        Assert.Equal(PrimaryAdapterStatus.PinnedMissing, result.Status);
    }

    [Fact]
    public void Pinned_Missing_WithFallback_UsesAuto()
    {
        var result = PrimaryAdapterSelector.Select([WiFi], pinned: Ethernet.InterfaceGuid, allowFallback: true);

        Assert.Equal(WiFi, result.Adapter);
        Assert.Equal(PrimaryAdapterStatus.FallbackFromPinned, result.Status);
    }

    [Fact]
    public void NoUsableAdapters_IsReported()
    {
        var down = WiFi with { IsUp = false };

        Assert.Equal(PrimaryAdapterStatus.NoneAvailable, PrimaryAdapterSelector.Select([down, Radmin], null, false).Status);
    }

    [Fact]
    public void PublicOnLinkNetworks_AreReportedAsConflicts()
    {
        var conflicts = PrimaryAdapterSelector.PublicOnLinkConflicts([WiFi, Radmin, VEthernet]).ToList();

        var conflict = Assert.Single(conflicts);
        Assert.Equal("Radmin VPN", conflict.Adapter.Name);
        Assert.Equal("26.0.0.0/8", conflict.Prefix.ToString());
    }
}
