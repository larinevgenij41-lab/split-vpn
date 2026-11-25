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
    public void Auto_PicksPppoeDialUp_ButNotOtherPppInterfaces()
    {
        // PPPoE без роутера: маршрут по умолчанию через интерфейс PPP без следующего узла.
        var pppoe = new AdapterCandidate
        {
            InterfaceGuid = Guid.NewGuid(), Name = "Высокоскоростное подключение", IfType = 23, IsHardware = false,
            IsBroadbandDialUp = true, IsUp = true, InterfaceIndex = 30, DefaultGateway = 0, DefaultRouteMetric = 26,
        };
        var foreignVpn = pppoe with { InterfaceGuid = Guid.NewGuid(), Name = "Рабочий VPN", IsBroadbandDialUp = false, DefaultRouteMetric = 1 };

        Assert.Equal(pppoe, PrimaryAdapterSelector.Select([foreignVpn, pppoe], pinned: null, allowFallback: false).Adapter);
        Assert.Equal(PrimaryAdapterStatus.NoneAvailable, PrimaryAdapterSelector.Select([foreignVpn], pinned: null, allowFallback: false).Status);
        Assert.Equal(pppoe, PrimaryAdapterSelector.Select([pppoe], pinned: pppoe.InterfaceGuid, allowFallback: false).Adapter);
    }

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

    /// <summary>Сброс сети Windows выдал адаптеру новый GUID: закрепление находит его по описанию драйвера.</summary>
    [Fact]
    public void PinnedGuidGone_ReboundsToSameDriver()
    {
        const string driver = "Intel(R) Wi-Fi 6 AX200 160MHz";
        var renewed = WiFi with { InterfaceGuid = Guid.NewGuid(), Description = driver };
        var ethernet = WiFi with { InterfaceGuid = Guid.NewGuid(), Name = "Ethernet", Description = "Realtek Gaming 2.5GbE", InterfaceIndex = 3, DefaultRouteMetric = 5 };

        var result = PrimaryAdapterSelector.Select([ethernet, renewed], Guid.NewGuid(), false, driver);

        Assert.Equal(PrimaryAdapterStatus.PinnedRebound, result.Status);
        Assert.Same(renewed, result.Adapter);
    }

    /// <summary>Прежний GUID на месте, но адаптер выключен: это не смена GUID, перехода на соседа нет.</summary>
    [Fact]
    public void PinnedAdapterDown_IsNotRebound()
    {
        const string driver = "Intel(R) Wi-Fi 6 AX200 160MHz";
        var pinned = WiFi with { InterfaceGuid = Guid.NewGuid(), Description = driver, IsUp = false };
        var twin = WiFi with { InterfaceGuid = Guid.NewGuid(), Description = driver, InterfaceIndex = 12 };

        var result = PrimaryAdapterSelector.Select([pinned, twin], pinned.InterfaceGuid, false, driver);

        Assert.Equal(PrimaryAdapterStatus.PinnedMissing, result.Status);
        Assert.Null(result.Adapter);
    }

    /// <summary>Два адаптера с одинаковым драйвером: какой из них прежний, неизвестно, закрепление не переносится.</summary>
    [Fact]
    public void PinnedGuidGone_TwoSameDrivers_StaysMissing()
    {
        const string driver = "Intel(R) Wi-Fi 6 AX200 160MHz";
        var first = WiFi with { InterfaceGuid = Guid.NewGuid(), Description = driver };
        var second = WiFi with { InterfaceGuid = Guid.NewGuid(), Description = driver, InterfaceIndex = 12 };

        Assert.Equal(PrimaryAdapterStatus.PinnedMissing, PrimaryAdapterSelector.Select([first, second], Guid.NewGuid(), false, driver).Status);
    }

    /// <summary>Аудит ID83: огромная метрика интерфейса не переполняет сумму и не делает адаптер самым дешёвым.</summary>
    [Fact]
    public void EffectiveMetric_SaturatesInsteadOfWrapping()
    {
        Assert.Equal(uint.MaxValue, RouteMetric.Effective(10, uint.MaxValue - 5));
        Assert.Equal(135u, RouteMetric.Effective(100, 35));

        var huge = WiFi with { InterfaceGuid = Guid.NewGuid(), InterfaceIndex = 3, DefaultRouteMetric = RouteMetric.Effective(10, uint.MaxValue - 5) };
        var normal = WiFi with { DefaultRouteMetric = RouteMetric.Effective(0, 100) };
        Assert.Same(normal, PrimaryAdapterSelector.Select([huge, normal], null, false).Adapter);
    }
}
