using SplitVpn.Core.Net;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Protection;

/// <summary>
/// Разрешения для системных клиентов (DHCP, проверка интернета Windows) действуют только для svchost.exe:
/// иначе любая программа ходила бы этими портами и адресами мимо защиты.
/// </summary>
public partial class FilterPlanTests
{
    private static readonly uint NcsiHost = Ipv4.Parse("23.215.0.140");

    private static ProtectionInputs WithNcsi(ProtectionInputs inputs) =>
        inputs with { ConnectivityCheckEndpoints = [new RevocationEndpoint(NcsiHost, 80)] };

    [Fact]
    public void ConnectivityCheck_OnlySvchost_WithDomainWeight()
    {
        var inputs = WithNcsi(Inputs(tunnel: null) with { OutageMode = OutageMode.BlockAllPublic });

        var ncsi = Assert.Single(FilterPlanBuilder.BuildDynamic(inputs), f => f.Name.StartsWith("Проверка интернета Windows", StringComparison.Ordinal));
        Assert.Contains(new AppIdCondition(FilterPlanBuilder.SvchostExecutablePath), ncsi.Conditions);
        // Вес правил для доменов: выше блока «Туннель недоступен» (вес запретов пользователя), обрыва и чужого адаптера.
        Assert.Equal(FilterPlanBuilder.WeightDomain, ncsi.Weight);
        Assert.True(ncsi.Weight > FilterPlanBuilder.WeightUserBlock);
        Assert.True(ncsi.Weight > FilterPlanBuilder.WeightBlockPublicOnOutage);
        Assert.True(ncsi.Weight > FilterPlanBuilder.WeightForeignInterface);
        Assert.True(ncsi.Weight > FilterPlanBuilder.WeightRouteGuard);

        var filters = All(inputs);
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(NcsiHost, 80, WiFi) with { AppPath = FilterPlanBuilder.SvchostExecutablePath }));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(NcsiHost, 80, WiFi)));
    }

    /// <summary>
    /// Адрес www.msftconnecttest.com из общей сети доставки попал в диапазон лежащего дополнительного туннеля: блок
    /// «Туннель недоступен» (13) не должен перебивать пробу NCSI, иначе Windows помечает сеть «без интернета» и
    /// сбрасывает Wi-Fi. Чужая программа к тому же адресу и порту по-прежнему блокируется.
    /// </summary>
    [Fact]
    public void ConnectivityCheck_InRangeOfDownSecondTunnel_PermittedOnlyForSvchost()
    {
        var inputs = Inputs(Tunnel, second: null) with { ConnectivityCheckEndpoints = [new RevocationEndpoint(SecondNetwork, 80)] };
        Assert.Contains(FilterPlanBuilder.BuildRuntime(inputs), f => f.Name.StartsWith("Туннель недоступен «Второй»", StringComparison.Ordinal));
        var filters = All(inputs);

        Assert.Equal(FilterAction.Permit,
            Evaluate(filters, Tcp(SecondNetwork, 80, WiFi) with { AppPath = FilterPlanBuilder.SvchostExecutablePath }));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(SecondNetwork, 80, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(SecondNetwork, 80, WiFi) with { AppPath = @"C:\app.exe" }));
        Assert.Equal(FilterAction.Block,
            Evaluate(filters, Tcp(SecondNetwork, 443, WiFi) with { AppPath = FilterPlanBuilder.SvchostExecutablePath }));
    }

    [Fact]
    public void RevocationCheck_KeepsDomainWeightWithoutAppCondition()
    {
        var inputs = Inputs(tunnel: null) with { RevocationEndpoints = [new RevocationEndpoint(NcsiHost, 80)] };

        var revocation = Assert.Single(FilterPlanBuilder.BuildDynamic(inputs), f => f.Name.StartsWith("Проверка отзыва", StringComparison.Ordinal));
        Assert.Equal(FilterPlanBuilder.WeightDomain, revocation.Weight);
        Assert.DoesNotContain(revocation.Conditions, c => c is AppIdCondition);
    }

    [Theory]
    [InlineData("DHCPv4")]
    [InlineData("DHCPv6")]
    public void Dhcp_OnlySvchost(string name)
    {
        var dhcp = Assert.Single(FilterPlanBuilder.BuildBase(Inputs(tunnel: Tunnel)), f => f.Name == name);

        Assert.Contains(new AppIdCondition(FilterPlanBuilder.SvchostExecutablePath), dhcp.Conditions);
        Assert.EndsWith(@"\svchost.exe", FilterPlanBuilder.SvchostExecutablePath, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Dhcp_OtherProgramOnDhcpPorts_IsBlocked()
    {
        var filters = All(Inputs(tunnel: Tunnel) with { LocalAccess = false });

        Assert.Equal(FilterAction.Permit, Evaluate(filters, Packet.Dhcp(WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Packet.Dhcp(WiFi) with { AppPath = @"C:\app.exe" }));
    }

    /// <summary>Соседские сообщения IPv6 шлёт ядро, а не процесс: условие приложения к ним не ставится.</summary>
    [Fact]
    public void Ipv6NeighborDiscovery_HasNoAppCondition()
    {
        var nd = Assert.Single(FilterPlanBuilder.BuildBase(Inputs(tunnel: Tunnel)), f => f.Name == "IPv6 ND");

        Assert.DoesNotContain(nd.Conditions, c => c is AppIdCondition);
    }
}
