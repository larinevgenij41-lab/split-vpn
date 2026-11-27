using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Protection;

/// <summary>
/// Аудит 26.11.2026: сеть доверенного адаптера (Radmin 26.0.0.0/8) открыта только через сам адаптер. Разрешение
/// «Сеть интерфейса» без условия на интерфейс выпускало бы её через основной адаптер, когда Radmin выключен (служба
/// помнит его сети), а VPN лёг.
/// </summary>
public partial class FilterPlanTests
{
    [Theory]
    [InlineData(OutageMode.BlockVpnTraffic)]
    [InlineData(OutageMode.BlockAllPublic)]
    public void TrustedAdapterNetwork_DuringOutage_IsBlockedThroughPrimary(OutageMode mode)
    {
        var inputs = Inputs(tunnel: null) with { OutageMode = mode, TrustedAdapters = [RadminAdapter] };
        var filters = All(inputs);

        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(Ipv4.Parse("26.1.2.3"), 443, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Ipv4.Parse("26.1.2.3"), 443, Radmin)));
        // Своя сеть основного адаптера открыта как прежде.
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Ipv4.Parse("192.168.1.50"), 80, WiFi)));
        Assert.DoesNotContain(FilterPlanBuilder.BuildRuntime(inputs),
            f => f.Name.StartsWith("Сеть интерфейса", StringComparison.Ordinal) && f.Conditions.OfType<RemoteRangeV4>().Any(r => r.Start <= Ipv4.Parse("26.1.2.3") && Ipv4.Parse("26.1.2.3") <= r.End));
    }

    [Fact]
    public void TrustedAdapterNetwork_TunnelUp_DoesNotGoDirectThroughPrimary()
    {
        var filters = All(Inputs(tunnel: Tunnel) with { TrustedAdapters = [RadminAdapter] });

        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(Ipv4.Parse("26.1.2.3"), 443, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Ipv4.Parse("26.1.2.3"), 443, Radmin)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Ipv4.Parse("192.168.1.50"), 80, WiFi)));
    }

    /// <summary>Частная сеть, общая у основного и доверенного адаптеров, из «Сети интерфейса» не вычитается.</summary>
    [Fact]
    public void TrustedAdapterPrivateNetwork_SharedWithPrimary_StaysOpenThroughPrimary()
    {
        var shared = new TrustedAdapterInput(Radmin, "Radmin VPN") { Prefixes = [Ipv4Cidr.Parse("26.0.0.0/8"), Ipv4Cidr.Parse("192.168.1.0/24")] };
        var runtime = FilterPlanBuilder.BuildRuntime(Inputs(tunnel: null) with { TrustedAdapters = [shared] });

        Assert.Contains(runtime, f => f.Name == "Сеть интерфейса 192.168.1.0-192.168.1.255");
        Assert.Equal(FilterAction.Permit, Evaluate(All(Inputs(tunnel: null) with { TrustedAdapters = [shared] }), Tcp(Ipv4.Parse("192.168.1.50"), 80, WiFi)));
    }

    /// <summary>
    /// Ревью: зарезервированные сети, частные у любого адаптера (198.18.0.0/15 fake-IP TUN, 192.0.0.0/29 DS-Lite), тоже не
    /// вычитаются: у доверенного TUN и у недоверенного основного адаптера та же сеть, и при обрыве в режиме «Блокировать
    /// весь публичный» трафик основного адаптера к ней иначе блокировался бы.
    /// </summary>
    [Theory]
    [InlineData("198.18.0.0/15", "198.18.0.5")]
    [InlineData("192.0.0.0/29", "192.0.0.2")]
    public void TrustedAdapterReservedPrivateNetwork_SharedWithPrimary_StaysOpenThroughPrimary(string prefix, string address)
    {
        var tun = new TrustedAdapterInput(Radmin, "Clash TUN") { Prefixes = [Ipv4Cidr.Parse(prefix)] };
        var inputs = Inputs(tunnel: null) with
        {
            Policy = PolicyCompiler.Compile(new PolicyInput
            {
                DefaultTarget = RouteTarget.Tunnel(TunnelA),
                ServerAddresses = [Server],
                ServiceDnsAddresses = [RouterDns],
                OnLinePrefixes = [Ipv4Cidr.Parse("192.168.1.0/24"), Ipv4Cidr.Parse(prefix)],
            }),
            OutageMode = OutageMode.BlockAllPublic,
            TrustedAdapters = [tun],
            OnLinkPrefixes = [Ipv4Cidr.Parse("192.168.1.0/24"), Ipv4Cidr.Parse(prefix)],
        };

        Assert.Equal(FilterAction.Permit, Evaluate(All(inputs), Tcp(Ipv4.Parse(address), 443, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(All(inputs), Tcp(Ipv4.Parse(address), 443, Radmin)));
    }
}
