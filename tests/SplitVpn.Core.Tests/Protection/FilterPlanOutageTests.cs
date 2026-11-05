using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;

namespace SplitVpn.Core.Tests.Protection;

/// <summary>
/// Круг 3 код-ревью: частные сети, назначенные носителю «остального интернета», не уходят в LAN, пока он не
/// поднят (S1); положенный пользователем носитель - не обрыв для «Разрешить всё» (S5); узлы проверки отзыва
/// открываются только по TCP на порт ссылки через основной адаптер (S3).
/// </summary>
public partial class FilterPlanTests
{
    private static readonly uint OfficeHost = Ipv4.Parse("10.20.1.1");
    private static readonly uint CrlHost = Ipv4.Parse("23.215.0.136");
    // Свойство, а не поле: порядок инициализации статических полей между частями класса не определён, и TunnelA ещё пуст.
    private static UserRule OfficeIntoMainTunnel => new(Ipv4Cidr.Parse("10.20.0.0/16"), RouteTarget.Tunnel(TunnelA));

    private static ProtectionInputs MainTunnelDown(bool paused = false, OutageMode mode = OutageMode.BlockVpnTraffic, Intent intent = Intent.Connected)
    {
        var inputs = Inputs(tunnel: null, second: null, extraRules: [OfficeIntoMainTunnel]);
        return inputs with
        {
            OutageMode = mode,
            Intent = intent,
            Tunnels = [.. inputs.Tunnels.Select(t => t.ServesDefault ? t with { Paused = paused } : t)],
        };
    }

    [Theory]
    [InlineData(false, OutageMode.BlockVpnTraffic, Intent.Connected)]
    [InlineData(true, OutageMode.BlockVpnTraffic, Intent.Connected)]
    [InlineData(false, OutageMode.BlockAllPublic, Intent.Connected)]
    [InlineData(true, OutageMode.AllowAll, Intent.Connected)]
    [InlineData(false, OutageMode.AllowAll, Intent.Protected)]
    public void MainTunnelNotUp_PrivateNetworkAssignedToIt_DoesNotLeakIntoLan(bool paused, OutageMode mode, Intent intent)
    {
        var filters = All(MainTunnelDown(paused, mode, intent));

        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(OfficeHost, 445, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(OfficeHost, 445, Radmin)));
        // Своя сеть адаптера и прочие частные адреса по-прежнему открыты «Локальным доступом».
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Ipv4.Parse("192.168.1.50"), 80, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Ipv4.Parse("172.16.5.5"), 80, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Ipv4.Parse("26.1.2.3"), 80, Radmin)));

        var block = Assert.Single(FilterPlanBuilder.BuildRuntime(MainTunnelDown(paused, mode, intent)),
            f => f.Name.StartsWith("Туннель недоступен «Основной»", StringComparison.Ordinal));
        Assert.Equal(FilterPlanBuilder.WeightUserBlock, block.Weight);
    }

    [Fact]
    public void MainTunnelUp_PrivateNetworkAssignedToIt_GoesOnlyThroughTunnel()
    {
        var filters = All(Inputs(Tunnel, second: null, extraRules: [OfficeIntoMainTunnel]));

        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(OfficeHost, 445, Tunnel)));
        Assert.DoesNotContain(FilterPlanBuilder.BuildRuntime(Inputs(Tunnel, second: null, extraRules: [OfficeIntoMainTunnel])),
            f => f.Name.StartsWith("Туннель недоступен «Основной»", StringComparison.Ordinal));
    }

    /// <summary>Настоящий обрыв в режиме «Разрешить всё» отпускает трафик носителя, частный тоже: так задумано режимом.</summary>
    [Fact]
    public void AllowAll_RealOutage_ReleasesPrivateNetworkOfMainTunnel()
    {
        var filters = All(MainTunnelDown(paused: false, OutageMode.AllowAll));

        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(OfficeHost, 445, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Cloudflare, 443, WiFi)));
    }

    /// <summary>
    /// Сеть адаптера, которой ещё нет в собранной политике (она пока за носителем), не уходит мимо него через
    /// разрешение «Сеть интерфейса».
    /// </summary>
    [Fact]
    public void MainTunnelNotUp_OnLinkNetworkStillAssignedToIt_IsBlocked()
    {
        var fresh = Ipv4Cidr.Parse("5.5.5.0/24");
        var inputs = MainTunnelDown() with { OnLinkPrefixes = [Ipv4Cidr.Parse("192.168.1.0/24"), Ipv4Cidr.Parse("26.0.0.0/8"), fresh] };

        Assert.Equal(FilterAction.Block, Evaluate(All(inputs), Tcp(Ipv4.Parse("5.5.5.5"), 443, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(All(inputs), Tcp(Ipv4.Parse("192.168.1.50"), 80, WiFi)));
    }

    [Fact]
    public void AllowAll_PausedMainTunnel_IsNotOutage_TrafficStaysBlocked()
    {
        var paused = MainTunnelDown(paused: true, OutageMode.AllowAll);
        var filters = All(paused);

        Assert.False(FilterPlanBuilder.IsOutage(paused));
        Assert.True(FilterPlanBuilder.IsOutage(MainTunnelDown(paused: false, OutageMode.AllowAll)));
        Assert.DoesNotContain(filters, f => f.Name == "Обрыв: разрешить всё");
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(Cloudflare, 443, WiFi)));
        // Россия по-прежнему напрямую: положен только носитель «остального интернета».
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Yandex, 443, WiFi)));
    }

    /// <summary>Группа «остального интернета»: обрыв, только если хоть один участник лёг не по воле пользователя.</summary>
    [Fact]
    public void AllowAll_GroupCarrier_IsOutageOnlyWhenNotEveryMemberPaused()
    {
        var baseline = Inputs(tunnel: null) with { OutageMode = OutageMode.AllowAll };
        ProtectionInputs Group(bool aPaused, bool bPaused, bool groupPaused) => baseline with
        {
            Tunnels =
            [
                new TunnelInput { Id = TunnelA, Name = "Основной", ServesDefault = true, Paused = aPaused },
                new TunnelInput { Id = TunnelB, Name = "Второй", ServesDefault = true, Paused = bPaused },
                new TunnelInput { Id = GroupAb, Name = "Группа", ServesDefault = true, Paused = groupPaused },
            ],
        };

        Assert.False(FilterPlanBuilder.IsOutage(Group(true, true, true)));
        Assert.True(FilterPlanBuilder.IsOutage(Group(true, false, false)));
    }

    [Fact]
    public void RevocationEndpoint_OpensOnlyTcpPortThroughPrimary()
    {
        var inputs = Inputs(tunnel: null) with { RevocationEndpoints = [new RevocationEndpoint(CrlHost, 80)] };
        var filters = All(inputs);

        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(CrlHost, 80, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(CrlHost, 443, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Udp(CrlHost, 80, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(CrlHost, 80, Radmin)));
        Assert.All(FilterPlanBuilder.BuildDynamic(inputs), f => Assert.Equal(FilterGroup.Dynamic, f.Group));
    }

    [Fact]
    public void RevocationEndpoint_WorksDuringOutageWithAllPublicBlocked_ButNotWithoutPrimary()
    {
        var outage = Inputs(tunnel: null) with { OutageMode = OutageMode.BlockAllPublic, RevocationEndpoints = [new RevocationEndpoint(CrlHost, 8080)] };

        Assert.Equal(FilterAction.Permit, Evaluate(All(outage), Tcp(CrlHost, 8080, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(All(outage), Tcp(CrlHost, 80, WiFi)));
        Assert.DoesNotContain(FilterPlanBuilder.BuildDynamic(outage with { PrimaryLuid = null }),
            f => f.Name.StartsWith("Проверка отзыва", StringComparison.Ordinal));
    }

    /// <summary>Тот же адрес через живой туннель ходит как обычно: служебное разрешение не уводит его напрямую.</summary>
    [Fact]
    public void RevocationEndpoint_DoesNotPinAddressDirect()
    {
        var inputs = Inputs(Tunnel) with { RevocationEndpoints = [new RevocationEndpoint(CrlHost, 80)] };

        Assert.Equal(FilterAction.Permit, Evaluate(All(inputs), Tcp(CrlHost, 443, Tunnel)));
        Assert.DoesNotContain(FilterPlanBuilder.BuildDynamic(inputs), f => f.Action == FilterAction.Block);
    }
}
