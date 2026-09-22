using SplitVpn.Core.Geo;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Service.Coordination;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Второй автообновляемый список — «обход блокировок». У него своё хранилище версий, свои настройки
/// обновления и своя цель; команды к нему приходят с указанием списка и RU-базы не касаются.
/// </summary>
public sealed partial class CoordinatorTests
{
    private static readonly string BlockedCidr = "77.88.8.0/24";

    private void SeedBypass(params string[] cidrs)
    {
        var store = new GeoStore(_world.Paths.Bypass);
        var text = string.Join('\n', Enumerable.Range(0, 150).Select(i => $"203.0.{i}.0/24").Concat(cidrs));
        var bytes = GeoUpdateEvaluator.ToStoredBytes(text);
        var id = GeoStore.ComputeId(bytes);
        store.SaveRevision(bytes, new GeoRevision { Id = id, SourceId = ReFilterSource.SourceId, V4Count = 151 });
        store.Activate(id);
    }

    [Fact]
    public async Task BypassList_OverridesGeo_AndIsShownInStatus()
    {
        SeedBypass(BlockedCidr);
        new ServiceStores(_world.Paths).SaveSettings(Settings() with
        {
            GeoTarget = RouteTarget.Direct,
            BypassTarget = RouteTarget.Tunnel(_profile.Id),
        });

        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        // 77.88.0.0/18 лежит в RU-базе стенда: адрес из списка обхода всё равно уходит в туннель.
        var blocked = coordinator.Facts.Policy!.Classify(Ipv4.Parse("77.88.8.8"));
        Assert.Equal(Decision.Vpn, blocked.Decision);
        Assert.Equal(DecisionSource.Bypass, blocked.Source);
        Assert.Equal(Decision.Direct, coordinator.Facts.Policy!.Classify(Ipv4.Parse("77.88.55.242")).Decision);

        var status = coordinator.BuildStatus();
        var bypass = Assert.IsType<GeoListStatusDto>(status.Bypass);
        Assert.Equal(GeoListKind.Bypass, bypass.List);
        Assert.Equal(151, bypass.V4Count);
        Assert.False(bypass.FollowsDefault);
    }

    [Fact]
    public async Task WithoutBypassList_RoutingIsUnchanged()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        Assert.Equal(DecisionSource.Geo, coordinator.Facts.Policy!.Classify(Ipv4.Parse("77.88.8.8")).Source);
        Assert.Equal(0, coordinator.BuildStatus().Bypass!.V4Count);
        Assert.True(coordinator.BuildStatus().Bypass!.FollowsDefault);
    }

    /// <summary>Откат списка обхода не трогает RU-базу: хранилища у них разные.</summary>
    [Fact]
    public async Task RollbackOfBypass_LeavesGeoBaseAlone()
    {
        SeedBypass(BlockedCidr);
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var geoRevision = coordinator.BuildStatus().GeoRevision;

        var response = await coordinator.HandleRequestAsync(
            new GeoRollbackRequest { List = GeoListKind.Bypass }, CancellationToken.None);

        // Предыдущей версии списка нет — отказ; RU-база при этом на месте.
        Assert.False(response.Ok);
        Assert.Equal(geoRevision, coordinator.BuildStatus().GeoRevision);
        Assert.NotNull(coordinator.BuildStatus().Bypass!.Revision);
    }
}
