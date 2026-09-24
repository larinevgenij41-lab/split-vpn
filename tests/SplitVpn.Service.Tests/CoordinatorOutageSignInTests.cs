using SplitVpn.Core.OpenConnect;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Опорный туннель лежит, а поднять нужно дополнительный AnyConnect. Посредник в это время уходит в
/// offline и не разрешает ни одного имени — вход становится невозможен именно тогда, когда он нужнее
/// всего. Разбирается жалоба: «когда с опорным подключением проблемы, AnyConnect не подключается».
/// </summary>
public sealed partial class CoordinatorTests
{
    /// <summary>Опорный туннель не поднимется: сервер отказал в доступе, повторов не будет.</summary>
    private void FailAnchorDial() =>
        _world.Ras.ResultsByEntry[Coordinator.EntryNameFor(_profile)] =
            new Queue<RasDialResult>([new RasDialResult(false, null, 691, "Отказано в доступе")]);

    [Fact]
    public async Task AnchorDown_GatewayNameStillResolves_AndSignInIsExplained()
    {
        FailAnchorDial();
        var coordinator = await StartWithAnyConnectAsync();
        await ConnectAsync(coordinator);

        // Шлюз просит вход через браузер — ровно тот случай, когда посредник обязан разрешить его имя.
        _world.AnyConnect.Last!.Emit(new SsoOpenEvent(Guid.NewGuid(), "https://" + Gateway + "/+CSCOE+/saml/sp/login", Gateway));
        await CompleteDialAsync(coordinator);

        Assert.Equal(DnsProxyMode.Offline, _world.Proxy.Configuration.Mode);
        var route = Assert.Single(_world.Proxy.Configuration.DomainRoutes, d => d.Suffix == Gateway);
        Assert.NotNull(route.Route);
        Assert.False(route.PinAddresses);

        var warning = Assert.Single(coordinator.BuildStatus().Warnings, w => w.Code == "sign-in-required");
        Assert.Contains("защита при обрыве блокирует", warning.Text, StringComparison.Ordinal);
    }

    /// <summary>Опорный туннель поднят: имя шлюза разрешается как раньше, через DNS туннеля.</summary>
    [Fact]
    public async Task AnchorUp_GatewayNameGoesThroughTunnelAsBefore()
    {
        var coordinator = await StartWithAnyConnectAsync();
        await ConnectAsync(coordinator);

        Assert.Equal(DnsProxyMode.Online, _world.Proxy.Configuration.Mode);
        Assert.DoesNotContain(_world.Proxy.Configuration.DomainRoutes, d => d.Suffix == Gateway);
    }
}
