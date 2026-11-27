using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Маршруты применяются частично (как RouteOps.Reconcile): маршрут к сети не добавился на новый интерфейс, прежний к ней
/// снят или оставлен (если его интерфейс всё ещё покрывает сеть). Защита при этом не должна выпустить трафик к сети мимо
/// новой цели: куда бы Windows ни отправила пакет по оставшимся маршрутам, фильтры его блокируют или это сама цель.
/// </summary>
public sealed partial class CoordinatorTests
{
    private static readonly Ipv4Cidr ChangedNetwork = Ipv4Cidr.Parse("13.107.0.0/16");

    public enum PartialRouteFrom
    {
        /// <summary>Сеть шла напрямую через Wi-Fi.</summary>
        Direct,

        /// <summary>Сеть шла через основной туннель (он же несёт «остальной интернет» - половинные маршруты остаются).</summary>
        PrimaryTunnel,

        /// <summary>
        /// Сеть шла через основной туннель внутри большей сети «напрямую»: свой маршрут /16 на основной туннель нужен, и
        /// при сбое он остаётся (его интерфейс покрывает сеть половинными маршрутами) - трафик идёт в основной туннель.
        /// </summary>
        PrimaryTunnelInsideDirect,
    }

    [Theory]
    [InlineData(PartialRouteFrom.Direct)]
    [InlineData(PartialRouteFrom.PrimaryTunnel)]
    [InlineData(PartialRouteFrom.PrimaryTunnelInsideDirect)]
    public async Task PartialRouteFailure_DuringTargetChangeToSecondTunnel_NeverLeaks(PartialRouteFrom from)
    {
        var second = SecondProfile();
        var oldTarget = from == PartialRouteFrom.Direct ? RouteTarget.Direct : RouteTarget.Tunnel(_profile.Id);
        UserRuleSetting[] outer = from == PartialRouteFrom.PrimaryTunnelInsideDirect
            ? [new UserRuleSetting { Cidr = "13.0.0.0/8", Target = RouteTarget.Direct }]
            : [];
        SaveSettings(Settings() with
        {
            Profiles = [_profile, second],
            Rules = [.. outer, new UserRuleSetting { Cidr = ChangedNetwork.ToString(), Target = oldTarget }],
        });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var newLuid = FakeInventory.TunnelLuid(1);
        Assert.Equal(2, _world.Ras.ConnectedEntries.Count);

        // Добавление маршрута к сети на второй туннель не проходит; остальное применяется.
        _world.Routes.FailDestinations.Add(ChangedNetwork);
        var changed = coordinator.Settings with
        {
            Rules = [.. outer, new UserRuleSetting { Cidr = ChangedNetwork.ToString(), Target = RouteTarget.Tunnel(second.Id) }],
        };
        await coordinator.HandleRequestAsync(new SaveSettingsRequest(changed), CancellationToken.None);
        await CompleteDialAsync(coordinator);

        Assert.True(_world.Routes.FailedAdds > 0, "сбой добавления маршрута не случился - проверять нечего");
        Assert.DoesNotContain(_world.Routes.Current, r => r.Destination == ChangedNetwork && r.InterfaceLuid == newLuid);
        if (from == PartialRouteFrom.PrimaryTunnelInsideDirect)
        {
            // Ветка «прежний маршрут оставлен» (RouteOps.StillPermitted) действительно проверена.
            Assert.True(_world.Routes.KeptStillPermitted > 0, "прежний маршрут к сети не оставлен");
        }

        TestContext.Current.TestOutputHelper?.WriteLine($"{from}: оставлено прежних маршрутов {_world.Routes.KeptStillPermitted}; маршруты к сети: "
            + string.Join(", ", _world.Routes.Current.Where(r => r.Destination.Contains(ChangedNetwork.Network)).Select(r => $"{r.Destination}@{r.InterfaceLuid}")));
        foreach (var address in new[] { ChangedNetwork.Network + 1, Ipv4.Parse("13.107.1.1"), ChangedNetwork.Network + 0xFFFE })
        {
            foreach (var luid in ChosenInterfaces(address))
            {
                var action = RoutingAction(address, luid);
                Assert.True(action == FilterAction.Block || luid == newLuid,
                    $"{Ipv4.Format(address)}: пакет уходит в интерфейс {luid} и пропускается ({action}); маршруты: "
                    + string.Join(", ", _world.Routes.Current.Where(r => r.Destination.Contains(address)).Select(r => $"{r.Destination}@{r.InterfaceLuid}")));
            }
        }
    }

    /// <summary>
    /// Интерфейсы, которые выберет Windows для адреса: самый длинный префикс среди маршрутов службы и маршрута по умолчанию
    /// Wi-Fi. При равной длине префикса - все кандидаты (метрики модель не различает, поэтому проверяются все).
    /// </summary>
    private List<ulong> ChosenInterfaces(uint address)
    {
        var candidates = _world.Routes.Current
            .Where(r => r.Destination.Contains(address))
            .Select(r => (Prefix: r.Destination.PrefixLength, Luid: r.InterfaceLuid))
            .Append((Prefix: 0, Luid: FakeWorld.WiFiLuid))
            .ToList();
        var longest = candidates.Max(c => c.Prefix);
        return candidates.Where(c => c.Prefix == longest).Select(c => c.Luid).Distinct().ToList();
    }
}
