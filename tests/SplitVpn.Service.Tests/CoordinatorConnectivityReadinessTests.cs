using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Ревью 0.15.18: готовность ответа DNS решается по его собственным адресам, а не по общему номеру набора закреплений.
/// </summary>
public sealed partial class CoordinatorTests
{
    /// <summary>
    /// Ответ другой программы по правилу ждёт занятую очередь (запуск Windows). Ответ на проверку интернета Windows с уже
    /// открытым адресом не должен ждать его вместе с ним: иначе через 8 с отказ DNS и сброс Wi-Fi.
    /// </summary>
    [Fact]
    public async Task ConnectivityCheck_AnswerOnOpenAddress_DoesNotWaitForUnrelatedPendingPin()
    {
        var coordinator = await StartProtectedForConnectivityCheckAsync();
        var warm = Addresses(1, 3);
        await coordinator.OnConnectivityCheckResolvedAsync(coordinator.ConnectivityPinContext, warm);

        var unrelated = coordinator.ObservePinnedAsync(new PinnedRouteNotice("busy.example", "busy.example", RouteTarget.Direct,
            [Ipv4.Parse("198.51.100.10")], TimeSpan.FromMinutes(5)), CancellationToken.None).AsTask();
        Assert.False(unrelated.IsCompleted);

        var pin = ObserveConnectivityCheckWithoutDrain(coordinator, [warm[0]]).AsTask();
        Assert.True(await pin.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken));

        await coordinator.DrainAsync();
        await unrelated.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
    }

    /// <summary>То же для обычного правила: повторный ответ с уже применённым адресом не ждёт чужое закрепление.</summary>
    [Fact]
    public async Task DomainPins_AnswerOnAppliedAddress_DoesNotWaitForUnrelatedPendingPin()
    {
        SaveSettings(Settings() with { DomainRules = [new DomainRuleSetting { Suffix = "ready.example", Target = RouteTarget.Direct }] });
        var coordinator = await StartProtectedForConnectivityCheckAsync();
        var notice = new PinnedRouteNotice("ready.example", "ready.example", RouteTarget.Direct, [Ipv4.Parse("198.51.100.20")], TimeSpan.FromMinutes(5));
        var first = coordinator.ObservePinnedAsync(notice, CancellationToken.None);
        await coordinator.DrainAsync();
        Assert.True(await first);

        var unrelated = coordinator.ObservePinnedAsync(new PinnedRouteNotice("busy.example", "busy.example", RouteTarget.Direct,
            [Ipv4.Parse("198.51.100.10")], TimeSpan.FromMinutes(5)), CancellationToken.None).AsTask();
        Assert.False(unrelated.IsCompleted);

        var repeated = coordinator.ObservePinnedAsync(notice, CancellationToken.None).AsTask();
        Assert.True(await repeated.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken));

        // Новый адрес по-прежнему ждёт применения.
        var fresh = coordinator.ObservePinnedAsync(notice with { Addresses = [Ipv4.Parse("198.51.100.21")] }, CancellationToken.None).AsTask();
        Assert.False(fresh.IsCompleted);
        await coordinator.DrainAsync();
        Assert.True(await fresh.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken));
        await unrelated.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// Сеть доставки ответила Windows новым адресом, а очередь занята: адрес не открыт вовремя. Служба отдаёт посреднику
    /// уже открытые адреса прогрева и держит их открытыми, хотя новый ответ вытеснил прогрев.
    /// </summary>
    [Fact]
    public async Task ConnectivityCheck_FreshAddressNotOpenedInTime_ServiceOffersOpenAddresses()
    {
        var coordinator = await StartProtectedForConnectivityCheckAsync();
        var warm = Addresses(1, 2);
        await coordinator.OnConnectivityCheckResolvedAsync(coordinator.ConnectivityPinContext, warm);

        var fresh = new PinnedRouteNotice(Coordinator.ConnectivityCheckWebHost, Coordinator.ConnectivityCheckWebHost, RouteTarget.Direct,
            [Ipv4.Parse("23.215.9.9")], TimeSpan.FromMinutes(5), coordinator.ConnectivityPinContext) { LeaseId = Guid.NewGuid() };
        var pin = coordinator.ObservePinnedAsync(fresh, CancellationToken.None).AsTask();
        await Task.Delay(20, TestContext.Current.CancellationToken);
        _world.Time.Advance(Coordinator.ConnectivityPinApplyTimeout + TimeSpan.FromSeconds(1));
        Assert.False(await pin.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken));

        // Отмена временного владельца не ждёт занятую очередь.
        Assert.False(await coordinator.CompletePinnedAsync(fresh, accepted: false).AsTask()
            .WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken));

        Assert.Equal(warm.Order(), coordinator.OpenConnectivityCheckAddresses(fresh));

        // Следующее применение порт этих адресов не закрывает: Windows их ещё помнит.
        await TickAsync(coordinator);
        Assert.Equal(warm.Select(a => $"Проверка интернета Windows {Ipv4.Format(a)}:80").Order(),
            ConnectivityFilters().Select(f => f.Name).Order());
    }

    /// <summary>Чужое имя и ответ прежнего пути DNS уже открытых адресов проверки не получают.</summary>
    [Fact]
    public async Task ConnectivityCheck_OpenAddresses_OnlyForCurrentContextOfServiceRule()
    {
        var coordinator = await StartProtectedForConnectivityCheckAsync();
        await coordinator.OnConnectivityCheckResolvedAsync(coordinator.ConnectivityPinContext, Addresses(1, 2));
        var notice = new PinnedRouteNotice(Coordinator.ConnectivityCheckWebHost, Coordinator.ConnectivityCheckWebHost, RouteTarget.Direct,
            [Ipv4.Parse("23.215.9.9")], TimeSpan.FromMinutes(5), coordinator.ConnectivityPinContext);

        Assert.Empty(coordinator.OpenConnectivityCheckAddresses(notice with { PinContext = "0|прежний путь" }));
        Assert.Empty(coordinator.OpenConnectivityCheckAddresses(notice with { Name = "other.example", Suffix = "other.example" }));
        Assert.Empty(coordinator.OpenConnectivityCheckAddresses(notice with { IsCurrent = () => false }));
        Assert.Equal(2, coordinator.OpenConnectivityCheckAddresses(notice).Count);
    }
}
