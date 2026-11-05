using SplitVpn.Core.Ipc;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;

namespace SplitVpn.Service.Tests;

/// <summary>Системное уведомление о смене сети: новый адаптер становится основным без ожидания тика.</summary>
public sealed partial class CoordinatorTests
{
    [Fact]
    public async Task NetworkNotification_SelectsNewAdapterBeforeNextTick()
    {
        new ServiceStores(_world.Paths).SaveState(new ServiceStateFile { Intent = Intent.Protected });
        _world.Inventory.WiFiUp = false;
        Action? notify = null;
        var coordinator = new Coordinator(_world.Dependencies() with
        {
            SubscribeNetworkChanges = changed =>
            {
                notify = changed;
                return null;
            },
        });
        using var cancellation = new CancellationTokenSource();
        var run = Task.Run(() => coordinator.RunAsync(cancellation.Token), CancellationToken.None);
        await WaitQueueAsync(coordinator);
        Assert.NotNull(notify);
        Assert.DoesNotContain(await EventsAsync(coordinator), e => e == "Основной адаптер: Беспроводная сеть.");

        // Wi-Fi подключился. Периодический тик (2 с) ещё не наступил: сверку ставит только уведомление.
        _world.Inventory.WiFiUp = true;
        notify!();
        notify();
        _world.Time.Advance(Coordinator.NetworkChangeDebounce);
        await WaitQueueAsync(coordinator);

        Assert.Contains(await EventsAsync(coordinator), e => e == "Основной адаптер: Беспроводная сеть.");
        await StopAsync(cancellation, run);
    }

    [Fact]
    public async Task NetworkNotification_WithoutDebounceElapsed_DoesNotReconcile()
    {
        new ServiceStores(_world.Paths).SaveState(new ServiceStateFile { Intent = Intent.Protected });
        _world.Inventory.WiFiUp = false;
        Action? notify = null;
        var coordinator = new Coordinator(_world.Dependencies() with
        {
            SubscribeNetworkChanges = changed =>
            {
                notify = changed;
                return null;
            },
        });
        using var cancellation = new CancellationTokenSource();
        var run = Task.Run(() => coordinator.RunAsync(cancellation.Token), CancellationToken.None);
        await WaitQueueAsync(coordinator);

        _world.Inventory.WiFiUp = true;
        notify!();
        await WaitQueueAsync(coordinator);

        Assert.DoesNotContain(await EventsAsync(coordinator), e => e == "Основной адаптер: Беспроводная сеть.");
        await StopAsync(cancellation, run);
    }

    [Fact]
    public async Task NetworkSubscriptionFailure_ServiceStillStarts()
    {
        var coordinator = new Coordinator(_world.Dependencies() with
        {
            SubscribeNetworkChanges = _ => throw new InvalidOperationException("нет IP Helper"),
        });
        using var cancellation = new CancellationTokenSource();
        var run = Task.Run(() => coordinator.RunAsync(cancellation.Token), CancellationToken.None);
        await WaitQueueAsync(coordinator);

        var status = await coordinator.SubmitAsync(new GetStatusRequest(), TestContext.Current.CancellationToken);
        Assert.True(status.Ok);
        await StopAsync(cancellation, run);
    }

    private static async Task<List<string>> EventsAsync(Coordinator coordinator)
    {
        var events = await coordinator.SubmitAsync(new GetEventsRequest(0), TestContext.Current.CancellationToken);
        return events.ResultAs<List<ServiceEvent>>()!.Select(e => e.Text).ToList();
    }
}
