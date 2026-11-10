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

    /// <summary>
    /// Уведомление пришло, пока шла сверка, уже прочитавшая сеть: тик в очереди отбрасывался как лишний, и
    /// новый адаптер ждал следующего периодического тика. Теперь сразу после идущей сверки идёт ещё одна.
    /// </summary>
    [Fact]
    public async Task NetworkNotification_DuringRunningTick_ReconcilesRightAfterIt()
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

        // Периодический тик снял снимок сети без Wi-Fi и стоит на воротах.
        using var gate = new ManualResetEventSlim();
        _world.Inventory.CaptureGate = gate;
        _world.Time.Advance(Coordinator.TickInterval);
        await _world.Inventory.CaptureEntered.Task.WaitAsync(QueueWait, TestContext.Current.CancellationToken);

        _world.Inventory.WiFiUp = true;
        notify!();
        _world.Time.Advance(Coordinator.NetworkChangeDebounce);
        _world.Inventory.CaptureGate = null;
        gate.Set();

        // Первый маркер может встать в очередь раньше повтора, второй - уже после него.
        await WaitQueueAsync(coordinator);
        await WaitQueueAsync(coordinator);

        Assert.Contains(await EventsAsync(coordinator), e => e == "Основной адаптер: Беспроводная сеть.");
        await StopAsync(cancellation, run);
    }

    /// <summary>
    /// Чужое подключение Windows поднимает свой интерфейс: детектор конфликтов запускается по уведомлению,
    /// а не через 5 минут обычного интервала.
    /// </summary>
    [Fact]
    public async Task NetworkNotification_RunsConflictCheckBeforeRegularInterval()
    {
        var detections = 0;
        Action? notify = null;
        var coordinator = new Coordinator(_world.Dependencies() with
        {
            SubscribeNetworkChanges = changed =>
            {
                notify = changed;
                return null;
            },
            DetectConflicts = _ =>
            {
                Interlocked.Increment(ref detections);
                return [];
            },
        });
        using var cancellation = new CancellationTokenSource();
        var run = Task.Run(() => coordinator.RunAsync(cancellation.Token), CancellationToken.None);
        await WaitQueueAsync(coordinator);

        // Первый тик запускает обычную проверку; следующие 10 с новых проверок нет.
        _world.Time.Advance(Coordinator.TickInterval);
        await WaitDetectionsAsync(coordinator, () => Volatile.Read(ref detections), 1);
        _world.Time.Advance(Coordinator.NetworkChangeConflictCheckInterval);
        await WaitQueueAsync(coordinator);
        Assert.Equal(1, Volatile.Read(ref detections));

        notify!();
        _world.Time.Advance(Coordinator.NetworkChangeDebounce);
        await WaitDetectionsAsync(coordinator, () => Volatile.Read(ref detections), 2);

        await StopAsync(cancellation, run);
    }

    private static async Task WaitDetectionsAsync(Coordinator coordinator, Func<int> count, int expected)
    {
        // Результат детектора возвращается работой очереди: пока она не прошла, следующая проверка считается идущей.
        for (var i = 0; i < 400 && (count() < expected || coordinator.Facts.ConflictCheckRunning); i++)
        {
            await WaitQueueAsync(coordinator);
            await Task.Delay(5, TestContext.Current.CancellationToken);
        }

        Assert.Equal(expected, count());
        Assert.False(coordinator.Facts.ConflictCheckRunning);
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
