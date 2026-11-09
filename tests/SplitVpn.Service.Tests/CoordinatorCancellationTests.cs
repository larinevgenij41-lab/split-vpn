using SplitVpn.Core.Ipc;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests
{
    [Fact]
    public async Task BlockedQueue_DoesNotAccumulateTimerTicks()
    {
        var coordinator = new Coordinator(_world.Dependencies());
        using var stopping = new CancellationTokenSource();
        var run = Task.Run(() => coordinator.RunAsync(stopping.Token), CancellationToken.None);
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        try
        {
            await WaitQueueAsync(coordinator);
            await coordinator.EnqueueAsync("Test:Blocked", async () =>
            {
                entered.TrySetResult();
                await gate.Task;
            });
            await entered.Task.WaitAsync(QueueWait, TestContext.Current.CancellationToken);
            for (var i = 0; i < 25; i++)
            {
                _world.Time.Advance(Coordinator.TickInterval);
                await Task.Delay(5, TestContext.Current.CancellationToken);
            }

            Assert.Equal(1, coordinator.QueuedCount);
        }
        finally
        {
            gate.TrySetResult();
            await StopAsync(stopping, run);
        }
    }

    [Fact]
    public async Task CancelledQueuedCommand_DoesNotChangeIntentLater()
    {
        var coordinator = new Coordinator(_world.Dependencies());
        using var stopping = new CancellationTokenSource();
        var run = Task.Run(() => coordinator.RunAsync(stopping.Token), CancellationToken.None);
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        try
        {
            await WaitQueueAsync(coordinator);
            await coordinator.EnqueueAsync("Test:Blocked", async () =>
            {
                entered.TrySetResult();
                await gate.Task;
            });
            await entered.Task.WaitAsync(QueueWait, TestContext.Current.CancellationToken);
            using var cancelled = new CancellationTokenSource();
            var command = coordinator.SubmitAsync(new DisconnectRequest(KeepProtection: true), cancelled.Token);
            await cancelled.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => command);
            gate.TrySetResult();
            await WaitQueueAsync(coordinator);

            Assert.Equal(Intent.Off, coordinator.State.Intent);
        }
        finally
        {
            gate.TrySetResult();
            await StopAsync(stopping, run);
        }
    }
}
