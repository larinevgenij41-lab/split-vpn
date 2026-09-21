using System.Diagnostics;
using Microsoft.Extensions.Logging;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;

namespace SplitVpn.Service.Tests;

/// <summary>Очередь актора: ответы интерфейсу во время долгой работы, живучесть цикла, замеры.</summary>
public sealed partial class CoordinatorTests
{
    private static readonly TimeSpan QueueWait = TimeSpan.FromSeconds(10);

    [Fact]
    public async Task LongWorkInQueue_ReadsAnswerWithinSecond()
    {
        var coordinator = new Coordinator(_world.Dependencies());
        using var cancellation = new CancellationTokenSource();
        var run = Task.Run(() => coordinator.RunAsync(cancellation.Token), CancellationToken.None);
        await WaitQueueAsync(coordinator);

        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await coordinator.EnqueueAsync("Test:Long", async () =>
        {
            entered.TrySetResult();
            await gate.Task;
        });
        await entered.Task.WaitAsync(QueueWait, TestContext.Current.CancellationToken);

        var watch = Stopwatch.StartNew();
        var status = await coordinator.SubmitAsync(new GetStatusRequest(), TestContext.Current.CancellationToken);
        var adapters = await coordinator.SubmitAsync(new GetAdaptersRequest(), TestContext.Current.CancellationToken);
        var settings = await coordinator.SubmitAsync(new GetSettingsRequest(), TestContext.Current.CancellationToken);
        var events = await coordinator.SubmitAsync(new GetEventsRequest(0), TestContext.Current.CancellationToken);
        var report = await coordinator.SubmitAsync(new ExportReportRequest(MaskPersonalData: false), TestContext.Current.CancellationToken);
        watch.Stop();

        Assert.True(status.Ok);
        Assert.Equal(ConnectionState.Disconnected, status.ResultAs<StatusDto>()!.State);
        Assert.True(adapters.Ok);
        Assert.Contains(adapters.ResultAs<List<AdapterDto>>()!, a => a.Name == "Беспроводная сеть");
        Assert.Equal(_profile.Id, Assert.Single(settings.ResultAs<AppSettings>()!.Profiles).Id);
        Assert.Contains(events.ResultAs<List<ServiceEvent>>()!, e => e.Text.StartsWith("Служба запущена", StringComparison.Ordinal));
        Assert.Contains("Беспроводная сеть", report.ResultAs<string>()!, StringComparison.Ordinal);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(2), $"пять чтений заняли {watch.ElapsedMilliseconds} мс");
        Assert.False(gate.Task.IsCompleted);

        gate.TrySetResult();
        await StopAsync(cancellation, run);
    }

    [Fact]
    public async Task StatusAnswers_WhileStartupIsStillRunning()
    {
        new ServiceStores(_world.Paths).SaveState(new ServiceStateFile { Intent = Intent.Protected });
        using var gate = new ManualResetEventSlim(false);
        _world.Inventory.CaptureGate = gate;
        var coordinator = new Coordinator(_world.Dependencies());
        using var cancellation = new CancellationTokenSource();
        var run = Task.Run(() => coordinator.RunAsync(cancellation.Token), CancellationToken.None);
        await _world.Inventory.CaptureEntered.Task.WaitAsync(QueueWait, TestContext.Current.CancellationToken);

        var watch = Stopwatch.StartNew();
        var response = await coordinator.SubmitAsync(new GetStatusRequest(), TestContext.Current.CancellationToken);
        watch.Stop();

        Assert.True(response.Ok);
        Assert.Equal(ConnectionState.PreparingProtection, response.ResultAs<StatusDto>()!.State);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(1), $"состояние при запуске заняло {watch.ElapsedMilliseconds} мс");

        _world.Inventory.CaptureGate = null;
        gate.Set();
        await WaitQueueAsync(coordinator);
        var started = await coordinator.SubmitAsync(new GetStatusRequest(), TestContext.Current.CancellationToken);
        Assert.NotEqual(ConnectionState.PreparingProtection, started.ResultAs<StatusDto>()!.State);
        await StopAsync(cancellation, run);
    }

    [Fact]
    public async Task FailingWork_DoesNotStopActorLoop()
    {
        var coordinator = new Coordinator(_world.Dependencies());
        using var cancellation = new CancellationTokenSource();
        var run = Task.Run(() => coordinator.RunAsync(cancellation.Token), CancellationToken.None);

        await coordinator.EnqueueAsync("Test:InvalidOperation", () => throw new InvalidOperationException("сбой в работе"));
        await coordinator.EnqueueAsync("Test:NullReference", async () =>
        {
            await Task.Yield();
            throw new NullReferenceException();
        });
        await WaitQueueAsync(coordinator);

        Assert.False(run.IsCompleted, "цикл актора остановился после исключения в работе");
        var response = await coordinator.SubmitAsync(new DisconnectRequest(KeepProtection: true), TestContext.Current.CancellationToken);
        Assert.True(response.Ok);
        Assert.Equal(Intent.Protected, coordinator.State.Intent);
        await StopAsync(cancellation, run);
    }

    [Fact]
    public async Task SlowWork_IsReportedWithKind_FastWorkIsNot()
    {
        var logger = new ListLogger();
        _world.Logger = logger;
        var coordinator = new Coordinator(_world.Dependencies());
        using var cancellation = new CancellationTokenSource();
        var run = Task.Run(() => coordinator.RunAsync(cancellation.Token), CancellationToken.None);

        await coordinator.EnqueueAsync("Test:Fast", () => Task.CompletedTask);
        await coordinator.EnqueueAsync("Test:Slow", () => Task.Delay(700));
        await WaitQueueAsync(coordinator);

        Assert.Contains(logger.Messages, m => m.Level == LogLevel.Warning && m.Text.StartsWith("Очередь службы: Test:Slow выполнялась", StringComparison.Ordinal));
        Assert.DoesNotContain(logger.Messages, m => m.Text.Contains("Test:Fast", StringComparison.Ordinal));
        await StopAsync(cancellation, run);
    }

    /// <summary>Дождаться, пока очередь дойдёт до поставленной сейчас работы (то есть запуск завершён).</summary>
    private static async Task WaitQueueAsync(Coordinator coordinator)
    {
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await coordinator.EnqueueAsync("Test:Marker", () =>
        {
            reached.TrySetResult();
            return Task.CompletedTask;
        });
        await reached.Task.WaitAsync(QueueWait, TestContext.Current.CancellationToken);
    }

    private static async Task StopAsync(CancellationTokenSource cancellation, Task run)
    {
        await cancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.WaitAsync(QueueWait, TestContext.Current.CancellationToken));
    }

    private sealed class ListLogger : ILogger
    {
        private readonly Lock _lock = new();
        private readonly List<(LogLevel Level, string Text)> _messages = [];

        public IReadOnlyList<(LogLevel Level, string Text)> Messages
        {
            get
            {
                lock (_lock)
                {
                    return _messages.ToList();
                }
            }
        }

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (_lock)
            {
                _messages.Add((logLevel, formatter(state, exception)));
            }
        }
    }
}
