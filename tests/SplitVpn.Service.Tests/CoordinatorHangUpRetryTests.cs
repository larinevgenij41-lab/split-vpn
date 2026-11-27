using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Native;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Повторы разрыва, который RAS не отпустил в фоне, осиротевший сеанс выключенного профиля, предупреждение о
/// российской цели после разрыва проверявшего её туннеля и сбой запуска дозвона после отметки «в дозвоне».
/// </summary>
public sealed partial class CoordinatorTests
{
    /// <summary>
    /// RAS отказывает и в повторном разрыве, причём не сразу: повтор ждётся целиком, отказ возвращается сверке
    /// (неполное применение с растущей паузой), а не уходит снова в фон по кругу. Запись «Ошибка» о разрыве одна,
    /// ложной записи «разорвано» нет.
    /// </summary>
    [Fact]
    public async Task SlowHangUp_RepeatedAsyncRefusal_RetriesWithBackoff_WithoutLoop()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        var entry = Coordinator.EntryNameFor(_profile);
        var handle = tunnel.Connection!.Value;
        var pending = new ConcurrentQueue<TaskCompletionSource>();
        _world.Ras.HangUpHook = _ =>
        {
            var hangUp = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            pending.Enqueue(hangUp);
            return hangUp.Task;
        };
        var journalStart = _world.Journal.Since(0).Count;
        try
        {
            var pausing = coordinator.HandleRequestAsync(new SetTunnelPausedRequest(_profile.Id, true), CancellationToken.None);
            _world.Time.Advance(Coordinator.ActorHangUpWait);
            Assert.True((await pausing.WaitAsync(ReleaseTestWait, TestContext.Current.CancellationToken)).Ok);
            Assert.Equal(1, coordinator.ReleasingCount);
            Assert.True(pending.TryDequeue(out var first));

            // RAS не отпустил соединение за свой срок: событие завершения возвращает сеанс туннелю и повторяет разрыв.
            first.SetException(new NativeCallException("RasHangUp", 1460));
            var handling = DrainWhenQueuedAsync(coordinator);
            await WaitForAsync(() => !pending.IsEmpty);

            // Повтор тоже не отпускается быстро: срок короткого ожидания очереди истекает, затем RAS снова отказывает.
            _world.Time.Advance(Coordinator.ActorHangUpWait);
            await Task.Delay(50, TestContext.Current.CancellationToken);
            Assert.True(pending.TryDequeue(out var second));
            second.SetException(new NativeCallException("RasHangUp", 1460));
            await handling.WaitAsync(ReleaseTestWait, TestContext.Current.CancellationToken);
            await Task.Delay(50, TestContext.Current.CancellationToken);

            var journal = _world.Journal.Since(0).Skip(journalStart).ToList();
            Assert.Equal(0, coordinator.ReleasingCount);
            Assert.Equal(0, coordinator.QueuedCount);
            Assert.Equal(handle, tunnel.Connection);
            Assert.True(tunnel.HangUpPending);
            Assert.NotNull(coordinator.Facts.PartialError);
            Assert.True(coordinator.Facts.PartialErrorRetryAt > _world.Time.GetUtcNow());
            Assert.Single(journal, e => e.Text.Contains("Не удалось разорвать соединение", StringComparison.Ordinal));
            Assert.DoesNotContain(journal, e => e.Text.Contains("повтор разрыва", StringComparison.Ordinal));
            Assert.Contains(entry, _world.Ras.ConnectedEntries);

            // До конца паузы повторов нет; после неё RAS отпускает соединение, и сеанс разорван.
            var hangUps = _world.Ras.HangUps;
            await coordinator.TickAsync(CancellationToken.None);
            Assert.Equal(hangUps, _world.Ras.HangUps);

            _world.Ras.HangUpHook = null;
            _world.Time.Advance(TimeSpan.FromSeconds(3));
            await TickAsync(coordinator);

            Assert.Null(tunnel.Connection);
            Assert.False(tunnel.HangUpPending);
            Assert.DoesNotContain(entry, _world.Ras.ConnectedEntries);
            Assert.Null(coordinator.Facts.PartialError);
        }
        finally
        {
            _world.Ras.HangUpHook = null;
            while (pending.TryDequeue(out var left))
            {
                left.TrySetResult();
            }
        }
    }

    /// <summary>
    /// Пока прежний сеанс отпускается в фоне, тик не гоняет полную сверку ради дозвона, который всё равно не начнётся:
    /// сверку назначает событие завершения разрыва.
    /// </summary>
    [Fact]
    public async Task SlowHangUp_TicksDoNotReconcile_WhileReleasing()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _world.Ras.HangUpHook = _ => gate.Task;
        try
        {
            var pausing = coordinator.HandleRequestAsync(new SetTunnelPausedRequest(_profile.Id, true), CancellationToken.None);
            _world.Time.Advance(Coordinator.ActorHangUpWait);
            Assert.True((await pausing.WaitAsync(ReleaseTestWait, TestContext.Current.CancellationToken)).Ok);
            Assert.True((await coordinator.HandleRequestAsync(new SetTunnelPausedRequest(_profile.Id, false), CancellationToken.None)).Ok);
            Assert.Equal(1, coordinator.ReleasingCount);

            var reconciled = coordinator.Facts.LastFullReconcile;
            for (var i = 0; i < 3; i++)
            {
                _world.Time.Advance(TimeSpan.FromSeconds(2));
                await coordinator.TickAsync(CancellationToken.None);
            }

            Assert.Equal(reconciled, coordinator.Facts.LastFullReconcile);

            gate.SetResult();
            await WaitReleasedAsync(coordinator);
            await CompleteDialAsync(coordinator);
            Assert.NotNull(tunnel.Connection);
        }
        finally
        {
            gate.TrySetResult();
            _world.Ras.HangUpHook = null;
        }
    }

    /// <summary>
    /// Профиль выключили, пока его сеанс отпускается в фоне: туннель ждёт итога разрыва и при отказе RAS получает сеанс
    /// обратно, чтобы разорвать его. Без этого живой сеанс остался бы без владельца.
    /// </summary>
    [Fact]
    public async Task ProfileTurnedOff_WhileReleaseRefused_DoesNotOrphanSession()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with { Profiles = [_profile, second] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var entry = Coordinator.EntryNameFor(second);
        Assert.Contains(entry, _world.Ras.ConnectedEntries);
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _world.Ras.HangUpHook = async _ =>
        {
            await gate.Task;
            throw new NativeCallException("RasHangUp", 1460);
        };
        try
        {
            var pausing = coordinator.HandleRequestAsync(new SetTunnelPausedRequest(second.Id, true), CancellationToken.None);
            _world.Time.Advance(Coordinator.ActorHangUpWait);
            Assert.True((await pausing.WaitAsync(ReleaseTestWait, TestContext.Current.CancellationToken)).Ok);
            Assert.Equal(1, coordinator.ReleasingCount);

            var off = await coordinator.HandleRequestAsync(new SetProfileRoleRequest(second.Id, ProfileRole.Off), CancellationToken.None);
            Assert.True(off.Ok, off.ErrorMessage);
            Assert.Contains(second.Id, coordinator.Facts.Tunnels.Keys);

            // RAS отказал; следующий разрыв проходит.
            _world.Ras.HangUpHook = null;
            gate.SetResult();
            await WaitReleasedAsync(coordinator);
            await CompleteDialAsync(coordinator);

            Assert.DoesNotContain(entry, _world.Ras.ConnectedEntries);
            Assert.DoesNotContain(second.Id, coordinator.Facts.Tunnels.Keys);
            Assert.Contains(Coordinator.EntryNameFor(_profile), _world.Ras.ConnectedEntries);
        }
        finally
        {
            gate.TrySetResult();
            _world.Ras.HangUpHook = null;
        }
    }

    /// <summary>
    /// Снятие защиты ждёт разрыва сеанса туннеля целиком и тогда, когда свои соединения RAS не перечисляются: без
    /// ожидания в самом разрыве (waitForRelease) маршруты и фильтры снимались бы при живом сеансе.
    /// </summary>
    [Fact]
    public async Task Disconnect_EnumerationFailure_StillWaitsForRelease()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var routesAtRelease = -1;
        _world.Ras.HangUpHook = async _ =>
        {
            await gate.Task;
            routesAtRelease = coordinator.Facts.AppliedRoutes.Length;
        };
        _world.Ras.FailFind = true;
        try
        {
            var disconnecting = coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: false), CancellationToken.None);
            _world.Time.Advance(Coordinator.ActorHangUpWait * 5);
            await Task.Delay(50, TestContext.Current.CancellationToken);
            Assert.False(disconnecting.IsCompleted);
            Assert.True(_world.Ras.Connected);

            gate.SetResult();
            await disconnecting.WaitAsync(ReleaseTestWait, TestContext.Current.CancellationToken);

            Assert.True(routesAtRelease > 0);
            Assert.False(_world.Ras.Connected);
            Assert.Equal(0, coordinator.ReleasingCount);
        }
        finally
        {
            gate.TrySetResult();
            _world.Ras.HangUpHook = null;
            _world.Ras.FailFind = false;
        }
    }

    /// <summary>Туннель, чья проба выставила предупреждение о российской цели, разорван: предупреждение снимается.</summary>
    [Fact]
    public async Task RussianTargetWarning_ClearsWhenCheckingTunnelIsDown()
    {
        _world.Probes.RussianWorks = false;
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.True(coordinator.Facts.RussianTargetUnreachable);
        Assert.Contains(coordinator.BuildStatus().Warnings, w => w.Code == "russian-target-direct");

        var paused = await PauseAsync(coordinator, _profile.Id, paused: true);

        Assert.True(paused.Ok, paused.ErrorMessage);
        Assert.Equal(Intent.Connected, coordinator.State.Intent);
        Assert.False(coordinator.Facts.RussianTargetUnreachable);
        Assert.DoesNotContain(coordinator.BuildStatus().Warnings, w => w.Code == "russian-target-direct");
    }

    /// <summary>
    /// Исключение в запуске дозвона после отметки «в дозвоне» (здесь - запись в журнал): задачи дозвона нет, признак
    /// снимается, и туннель позже дозванивается снова по обычной паузе.
    /// </summary>
    [Fact]
    public async Task StartDial_FailureAfterDialingMark_TunnelDialsLater()
    {
        _world.Logger = new ThrowOnceLogger("Подключение к «");
        var coordinator = await StartAsync();
        await coordinator.HandleRequestAsync(new ConnectRequest(null, null), CancellationToken.None);
        await CompleteDialAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        Assert.Equal(0, _world.Ras.Dials);
        Assert.False(tunnel.Dialing);

        for (var i = 0; i < 10 && tunnel.Connection is null; i++)
        {
            _world.Time.Advance(TimeSpan.FromSeconds(5));
            await TickAsync(coordinator);
        }

        Assert.Equal(1, _world.Ras.Dials);
        Assert.NotNull(tunnel.Connection);
    }

    /// <summary>Журнал службы, который один раз падает на сообщении с заданным текстом.</summary>
    private sealed class ThrowOnceLogger(string marker) : ILogger
    {
        private int _thrown;

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (formatter(state, exception).Contains(marker, StringComparison.Ordinal) && Interlocked.Exchange(ref _thrown, 1) == 0)
            {
                throw new InvalidOperationException("сбой журнала для теста");
            }
        }
    }

    /// <summary>Ждёт события в очереди и обрабатывает очередь; задача завершается, когда обработка закончилась.</summary>
    private static async Task DrainWhenQueuedAsync(Coordinator coordinator)
    {
        for (var i = 0; i < 1000 && coordinator.QueuedCount == 0; i++)
        {
            await Task.Delay(5);
        }

        await coordinator.DrainAsync();
    }
}
