using SplitVpn.Core.Ipc;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Native;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Долгий разрыв RAS-соединения: очередь актора ждёт его не дольше <see cref="Coordinator.ActorHangUpWait"/>, остаток
/// ожидания идёт в фоне. Запись при этом занята: повторного дозвона и подхвата разрываемого сеанса нет, отказ RAS
/// возвращает сеанс туннелю для повтора разрыва, а снятие защиты ждёт разрыва целиком.
/// </summary>
public sealed partial class CoordinatorTests
{
    private static readonly TimeSpan ReleaseTestWait = TimeSpan.FromSeconds(10);

    [Fact]
    public async Task SlowHangUp_DoesNotHoldQueue_AndRedialWaitsForRelease()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        var entry = Coordinator.EntryNameFor(_profile);
        var dials = _world.Ras.Dials;
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _world.Ras.HangUpHook = _ => gate.Task;
        try
        {
            var pausing = coordinator.HandleRequestAsync(new SetTunnelPausedRequest(_profile.Id, true), CancellationToken.None);
            Assert.False(pausing.IsCompleted);

            // RAS не отпустил соединение за отведённое очереди время: команда завершается, ожидание - в фоне.
            _world.Time.Advance(Coordinator.ActorHangUpWait);
            var paused = await pausing.WaitAsync(ReleaseTestWait, TestContext.Current.CancellationToken);
            Assert.True(paused.Ok, paused.ErrorMessage);
            Assert.Equal(1, coordinator.ReleasingCount);
            Assert.Null(tunnel.Connection);
            Assert.Contains(entry, _world.Ras.ConnectedEntries);

            // Следующие команды и сверки идут, пока разрыв не завершён: ни дозвона поверх занятой записи, ни подхвата
            // разрываемого сеанса, хотя RAS ещё показывает его подключённым.
            var resumed = await coordinator.HandleRequestAsync(new SetTunnelPausedRequest(_profile.Id, false), CancellationToken.None);
            Assert.True(resumed.Ok, resumed.ErrorMessage);
            _world.Time.Advance(TimeSpan.FromSeconds(5));
            await coordinator.TickAsync(CancellationToken.None);
            Assert.Equal(dials, _world.Ras.Dials);
            Assert.Null(tunnel.Connection);
            Assert.Equal(1, coordinator.ReleasingCount);

            gate.SetResult();
            await WaitReleasedAsync(coordinator);
            await CompleteDialAsync(coordinator);

            // Событие завершения освободило запись: туннель поднялся новым дозвоном.
            Assert.Equal(0, coordinator.ReleasingCount);
            Assert.Equal(dials + 1, _world.Ras.Dials);
            Assert.NotNull(tunnel.Connection);
        }
        finally
        {
            gate.TrySetResult();
            _world.Ras.HangUpHook = null;
        }
    }

    [Fact]
    public async Task FastHangUp_StaysInQueue_WithoutBackgroundWait()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var paused = await PauseAsync(coordinator, _profile.Id, paused: true);

        Assert.True(paused.Ok, paused.ErrorMessage);
        Assert.Equal(0, coordinator.ReleasingCount);
        Assert.False(_world.Ras.Connected);
    }

    [Fact]
    public async Task SlowHangUp_TimedOut_ReturnsSessionToTunnel_ForRetry()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        var entry = Coordinator.EntryNameFor(_profile);
        var handle = tunnel.Connection!.Value;
        var dials = _world.Ras.Dials;
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _world.Ras.HangUpHook = async _ =>
        {
            await gate.Task;
            throw new NativeCallException("RasHangUp", 1460);
        };
        try
        {
            var pausing = coordinator.HandleRequestAsync(new SetTunnelPausedRequest(_profile.Id, true), CancellationToken.None);
            _world.Time.Advance(Coordinator.ActorHangUpWait);
            Assert.True((await pausing.WaitAsync(ReleaseTestWait, TestContext.Current.CancellationToken)).Ok);
            Assert.Null(tunnel.Connection);

            // RAS так и не отпустил соединение: повтор разрыва на сверке тоже отказывает сразу.
            _world.Ras.HangUpHook = _ => Task.FromException(new NativeCallException("RasHangUp", 1460));
            gate.SetResult();
            await WaitReleasedAsync(coordinator);
            await CompleteDialAsync(coordinator);

            Assert.Equal(0, coordinator.ReleasingCount);
            Assert.Equal(handle, tunnel.Connection);
            Assert.True(tunnel.HangUpPending);
            Assert.Contains(entry, _world.Ras.ConnectedEntries);
            Assert.Equal(dials, _world.Ras.Dials);
            Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("Не удалось разорвать соединение", StringComparison.Ordinal));

            // RAS снова отвечает: следующая сверка разрывает сеанс, положенный туннель не дозванивается.
            _world.Ras.HangUpHook = null;
            _world.Time.Advance(TimeSpan.FromSeconds(70));
            await TickAsync(coordinator);

            Assert.Null(tunnel.Connection);
            Assert.False(tunnel.HangUpPending);
            Assert.DoesNotContain(entry, _world.Ras.ConnectedEntries);
            Assert.Equal(dials, _world.Ras.Dials);
        }
        finally
        {
            gate.TrySetResult();
            _world.Ras.HangUpHook = null;
        }
    }

    /// <summary>Снятие защиты не уходит в фон: маршруты, DNS и фильтры снимаются, только когда сеанса нет.</summary>
    [Fact]
    public async Task Disconnect_WaitsForWholeRelease_BeforeRemovingProtection()
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
        try
        {
            var disconnecting = coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: false), CancellationToken.None);
            _world.Time.Advance(Coordinator.ActorHangUpWait * 5);
            await Task.Delay(50, TestContext.Current.CancellationToken);
            Assert.False(disconnecting.IsCompleted);
            Assert.True(_world.Ras.Connected);

            gate.SetResult();
            var response = await disconnecting.WaitAsync(ReleaseTestWait, TestContext.Current.CancellationToken);

            Assert.True(response.Ok, response.ErrorMessage);
            Assert.True(routesAtRelease > 0);
            Assert.False(_world.Ras.Connected);
            Assert.Equal(0, coordinator.ReleasingCount);
            Assert.Empty(coordinator.Facts.AppliedRoutes);
            Assert.Equal(Intent.Off, coordinator.State.Intent);
        }
        finally
        {
            gate.TrySetResult();
            _world.Ras.HangUpHook = null;
        }
    }

    /// <summary>
    /// Остановка службы посреди короткого ожидания: отмена проходит насквозь, как прежде, а RasHangUp уже вызван -
    /// RAS доводит разрыв сам, и сеанс не остаётся висеть.
    /// </summary>
    [Fact]
    public async Task ServiceStop_DuringHangUpWait_LeavesHangUpIssuedAndCompleted()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var hangUps = _world.Ras.HangUps;
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _world.Ras.HangUpHook = _ => gate.Task;
        using var stopping = new CancellationTokenSource();
        try
        {
            var pausing = coordinator.HandleRequestAsync(new SetTunnelPausedRequest(_profile.Id, true), stopping.Token);
            await stopping.CancelAsync();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pausing.WaitAsync(ReleaseTestWait, TestContext.Current.CancellationToken));
            Assert.Equal(hangUps + 1, _world.Ras.HangUps);
            Assert.Equal(1, coordinator.ReleasingCount);

            gate.SetResult();
            for (var i = 0; i < 500 && _world.Ras.Connected; i++)
            {
                await Task.Delay(10, TestContext.Current.CancellationToken);
            }

            Assert.False(_world.Ras.Connected);
        }
        finally
        {
            gate.TrySetResult();
            _world.Ras.HangUpHook = null;
        }
    }

    /// <summary>Ждёт, пока событие завершения фонового разрыва дойдёт до очереди и будет обработано.</summary>
    private static async Task WaitReleasedAsync(Coordinator coordinator)
    {
        for (var i = 0; i < 1000 && coordinator.ReleasingCount > 0; i++)
        {
            if (coordinator.QueuedCount > 0)
            {
                await coordinator.DrainAsync();
                continue;
            }

            await Task.Delay(5);
        }

        Assert.Equal(0, coordinator.ReleasingCount);
    }
}
