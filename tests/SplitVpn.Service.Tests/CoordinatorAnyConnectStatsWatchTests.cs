using SplitVpn.Core.Ipc;
using SplitVpn.Core.OpenConnect;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Зависший помощник AnyConnect: после подъёма сеанса статистика приходит каждые ~2 с. Если она пропала (встал цикл
/// библиотеки или поток колбэков помощника), служба останавливает помощника и завершает сеанс как сетевую ошибку.
/// Сон компьютера и перевод часов не дают ложного срабатывания.
/// </summary>
public sealed partial class CoordinatorTests
{
    private static readonly TimeSpan StatsStep = TimeSpan.FromSeconds(2);

    private async Task<Coordinator> StartWithAnyConnectClockAsync(TimeProvider clock)
    {
        _world.Resolver.Answers[Gateway] = [GatewayAddress];
        SaveSettings(Settings() with { Profiles = [_profile, _anyConnect] });
        _world.Secrets.Delete(_anyConnect.Id);
        return await StartWithClockAsync(clock);
    }

    /// <summary>Время идёт шагами по 2 с; на каждом шаге помощник (если жив) присылает статистику.</summary>
    private async Task RunHelperAsync(Coordinator coordinator, FakeAnyConnectSession session, TimeSpan duration, bool alive)
    {
        ulong bytes = 0;
        for (var passed = TimeSpan.Zero; passed < duration; passed += StatsStep)
        {
            _world.Time.Advance(StatsStep);
            if (alive)
            {
                bytes += 1000;
                session.Emit(new StatsEvent(bytes, bytes, true));
            }

            await CompleteDialAsync(coordinator);
        }
    }

    /// <summary>Проверка молчания в очереди актора в текущий момент - как по таймеру, но без ожидания его шага в 5 с.</summary>
    private async Task CheckSilenceAsync(Coordinator coordinator, int generation)
    {
        await coordinator.EnqueueAsync("Test:AnyConnectStats", () => coordinator.CheckAnyConnectSilenceAsync(_anyConnect.Id, generation, CancellationToken.None));
        await CompleteDialAsync(coordinator);
    }

    private static bool Stopped(FakeAnyConnectSession session) => session.Disposed && session.Commands.Any(c => c is StopCommand);

    [Fact]
    public async Task AnyConnect_StatsKeepComing_SessionStaysUp()
    {
        var coordinator = await StartWithAnyConnectAsync();
        var session = await EstablishAsync(coordinator);

        await RunHelperAsync(coordinator, session, TimeSpan.FromMinutes(2), alive: true);

        Assert.False(session.Disposed);
        Assert.DoesNotContain(session.Commands, c => c is StopCommand);
        Assert.Equal(ConnectionState.Connected, AnyConnectStatus(coordinator).State);
    }

    [Fact]
    public async Task AnyConnect_StatsStop_HelperStoppedAsNetworkError()
    {
        var coordinator = await StartWithAnyConnectAsync();
        var session = await EstablishAsync(coordinator);
        await RunHelperAsync(coordinator, session, TimeSpan.FromSeconds(10), alive: true);
        var generation = coordinator.Facts.Tunnels[_anyConnect.Id].AnyConnect!.Generation;

        // Граница срока молчания - ровно 20 с от последней статистики (а не «где-то между 12 и 32 с»): время идёт
        // шагами по секунде, проверки по таймеру остаются частыми и не принимаются за сон компьютера.
        Assert.Equal(TimeSpan.FromSeconds(20), Coordinator.AnyConnectStatsSilenceLimit);
        for (var second = 1; second < 20; second++)
        {
            _world.Time.Advance(TimeSpan.FromSeconds(1));
            await CompleteDialAsync(coordinator);
        }

        // За миллисекунду до срока - ещё не зависание.
        _world.Time.Advance(TimeSpan.FromSeconds(1) - TimeSpan.FromMilliseconds(1));
        await CheckSilenceAsync(coordinator, generation);
        Assert.False(session.Disposed);

        // Миллисекунда после срока - помощник остановлен.
        _world.Time.Advance(TimeSpan.FromMilliseconds(2));
        await CheckSilenceAsync(coordinator, generation);

        Assert.True(Stopped(session));
        var tunnel = coordinator.Facts.Tunnels[_anyConnect.Id];
        Assert.Null(tunnel.AnyConnect);
        Assert.Equal(ErrorCategory.ServerUnreachable, tunnel.LastErrorCategory);
        Assert.Equal(ErrorCategory.None, tunnel.BlockingError);
        Assert.Contains("не отвечает", tunnel.LastErrorText, StringComparison.Ordinal);
        Assert.Empty(_world.Routes.On(FakeInventory.TunnelLuid(AnyConnectSlot)));
        var status = AnyConnectStatus(coordinator);
        Assert.NotEqual(ConnectionState.Connected, status.State);
        Assert.Equal(SignInKind.Required, status.SignIn?.Kind);
        Assert.Single(_world.AnyConnect.Sessions);
    }

    /// <summary>Пока помощник ждёт ответа службы о узле шлюза (переподключение), статистики нет - это не зависание.</summary>
    [Fact]
    public async Task AnyConnect_ResolveDuringReconnect_ExtendsSilence()
    {
        var coordinator = await StartWithAnyConnectAsync();
        var session = await EstablishAsync(coordinator);
        await RunHelperAsync(coordinator, session, TimeSpan.FromSeconds(4), alive: true);

        session.Emit(new ResolveHostEvent(Gateway));
        await CompleteDialAsync(coordinator);
        await RunHelperAsync(coordinator, session, TimeSpan.FromSeconds(36), alive: false);
        Assert.False(session.Disposed);

        await RunHelperAsync(coordinator, session, TimeSpan.FromSeconds(30), alive: false);
        Assert.True(Stopped(session));
    }

    /// <summary>Сон: служба сама не наблюдала, молчание помощника за это время - не улика; потом контроль работает.</summary>
    [Fact]
    public async Task AnyConnect_AfterSleep_SilenceIsNotHang()
    {
        var coordinator = await StartWithAnyConnectAsync();
        var session = await EstablishAsync(coordinator);
        await RunHelperAsync(coordinator, session, TimeSpan.FromSeconds(6), alive: true);

        _world.Time.Advance(TimeSpan.FromMinutes(30));
        await CompleteDialAsync(coordinator);
        await RunHelperAsync(coordinator, session, TimeSpan.FromSeconds(4), alive: false);
        Assert.False(session.Disposed);

        await RunHelperAsync(coordinator, session, TimeSpan.FromSeconds(20), alive: true);
        Assert.False(session.Disposed);

        await RunHelperAsync(coordinator, session, TimeSpan.FromSeconds(30), alive: false);
        Assert.True(Stopped(session));
    }

    /// <summary>Часы ушли вперёд на 2 часа при живом помощнике - сеанс не рвётся.</summary>
    [Fact]
    public async Task AnyConnect_ClockJumpForward_DoesNotStopLiveHelper()
    {
        var clock = new ShiftedTimeProvider(_world.Time);
        var coordinator = await StartWithAnyConnectClockAsync(clock);
        var session = await EstablishAsync(coordinator);
        await RunHelperAsync(coordinator, session, TimeSpan.FromSeconds(6), alive: true);

        // Скачок пришёлся на паузу между двумя отчётами статистики: проверка видит его раньше свежей статистики.
        clock.Offset = TimeSpan.FromHours(2);
        await RunHelperAsync(coordinator, session, TimeSpan.FromSeconds(6), alive: false);
        await RunHelperAsync(coordinator, session, TimeSpan.FromMinutes(1), alive: true);

        Assert.False(session.Disposed);
        Assert.Equal(ConnectionState.Connected, AnyConnectStatus(coordinator).State);
    }

    /// <summary>Часы перевели назад на час: срок молчания сдвигается, зависший помощник всё равно замечается вовремя.</summary>
    [Fact]
    public async Task AnyConnect_ClockSetBack_HangStillDetectedInTime()
    {
        var clock = new ShiftedTimeProvider(_world.Time);
        var coordinator = await StartWithAnyConnectClockAsync(clock);
        var session = await EstablishAsync(coordinator);
        await RunHelperAsync(coordinator, session, TimeSpan.FromSeconds(10), alive: true);

        clock.Offset = -TimeSpan.FromHours(1);
        await RunHelperAsync(coordinator, session, TimeSpan.FromSeconds(40), alive: false);

        Assert.True(Stopped(session));
    }
}
