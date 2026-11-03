using SplitVpn.Core.Ipc;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Поведение при неудачной проверке готовности туннеля: живой сеанс не рвётся с первой непройденной пробы,
/// пауза между дозвонами не опускается ниже пола, счётчик снимает только успешная проверка, а недоступность
/// российской цели туннель не разрывает. Проверяет исправление цикла переподключений (см. docs\WINDOWS-AUDIT.md,
/// раздел 2.1) и его продолжение — разбор долгого подъёма туннеля 22.09.2026.
/// </summary>
public sealed partial class CoordinatorTests
{
    [Fact]
    public async Task VerificationFailure_GrowsRetryDelay_AndDoesNotResetOnRedial()
    {
        _world.Probes.TunnelWorks = false;
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        await ExhaustProbesAsync(coordinator, tunnel);
        var gaps = new List<TimeSpan> { tunnel.NextDialAt - _world.Time.GetUtcNow() };

        // Дожидаемся паузы и повторяем — дозвон снова успешен, проверка снова нет: счётчик не сбрасывается.
        for (var i = 0; i < 4; i++)
        {
            _world.Time.Advance(tunnel.NextDialAt - _world.Time.GetUtcNow() + TimeSpan.FromSeconds(1));
            await TickAsync(coordinator);
            await ExhaustProbesAsync(coordinator, tunnel);
            gaps.Add(tunnel.NextDialAt - _world.Time.GetUtcNow());
        }

        Assert.Equal(5, tunnel.VerifyFailures);
        Assert.All(gaps, gap => Assert.True(gap >= Coordinator.VerifyRetryFloor, $"пауза ниже пола: {gap}"));
        Assert.True(gaps[^1] > gaps[0], $"пауза не выросла: {gaps[0]} → {gaps[^1]}");
        Assert.NotEqual(ConnectionState.Connected, coordinator.DeriveState());
    }

    [Fact]
    public async Task SuccessfulVerification_ResetsRetryCounters()
    {
        _world.Probes.TunnelWorks = false;
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        await ExhaustProbesAsync(coordinator, tunnel);
        Assert.True(tunnel.VerifyFailures > 0);

        _world.Probes.TunnelWorks = true;
        _world.Time.Advance(tunnel.NextDialAt - _world.Time.GetUtcNow() + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);

        Assert.Equal(0, tunnel.VerifyFailures);
        Assert.Equal(0, tunnel.DialAttempt);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    [Fact]
    public async Task RussianTargetUnreachable_KeepsTunnel_AndWarns()
    {
        _world.Probes.RussianWorks = false;
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        // Иностранная цель доступна через туннель — подключение считается рабочим, туннель не разрывается.
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
        Assert.True(_world.Ras.Connected);
        Assert.Contains(coordinator.BuildStatus().Warnings, w => w.Code == "russian-target-direct");
    }

    /// <summary>
    /// Первая непройденная проба — ещё не отказ: сеанс RAS остаётся поднятым, счётчик неудачных проверок
    /// не растёт и ошибка пользователю не показывается.
    /// </summary>
    [Fact]
    public async Task FirstFailedProbe_KeepsSessionAlive()
    {
        _world.Probes.TunnelWorks = false;
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        Assert.Equal(1, tunnel.VerifyProbeFailures);
        Assert.Equal(0, tunnel.VerifyFailures);
        Assert.True(_world.Ras.Connected);
        Assert.Null(tunnel.LastErrorText);
        Assert.Equal(ConnectionState.ApplyingRoutes, coordinator.DeriveState());
    }

    /// <summary>
    /// Сервер отпустил прежнюю сессию, пока сеанс был жив: следующая проба того же сеанса проходит,
    /// и нового дозвона не потребовалось. Ради этого случая сеанс и не рвётся с первой пробы.
    /// </summary>
    [Fact]
    public async Task ProbeRecovers_WithoutRedial()
    {
        _world.Probes.TunnelWorks = false;
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        var dials = _world.Ras.Dials;

        _world.Probes.TunnelWorks = true;
        _world.Time.Advance(Coordinator.VerifyProbeInterval + TimeSpan.FromMilliseconds(1));
        await TickAsync(coordinator);

        Assert.Equal(dials, _world.Ras.Dials);
        Assert.Equal(0, tunnel.VerifyFailures);
        Assert.True(tunnel.Verified);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    /// <summary>Пробы исчерпаны: сеанс разорван, а следующий дозвон отложен не меньше чем на пол паузы.</summary>
    [Fact]
    public async Task ExhaustedProbes_HangUp_AndWaitAtLeastFloor()
    {
        _world.Probes.TunnelWorks = false;
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];

        await ExhaustProbesAsync(coordinator, tunnel);

        Assert.False(_world.Ras.Connected);
        Assert.Equal(1, tunnel.VerifyFailures);
        Assert.Equal(ErrorCategory.NoInternetInTunnel, tunnel.LastErrorCategory);
        Assert.True(tunnel.NextDialAt - _world.Time.GetUtcNow() >= Coordinator.VerifyRetryFloor);
    }

    /// <summary>
    /// Главное в исправлении: проба идёт вне очереди актора. Сверка завершается, хотя сокет пробы ещё висит,
    /// и очередь пуста — раньше все эти секунды служба не отвечала ни интерфейсу, ни тикам.
    /// </summary>
    [Fact]
    public async Task Verification_DoesNotHoldTheQueue()
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _world.Probes.Gate = gate;
        var coordinator = await StartAsync();
        await coordinator.HandleRequestAsync(new ConnectRequest(null, null), CancellationToken.None);

        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        await WaitForVerifyingAsync(coordinator, tunnel);

        Assert.True(tunnel.Verifying, "проверка не началась");
        Assert.True(tunnel.IsUp);
        Assert.Equal(0, coordinator.QueuedCount);

        // Проба отвечает — результат возвращается в очередь и туннель становится проверенным.
        gate.SetResult();
        await CompleteDialAsync(coordinator);
        Assert.True(tunnel.Verified);
    }

    /// <summary>Ждёт, пока дозвон дойдёт до очереди и служба запустит пробу готовности.</summary>
    private static async Task WaitForVerifyingAsync(Coordinator coordinator, TunnelFacts tunnel)
    {
        for (var i = 0; i < 600 && !tunnel.Verifying; i++)
        {
            await coordinator.DrainAsync();
            await Task.Delay(5);
        }
    }

    /// <summary>
    /// Доводит текущий сеанс до отказа проверки: рвёт его только последняя из
    /// <see cref="Coordinator.VerifyProbeAttempts"/> проб, а идут они по одной за тик.
    /// </summary>
    private async Task ExhaustProbesAsync(Coordinator coordinator, TunnelFacts tunnel)
    {
        var before = tunnel.VerifyFailures;
        for (var i = 0; i < Coordinator.VerifyProbeAttempts && tunnel.VerifyFailures == before; i++)
        {
            _world.Time.Advance(Coordinator.VerifyProbeInterval + TimeSpan.FromMilliseconds(1));
            await TickAsync(coordinator);
        }

        Assert.Equal(before + 1, tunnel.VerifyFailures);
    }
}
