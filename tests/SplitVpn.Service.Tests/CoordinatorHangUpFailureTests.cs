using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Native;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Сбой после решения разорвать сеанс: обновление маршрутов после состоявшегося разрыва (WFP) или сам RasHangUp.
/// Пауза до дозвона и отметка обрыва не должны теряться, а неудача - засчитываться на каждой следующей пробе.
/// </summary>
public sealed partial class CoordinatorTests
{
    /// <summary>
    /// Зависший короткий сеанс разорван, но фильтры после разрыва не применились: срок дозвона и отметка обрыва
    /// всё равно выставлены, и следующий тик не дозванивается без паузы.
    /// </summary>
    [Fact]
    public async Task LinkWatch_RoutesFailAfterHangUp_KeepsBackoffAndUncleanDrop()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        Assert.True(tunnel.Verified);
        var handle = tunnel.Connection!.Value;
        _world.Probes.TunnelWorks = false;

        await coordinator.OnLinkWatchAsync(_profile.Id, handle, false, CancellationToken.None);
        _world.Wfp.FailNextReplace = 1;
        await coordinator.OnLinkWatchAsync(_profile.Id, handle, false, CancellationToken.None);
        await CompleteDialAsync(coordinator);

        Assert.Equal(0, _world.Wfp.FailNextReplace);
        Assert.Null(tunnel.Connection);
        Assert.NotNull(tunnel.UncleanDropUtc);
        Assert.True(tunnel.NextDialAt > _world.Time.GetUtcNow(), Dump(coordinator));
        Assert.Equal(1, tunnel.DialAttempt);

        // Следующий тик до назначенного срока: нового дозвона нет.
        _world.Time.Advance((tunnel.NextDialAt - _world.Time.GetUtcNow()) / 2);
        await TickAsync(coordinator);

        Assert.Equal(1, _world.Ras.Dials);
        Assert.Equal(1, tunnel.DialAttempt);
    }

    /// <summary>
    /// Пробы исчерпаны, а RasHangUp отказывает: неудача засчитана один раз, сеанс больше не проверяется, разрыв
    /// повторяет сверка. Когда разрыв удаётся, дозвон идёт по уже назначенной паузе.
    /// </summary>
    [Fact]
    public async Task VerificationFailure_HangUpFails_CountsOnceAndRetriesHangUp()
    {
        _world.Probes.TunnelWorks = false;
        _world.Ras.HangUpFailure = new NativeCallException("RasHangUp", 668);
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];

        for (var i = 0; i < Coordinator.VerifyProbeAttempts + 1 && tunnel.VerifyFailures == 0; i++)
        {
            _world.Time.Advance(Coordinator.VerifyProbeInterval);
            await TickAsync(coordinator);
        }

        Assert.Equal(1, tunnel.VerifyFailures);
        Assert.Equal(1, tunnel.DialAttempt);
        Assert.True(tunnel.HangUpPending, Dump(coordinator));
        Assert.NotNull(tunnel.Connection);
        var hangUps = _world.Ras.HangUps;

        for (var i = 0; i < 20; i++)
        {
            _world.Time.Advance(TimeSpan.FromSeconds(2));
            await TickAsync(coordinator);
        }

        Assert.Equal(1, tunnel.VerifyFailures);
        Assert.Equal(1, tunnel.DialAttempt);
        Assert.Equal(1, _world.Ras.Dials);
        // Разрыв повторяется, но по растущей паузе неполного применения, а не на каждом тике.
        Assert.InRange(_world.Ras.HangUps - hangUps, 1, 10);

        _world.Ras.HangUpFailure = null;
        _world.Probes.TunnelWorks = true;
        _world.Time.Advance(TimeSpan.FromSeconds(60));
        await TickAsync(coordinator);
        Assert.False(tunnel.HangUpPending);
        for (var i = 0; i < 10 && tunnel.Connection is null; i++)
        {
            _world.Time.Advance(TimeSpan.FromSeconds(5));
            await TickAsync(coordinator);
        }

        Assert.Equal(2, _world.Ras.Dials);
        Assert.True(tunnel.Verified, Dump(coordinator));
    }
}
