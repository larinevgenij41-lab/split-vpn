using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Контроль работающего сеанса RAS: соединение с сервером зависло, не закрываясь. Windows замечает это через
/// 60-75 секунд, служба - по тишине от сервера и пробам через туннель, и переподключается сама.
/// </summary>
public sealed partial class CoordinatorTests
{
    /// <summary>Устойчивый сеанс молчит, пробы не проходят: сеанс разрывается и сразу поднимается заново, без паузы.</summary>
    [Fact]
    public async Task LinkWatch_StalledStableSession_HangsUpAndRedialsAtOnce()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        Assert.True(tunnel.Verified);
        var handle = tunnel.Connection!.Value;
        _world.Time.Advance(TunnelFacts.StableSession + TimeSpan.FromSeconds(1));

        await coordinator.OnLinkWatchAsync(_profile.Id, handle, false, CancellationToken.None);
        Assert.Equal(0, _world.Ras.HangUps);
        Assert.Equal(1, tunnel.LinkWatchFailures);

        await coordinator.OnLinkWatchAsync(_profile.Id, handle, false, CancellationToken.None);
        await CompleteDialAsync(coordinator);

        Assert.True(_world.Ras.HangUps > 0, Dump(coordinator));
        Assert.Equal(2, _world.Ras.Dials);
        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("соединение зависло - данных от сервера нет", StringComparison.Ordinal));
        Assert.NotNull(tunnel.Connection);
        Assert.True(tunnel.Verified);
        Assert.Equal(0, tunnel.LinkWatchFailures);
    }

    /// <summary>Сеанс завис в первую минуту: подключение не работает, новый дозвон ждёт растущей паузы, а не идёт по кругу.</summary>
    [Fact]
    public async Task LinkWatch_StalledShortSession_BacksOff()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        var handle = tunnel.Connection!.Value;

        await coordinator.OnLinkWatchAsync(_profile.Id, handle, false, CancellationToken.None);
        await coordinator.OnLinkWatchAsync(_profile.Id, handle, false, CancellationToken.None);
        await CompleteDialAsync(coordinator);

        Assert.True(_world.Ras.HangUps > 0);
        Assert.Equal(1, _world.Ras.Dials);
        Assert.Null(tunnel.Connection);
        Assert.True(tunnel.NextDialAt > _world.Time.GetUtcNow());
        // Сервер о разрыве мог не узнать: окно ожидания прежнего сеанса открыто.
        Assert.NotNull(tunnel.UncleanDropUtc);
    }

    /// <summary>Одна потерянная проба сеанс не рвёт, а прошедшая следом снимает счёт.</summary>
    [Fact]
    public async Task LinkWatch_SingleLostProbe_KeepsSession()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        var handle = tunnel.Connection!.Value;

        await coordinator.OnLinkWatchAsync(_profile.Id, handle, false, CancellationToken.None);
        Assert.Equal(_world.Time.GetUtcNow() + Coordinator.LinkWatchRetry, tunnel.NextLinkWatchAt);
        await coordinator.OnLinkWatchAsync(_profile.Id, handle, true, CancellationToken.None);

        Assert.Equal(0, tunnel.LinkWatchFailures);
        Assert.Equal(0, _world.Ras.HangUps);
        Assert.Equal(1, _world.Ras.Dials);
        Assert.Equal(_world.Time.GetUtcNow() + Coordinator.LinkWatchInterval, tunnel.NextLinkWatchAt);
    }

    /// <summary>Ответ пробы прежнего сеанса к нынешнему не применяется.</summary>
    [Fact]
    public async Task LinkWatch_ResultOfPreviousSession_IsIgnored()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        var stale = new RasConnectionHandle(tunnel.Connection!.Value.Value + 12345);

        await coordinator.OnLinkWatchAsync(_profile.Id, stale, false, CancellationToken.None);
        await coordinator.OnLinkWatchAsync(_profile.Id, stale, false, CancellationToken.None);

        Assert.Equal(0, tunnel.LinkWatchFailures);
        Assert.Equal(0, _world.Ras.HangUps);
    }

    /// <summary>
    /// Полный путь по тикам: счётчик принятых байт стоит, проба через туннель не отвечает - после второй неудачной
    /// пробы сеанс разорван. Пока связь есть, тики сеанс не трогают.
    /// </summary>
    [Fact]
    public async Task LinkWatch_Ticks_ProbeSilentSessionAndHangUp()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];

        for (var i = 0; i < 4; i++)
        {
            _world.Time.Advance(Coordinator.LinkWatchInterval);
            await TickAsync(coordinator);
        }

        Assert.Equal(0, _world.Ras.HangUps);
        Assert.Equal(0, tunnel.LinkWatchFailures);

        _world.Probes.TunnelWorks = false;
        _world.Time.Advance(Coordinator.LinkWatchInterval);
        await TickAsync(coordinator);
        Assert.Equal(1, tunnel.LinkWatchFailures);
        Assert.Equal(0, _world.Ras.HangUps);

        _world.Time.Advance(Coordinator.LinkWatchRetry);
        await TickAsync(coordinator);

        Assert.True(_world.Ras.HangUps > 0, Dump(coordinator));
        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("соединение зависло", StringComparison.Ordinal));
    }
}
