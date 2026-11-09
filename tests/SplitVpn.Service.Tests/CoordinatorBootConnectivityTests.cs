using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Разбор старта 09.11.2026: Windows сбрасывала Wi-Fi через ~30 с после подключения, потому что её проверка интернета
/// (NCSI) упиралась в блокировку до подъёма VPN; после обрыва сервер ~2 минуты держал прежний сеанс, а служба каждые
/// ~22 с рвала молчащий новый; при запуске служба называла неподключённый Wi-Fi «не найденным».
/// </summary>
public sealed partial class CoordinatorTests
{
    /// <summary>
    /// Пока VPN не поднят, проверка интернета Windows разрешается через DNS основного адаптера, а к её адресу открыт
    /// только TCP 80 через основной адаптер: ни маршрута, ни обычного закрепления адрес общей сети доставки не получает.
    /// </summary>
    [Fact]
    public async Task ConnectivityCheck_IsResolvedDirect_AndOpensOnlyPort80_BeforeTunnelIsUp()
    {
        _world.Ras.Results.Enqueue(new RasDialResult(false, null, 809, "Нет ответа"));
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.False(coordinator.Facts.Tunnels[_profile.Id].IsUp);

        var routes = _world.Proxy.Configuration.DomainRoutes;
        Assert.Contains(routes, d => d.Suffix == Coordinator.ConnectivityCheckWebHost && d.Target.Kind == TargetKind.Direct && d.ExactName && d.PinAddresses);
        Assert.Contains(routes, d => d.Suffix == Coordinator.ConnectivityCheckDnsHost && d.Target.Kind == TargetKind.Direct && d.ExactName && !d.PinAddresses);

        var address = Ipv4.Parse("23.215.0.136");
        var pin = coordinator.ObservePinnedAsync(new PinnedRouteNotice(Coordinator.ConnectivityCheckWebHost, Coordinator.ConnectivityCheckWebHost,
            RouteTarget.Direct, [address], TimeSpan.FromMinutes(5)), CancellationToken.None);
        await coordinator.DrainAsync();
        Assert.True(await pin);

        var dynamic = _world.Wfp.Group(FilterGroup.Dynamic);
        Assert.Contains(dynamic, f => f.Name == "Проверка интернета Windows 23.215.0.136:80");
        Assert.DoesNotContain(dynamic, f => f.Name.StartsWith("Проверка отзыва", StringComparison.Ordinal));
        Assert.False(coordinator.Facts.Pinned.ContainsKey(address));
        Assert.DoesNotContain(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(address, 32));
    }

    /// <summary>Правило пользователя для того же имени важнее служебного: проверку можно увести в VPN.</summary>
    [Fact]
    public async Task ConnectivityCheck_UserRuleWins()
    {
        SaveSettings(Settings() with { DomainRules = [new DomainRuleSetting { Suffix = "msftconnecttest.com", Target = RouteTarget.Tunnel(_profile.Id) }] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var routes = _world.Proxy.Configuration.DomainRoutes;
        Assert.DoesNotContain(routes, d => d.Suffix == Coordinator.ConnectivityCheckWebHost);
        Assert.Contains(routes, d => d.Suffix == "msftconnecttest.com" && d.Target.Kind == TargetKind.Tunnel);
        Assert.Contains(routes, d => d.Suffix == Coordinator.ConnectivityCheckDnsHost);
    }

    /// <summary>
    /// Wi-Fi пропал, сервер обрыва не видел и держит прежний сеанс: новый сеанс молчит дольше обычных проб, но служба
    /// его не рвёт и не дозванивается заново. Сервер отпустил прежний сеанс - тот же сеанс проходит проверку.
    /// </summary>
    [Fact]
    public async Task UncleanDrop_NewSessionWaitsForServer_WithoutRedial()
    {
        var coordinator = await StartAsync();
        var tunnel = await RedialAfterUncleanDropAsync(coordinator);
        var dials = _world.Ras.Dials;

        for (var i = 0; i < Coordinator.VerifyProbeAttempts * 3; i++)
        {
            _world.Time.Advance(Coordinator.VerifyProbeInterval + TimeSpan.FromMilliseconds(1));
            await TickAsync(coordinator);
        }

        Assert.True(_world.Ras.Connected, Dump(coordinator));
        Assert.True(tunnel.VerifyProbeFailures > Coordinator.VerifyProbeAttempts);
        Assert.Equal(dials, _world.Ras.Dials);
        Assert.Equal(0, tunnel.VerifyFailures);
        Assert.Null(tunnel.LastErrorText);
        Assert.Single(_world.Journal.Since(0), e => e.Text.Contains("держит прежний сеанс", StringComparison.Ordinal));

        _world.Probes.TunnelWorks = true;
        _world.Time.Advance(Coordinator.VerifyProbeInterval + TimeSpan.FromMilliseconds(1));
        await TickAsync(coordinator);

        Assert.True(tunnel.Verified);
        Assert.Null(tunnel.UncleanDropUtc);
        Assert.Equal(dials, _world.Ras.Dials);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    /// <summary>Срок ожидания сервера вышел, а трафика всё нет: дальше обычное правило - сеанс разрывается.</summary>
    [Fact]
    public async Task UncleanDrop_ServerHoldWindowExpires_HangsUp()
    {
        var coordinator = await StartAsync();
        var tunnel = await RedialAfterUncleanDropAsync(coordinator);
        var dropped = tunnel.UncleanDropUtc!.Value;

        for (var i = 0; i < 100 && tunnel.VerifyFailures == 0; i++)
        {
            _world.Time.Advance(TimeSpan.FromSeconds(10));
            await TickAsync(coordinator);
        }

        Assert.Equal(1, tunnel.VerifyFailures);
        Assert.True(_world.Time.GetUtcNow() - dropped >= Coordinator.ServerHoldWindow, Dump(coordinator));
        Assert.Equal(ErrorCategory.NoInternetInTunnel, tunnel.LastErrorCategory);
    }

    /// <summary>Свой разрыв сервер видит: без обрыва молчащий сеанс по-прежнему рвётся после обычных проб.</summary>
    [Fact]
    public async Task NoUncleanDrop_ExhaustedProbes_StillHangUp()
    {
        _world.Probes.TunnelWorks = false;
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];

        Assert.Null(tunnel.UncleanDropUtc);
        await ExhaustProbesAsync(coordinator, tunnel);
        Assert.False(_world.Ras.Connected);
    }

    /// <summary>
    /// Запуск Windows: закреплённый Wi-Fi есть, но ещё не подключён. Это ожидание, а не «адаптер не найден»: в журнале
    /// сведения, а не ошибка, в статусе - «ждём подключения». Wi-Fi подключился - VPN поднимается сам.
    /// </summary>
    [Fact]
    public async Task PinnedAdapterNotConnectedYet_IsWaitingNotMissing()
    {
        _world.Inventory.WiFiUp = false;
        SaveSettings(Settings() with { Profiles = [Pinned(FakeWorld.WiFiGuid, _world.Inventory.WiFiDescription)] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var warnings = coordinator.BuildStatus().Warnings;
        Assert.Contains(warnings, w => w.Code == "pinned-adapter-offline" && w.Text.Contains("«Беспроводная сеть»", StringComparison.Ordinal));
        Assert.DoesNotContain(warnings, w => w.Code == "pinned-adapter-missing");
        Assert.DoesNotContain(_world.Journal.Since(0), e => e.Text.Contains("не найден", StringComparison.Ordinal));
        Assert.Contains(_world.Journal.Since(0), e => e.Level == "Сведения" && e.Text.Contains("не подключён к сети", StringComparison.Ordinal));

        _world.Inventory.WiFiUp = true;
        _world.Time.Advance(TimeSpan.FromSeconds(5));
        await TickAsync(coordinator);

        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
        Assert.DoesNotContain(coordinator.BuildStatus().Warnings, w => w.Code.StartsWith("pinned-adapter", StringComparison.Ordinal));
    }

    /// <summary>Поднятый и проверенный туннель обрывается не нами (пропал Wi-Fi), служба дозванивается заново, а трафик не идёт.</summary>
    private async Task<TunnelFacts> RedialAfterUncleanDropAsync(Coordinator coordinator)
    {
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        Assert.True(tunnel.Verified);

        _world.Probes.TunnelWorks = false;
        _world.Ras.Drop();
        await TickAsync(coordinator);
        Assert.NotNull(tunnel.UncleanDropUtc);

        _world.Time.Advance(tunnel.NextDialAt - _world.Time.GetUtcNow() + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);
        Assert.True(tunnel.IsUp, Dump(coordinator));
        Assert.False(tunnel.Verified);
        return tunnel;
    }
}
