using SplitVpn.Core.Ipc;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Native;
using SplitVpn.Windows.Ras;
using SplitVpn.Windows.Security;

namespace SplitVpn.Service.Tests;

/// <summary>Исправления по ревью всей программы 0.15.5 (агенты и Codex, 2026-11-07).</summary>
public sealed partial class CoordinatorTests
{
    /// <summary>RAS не отпустил соединение: «Отключить и восстановить интернет» всё равно снимает защиту и DNS.</summary>
    [Fact]
    public async Task Off_HangUpFailure_StillRemovesProtectionAndRestoresDns()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        _world.Ras.HangUpFailure = new NativeCallException("RasHangUp", 5);

        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: false), CancellationToken.None);

        // Сбой разрыва запомнен для повтора, но защита и DNS уже сняты.
        Assert.NotNull(coordinator.Facts.PartialError);
        Assert.Empty(_world.Wfp.Groups);
        Assert.Empty(_world.Routes.Current);
        Assert.Equal("", _world.Dns.NameServers[FakeWorld.WiFiGuid]);

        // Повтор отключения доводит дело до конца.
        _world.Ras.HangUpFailure = null;
        await TickAsync(coordinator);
        Assert.Null(coordinator.Facts.PartialError);
        Assert.False(_world.Ras.Connected);
    }

    /// <summary>Сервер изменён, а разрыв старого соединения не удался: следующая сверка разрывает его снова.</summary>
    [Fact]
    public async Task SaveSettings_HangUpFailure_ReconnectsOnNextReconcile()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        _world.Ras.HangUpFailure = new NativeCallException("RasHangUp", 5);
        var changed = coordinator.Settings with { Profiles = [_profile with { Server = "203.0.113.11:4443" }] };

        var request = coordinator.SubmitAsync(new SaveSettingsRequest(changed), CancellationToken.None);
        await coordinator.DrainAsync();
        Assert.False((await request).Ok);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        Assert.True(tunnel.ReconnectRequired);

        _world.Ras.HangUpFailure = null;
        var hangUps = _world.Ras.HangUps;
        await TickAsync(coordinator);

        Assert.True(_world.Ras.HangUps > hangUps);
        Assert.False(tunnel.ReconnectRequired);
    }

    /// <summary>Туннель с блокирующей ошибкой не дозванивается, и тик не гоняет из-за него полную сверку каждые 2 с.</summary>
    [Fact]
    public async Task BlockedTunnel_DoesNotTriggerReconcileEveryTick()
    {
        _world.Ras.Results.Enqueue(new RasDialResult(false, null, 691, "Отказано в доступе"));
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        Assert.NotEqual(ErrorCategory.None, tunnel.BlockingError);

        _world.Time.Advance(TimeSpan.FromMinutes(5));
        await TickAsync(coordinator);
        var reconciled = coordinator.Facts.LastFullReconcile;
        _world.Time.Advance(TimeSpan.FromSeconds(2));
        await TickAsync(coordinator);

        Assert.Equal(reconciled, coordinator.Facts.LastFullReconcile);
    }

    /// <summary>
    /// DNS идёт путём «остального интернета»: при «Напрямую» - через DNS провайдера, даже когда VPN поднят для
    /// отдельных правил. При «Блокировать» имена по-прежнему разрешаются через опорный туннель.
    /// </summary>
    [Theory]
    [InlineData(TargetKind.Direct, DnsProxyMode.DirectAllowed)]
    [InlineData(TargetKind.Block, DnsProxyMode.Online)]
    public async Task GeneralDns_FollowsDefaultTargetPath(TargetKind kind, DnsProxyMode expected)
    {
        SaveSettings(Settings() with
        {
            DefaultTarget = new RouteTarget(kind),
            Rules = [new UserRuleSetting { Cidr = "10.0.0.0/8", Target = RouteTarget.Tunnel(_profile.Id) }],
        });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        Assert.True(coordinator.Facts.Tunnels[_profile.Id].IsUp);
        Assert.Equal(expected, _world.Proxy.Configuration.Mode);
    }

    /// <summary>Подключение выключенного профиля с главной не отменяет раздельную маршрутизацию «Напрямую».</summary>
    [Fact]
    public async Task ConnectingOffProfile_KeepsSplitRoutingDirect()
    {
        SaveSettings(Settings() with
        {
            Profiles = [_profile with { Role = ProfileRole.Off }],
            DefaultTarget = RouteTarget.Direct,
            DomainRules = [new DomainRuleSetting { Suffix = "corp.example", Target = RouteTarget.Tunnel(_profile.Id) }],
        });
        var coordinator = await StartAsync();

        await coordinator.HandleRequestAsync(new ConnectRequest(_profile.Id, null), CancellationToken.None);

        Assert.Equal(ProfileRole.Primary, coordinator.Settings.Profile(_profile.Id)!.Role);
        Assert.Equal(RouteTarget.Direct, coordinator.Settings.DefaultTarget);
    }

    /// <summary>32-битные счётчики RAS после 4 ГБ продолжают расти, а не начинаются с нуля.</summary>
    [Fact]
    public void RasCounters_ExtendAcrossWrap()
    {
        var before = new RasStatistics(0xFFFF_FF00UL, 10, TimeSpan.Zero);
        var wrapped = Coordinator.ExtendCounters(before, new RasStatistics(0x100, 20, TimeSpan.FromSeconds(1)))!;
        var again = Coordinator.ExtendCounters(wrapped, new RasStatistics(0x200, 30, TimeSpan.FromSeconds(2)))!;

        Assert.Equal(0x1_0000_0100UL, wrapped.BytesSent);
        Assert.Equal(20UL, wrapped.BytesReceived);
        Assert.Equal(0x1_0000_0200UL, again.BytesSent);
        Assert.Null(Coordinator.ExtendCounters(before, null));
        Assert.Equal(5UL, Coordinator.ExtendCounters(null, new RasStatistics(5, 5, TimeSpan.Zero))!.BytesSent);
    }

    /// <summary>Временный сбой DPAPI не удаляет сохранённый пароль; испорченное значение удаляется.</summary>
    [Theory]
    [InlineData(13u, true)]
    [InlineData(0x8009000Bu, true)]
    [InlineData(1325u, true)]
    [InlineData(1722u, false)] // RPC_S_SERVER_UNAVAILABLE
    [InlineData(14u, false)] // ERROR_OUTOFMEMORY
    public void DecryptFailure_IsPermanentOnlyForBadData(uint code, bool permanent) =>
        Assert.Equal(permanent, SecretStore.IsPermanentDecryptFailure(code));
}
