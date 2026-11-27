using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Закрепление по правилу для домена переживает TTL, пока к адресу идут уже открытые соединения (запас для UDP/QUIC,
/// дальше - по таблице соединений TCP), но не дольше суток; смена правила, разрыв цели и ответ другого домена с другой
/// целью снимают продлённое сразу. Пределы числа адресов: доля правила и вытеснение продлённых.
/// </summary>
public sealed partial class CoordinatorTests
{
    private static readonly uint LingerAddress = Ipv4.Parse("93.184.216.40");

    private async Task<Coordinator> WithLingerRulesAsync(RouteTarget? first = null, RouteTarget? second = null, RouteTarget? defaultTarget = null)
    {
        SaveSettings(Settings() with
        {
            DefaultTarget = defaultTarget ?? RouteTarget.Direct,
            DomainRules =
            [
                new DomainRuleSetting { Suffix = "first.example", Target = first ?? RouteTarget.Tunnel(_profile.Id) },
                new DomainRuleSetting { Suffix = "second.example", Target = second ?? RouteTarget.Direct },
            ],
        });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        return coordinator;
    }

    private static async Task<bool> PinAsync(Coordinator coordinator, string suffix, RouteTarget target, TimeSpan ttl, params uint[] addresses)
    {
        var pending = coordinator.ObservePinnedAsync(new PinnedRouteNotice(suffix, suffix, target, addresses, ttl), CancellationToken.None);
        await coordinator.DrainAsync();
        return await pending;
    }

    private async Task AdvanceAndTickAsync(Coordinator coordinator, TimeSpan time)
    {
        _world.Time.Advance(time);
        await TickAsync(coordinator);
    }

    [Fact]
    public async Task Linger_LiveTcpConnectionKeepsPinAfterTtl_UntilItCloses()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var coordinator = await WithLingerRulesAsync();
        Assert.True(await PinAsync(coordinator, "first.example", vpn, TimeSpan.FromSeconds(60), LingerAddress));
        _world.TcpConnections = [LingerAddress];

        // TTL истёк: запас для UDP/QUIC держит закрепление без всякой таблицы.
        await AdvanceAndTickAsync(coordinator, TimeSpan.FromSeconds(61));
        Assert.Equal(_profile.Id, coordinator.Facts.Policy!.Classify(LingerAddress).Tunnel);
        Assert.Equal(0, _world.TcpTableReads);

        // Запас вышел, но соединение TCP к адресу живо: закрепление держится.
        await AdvanceAndTickAsync(coordinator, Coordinator.PinLingerGrace);
        Assert.Equal(_profile.Id, coordinator.Facts.Policy!.Classify(LingerAddress).Tunnel);
        Assert.True(_world.TcpTableReads > 0);

        // Соединение закрылось: на ближайшей проверке закрепление снимается, адрес идёт по адресной политике.
        _world.TcpConnections = [];
        await AdvanceAndTickAsync(coordinator, Coordinator.PinLingerRecheck + TimeSpan.FromSeconds(1));
        Assert.DoesNotContain(LingerAddress, coordinator.Facts.Pinned.Keys);
        Assert.Equal(Decision.Direct, coordinator.Facts.Policy!.Classify(LingerAddress).Decision);
    }

    [Fact]
    public async Task Linger_WithoutConnections_PinGoesAfterGrace()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var coordinator = await WithLingerRulesAsync();
        Assert.True(await PinAsync(coordinator, "first.example", vpn, TimeSpan.FromSeconds(60), LingerAddress));

        await AdvanceAndTickAsync(coordinator, TimeSpan.FromSeconds(61));
        Assert.Contains(LingerAddress, coordinator.Facts.Pinned.Keys);

        await AdvanceAndTickAsync(coordinator, Coordinator.PinLingerGrace);
        Assert.DoesNotContain(LingerAddress, coordinator.Facts.Pinned.Keys);
        Assert.Equal(Decision.Direct, coordinator.Facts.Policy!.Classify(LingerAddress).Decision);
    }

    [Fact]
    public async Task Linger_UnreadableConnectionTable_PinGoesAfterGrace()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var coordinator = await WithLingerRulesAsync();
        Assert.True(await PinAsync(coordinator, "first.example", vpn, TimeSpan.FromSeconds(60), LingerAddress));
        _world.TcpConnections = null;

        await AdvanceAndTickAsync(coordinator, TimeSpan.FromSeconds(61) + Coordinator.PinLingerGrace);
        Assert.DoesNotContain(LingerAddress, coordinator.Facts.Pinned.Keys);
    }

    [Fact]
    public async Task Linger_HasUpperBound()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var coordinator = await WithLingerRulesAsync();
        Assert.True(await PinAsync(coordinator, "first.example", vpn, TimeSpan.FromSeconds(60), LingerAddress));
        _world.TcpConnections = [LingerAddress];

        await AdvanceAndTickAsync(coordinator, TimeSpan.FromSeconds(61) + Coordinator.PinLingerGrace);
        await AdvanceAndTickAsync(coordinator, Coordinator.MaxPinLinger - TimeSpan.FromHours(1));
        Assert.Contains(LingerAddress, coordinator.Facts.Pinned.Keys);

        // Соединение живо и дальше, но сутки после TTL вышли.
        await AdvanceAndTickAsync(coordinator, TimeSpan.FromHours(1));
        Assert.DoesNotContain(LingerAddress, coordinator.Facts.Pinned.Keys);
    }

    [Fact]
    public async Task Linger_DirectPinUnderTunnelPolicy_HasShortUpperBound()
    {
        // «Напрямую» при «остальное в туннель»: продление выводит адрес (и чужие домены на нём) из-под VPN.
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var coordinator = await WithLingerRulesAsync(first: RouteTarget.Direct, defaultTarget: vpn);
        Assert.True(await PinAsync(coordinator, "first.example", RouteTarget.Direct, TimeSpan.FromSeconds(60), LingerAddress));
        _world.TcpConnections = [LingerAddress];

        await AdvanceAndTickAsync(coordinator, TimeSpan.FromSeconds(61) + Coordinator.PinLingerGrace);
        Assert.Equal(Decision.Direct, coordinator.Facts.Policy!.Classify(LingerAddress).Decision);
        await AdvanceAndTickAsync(coordinator, Coordinator.MaxUnprotectedPinLinger - Coordinator.PinLingerGrace - TimeSpan.FromMinutes(2));
        Assert.Contains(LingerAddress, coordinator.Facts.Pinned.Keys);

        // Соединение живо, но короткий предел вышел: адрес возвращается в туннель.
        await AdvanceAndTickAsync(coordinator, TimeSpan.FromMinutes(2));
        Assert.DoesNotContain(LingerAddress, coordinator.Facts.Pinned.Keys);
        Assert.Equal(_profile.Id, coordinator.Facts.Policy!.Classify(LingerAddress).Tunnel);
    }

    [Fact]
    public async Task Linger_TunnelPinOnBlockedAddress_HasShortUpperBound()
    {
        // Адресная политика блокирует адрес («остальное — блокировать»), правило домена ведёт его в туннель: продление
        // держит заблокированный адрес (и чужие домены на нём) доступным, поэтому предел короткий, как у «напрямую»
        // поверх туннеля. Запрет ручным правилом по адресу закрепление не принимает вовсе (PolicyCompiler.PinRejection).
        var vpn = RouteTarget.Tunnel(_profile.Id);
        SaveSettings(Settings() with
        {
            DefaultTarget = RouteTarget.Blocked,
            DomainRules = [new DomainRuleSetting { Suffix = "first.example", Target = vpn }],
        });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.True(await PinAsync(coordinator, "first.example", vpn, TimeSpan.FromSeconds(60), LingerAddress));
        _world.TcpConnections = [LingerAddress];

        await AdvanceAndTickAsync(coordinator, TimeSpan.FromSeconds(61) + Coordinator.PinLingerGrace);
        Assert.Equal(_profile.Id, coordinator.Facts.Policy!.Classify(LingerAddress).Tunnel);
        await AdvanceAndTickAsync(coordinator, Coordinator.MaxUnprotectedPinLinger - Coordinator.PinLingerGrace - TimeSpan.FromMinutes(2));
        Assert.Contains(LingerAddress, coordinator.Facts.Pinned.Keys);

        // Соединение живо, но короткий предел вышел: адрес снова заблокирован.
        await AdvanceAndTickAsync(coordinator, TimeSpan.FromMinutes(2));
        Assert.DoesNotContain(LingerAddress, coordinator.Facts.Pinned.Keys);
        Assert.Equal(Decision.Block, coordinator.Facts.Policy!.Classify(LingerAddress).Decision);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Linger_PinThatKeepsProtection_HasLongUpperBound(bool direct)
    {
        // В туннель при «остальное напрямую» и «напрямую» при «остальное напрямую»: из-под защиты продление ничего не выводит.
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var target = direct ? RouteTarget.Direct : vpn;
        var coordinator = await WithLingerRulesAsync(first: target);
        Assert.True(await PinAsync(coordinator, "first.example", target, TimeSpan.FromSeconds(60), LingerAddress));
        _world.TcpConnections = [LingerAddress];

        await AdvanceAndTickAsync(coordinator, TimeSpan.FromSeconds(61) + Coordinator.PinLingerGrace);
        await AdvanceAndTickAsync(coordinator, Coordinator.MaxUnprotectedPinLinger + TimeSpan.FromHours(1));
        Assert.Contains(LingerAddress, coordinator.Facts.Pinned.Keys);
        Assert.Equal(target, coordinator.Facts.Pinned[LingerAddress].Target);
    }

    [Fact]
    public async Task Linger_OneTableSnapshotServesAllPins()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var coordinator = await WithLingerRulesAsync();
        uint[] addresses = [LingerAddress, LingerAddress + 1, LingerAddress + 2];
        Assert.True(await PinAsync(coordinator, "first.example", vpn, TimeSpan.FromSeconds(60), addresses));
        _world.TcpConnections = [.. addresses];

        await AdvanceAndTickAsync(coordinator, TimeSpan.FromSeconds(61) + Coordinator.PinLingerGrace);
        Assert.Equal(1, _world.TcpTableReads);
        Assert.All(addresses, address => Assert.Contains(address, coordinator.Facts.Pinned.Keys));

        // Следующие тики до срока проверки таблицу не читают.
        await AdvanceAndTickAsync(coordinator, TimeSpan.FromSeconds(5));
        await AdvanceAndTickAsync(coordinator, TimeSpan.FromSeconds(5));
        Assert.Equal(1, _world.TcpTableReads);
    }

    [Fact]
    public async Task Linger_RuleChangedToBlock_DropsDirectPinImmediately()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var coordinator = await WithLingerRulesAsync(first: RouteTarget.Direct, defaultTarget: vpn);
        Assert.True(await PinAsync(coordinator, "first.example", RouteTarget.Direct, TimeSpan.FromSeconds(60), LingerAddress));
        _world.TcpConnections = [LingerAddress];
        await AdvanceAndTickAsync(coordinator, TimeSpan.FromSeconds(61));
        Assert.Equal(Decision.Direct, coordinator.Facts.Policy!.Classify(LingerAddress).Decision);

        var response = await coordinator.HandleRequestAsync(new SaveSettingsRequest(coordinator.Settings with
        {
            DomainRules = [.. coordinator.Settings.DomainRules.Select(r => r.Suffix == "first.example" ? r with { Target = RouteTarget.Blocked } : r)],
        }), CancellationToken.None);

        Assert.True(response.Ok);
        Assert.DoesNotContain(LingerAddress, coordinator.Facts.Pinned.Keys);
        Assert.Equal(_profile.Id, coordinator.Facts.Policy!.Classify(LingerAddress).Tunnel);
    }

    [Fact]
    public async Task Linger_YieldsToAnotherDomainWithOtherTarget_ButPrimaryPinStillConflicts()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var coordinator = await WithLingerRulesAsync();
        Assert.True(await PinAsync(coordinator, "first.example", vpn, TimeSpan.FromSeconds(60), LingerAddress));
        _world.TcpConnections = [LingerAddress];

        // Пока TTL не истёк, другой домен с другой целью этот адрес не получает.
        Assert.False(await PinAsync(coordinator, "second.example", RouteTarget.Direct, TimeSpan.FromMinutes(5), LingerAddress));

        await AdvanceAndTickAsync(coordinator, TimeSpan.FromSeconds(61) + Coordinator.PinLingerGrace);
        Assert.Equal(_profile.Id, coordinator.Facts.Policy!.Classify(LingerAddress).Tunnel);

        // Продлённое закрепление уступает: адрес целиком переходит к новому ответу, прежняя цель снята.
        Assert.True(await PinAsync(coordinator, "second.example", RouteTarget.Direct, TimeSpan.FromMinutes(5), LingerAddress));
        Assert.Equal(RouteTarget.Direct, coordinator.Facts.Pinned[LingerAddress].Target);
        Assert.Equal(Decision.Direct, coordinator.Facts.Policy!.Classify(LingerAddress).Decision);

        // Соединение к адресу ещё есть, но прежнее закрепление не возвращается и после TTL нового.
        await AdvanceAndTickAsync(coordinator, TimeSpan.FromMinutes(6) + Coordinator.PinLingerGrace);
        Assert.NotEqual(vpn, coordinator.Facts.Pinned.GetValueOrDefault(LingerAddress).Target);
    }

    [Fact]
    public async Task Linger_TargetTunnelDrop_ReleasesLingeringPinOnly()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var coordinator = await WithLingerRulesAsync();
        var fresh = LingerAddress + 10;
        Assert.True(await PinAsync(coordinator, "first.example", vpn, TimeSpan.FromSeconds(60), LingerAddress));
        Assert.True(await PinAsync(coordinator, "first.example", vpn, TimeSpan.FromHours(1), fresh));
        _world.TcpConnections = [LingerAddress];
        await AdvanceAndTickAsync(coordinator, TimeSpan.FromSeconds(61));
        Assert.Contains(LingerAddress, coordinator.Facts.Pinned.Keys);

        _world.Ras.Drop(Coordinator.EntryNameFor(_profile));
        await TickAsync(coordinator);

        Assert.DoesNotContain(LingerAddress, coordinator.Facts.Pinned.Keys);
        Assert.Contains(fresh, coordinator.Facts.Pinned.Keys);
    }

    [Fact]
    public async Task PinLimit_RuleQuotaRefusesOnlyThatRule()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var coordinator = await WithLingerRulesAsync();
        var quota = Enumerable.Range(0, Coordinator.MaxPinsPerRule).Select(i => Ipv4.Parse("5.1.0.0") + (uint)i).ToArray();
        Assert.True(await PinAsync(coordinator, "first.example", vpn, TimeSpan.FromHours(1), quota));

        var extra = Ipv4.Parse("5.2.0.1");
        Assert.False(await PinAsync(coordinator, "first.example", vpn, TimeSpan.FromHours(1), extra));
        Assert.True(await PinAsync(coordinator, "second.example", RouteTarget.Direct, TimeSpan.FromHours(1), extra));

        // Частичный ответ: уже закреплённый адрес правила отдаётся, новый сверх доли - нет.
        var pending = coordinator.ObservePinnedPartialAsync(new PinnedRouteNotice("first.example", "first.example", vpn,
            [quota[0], extra + 1], TimeSpan.FromHours(1)), CancellationToken.None);
        await coordinator.DrainAsync();
        Assert.Equal(new[] { quota[0] }, await pending);

        Assert.Contains(coordinator.BuildStatus().Warnings, w => w.Code == "domain-pin-limit" && w.Text.Contains("first.example", StringComparison.Ordinal));
        Assert.DoesNotContain(coordinator.BuildStatus().Warnings, w => w.Code == "domain-pin-limit" && w.Text.Contains("second.example", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Partial_ConflictingAddressIsLeftOut_OthersArePinned()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var coordinator = await WithLingerRulesAsync();
        var other = LingerAddress + 1;
        Assert.True(await PinAsync(coordinator, "first.example", vpn, TimeSpan.FromHours(1), LingerAddress));

        var pending = coordinator.ObservePinnedPartialAsync(new PinnedRouteNotice("second.example", "second.example", RouteTarget.Direct,
            [LingerAddress, other], TimeSpan.FromMinutes(5)), CancellationToken.None);
        await coordinator.DrainAsync();

        Assert.Equal(new[] { other }, await pending);
        Assert.Equal(vpn, coordinator.Facts.Pinned[LingerAddress].Target);
        Assert.Equal(RouteTarget.Direct, coordinator.Facts.Pinned[other].Target);

        // Весь ответ из конфликтующих адресов - отказ; обычное наблюдение по-прежнему всё или ничего.
        var refused = coordinator.ObservePinnedPartialAsync(new PinnedRouteNotice("second.example", "second.example", RouteTarget.Direct,
            [LingerAddress], TimeSpan.FromMinutes(5)), CancellationToken.None);
        await coordinator.DrainAsync();
        Assert.Null(await refused);
        Assert.False(await PinAsync(coordinator, "second.example", RouteTarget.Direct, TimeSpan.FromMinutes(5), LingerAddress, other + 1));
        Assert.DoesNotContain(other + 1, coordinator.Facts.Pinned.Keys);
    }

    [Fact]
    public async Task RefusedLease_IsReleasedWithoutWaitingForTheQueue()
    {
        var coordinator = await WithLingerRulesAsync();
        var notice = new PinnedRouteNotice("second.example", "second.example", RouteTarget.Direct, [LingerAddress], TimeSpan.FromMinutes(5))
        {
            LeaseId = Guid.NewGuid(),
        };
        var pending = coordinator.ObservePinnedAsync(notice, CancellationToken.None);
        await coordinator.DrainAsync();
        Assert.True(await pending);
        Assert.Contains(LingerAddress, coordinator.Facts.Pinned.Keys);

        var completion = coordinator.CompletePinnedAsync(notice, accepted: false);
        Assert.True(completion.IsCompleted);
        Assert.False(await completion);

        // Снятие стоит в очереди и применяется ближайшей работой актора.
        await coordinator.DrainAsync();
        Assert.DoesNotContain(LingerAddress, coordinator.Facts.Pinned.Keys);
    }
}
