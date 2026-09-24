using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Управление отдельным подключением: выключатель «сейчас» (настройки не меняются) и порядок списка,
/// который задаёт и вид на экране, и очерёдность подъёма.
/// </summary>
public sealed partial class CoordinatorTests
{
    [Fact]
    public async Task PauseTunnel_HangsUpOnlyIt_AndLeavesSettingsAlone()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with { Profiles = [_profile, second] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.Equal(2, _world.Ras.ConnectedEntries.Count);

        var response = await PauseAsync(coordinator, second.Id, paused: true);

        Assert.True(response.Ok);
        Assert.Equal([Coordinator.EntryNameFor(_profile)], _world.Ras.ConnectedEntries);
        // Роль в настройках не тронута: цели, назначенные на подключение, не осиротели.
        Assert.Equal(ProfileRole.Secondary, coordinator.Settings.Profile(second.Id)!.Role);

        var status = coordinator.BuildStatus();
        var row = status.Tunnels.Single(t => t.ProfileId == second.Id);
        Assert.True(row.Paused);
        Assert.Equal(ConnectionState.Disconnected, row.State);
        Assert.Equal(ConnectionState.Connected, status.Tunnels.Single(t => t.ProfileId == _profile.Id).State);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    [Fact]
    public async Task PausedTunnel_IsNotDialedAgain_UntilResumed()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with { Profiles = [_profile, second] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        await PauseAsync(coordinator, second.Id, paused: true);
        var dials = _world.Ras.Dials;

        for (var i = 0; i < 3; i++)
        {
            _world.Time.Advance(TimeSpan.FromSeconds(30));
            await TickAsync(coordinator);
        }

        Assert.Equal(dials, _world.Ras.Dials);

        await PauseAsync(coordinator, second.Id, paused: false);

        Assert.Equal(dials + 1, _world.Ras.Dials);
        Assert.False(coordinator.BuildStatus().Tunnels.Single(t => t.ProfileId == second.Id).Paused);
        Assert.Contains(Coordinator.EntryNameFor(second), _world.Ras.ConnectedEntries);
    }

    /// <summary>Положенный туннель для защиты неотличим от упавшего: его адреса блокируются, а не утекают.</summary>
    [Fact]
    public async Task PausedTunnel_BlocksItsNetworks()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with
        {
            Profiles = [_profile, second],
            Rules = [new UserRuleSetting { Cidr = "13.107.0.0/16", Target = RouteTarget.Tunnel(second.Id) }],
        });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.Contains(Ipv4Cidr.Parse("13.107.0.0/16"), _world.Routes.On(FakeInventory.TunnelLuid(1)));

        await PauseAsync(coordinator, second.Id, paused: true);

        Assert.Equal(1, _world.Wfp.TunnelPermits);
        Assert.Contains(_world.Wfp.Group(FilterGroup.Runtime), f => f.Action == FilterAction.Block && f.Name.Contains("Туннель недоступен", StringComparison.Ordinal));
        Assert.DoesNotContain(Ipv4Cidr.Parse("13.107.0.0/16"), _world.Routes.On(FakeInventory.TunnelLuid(1)));
        Assert.True(_world.Routes.HasHalfRoutesOn(FakeInventory.TunnelLuid(0)));
    }

    /// <summary>Положен носитель «остального интернета»: интернета нет, и сказать об этом надо прямо.</summary>
    [Fact]
    public async Task PausedAnchor_ReportsTrafficBlocked_AndWarns()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        await PauseAsync(coordinator, _profile.Id, paused: true);

        Assert.Equal(ConnectionState.TrafficBlocked, coordinator.DeriveState());
        var warning = Assert.Single(coordinator.BuildStatus().Warnings, w => w.Code == "tunnel-paused");
        Assert.Contains("Остальной интернет не работает", warning.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Connect_ClearsPause()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with { Profiles = [_profile, second] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        await PauseAsync(coordinator, second.Id, paused: true);

        await ConnectAsync(coordinator);

        Assert.False(coordinator.BuildStatus().Tunnels.Single(t => t.ProfileId == second.Id).Paused);
        Assert.Equal(2, _world.Ras.ConnectedEntries.Count);
    }

    /// <summary>Дозвон, начатый до нажатия, не должен присоединиться после него.</summary>
    [Fact]
    public async Task DialFinishingAfterPause_IsHungUp()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with { Profiles = [_profile, second] });
        var entry = Coordinator.EntryNameFor(second);
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _world.Ras.Gates[entry] = gate;
        var coordinator = await StartAsync();
        await coordinator.HandleRequestAsync(new ConnectRequest(null, null), CancellationToken.None);

        await PauseAsync(coordinator, second.Id, paused: true);
        gate.SetResult();
        _world.Ras.Gates.Remove(entry);
        await CompleteDialAsync(coordinator);

        Assert.DoesNotContain(entry, _world.Ras.ConnectedEntries);
        Assert.True(coordinator.BuildStatus().Tunnels.Single(t => t.ProfileId == second.Id).Paused);
    }

    [Fact]
    public async Task PauseTunnel_RejectsProfileThatIsOffCompletely()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with { Profiles = [_profile, second with { Role = ProfileRole.Off }] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var response = await PauseAsync(coordinator, second.Id, paused: true);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.InvalidSettings, response.ErrorCode);
    }

    [Fact]
    public async Task DialOrder_FollowsProfileList()
    {
        var second = SecondProfile();
        // Опорное подключение стоит вторым: порядок задаёт список, а не роль.
        SaveSettings(Settings() with { Profiles = [second, _profile] });
        var coordinator = await StartAsync();

        await ConnectAsync(coordinator);

        var status = coordinator.BuildStatus();
        Assert.Equal([second.Id, _profile.Id], status.Tunnels.Select(t => t.ProfileId));
        Assert.Equal([Coordinator.EntryNameFor(second), Coordinator.EntryNameFor(_profile)], _world.Ras.DialOrder);
    }

    [Fact]
    public async Task SetProfileOrder_SwapsProfiles_AndRejectsForeignSet()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with { Profiles = [_profile, second] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var response = await coordinator.HandleRequestAsync(new SetProfileOrderRequest([second.Id, _profile.Id]), CancellationToken.None);

        Assert.True(response.Ok);
        Assert.Equal([second.Id, _profile.Id], coordinator.Settings.Profiles.Select(p => p.Id));
        Assert.Equal([second.Id, _profile.Id], coordinator.BuildStatus().Tunnels.Select(t => t.ProfileId));

        var bad = await coordinator.HandleRequestAsync(new SetProfileOrderRequest([second.Id]), CancellationToken.None);
        Assert.False(bad.Ok);
        Assert.Equal([second.Id, _profile.Id], coordinator.Settings.Profiles.Select(p => p.Id));
    }

    [Fact]
    public async Task SequentialDial_WaitsForPreviousTunnel()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with { Profiles = [_profile, second], SequentialDial = true });
        var first = Coordinator.EntryNameFor(_profile);
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _world.Ras.Gates[first] = gate;
        var coordinator = await StartAsync();

        await coordinator.HandleRequestAsync(new ConnectRequest(null, null), CancellationToken.None);
        await coordinator.DrainAsync();

        // Первый висит в дозвоне — второй ещё не начинал.
        Assert.Equal(1, _world.Ras.Dials);

        gate.SetResult();
        _world.Ras.Gates.Remove(first);
        await CompleteDialAsync(coordinator);

        Assert.Equal(2, _world.Ras.Dials);
        Assert.Equal(2, _world.Ras.ConnectedEntries.Count);
    }

    [Fact]
    public async Task SequentialDial_DoesNotWaitForTunnelThatFailed()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with { Profiles = [_profile, second], SequentialDial = true });
        _world.Ras.ResultsByEntry[Coordinator.EntryNameFor(_profile)] = new Queue<RasDialResult>([new RasDialResult(false, null, 809, "Нет ответа")]);
        var coordinator = await StartAsync();

        await ConnectAsync(coordinator);

        // Отказ предыдущего — тоже исход: очередь идёт дальше, а не встаёт.
        Assert.Equal(2, _world.Ras.Dials);
        Assert.Contains(Coordinator.EntryNameFor(second), _world.Ras.ConnectedEntries);
    }

    /// <summary>Зависший дозвон держит очередь не дольше отведённого срока.</summary>
    [Fact]
    public async Task SequentialDial_ReleasesQueueAfterWait()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with { Profiles = [_profile, second], SequentialDial = true });
        var first = Coordinator.EntryNameFor(_profile);
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _world.Ras.Gates[first] = gate;
        var coordinator = await StartAsync();
        await coordinator.HandleRequestAsync(new ConnectRequest(null, null), CancellationToken.None);
        await coordinator.DrainAsync();
        Assert.Equal(1, _world.Ras.Dials);

        _world.Time.Advance(Coordinator.SequentialDialWait + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);

        Assert.Equal(2, _world.Ras.Dials);
        gate.SetResult();
        _world.Ras.Gates.Remove(first);
        await CompleteDialAsync(coordinator);
    }

    private static async Task<IpcResponse> PauseAsync(Coordinator coordinator, Guid profileId, bool paused)
    {
        var response = await coordinator.HandleRequestAsync(new SetTunnelPausedRequest(profileId, paused), CancellationToken.None);
        await CompleteDialAsync(coordinator);
        return response;
    }
}
