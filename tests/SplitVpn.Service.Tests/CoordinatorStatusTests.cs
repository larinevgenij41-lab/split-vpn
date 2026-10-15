using SplitVpn.Core.Ipc;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Tests;

/// <summary>Общее состояние и подсказки интерфейсу при нескольких туннелях.</summary>
public sealed partial class CoordinatorTests
{
    [Fact]
    public async Task SecondaryAuthenticationFailure_KeepsOverallConnected_AndShowsError()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with
        {
            Profiles = [_profile, second],
            Rules = [new UserRuleSetting { Cidr = "13.107.0.0/16", Target = RouteTarget.Tunnel(second.Id) }],
        });
        _world.Ras.ResultsByEntry[Coordinator.EntryNameFor(second)] = new Queue<RasDialResult>([new RasDialResult(false, null, 691, "Отказано в доступе")]);
        var coordinator = await StartAsync();

        await ConnectAsync(coordinator);

        var status = coordinator.BuildStatus();
        Assert.Equal(ConnectionState.Connected, status.State);
        Assert.Equal(ConnectionState.Error, status.Tunnels.Single(t => t.ProfileId == second.Id).State);
        Assert.Contains("Резерв", status.ErrorText, StringComparison.Ordinal);
        Assert.Contains("Остальные адреса → через «Нидерланды»", StatusText.Format(status), StringComparison.Ordinal);
    }

    [Fact]
    public async Task PrimaryDown_IsNotConnected_EvenIfSecondaryIsUp()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with
        {
            Profiles = [_profile, second],
            Rules = [new UserRuleSetting { Cidr = "13.107.0.0/16", Target = RouteTarget.Tunnel(second.Id) }],
        });
        _world.Ras.ResultsByEntry[Coordinator.EntryNameFor(_profile)] = new Queue<RasDialResult>([new RasDialResult(false, null, 691, "Отказано в доступе")]);
        var coordinator = await StartAsync();

        await ConnectAsync(coordinator);

        var status = coordinator.BuildStatus();
        Assert.Equal(ConnectionState.Error, status.State);
        Assert.Contains("Остальные адреса → заблокированы", StatusText.Format(status), StringComparison.Ordinal);
    }

    [Fact]
    public async Task PasswordWithoutProfile_GoesToTunnelThatWaitsForIt_NotToPrimary()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with
        {
            Profiles = [_profile, second],
            Rules = [new UserRuleSetting { Cidr = "13.107.0.0/16", Target = RouteTarget.Tunnel(second.Id) }],
        });
        _world.Secrets.Delete(second.Id);
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var status = coordinator.BuildStatus();
        Assert.Equal(ConnectionState.PasswordRequired, status.Tunnels.Single(t => t.ProfileId == second.Id).State);
        Assert.Contains(status.Warnings, w => w.Code == "password-required" && w.Text.Contains("«Резерв»", StringComparison.Ordinal));

        await coordinator.HandleRequestAsync(new ConnectRequest(null, "второй"), CancellationToken.None);
        await CompleteDialAsync(coordinator);

        Assert.Equal("secret", new string(_world.Secrets.TryLoad(_profile.Id)));
        Assert.Equal("второй", new string(_world.Secrets.TryLoad(second.Id)));
        Assert.Equal(ConnectionState.Connected, coordinator.BuildStatus().Tunnels.Single(t => t.ProfileId == second.Id).State);
    }

    [Fact]
    public async Task PasswordForExplicitProfile_IsStoredForThatProfile()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with { Profiles = [_profile, second] });
        var coordinator = await StartAsync();

        await coordinator.HandleRequestAsync(new ConnectRequest(second.Id, "явный"), CancellationToken.None);
        await CompleteDialAsync(coordinator);

        Assert.Equal("secret", new string(_world.Secrets.TryLoad(_profile.Id)));
        Assert.Equal("явный", new string(_world.Secrets.TryLoad(second.Id)));
    }

    [Fact]
    public async Task FailoverGroupWithoutLiveMembers_WarnsThatTrafficIsBlocked()
    {
        var second = SecondProfile();
        var group = new TunnelGroupSetting { Name = "Резервная", Members = [_profile.Id, second.Id], Mode = BalanceMode.Failover };
        SaveSettings(Settings() with { Profiles = [_profile, second], Groups = [group], DefaultTarget = RouteTarget.Group(group.Id) });
        _world.Ras.Results.Enqueue(new RasDialResult(false, null, 809, "Нет ответа"));
        _world.Ras.Results.Enqueue(new RasDialResult(false, null, 809, "Нет ответа"));
        var coordinator = await StartAsync();

        await ConnectAsync(coordinator);

        var warning = Assert.Single(coordinator.BuildStatus().Warnings, w => w.Code == "group-degraded");
        Assert.Contains("доступно 0 из 2", warning.Text, StringComparison.Ordinal);
        Assert.Contains("заблокирован", warning.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("перераспределена", warning.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ExternalDisconnectOfSecondary_KeepsPrimaryConnected_AndDoesNotRedialIt()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with
        {
            Profiles = [_profile, second],
            Rules = [new UserRuleSetting { Cidr = "13.107.0.0/16", Target = RouteTarget.Tunnel(second.Id) }],
        });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var dials = _world.Ras.Dials;

        _world.TerminationReason = 631;
        _world.Ras.Drop(Coordinator.EntryNameFor(second));
        await TickAsync(coordinator);
        _world.Time.Advance(TimeSpan.FromMinutes(2));
        await TickAsync(coordinator);

        var status = coordinator.BuildStatus();
        Assert.Equal(Intent.Connected, coordinator.State.Intent);
        Assert.Equal(dials, _world.Ras.Dials);
        Assert.Equal(ConnectionState.Connected, status.State);
        Assert.Equal(ConnectionState.DisconnectedExternally, status.Tunnels.Single(t => t.ProfileId == second.Id).State);
        Assert.True(_world.Routes.HasHalfRoutesOn(FakeInventory.TunnelLuid(0)));

        await ConnectAsync(coordinator);
        Assert.Equal(dials + 1, _world.Ras.Dials);
    }

    [Fact]
    public async Task MaskedReport_HidesProfileNames()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var response = await coordinator.HandleRequestAsync(new ExportReportRequest(MaskPersonalData: true), CancellationToken.None);
        var report = response.ResultAs<string>()!;

        Assert.DoesNotContain("Нидерланды", report, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Ipv6Warning_OnlyWhileProtectionIsOn()
    {
        var coordinator = await StartAsync();
        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: false), CancellationToken.None);

        Assert.DoesNotContain(coordinator.BuildStatus().Warnings, w => w.Code == "ipv6-restricted");

        await ConnectAsync(coordinator);
        Assert.Contains(coordinator.BuildStatus().Warnings, w => w.Code == "ipv6-restricted");
    }

    [Fact]
    public void Journal_AfterServiceRestart_ReturnsWholeLog_ForStaleId()
    {
        var journal = new EventJournal(_world.Time);
        journal.Add("Сведения", "первое");
        journal.Add("Сведения", "второе");

        Assert.Equal(2, journal.Since(0).Count);
        Assert.Single(journal.Since(1));
        Assert.Empty(journal.Since(2));
        Assert.Equal(2, journal.Since(40).Count);
    }
}
