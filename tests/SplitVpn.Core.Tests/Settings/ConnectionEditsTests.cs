using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Settings;

public class ConnectionEditsTests
{
    private static readonly ConnectionProfile Main = new() { Name = "Основное", Server = "vpn.example.org", UserName = "u", Role = ProfileRole.Primary };
    private static readonly ConnectionProfile Extra = new() { Name = "Дополнительное", Server = "vpn2.example.org", UserName = "u", Role = ProfileRole.Secondary };

    [Theory]
    [InlineData(TargetKind.Direct)]
    [InlineData(TargetKind.Block)]
    public void SaveProfile_KeepsDeliberateDefaultTarget_WhenPrimaryIsEdited(TargetKind kind)
    {
        var fresh = new AppSettings { Profiles = [Main], DefaultTarget = new RouteTarget(kind) };

        var updated = ConnectionEdits.SaveProfile(fresh, Main with { Name = "Переименовано" });

        Assert.Equal(new RouteTarget(kind), updated.DefaultTarget);
        Assert.Equal("Переименовано", updated.Profiles.Single().Name);
    }

    [Fact]
    public void SaveProfile_MovesDefaultToProfile_OnlyWhenItBecomesPrimary()
    {
        var off = Extra with { Role = ProfileRole.Off };
        var fresh = new AppSettings { Profiles = [off], DefaultTarget = RouteTarget.Direct };

        var updated = ConnectionEdits.SaveProfile(fresh, off with { Role = ProfileRole.Primary });

        Assert.Equal(RouteTarget.Tunnel(off.Id), updated.DefaultTarget);
    }

    [Fact]
    public void SaveProfile_KeepsPositionAndOtherProfiles_AndDemotesPreviousPrimary()
    {
        var fresh = new AppSettings { Profiles = [Main, Extra], DefaultTarget = RouteTarget.Tunnel(Main.Id) };

        var updated = ConnectionEdits.SaveProfile(fresh, Extra with { Role = ProfileRole.Primary });

        Assert.Equal([Main.Id, Extra.Id], updated.Profiles.Select(p => p.Id));
        Assert.Equal(ProfileRole.Secondary, updated.Profiles[0].Role);
        Assert.Equal(ProfileRole.Primary, updated.Profiles[1].Role);
        Assert.Equal(RouteTarget.Tunnel(Main.Id), updated.DefaultTarget);
    }

    [Fact]
    public void RemoveProfile_DropsDeletedGroupMembers_AndEmptyGroups()
    {
        var group = new TunnelGroupSetting { Name = "Группа", Members = [Main.Id, Extra.Id] };
        var lonely = new TunnelGroupSetting { Name = "Одинокая", Members = [Extra.Id] };
        var fresh = new AppSettings
        {
            Profiles = [Main, Extra],
            Groups = [group, lonely],
            DefaultTarget = RouteTarget.Group(lonely.Id),
            GeoTarget = RouteTarget.Group(group.Id),
        };

        var updated = ConnectionEdits.RemoveProfile(fresh, Extra.Id);

        Assert.Equal([Main.Id], updated.Groups.Single().Members);
        Assert.Equal(RouteTarget.Direct, updated.DefaultTarget);
        Assert.Equal(RouteTarget.Group(group.Id), updated.GeoTarget);
        Assert.True(SettingsValidator.Validate(updated).IsValid, string.Join("; ", SettingsValidator.Validate(updated).Errors));
    }

    [Fact]
    public void NewlyDirect_ListsWhatLeavesVpn_WhenProfileIsTurnedOff()
    {
        var fresh = new AppSettings
        {
            Profiles = [Main],
            DefaultTarget = RouteTarget.Tunnel(Main.Id),
            GeoTarget = RouteTarget.Direct,
            Rules = [new UserRuleSetting { Cidr = "203.0.113.0/24", Target = RouteTarget.Tunnel(Main.Id) }],
        };

        var updated = ConnectionEdits.SaveProfile(fresh, Main with { Role = ProfileRole.Off });

        Assert.Equal(["«Остальной интернет»", "подсеть 203.0.113.0/24"], ConnectionEdits.NewlyDirect(fresh, updated));
    }

    [Fact]
    public void SecretBinding_ChangesWithServerProtocolAndLogin_NotWithNameOrCase()
    {
        Assert.False(ConnectionEdits.PasswordBindingChanged(Main, Main with { Name = "Другое", Server = " VPN.example.org ", UserName = "U" }));
        Assert.True(ConnectionEdits.PasswordBindingChanged(Main, Main with { Server = "evil.example.org" }));
        Assert.True(ConnectionEdits.PasswordBindingChanged(Main, Main with { Protocol = VpnProtocol.Pptp }));
        Assert.True(ConnectionEdits.PasswordBindingChanged(Main, Main with { AuthMethod = AuthMethod.Pap }));
        Assert.True(ConnectionEdits.PasswordBindingChanged(Main, Main with { Domain = "CORP" }));
        Assert.True(ConnectionEdits.PreSharedKeyBindingChanged(Main, Main with { Server = "vpn.example.org:4443" }));
        Assert.False(ConnectionEdits.PreSharedKeyBindingChanged(Main, Main with { UserName = "другой" }));
    }

    [Theory]
    [InlineData("lan", true)]
    [InlineData("home.arpa", true)]
    [InlineData("192.168.1.1/24", false)]
    [InlineData("плохо имя", false)]
    public void Validator_ChecksLocalDnsSuffixes(string suffix, bool valid)
    {
        var settings = new AppSettings { Profiles = [Main], DefaultTarget = RouteTarget.Tunnel(Main.Id), LocalDnsSuffixes = [suffix] };

        Assert.Equal(valid, SettingsValidator.Validate(settings).IsValid);
    }

    [Fact]
    public void PrepareImport_ResetsMachineSpecificFields_AndMakesNamesUnique()
    {
        var foreign = Main with
        {
            PrimaryAdapter = AdapterSelection.Pinned,
            PinnedInterfaceGuid = Guid.NewGuid(),
            AllowFallbackWhenPinnedMissing = true,
            Retry = new RetrySettings { Enabled = false, MaxDelaySeconds = 1 },
        };

        var prepared = ConnectionEdits.PrepareImport(["основное"], [foreign, foreign with { Id = Guid.NewGuid() }, null]);

        Assert.Equal(["Основное 2", "Основное 3"], prepared.Select(p => p.Name));
        Assert.All(prepared, p =>
        {
            Assert.NotEqual(Main.Id, p.Id);
            Assert.Equal(ProfileRole.Off, p.Role);
            Assert.Equal(AdapterSelection.Auto, p.PrimaryAdapter);
            Assert.Null(p.PinnedInterfaceGuid);
            Assert.Equal(new RetrySettings(), p.Retry);
        });
    }
}
