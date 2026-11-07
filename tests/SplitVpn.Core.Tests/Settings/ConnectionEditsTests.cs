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

    /// <summary>
    /// Раздельная маршрутизация («Напрямую», а в VPN идут отдельные правила) - осознанный выбор: новое опорное
    /// подключение её не отменяет. «Блокировать» и «Напрямую» без единого правила в VPN переходят на подключение.
    /// </summary>
    [Fact]
    public void SaveProfile_KeepsSplitRoutingDirect_ButTakesBlockedOrEmptyDefault()
    {
        var off = Extra with { Role = ProfileRole.Off };
        var split = new AppSettings
        {
            Profiles = [off],
            DefaultTarget = RouteTarget.Direct,
            Rules = [new UserRuleSetting { Cidr = "10.0.0.0/8", Target = RouteTarget.Tunnel(off.Id) }],
        };
        var blocked = new AppSettings { Profiles = [off], DefaultTarget = RouteTarget.Blocked };

        Assert.Equal(RouteTarget.Direct, ConnectionEdits.SaveProfile(split, off with { Role = ProfileRole.Primary }).DefaultTarget);
        Assert.Equal(RouteTarget.Tunnel(off.Id), ConnectionEdits.SaveProfile(blocked, off with { Role = ProfileRole.Primary }).DefaultTarget);
        Assert.False(split.DefaultFollowsNewPrimary());
        Assert.True(split with { Rules = [] } is var empty && empty.DefaultFollowsNewPrimary());
        Assert.False((split with { Rules = [], GeoTarget = RouteTarget.Tunnel(off.Id) }).DefaultFollowsNewPrimary());
        Assert.False((split with { DefaultTarget = RouteTarget.Tunnel(off.Id) }).DefaultFollowsNewPrimary());
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
    public void RemoveProfile_ReturnsGatewayNetworksToOwnTunnel_AndKeepsDeliberateDirect()
    {
        ConnectionProfile Gateway(string name, RouteTarget target) => new()
        {
            Name = name,
            Server = name + ".example.org",
            Protocol = VpnProtocol.AnyConnect,
            AuthMethod = AuthMethod.GatewayForm,
            Role = ProfileRole.Secondary,
            AnyConnect = new AnyConnectSettings { ServerNetworksTarget = target },
        };
        var toExtra = Gateway("office", RouteTarget.Tunnel(Extra.Id));
        var direct = Gateway("office2", RouteTarget.Direct);
        var fresh = new AppSettings { Profiles = [Main, Extra, toExtra, direct], DefaultTarget = RouteTarget.Tunnel(Main.Id) };

        var updated = ConnectionEdits.RemoveProfile(fresh, Extra.Id);

        Assert.Null(updated.Profile(toExtra.Id)!.AnyConnect.ServerNetworksTarget);
        Assert.Equal(RouteTarget.Direct, updated.Profile(direct.Id)!.AnyConnect.ServerNetworksTarget);
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

    [Fact]
    public void ExportThenImport_KeepsServerNetworksTargetOnImportedProfile()
    {
        var other = new ConnectionProfile { Name = "Второе", Server = "vpn2.example.org", UserName = "u", Role = ProfileRole.Secondary };
        var gateway = new ConnectionProfile
        {
            Name = "Шлюз",
            Protocol = VpnProtocol.AnyConnect,
            Server = "gw.example.org",
            AnyConnect = new AnyConnectSettings { ServerNetworksTarget = RouteTarget.Tunnel(other.Id) },
        };

        var exported = ConnectionEdits.PrepareExport([other, gateway]);
        var exportedOther = exported.Single(p => p.Name == "Второе");
        var exportedGateway = exported.Single(p => p.Name == "Шлюз");
        Assert.NotEqual(other.Id, exportedOther.Id);
        Assert.Equal(RouteTarget.Tunnel(exportedOther.Id), exportedGateway.AnyConnect.ServerNetworksTarget);

        var imported = ConnectionEdits.PrepareImport([], exported);
        var importedOther = imported.Single(p => p.Name == "Второе");
        var importedGateway = imported.Single(p => p.Name == "Шлюз");
        Assert.NotEqual(exportedOther.Id, importedOther.Id);
        Assert.Equal(RouteTarget.Tunnel(importedOther.Id), importedGateway.AnyConnect.ServerNetworksTarget);
    }

    [Fact]
    public void PrepareImport_DropsServerNetworksTargetThatPointsOutsideTheFile()
    {
        var gateway = new ConnectionProfile
        {
            Name = "Шлюз",
            Protocol = VpnProtocol.AnyConnect,
            Server = "gw.example.org",
            AnyConnect = new AnyConnectSettings { ServerNetworksTarget = RouteTarget.Tunnel(Guid.NewGuid()) },
        };
        var direct = gateway with { Id = Guid.NewGuid(), Name = "Напрямую", AnyConnect = new AnyConnectSettings { ServerNetworksTarget = RouteTarget.Direct } };

        var imported = ConnectionEdits.PrepareImport([], [gateway, direct]);

        Assert.Null(imported.Single(p => p.Name == "Шлюз").AnyConnect.ServerNetworksTarget);
        Assert.Equal(RouteTarget.Direct, imported.Single(p => p.Name == "Напрямую").AnyConnect.ServerNetworksTarget);
    }

    private static readonly Guid VanishedAdapter = Guid.NewGuid();
    private static readonly Guid ReboundAdapter = Guid.NewGuid();

    private static readonly ConnectionProfile PinnedAtLoad = Main with
    {
        PrimaryAdapter = AdapterSelection.Pinned,
        PinnedInterfaceGuid = VanishedAdapter,
        PinnedAdapterDescription = "Intel(R) Wi-Fi 6 AX200 160MHz",
    };

    [Fact]
    public void MergePinnedAdapter_KeepsServiceRebind_WhenFormAdapterUnchanged()
    {
        // Служба перенесла закрепление на новый GUID того же адаптера, пока форма была открыта.
        var basis = PinnedAtLoad with { PinnedInterfaceGuid = ReboundAdapter };

        var (guid, description) = ConnectionEdits.MergePinnedAdapter(PinnedAtLoad, basis, VanishedAdapter);

        Assert.Equal(ReboundAdapter, guid);
        Assert.Equal("Intel(R) Wi-Fi 6 AX200 160MHz", description);
    }

    [Fact]
    public void MergePinnedAdapter_KeepsServicePin_WhenFormSelectionWasCleared()
    {
        // Прежнего адаптера нет в списке, и выбор в форме пуст: пользователь адаптер не выбирал.
        var basis = PinnedAtLoad with { PinnedInterfaceGuid = ReboundAdapter };

        var (guid, description) = ConnectionEdits.MergePinnedAdapter(PinnedAtLoad, basis, null);

        Assert.Equal(ReboundAdapter, guid);
        Assert.Equal("Intel(R) Wi-Fi 6 AX200 160MHz", description);
    }

    [Fact]
    public void MergePinnedAdapter_TakesUserChoice_WithoutForeignDescription()
    {
        var chosen = Guid.NewGuid();
        var basis = PinnedAtLoad with { PinnedInterfaceGuid = ReboundAdapter };

        var (guid, description) = ConnectionEdits.MergePinnedAdapter(PinnedAtLoad, basis, chosen);

        Assert.Equal(chosen, guid);
        Assert.Null(description);
    }

    [Fact]
    public void MergePinnedAdapter_KeepsDescription_WhenNothingChanged()
    {
        var (guid, description) = ConnectionEdits.MergePinnedAdapter(PinnedAtLoad, PinnedAtLoad, VanishedAdapter);

        Assert.Equal(VanishedAdapter, guid);
        Assert.Equal("Intel(R) Wi-Fi 6 AX200 160MHz", description);
    }

    [Fact]
    public void MergePinnedAdapter_NewPin_HasNoDescriptionUntilServiceSeesAdapter()
    {
        var auto = Main with { PrimaryAdapter = AdapterSelection.Auto };
        var chosen = Guid.NewGuid();

        Assert.Equal((chosen, (string?)null), ConnectionEdits.MergePinnedAdapter(auto, auto, chosen));
        Assert.Equal(((Guid?)null, (string?)null), ConnectionEdits.MergePinnedAdapter(auto, auto, null));
    }
}
