using SplitVpn.Core.Ipc;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Windows.Operations;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests
{
    /// <summary>Настройки с одним опорным туннелем: «остальной интернет» идёт в него.</summary>
    private static AppSettings Multi(ConnectionProfile profile) => new()
    {
        Profiles = [profile with { Role = ProfileRole.Primary }],
        DefaultTarget = Core.Policy.RouteTarget.Tunnel(profile.Id),
    };

    [Fact]
    public async Task L2tpWithoutPskDoesNotDialAndExplainsMissingKey()
    {
        var profile = _profile with { Protocol = VpnProtocol.L2tpIpsec, Server = "203.0.113.10" };
        var coordinator = await StartAsync();
        await coordinator.HandleRequestAsync(new SaveSettingsRequest(Multi(profile)), CancellationToken.None);
        await ConnectAsync(coordinator);
        Assert.Equal(0, _world.Ras.Dials);
        Assert.Equal(ConnectionState.Error, coordinator.DeriveState());
        Assert.Contains("IPsec", coordinator.BuildStatus().ErrorText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SavingConnectionDeliversPskBeforeFirstDial()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var profile = _profile with { Protocol = VpnProtocol.L2tpIpsec, Server = "203.0.113.10", AuthMethod = AuthMethod.EapMsChapV2 };
        var response = await coordinator.HandleRequestAsync(new SaveConnectionRequest(Multi(profile),
            profile.Id, "new-password", "new-psk"), CancellationToken.None);
        await CompleteDialAsync(coordinator);
        Assert.True(response.Ok);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
        Assert.Equal(profile.Protocol, _world.Ras.SavedProfile!.Protocol);
        Assert.Equal(profile.AuthMethod, _world.Ras.SavedProfile.AuthMethod);
        Assert.Equal("new-psk", _world.Ras.SavedKey);
        Assert.Equal("new-password", _world.Secrets.Saved[profile.Id]);
        Assert.DoesNotContain(_world.Journal.Since(0), e => e.Text.Contains("new-psk", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ChangingProtocolAtSameHostReconnectsAndReplacesTransport()
    {
        var coordinator = await StartAsync();
        var profile = _profile with { Server = "203.0.113.10" };
        await coordinator.HandleRequestAsync(new SaveSettingsRequest(Multi(profile)), CancellationToken.None);
        // Смена порта сервера удаляет сохранённый пароль: пользователь вводит его заново.
        _world.Secrets.Save(profile.Id, "secret");
        await ConnectAsync(coordinator);
        profile = profile with { Protocol = VpnProtocol.Ikev2, AuthMethod = AuthMethod.EapMsChapV2 };
        await coordinator.HandleRequestAsync(new SaveConnectionRequest(Multi(profile), profile.Id, "password", null), CancellationToken.None);
        await CompleteDialAsync(coordinator);
        Assert.Equal(2, _world.Ras.Dials);
        Assert.Equal(VpnProtocol.Ikev2, _world.Ras.SavedProfile!.Protocol);
        Assert.Contains(_world.Wfp.Groups[FilterGroup.Runtime], f => f.Conditions.Contains(new RemotePortCondition(4500)));
        Assert.DoesNotContain(_world.Wfp.Groups[FilterGroup.Runtime], f => f.Conditions.Contains(new RemotePortCondition(443)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ChangingAuthenticationWithoutNewPassword_DropsTheOldSession(bool changeProtocol)
    {
        var original = _profile with { Server = "203.0.113.10" };
        SaveSettings(Multi(original));
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var changed = original with
        {
            Protocol = changeProtocol ? VpnProtocol.Ikev2 : original.Protocol,
            AuthMethod = AuthMethod.EapMsChapV2,
        };

        var response = await coordinator.HandleRequestAsync(new SaveSettingsRequest(Multi(changed)), CancellationToken.None);
        await CompleteDialAsync(coordinator);

        Assert.True(response.Ok, response.ErrorMessage);
        Assert.False(_world.Ras.Connected);
        Assert.Equal(ConnectionState.PasswordRequired, coordinator.DeriveState());
        Assert.Equal(1, _world.Ras.Dials);
    }

    [Fact]
    public async Task MachineCertificateDoesNotRequireUserPassword()
    {
        var coordinator = await StartAsync();
        var profile = _profile with { Protocol = VpnProtocol.Ikev2, Server = "203.0.113.10", AuthMethod = AuthMethod.MachineCertificate, UserName = "" };
        await coordinator.HandleRequestAsync(new SaveSettingsRequest(Multi(profile)), CancellationToken.None);
        await ConnectAsync(coordinator);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
        Assert.False(_world.Secrets.Contains(profile.Id));
    }

    [Fact]
    public async Task SettingsChangesDuringDialAreRejected()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        coordinator.Facts.Tunnels.Values.First().Dialing = true;
        var response = await coordinator.HandleRequestAsync(new SaveSettingsRequest(new AppSettings()), CancellationToken.None);
        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.Busy, response.ErrorCode);
    }

    [Fact]
    public async Task SwitchingAwayFromL2tpRemovesPsk()
    {
        var coordinator = await StartAsync();
        _world.Secrets.Save(_profile.Id, "old-psk", SecretKind.PreSharedKey);
        var response = await coordinator.HandleRequestAsync(new SaveSettingsRequest(Multi(_profile)), CancellationToken.None);
        Assert.True(response.Ok);
        Assert.False(_world.Secrets.Contains(_profile.Id, SecretKind.PreSharedKey));
    }

    [Theory]
    [InlineData("server")]
    [InlineData("protocol")]
    [InlineData("user")]
    public async Task ChangingServerProtocolOrLogin_DeletesStoredPassword_AndAsksForIt(string change)
    {
        var original = _profile with { Server = "203.0.113.10" };
        SaveSettings(Multi(original));
        var coordinator = await StartAsync();
        var changed = change switch
        {
            "server" => original with { Server = "203.0.113.9" },
            "protocol" => original with { Protocol = VpnProtocol.Ikev2, AuthMethod = AuthMethod.EapMsChapV2 },
            _ => original with { UserName = "other" },
        };

        var response = await coordinator.HandleRequestAsync(new SaveSettingsRequest(Multi(changed)), CancellationToken.None);
        await ConnectAsync(coordinator);

        Assert.True(response.Ok, response.ErrorMessage);
        Assert.False(_world.Secrets.Contains(original.Id));
        Assert.Equal(0, _world.Ras.Dials);
        Assert.Equal(ConnectionState.PasswordRequired, coordinator.DeriveState());
    }

    [Fact]
    public async Task RenamingProfile_KeepsStoredPasswordAndPsk()
    {
        var l2tp = _profile with { Protocol = VpnProtocol.L2tpIpsec, Server = "203.0.113.10" };
        SaveSettings(Multi(l2tp));
        _world.Secrets.Save(l2tp.Id, "psk", SecretKind.PreSharedKey);
        var coordinator = await StartAsync();

        await coordinator.HandleRequestAsync(new SaveSettingsRequest(Multi(l2tp with { Name = "Новое имя", UserName = " USER " })), CancellationToken.None);

        Assert.True(_world.Secrets.Contains(l2tp.Id));
        Assert.True(_world.Secrets.Contains(l2tp.Id, SecretKind.PreSharedKey));
    }

    [Fact]
    public async Task OldClientCannotMutateNewSettings()
    {
        var coordinator = await StartAsync();
        var response = await coordinator.HandleRequestAsync(new SaveSettingsRequest(new AppSettings()) { ContractVersion = 1 }, CancellationToken.None);
        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.BadRequest, response.ErrorCode);
    }
}
