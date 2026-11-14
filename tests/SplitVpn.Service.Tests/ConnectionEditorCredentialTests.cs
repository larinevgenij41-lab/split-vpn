using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;
using SplitVpn.Windows.Operations;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EditorConfirmedBindingChangePreservesPasswordAndPsk(bool reuse)
    {
        var original = _profile with { Protocol = VpnProtocol.L2tpIpsec, Server = "203.0.113.10" };
        SaveSettings(Multi(original));
        _world.Secrets.Save(original.Id, "shared-key", SecretKind.PreSharedKey);
        var coordinator = await StartAsync();
        var changed = original with { Server = "203.0.113.20", UserName = "new-user" };
        var response = await coordinator.HandleRequestAsync(new SaveConnectionRequest(Multi(changed), changed.Id,
            null, null, reuse ? original : null), CancellationToken.None);
        Assert.True(response.Ok);
        Assert.Equal(reuse, _world.Secrets.Contains(original.Id));
        Assert.Equal(reuse, _world.Secrets.Contains(original.Id, SecretKind.PreSharedKey));
        if (reuse)
        {
            Assert.Equal("secret", _world.Secrets.Saved[original.Id]);
            Assert.Equal("shared-key", _world.Secrets.Keys[original.Id]);
        }
    }

    [Fact]
    public async Task EditorConfirmedBindingChangePreservesMemoryPassword()
    {
        var original = _profile with { SavePassword = false };
        SaveSettings(Multi(original));
        var coordinator = await StartAsync();
        await coordinator.HandleRequestAsync(new SetPasswordRequest(original.Id, "memory-secret"), CancellationToken.None);
        var changed = original with { UserName = "new-user" };
        var result = await coordinator.HandleRequestAsync(new SaveConnectionRequest(Multi(changed), changed.Id, null, null, original), CancellationToken.None);
        Assert.True(result.Ok);
        Assert.Equal("memory-secret", new string(coordinator.Facts.MemoryPasswords[original.Id]));
        Assert.False(_world.Secrets.Contains(original.Id));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EditorRejectsStaleOrForeignCredentialSource(bool foreign)
    {
        var coordinator = await StartAsync();
        var source = foreign ? _profile with { Id = Guid.NewGuid() } : _profile with { UserName = "stale-user" };
        var changed = _profile with { Server = "203.0.113.20" };
        var result = await coordinator.HandleRequestAsync(new SaveConnectionRequest(Multi(changed), changed.Id, null, null, source), CancellationToken.None);
        Assert.False(result.Ok);
        Assert.Equal(_profile.Server, coordinator.Settings.Profile(_profile.Id)!.Server);
        Assert.Equal("secret", _world.Secrets.Saved[_profile.Id]);
    }

    [Fact]
    public async Task EditorReuseDoesNotApplyToOtherProfilesInRequest()
    {
        var other = _profile with { Id = Guid.NewGuid(), Name = "Другой", Role = ProfileRole.Secondary };
        SaveSettings(Settings() with { Profiles = [_profile, other] });
        _world.Secrets.Save(other.Id, "other-secret");
        var coordinator = await StartAsync();
        var updated = coordinator.Settings with { Profiles = [_profile with { UserName = "new" }, other with { UserName = "other-new" }] };
        var result = await coordinator.HandleRequestAsync(new SaveConnectionRequest(updated, _profile.Id, null, null, _profile), CancellationToken.None);
        Assert.True(result.Ok);
        Assert.Equal("secret", _world.Secrets.Saved[_profile.Id]);
        Assert.False(_world.Secrets.Contains(other.Id));
    }

    [Fact]
    public async Task EditorReuseRespectsExplicitKeyRemovalAndPasswordReplacement()
    {
        var original = _profile with { Protocol = VpnProtocol.L2tpIpsec, Server = "203.0.113.10" };
        SaveSettings(Multi(original));
        _world.Secrets.Save(original.Id, "key", SecretKind.PreSharedKey);
        var coordinator = await StartAsync();
        var updated = original with { UserName = "new-user" };
        var result = await coordinator.HandleRequestAsync(new SaveConnectionRequest(Multi(updated), original.Id, "replacement", "", original), CancellationToken.None);
        Assert.True(result.Ok);
        Assert.Equal("replacement", _world.Secrets.Saved[original.Id]);
        Assert.False(_world.Secrets.Contains(original.Id, SecretKind.PreSharedKey));
    }

    [Fact]
    public async Task EditorOrdinarySettingsChangesKeepStoredPassword()
    {
        var coordinator = await StartAsync();
        var changed = _profile with { Name = "Переименовано", AllowFallbackWhenPinnedMissing = true };
        var result = await coordinator.HandleRequestAsync(new SaveConnectionRequest(Multi(changed), changed.Id, null, null), CancellationToken.None);
        Assert.True(result.Ok);
        Assert.Equal("secret", _world.Secrets.Saved[changed.Id]);
    }
}
