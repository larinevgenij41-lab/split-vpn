using SplitVpn.Core.Ipc;
using SplitVpn.Core.State;

namespace SplitVpn.Service.Tests;

/// <summary>Состояние службы и настройки на диске: исправления аудита 2026-11-01 (ID13, ID14, ID40).</summary>
public sealed partial class CoordinatorTests
{
    /// <summary>ID13: «servers»: null и неверные адреса в кеше не ломают сверку и убираются при загрузке.</summary>
    [Fact]
    public async Task NullServerCache_DoesNotBreakReconcile()
    {
        var named = _profile with { Server = "vpn.example.org:4443" };
        SaveSettings(Settings() with { Profiles = [named] });
        File.WriteAllText(_world.Paths.State, """{"intent":"Connected","servers":null}""");

        var coordinator = await StartAsync();

        Assert.NotNull(coordinator.State.Servers);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    [Fact]
    public void ServerCache_DropsInvalidAddresses()
    {
        File.WriteAllText(_world.Paths.State, $$"""
        {"servers":[null,{"profileId":"{{_profile.Id}}","addresses":["не адрес",null,"203.0.113.10"],"resolvedUtc":"2026-11-01T00:00:00Z","sessionAddresses":["x"],"revocationHosts":[null,"crl.example.org"]}]}
        """);

        var state = new ServiceStores(_world.Paths).LoadState();

        var entry = Assert.Single(state.Servers);
        Assert.Equal(["203.0.113.10"], entry.Addresses);
        Assert.Empty(entry.SessionAddresses!);
        Assert.Equal(["crl.example.org"], entry.RevocationHosts!);
    }

    /// <summary>ID14: команда, намерение которой не записалось на диск, не меняет ни состояние, ни сеть.</summary>
    [Fact]
    public async Task IntentNotSaved_HasNoNetworkEffect()
    {
        new ServiceStores(_world.Paths).SaveState(new ServiceStateFile());
        var coordinator = await StartAsync();

        using (new FileStream(_world.Paths.State, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            await Assert.ThrowsAnyAsync<Exception>(() => coordinator.HandleRequestAsync(new ConnectRequest(null, null), CancellationToken.None));
        }

        Assert.Equal(Intent.Off, coordinator.State.Intent);
        await TickAsync(coordinator);
        Assert.Equal(0, _world.Ras.Dials);
        Assert.Empty(_world.Wfp.Groups);
        Assert.Equal(Intent.Off, new ServiceStores(_world.Paths).LoadState().Intent);
    }

    /// <summary>ID40: проверяется и сохраняется одна и та же нормализованная модель — «null» из канала в файл не попадает.</summary>
    [Fact]
    public async Task SaveSettings_PersistsNormalizedModel()
    {
        var coordinator = await StartAsync();

        var response = await coordinator.HandleRequestAsync(new SaveSettingsRequest(Settings() with { AppUpdate = null!, CheckTargets = null! }), CancellationToken.None);

        Assert.True(response.Ok);
        Assert.NotNull(coordinator.Settings.AppUpdate);
        Assert.NotNull(coordinator.Settings.CheckTargets);
        var saved = File.ReadAllText(_world.Paths.Settings);
        Assert.DoesNotContain("\"appUpdate\": null", saved, StringComparison.Ordinal);
        Assert.DoesNotContain("\"checkTargets\": null", saved, StringComparison.Ordinal);
    }
}
