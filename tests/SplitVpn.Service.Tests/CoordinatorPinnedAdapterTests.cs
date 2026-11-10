using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Закреплённый основной адаптер после сброса сети Windows: адаптер получает новый GUID, и служба с прежним
/// закреплением не поднимала VPN и держала трафик заблокированным (разбор 04.11.2026).
/// </summary>
public sealed partial class CoordinatorTests
{
    [Fact]
    public async Task PinnedAdapter_RemembersDescription_WhenSeen()
    {
        SaveSettings(Settings() with { Profiles = [Pinned(FakeWorld.WiFiGuid, description: null)] });
        var coordinator = await StartAsync();

        await ConnectAsync(coordinator);

        Assert.Equal(_world.Inventory.WiFiDescription, coordinator.Settings.Profiles[0].PinnedAdapterDescription);
        Assert.Equal("Беспроводная сеть", coordinator.BuildStatus().PrimaryAdapterName);
    }

    [Fact]
    public async Task PinnedAdapter_WithNewGuid_IsReboundByDescription()
    {
        SaveSettings(Settings() with { Profiles = [Pinned(Guid.NewGuid(), _world.Inventory.WiFiDescription)] });
        var coordinator = await StartAsync();

        await ConnectAsync(coordinator);

        Assert.Equal(FakeWorld.WiFiGuid, coordinator.Settings.Profiles[0].PinnedInterfaceGuid);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
        Assert.DoesNotContain(coordinator.BuildStatus().Warnings, w => w.Code == "pinned-adapter-missing");
    }

    [Fact]
    public async Task PinnedAdapter_Missing_IsExplainedInStatus()
    {
        SaveSettings(Settings() with { Profiles = [Pinned(Guid.NewGuid(), description: null)] });
        var coordinator = await StartAsync();

        await ConnectAsync(coordinator);

        Assert.Null(coordinator.BuildStatus().PrimaryAdapterName);
        Assert.Contains(coordinator.BuildStatus().Warnings, w => w.Code == "pinned-adapter-missing");
    }

    private ConnectionProfile Pinned(Guid guid, string? description) => _profile with
    {
        PrimaryAdapter = AdapterSelection.Pinned,
        PinnedInterfaceGuid = guid,
        PinnedAdapterDescription = description,
    };
}
