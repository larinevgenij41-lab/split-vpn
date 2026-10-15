using SplitVpn.Core.Ipc;
using SplitVpn.Service.Coordination;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests
{
    [Fact]
    public async Task ServerDns_ThreeFailedDialsRefreshTheSuccessfulCacheEarly()
    {
        SaveSettings(Settings() with { Profiles = [_profile with { Server = "vpn.example" }] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var calls = _world.Resolver.Calls;
        coordinator.Facts.Tunnels[_profile.Id].FailedDialsSinceResolve = 3;

        await coordinator.ReconcileAsync(CancellationToken.None);
        await CompleteDialAsync(coordinator);

        Assert.Equal(calls + 1, _world.Resolver.Calls);
        Assert.Equal(0, coordinator.Facts.Tunnels[_profile.Id].FailedDialsSinceResolve);
    }

    [Fact]
    public async Task ServerDns_EmptyRefreshRetainsCachedAddressesAndRetriesAfterTenSeconds()
    {
        SaveSettings(Settings() with { Profiles = [_profile with { Server = "vpn.example" }] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        _world.Resolver.Answer = [];
        _world.Time.Advance(TimeSpan.FromHours(1));
        await coordinator.ReconcileAsync(CancellationToken.None);
        await CompleteDialAsync(coordinator);
        var calls = _world.Resolver.Calls;
        Assert.Equal([FakeWorld.Server], coordinator.Facts.Tunnels[_profile.Id].ServerAddresses);
        await coordinator.ReconcileAsync(CancellationToken.None);
        Assert.Equal(calls, _world.Resolver.Calls);

        _world.Time.Advance(TimeSpan.FromSeconds(10));
        await coordinator.ReconcileAsync(CancellationToken.None);
        await CompleteDialAsync(coordinator);
        Assert.Equal(calls + 1, _world.Resolver.Calls);
    }

    [Fact]
    public async Task SequentialDial_EmptyServerDnsDoesNotHoldTheNextProfile()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with { Profiles = [_profile with { Server = "missing.example" }, second], SequentialDial = true });
        _world.Resolver.Answer = [];
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        Assert.Contains(Coordinator.EntryNameFor(second), _world.Ras.ConnectedEntries);
        Assert.DoesNotContain(Coordinator.EntryNameFor(_profile), _world.Ras.ConnectedEntries);
    }

    [Fact]
    public async Task ChangedServer_RemovesTheOldPermanentDnsPin()
    {
        SaveSettings(Settings() with { Profiles = [_profile with { Server = "old.example:4443" }] });
        _world.Resolver.Answers["new.example"] = [FakeWorld.SecondServer];
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.Contains("old.example", _world.Proxy.Pinned.Keys);
        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: true), CancellationToken.None);

        var changed = coordinator.Settings with { Profiles = [_profile with { Server = "new.example:4443" }] };
        var response = await coordinator.HandleRequestAsync(new SaveSettingsRequest(changed), CancellationToken.None);

        Assert.True(response.Ok);
        Assert.DoesNotContain("old.example", _world.Proxy.Pinned.Keys);
        await CompleteDialAsync(coordinator);
        Assert.Contains("new.example", _world.Proxy.Pinned.Keys);
        Assert.Equal([FakeWorld.SecondServer], coordinator.Facts.Tunnels[_profile.Id].ServerAddresses);
        Assert.Equal([FakeWorld.SecondServer], _world.Proxy.Pinned["new.example"]);
        Assert.Null(_world.Proxy.PinLifetimes["new.example"]);
    }
}
