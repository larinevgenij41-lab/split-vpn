using SplitVpn.Core.Ipc;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests
{
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
        Assert.Contains("new.example", _world.Proxy.Pinned.Keys);
        Assert.Equal([FakeWorld.SecondServer], coordinator.Facts.Tunnels[_profile.Id].ServerAddresses);
        Assert.Equal([FakeWorld.SecondServer], _world.Proxy.Pinned["new.example"]);
        Assert.Null(_world.Proxy.PinLifetimes["new.example"]);
    }
}
