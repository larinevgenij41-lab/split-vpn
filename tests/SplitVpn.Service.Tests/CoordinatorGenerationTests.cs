using SplitVpn.Core.Ipc;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests
{
    [Fact]
    public async Task RecreatedProfile_DoesNotReuseAttemptGenerations()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var previous = coordinator.Facts.Tunnels[_profile.Id];
        var oldDial = previous.DialGeneration;
        var oldVerify = previous.VerifyGeneration;
        var settings = coordinator.Settings;
        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: true), CancellationToken.None);
        var disabled = settings with { Profiles = [_profile with { Role = ProfileRole.Off }], DefaultTarget = RouteTarget.Direct };
        Assert.True((await coordinator.HandleRequestAsync(new SaveSettingsRequest(disabled), CancellationToken.None)).Ok);
        Assert.DoesNotContain(_profile.Id, coordinator.Facts.Tunnels.Keys);
        Assert.True((await coordinator.HandleRequestAsync(new SaveSettingsRequest(settings), CancellationToken.None)).Ok);

        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _world.Probes.Gate = gate;
        try
        {
            await coordinator.HandleRequestAsync(new ConnectRequest(null, null), CancellationToken.None);
            var current = coordinator.Facts.Tunnels[_profile.Id];
            await WaitForVerifyingAsync(coordinator, current);
            Assert.True(current.Verifying);
            Assert.NotSame(previous, current);
            Assert.NotEqual(oldDial, current.DialGeneration);
            Assert.NotEqual(oldVerify, current.VerifyGeneration);

            await coordinator.OnVerifyFinishedAsync(_profile.Id, oldVerify, foreign: true, russianOk: true, CancellationToken.None);

            Assert.True(current.Verifying);
            Assert.False(current.Verified);
        }
        finally
        {
            gate.TrySetResult();
            await CompleteDialAsync(coordinator);
        }
    }

    [Fact]
    public async Task StaleVerification_DoesNotClearTheCurrentProbe()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        tunnel.Verified = false;
        tunnel.Verifying = true;
        var current = ++tunnel.VerifyGeneration;

        await coordinator.OnVerifyFinishedAsync(_profile.Id, current - 1, foreign: true, russianOk: true, CancellationToken.None);

        Assert.True(tunnel.Verifying);
        Assert.False(tunnel.Verified);
        Assert.Equal(0, tunnel.VerifyProbeFailures);
    }

    [Fact]
    public async Task StaleDial_DoesNotClearOrSettleTheCurrentAttempt()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        tunnel.Dialing = true;
        tunnel.DialSettled = false;
        var current = ++tunnel.DialGeneration;

        await coordinator.OnDialFinishedAsync(_profile.Id, new RasDialResult(false, null, 809, "старый отказ"), current - 1, CancellationToken.None);

        Assert.True(tunnel.Dialing);
        Assert.False(tunnel.DialSettled);
        Assert.Null(tunnel.LastErrorText);
    }

    [Fact]
    public async Task Pause_InvalidatesAnOutstandingProbe()
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _world.Probes.Gate = gate;
        var coordinator = await StartAsync();
        await coordinator.HandleRequestAsync(new ConnectRequest(null, null), CancellationToken.None);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        try
        {
            await WaitForVerifyingAsync(coordinator, tunnel);
            Assert.True(tunnel.Verifying);
            var old = tunnel.VerifyGeneration;

            await PauseAsync(coordinator, _profile.Id, paused: true);

            Assert.False(tunnel.Verifying);
            Assert.NotEqual(old, tunnel.VerifyGeneration);
            Assert.False(tunnel.Verified);
        }
        finally
        {
            gate.TrySetResult();
            await CompleteDialAsync(coordinator);
        }
    }
}
