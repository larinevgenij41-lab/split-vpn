using System.ServiceProcess;
using SplitVpn.Service.Coordination;
using SplitVpn.Service.Diagnostics;

namespace SplitVpn.Service.Tests;

/// <summary>Пробуждение после сна: соединения проверяются сразу, даже если Windows не сообщила о смене сети.</summary>
public sealed partial class CoordinatorTests
{
    [Fact]
    public async Task SystemResume_RechecksTunnelsWithoutNetworkNotification()
    {
        var coordinator = await StartWithSshAsync();
        await RaiseSshAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_ssh.Id];
        var link = tunnel.Ssh!;
        var later = _world.Time.GetUtcNow() + TimeSpan.FromMinutes(10);
        link.NextHealthAt = later;
        tunnel.NextLinkWatchAt = later;
        var path = link.PathGeneration;

        // Обычный тик срока проверки SSH не трогает.
        await TickAsync(coordinator);
        Assert.Equal(path, link.PathGeneration);
        Assert.Equal(later, link.NextHealthAt);

        coordinator.OnSystemResumed();
        _world.Time.Advance(Coordinator.NetworkChangeDebounce);
        await CompleteDialAsync(coordinator);

        // Контроль SSH — внеочередной (новое поколение пути, срок не ждётся), сеанс RAS проверяется без своего срока.
        Assert.True(link.PathGeneration > path);
        Assert.NotEqual(later, link.NextHealthAt);
        Assert.Equal(default, tunnel.NextLinkWatchAt);
    }

    [Theory]
    [InlineData(PowerBroadcastStatus.ResumeAutomatic, true)]
    [InlineData(PowerBroadcastStatus.ResumeCritical, true)]
    [InlineData(PowerBroadcastStatus.ResumeSuspend, false)]
    [InlineData(PowerBroadcastStatus.Suspend, false)]
    [InlineData(PowerBroadcastStatus.PowerStatusChange, false)]
    public void PowerEvent_OnlyResumeTriggersRecheck(PowerBroadcastStatus status, bool expected) =>
        Assert.Equal(expected, SessionAwareLifetime.IsResume(status));
}
