using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;
using SplitVpn.Core.Update;
using SplitVpn.Service.Coordination;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests
{
    [Fact]
    public async Task UpdateStateWriteFailure_CompletesTheRequestAndAllowsRetry()
    {
        var coordinator = await UpdatingAsync(new UpdateSource(Manifest()));
        var check = coordinator.HandleRequestAsync(new CheckUpdateRequest(), CancellationToken.None);
        await WaitForQueuedUpdateAsync(coordinator);
        using (var locked = new FileStream(Path.Combine(_world.Paths.Update, "state.json"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
        {
            // В рабочем цикле исключение перехватывает RunWorkAsync; здесь очередь разбирается тестом.
            _ = await Record.ExceptionAsync(coordinator.DrainAsync);
            var response = await check.WaitAsync(TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
            Assert.False(response.Ok);
            await coordinator.UpdateWork.WaitAsync(TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        }

        var retry = coordinator.HandleRequestAsync(new CheckUpdateRequest(), CancellationToken.None);
        await PumpAsync(coordinator, retry);
        Assert.True((await retry).Ok);
        Assert.Equal(UpdatePhase.Ready, Status(coordinator).Phase);
    }

    private static async Task WaitForQueuedUpdateAsync(Coordinator coordinator)
    {
        for (var i = 0; i < 600 && coordinator.QueuedCount == 0; i++)
        {
            await Task.Delay(5);
        }

        Assert.True(coordinator.QueuedCount > 0, "Обновление не вернулось в очередь.");
    }

    [Fact]
    public async Task SkippedUpdate_LateDownloadDoesNotRestoreReadyState()
    {
        SaveSettings(Settings() with { AppUpdate = new AppUpdateSettings { AutoDownload = false } });
        var coordinator = await UpdatingAsync(new UpdateSource(Manifest()));
        var check = coordinator.HandleRequestAsync(new CheckUpdateRequest(), CancellationToken.None);
        await PumpAsync(coordinator, check);
        Assert.Equal(UpdatePhase.Available, Status(coordinator).Phase);

        await coordinator.HandleRequestAsync(new DownloadUpdateRequest("0.9.0"), CancellationToken.None);
        await WaitForQueuedUpdateAsync(coordinator);
        Assert.True((await coordinator.HandleRequestAsync(new SkipUpdateRequest("0.9.0"), CancellationToken.None)).Ok);
        await PumpAsync(coordinator);

        Assert.Equal(UpdatePhase.Idle, Status(coordinator).Phase);
        Assert.Null(Status(coordinator).AvailableVersion);
        Assert.Equal("0.9.0", Status(coordinator).SkippedVersion);
        Assert.False(File.Exists(Path.Combine(_world.Paths.Update, "SplitVpn-0.9.0.msi")));
    }

    [Fact]
    public async Task SkippedUpdate_LateHashCheckDoesNotAuthorizeInstallation()
    {
        var coordinator = await ReadyAsync();
        var install = coordinator.HandleRequestAsync(new InstallUpdateRequest("0.9.0"), CancellationToken.None);
        await WaitForQueuedUpdateAsync(coordinator);

        await coordinator.HandleRequestAsync(new SkipUpdateRequest("0.9.0"), CancellationToken.None);
        await PumpAsync(coordinator, install);

        Assert.False((await install).Ok);
        Assert.Equal(UpdatePhase.Idle, Status(coordinator).Phase);
    }

    [Fact]
    public async Task InstallingUpdate_CannotBeSkippedAndDeleteItsPackage()
    {
        var coordinator = await InstallingAsync();

        var response = await coordinator.HandleRequestAsync(new SkipUpdateRequest("0.9.0"), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.Busy, response.ErrorCode);
        Assert.Equal(UpdatePhase.Installing, Status(coordinator).Phase);
        Assert.True(File.Exists(Path.Combine(_world.Paths.Update, "SplitVpn-0.9.0.msi")));
    }
}
