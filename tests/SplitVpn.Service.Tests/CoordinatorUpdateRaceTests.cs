using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;
using SplitVpn.Core.Update;
using SplitVpn.Service.Coordination;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests
{
    /// <summary>
    /// Файл состояния обновления заблокирован: запрос всё равно завершается, состояние живёт в памяти (иначе
    /// фаза «Загрузка» оставалась бы навсегда), а следующая проверка сохраняет его в файл.
    /// </summary>
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
            Assert.True(response.Ok);
            // Проверка прошла и запустила загрузку: её итог тоже применяется, пока файл заблокирован.
            await PumpAsync(coordinator, check);
            Assert.Equal(UpdatePhase.Ready, Status(coordinator).Phase);
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

    /// <summary>
    /// Круг 3, M16: плановая проверка, начатая до подготовки установки, не затирает фазу «Установка» найденным
    /// выпуском, и итог msiexec после неё применяется.
    /// </summary>
    [Fact]
    public async Task InstallingUpdate_IsNotOverwrittenByCheckStartedBeforeIt()
    {
        var source = new UpdateSource(Manifest());
        var coordinator = await ReadyWithAsync(source);
        using var gate = new ManualResetEventSlim();
        source.Override = HoldManifest(gate);

        var install = coordinator.HandleRequestAsync(new InstallUpdateRequest("0.9.0"), CancellationToken.None);
        await WaitForQueuedUpdateAsync(coordinator);
        _world.Time.Advance(TimeSpan.FromDays(3));
        await coordinator.TickAsync(CancellationToken.None);
        Assert.False(coordinator.UpdateWork.IsCompleted);

        await coordinator.DrainAsync();
        Assert.True((await install).Ok);
        Assert.Equal(UpdatePhase.Installing, Status(coordinator).Phase);

        gate.Set();
        await PumpAsync(coordinator);
        Assert.Equal(UpdatePhase.Installing, Status(coordinator).Phase);

        _world.ProcessExitCodes[4243] = 0;
        var started = coordinator.HandleRequestAsync(new UpdateStartedRequest(4243), CancellationToken.None);
        await PumpAsync(coordinator, started);
        Assert.Equal(UpdatePhase.Idle, Status(coordinator).Phase);
        Assert.Equal("Обновление установлено.", Status(coordinator).LastInstallResult);
    }

    /// <summary>Круг 3, M16: пока идёт проверка, установка не готовится — ответ «занято», фаза прежняя.</summary>
    [Fact]
    public async Task Install_IsBusyWhileCheckIsRunning()
    {
        var source = new UpdateSource(Manifest());
        var coordinator = await ReadyWithAsync(source);
        using var gate = new ManualResetEventSlim();
        source.Override = HoldManifest(gate);
        _world.Time.Advance(TimeSpan.FromDays(3));
        await coordinator.TickAsync(CancellationToken.None);

        var response = await coordinator.HandleRequestAsync(new InstallUpdateRequest("0.9.0"), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.Busy, response.ErrorCode);
        gate.Set();
        await PumpAsync(coordinator);
        Assert.Equal(UpdatePhase.Ready, Status(coordinator).Phase);
    }

    private async Task<Coordinator> ReadyWithAsync(UpdateSource source)
    {
        var coordinator = await UpdatingAsync(source);
        await TickAsync(coordinator);
        await PumpAsync(coordinator);
        Assert.Equal(UpdatePhase.Ready, Status(coordinator).Phase);
        return coordinator;
    }

    /// <summary>
    /// Задерживает ответ с манифестом до сигнала. Плановая проверка идёт на пуле потоков, поэтому ожидание
    /// не блокирует тест; проверка по команде начинается в вызывающем потоке, и с ней этот приём не годится.
    /// </summary>
    private static Func<HttpRequestMessage, HttpResponseMessage?> HoldManifest(ManualResetEventSlim gate) => request =>
    {
        if (request.RequestUri!.AbsoluteUri.EndsWith("update.json", StringComparison.Ordinal))
        {
            gate.Wait(TimeSpan.FromSeconds(10));
        }

        return null;
    };

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
