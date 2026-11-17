using SplitVpn.Core.Ipc;
using SplitVpn.Core.Update;
using SplitVpn.Service.Coordination;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Код выхода msiexec неизвестен. Мгновенно исчезнувший установщик (1618 и подобные) получает повтор, а тот,
/// что успел поработать и не сменил версию (откат неудачного MSI перезапустил службу, номер процесса занят
/// другой программой), - это неудачная установка с указанием журнала, а не молчаливое повторное предложение.
/// </summary>
public sealed partial class CoordinatorTests
{
    [Fact]
    public async Task VanishedInstaller_AfterServiceRestartDuringInstall_ReportsFailureWithLog()
    {
        var coordinator = await InstallingAsync();
        _world.RunningProcesses.Add(4244);
        var started = coordinator.HandleRequestAsync(new UpdateStartedRequest(4244), CancellationToken.None);
        await PumpAsync(coordinator, started);
        _world.Time.Advance(TimeSpan.FromMinutes(2));
        _world.RunningProcesses.Remove(4244);

        // Откат неудачного MSI вернул прежнюю службу: установщика уже нет, кода нет, версия прежняя.
        var restarted = await StartAsync();
        await PumpAsync(restarted);

        var status = Status(restarted);
        Assert.Equal(UpdatePhase.Failed, status.Phase);
        Assert.Contains("Подробности - в install-0.9.0-", status.LastInstallResult, StringComparison.Ordinal);
        Assert.Contains(_world.Journal.Since(0), e => e.Level == "Ошибка" && e.Text.Contains("результат определить не удалось", StringComparison.Ordinal));
    }

    [Fact]
    public async Task VanishedInstaller_AfterRunningAWhile_ReportsFailure_NotRetryOffer()
    {
        _world.HttpHandler = new UpdateSource(Manifest());
        var installer = new TaskCompletionSource<int?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var coordinator = new Coordinator(_world.Dependencies() with { WaitForProcessAsync = (_, _) => installer.Task });
        await coordinator.StartupAsync(CancellationToken.None);
        await CompleteDialAsync(coordinator);
        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: false), CancellationToken.None);
        await TickAsync(coordinator);
        await PumpAsync(coordinator);
        var install = coordinator.HandleRequestAsync(new InstallUpdateRequest("0.9.0"), CancellationToken.None);
        await PumpAsync(coordinator, install);
        Assert.True((await install).Ok);
        await coordinator.HandleRequestAsync(new UpdateStartedRequest(303), CancellationToken.None);

        // Установщик работал минуту и исчез без кода (номер занят другой программой или процесс не открылся).
        _world.Time.Advance(TimeSpan.FromMinutes(1));
        installer.SetResult(null);
        for (var i = 0; i < 20 && Status(coordinator).Phase == UpdatePhase.Installing; i++)
        {
            await Task.Delay(5, TestContext.Current.CancellationToken);
            await coordinator.DrainAsync();
        }

        Assert.Equal(UpdatePhase.Failed, Status(coordinator).Phase);
        Assert.Contains("Подробности - в", Status(coordinator).LastInstallResult, StringComparison.Ordinal);
    }

    /// <summary>
    /// Установщик исчез сразу (1618 и подобные), но очередь службы дошла до этого только через минуту: срок
    /// считается до исчезновения установщика, сбой не объявляется, и фаза остаётся «Установка».
    /// </summary>
    [Fact]
    public async Task VanishedInstaller_QuickExit_BusyQueue_IsNotReportedAsFailure()
    {
        _world.HttpHandler = new UpdateSource(Manifest());
        var installer = new TaskCompletionSource<int?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var coordinator = new Coordinator(_world.Dependencies() with { WaitForProcessAsync = (_, _) => installer.Task });
        await coordinator.StartupAsync(CancellationToken.None);
        await CompleteDialAsync(coordinator);
        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: false), CancellationToken.None);
        await TickAsync(coordinator);
        await PumpAsync(coordinator);
        var install = coordinator.HandleRequestAsync(new InstallUpdateRequest("0.9.0"), CancellationToken.None);
        await PumpAsync(coordinator, install);
        Assert.True((await install).Ok);
        await coordinator.HandleRequestAsync(new UpdateStartedRequest(303), CancellationToken.None);
        await coordinator.DrainAsync();
        var queued = coordinator.QueuedCount;

        // Установщик исчез через секунду без кода; его итог встал в очередь, а очередь занята ещё минуту.
        _world.Time.Advance(TimeSpan.FromSeconds(1));
        installer.SetResult(null);
        for (var i = 0; i < 200 && coordinator.QueuedCount <= queued; i++)
        {
            await Task.Delay(5, TestContext.Current.CancellationToken);
        }

        Assert.True(coordinator.QueuedCount > queued);
        _world.Time.Advance(TimeSpan.FromMinutes(1));
        await coordinator.DrainAsync();

        Assert.Equal(UpdatePhase.Installing, Status(coordinator).Phase);
        Assert.DoesNotContain(_world.Journal.Since(0), e => e.Level == "Ошибка" && e.Text.Contains("результат определить не удалось", StringComparison.Ordinal));
    }
}
