using System.Windows.Threading;
using SplitVpn.App.Services;
using SplitVpn.App.ViewModels;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Update;

namespace SplitVpn.App.Tests;

/// <summary>
/// Отказ в окне контроля учётных записей при установке обновления: служба узнаёт о нём с конечным сроком и
/// повторами, а пользователь видит причину, даже если служба не ответила.
/// </summary>
public sealed class UpdateInstallReportTests
{
    private const string Refused = "Установка отменена: для обновления нужны права администратора.";

    private static readonly Guid Attempt = Guid.NewGuid();

    /// <summary>Отчёт об отказе не доходит: интерфейс не висит, повторяет его и показывает причину с подсказкой.</summary>
    [Fact]
    public Task Refusal_ServiceSilent_ShowsReasonAfterBoundedRetries() => RunStaAsync(async () =>
    {
        var reports = new List<UpdateStartedRequest>();
        async Task<IpcResponse> Send(IpcRequest request, CancellationToken cancellationToken)
        {
            switch (request)
            {
                case InstallUpdateRequest:
                    return IpcResponse.Success(new UpdateInstallDto("msiexec.exe", "/i x.msi", "9.9.9", "log") { AttemptId = Attempt });
                case UpdateStartedRequest started:
                    reports.Add(started);
                    await Task.Delay(Timeout.Infinite, cancellationToken);
                    throw new InvalidOperationException("не достигается");
                default:
                    return IpcResponse.Failure(IpcErrorCodes.Failed, "нет в тесте");
            }
        }

        var about = CreateAbout(Send, out var service, out var main);
        using (service)
        using (main)
        {
            await about.InstallUpdateCommand.ExecuteAsync(null);

            Assert.Equal(AboutViewModel.RefusalReportAttempts, reports.Count);
            Assert.All(reports, r => Assert.Equal(0, r.ProcessId));
            Assert.All(reports, r => Assert.Equal(Attempt, r.AttemptId));
            Assert.True(about.MessageIsError);
            Assert.StartsWith(Refused, about.Message, StringComparison.Ordinal);
            Assert.Contains(AboutViewModel.RefusalNotReportedText, about.Message, StringComparison.Ordinal);
        }
    });

    /// <summary>Служба ответила со второй попытки: показывается только причина, без подсказки об ожидании.</summary>
    [Fact]
    public Task Refusal_ReportedOnRetry_ShowsReasonOnly() => RunStaAsync(async () =>
    {
        var reports = 0;
        Task<IpcResponse> Send(IpcRequest request, CancellationToken cancellationToken) => request switch
        {
            InstallUpdateRequest => Task.FromResult(IpcResponse.Success(new UpdateInstallDto("msiexec.exe", "/i x.msi", "9.9.9", "log") { AttemptId = Attempt })),
            UpdateStartedRequest when ++reports == 1 => Task.FromResult(IpcResponse.Failure(IpcErrorCodes.Failed, "сбой")),
            UpdateStartedRequest => Task.FromResult(IpcResponse.Success()),
            _ => Task.FromResult(IpcResponse.Failure(IpcErrorCodes.Failed, "нет в тесте")),
        };

        var about = CreateAbout(Send, out var service, out var main);
        using (service)
        using (main)
        {
            await about.InstallUpdateCommand.ExecuteAsync(null);

            Assert.Equal(2, reports);
            Assert.True(about.MessageIsError);
            Assert.Equal(Refused, about.Message);
        }
    });

    private static AboutViewModel CreateAbout(Func<IpcRequest, CancellationToken, Task<IpcResponse>> send,
        out ServiceConnection service, out MainViewModel main)
    {
        service = new ServiceConnection(send);
        main = new MainViewModel(service, new UiPreferences()) { Confirm = (_, _, _) => Task.FromResult(true) };
        main.ApplyTheme = _ => { };
        var about = main.About;
        about.LaunchInstaller = _ => (0, Refused);
        about.ReportTimeout = TimeSpan.FromMilliseconds(50);
        about.ReportPause = TimeSpan.FromMilliseconds(10);
        about.OnStatus(new StatusDto { Update = new UpdateStatusDto { Phase = UpdatePhase.Ready, AvailableVersion = "9.9.9" } });
        return about;
    }

    private static Task RunStaAsync(Func<Task> action)
    {
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            var dispatcher = Dispatcher.CurrentDispatcher;
            SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(dispatcher));
            dispatcher.BeginInvoke(new Action(async () =>
            {
                try { await action(); completion.TrySetResult(); }
                catch (Exception ex) { completion.TrySetException(ex); }
                finally { dispatcher.BeginInvokeShutdown(DispatcherPriority.Background); }
            }));
            Dispatcher.Run();
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        return completion.Task.WaitAsync(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken);
    }
}
