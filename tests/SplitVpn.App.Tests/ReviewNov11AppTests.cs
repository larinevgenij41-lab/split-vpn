using System.Windows.Threading;
using SplitVpn.App.Services;
using SplitVpn.App.ViewModels;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
namespace SplitVpn.App.Tests;
public sealed class ReviewNov11AppTests
{
    [Fact]
    public Task OldPollMustNotOverwriteCompletedDisconnect() => RunStaAsync(async () =>
    {
        var oldPoll = new TaskCompletionSource<IpcResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        var disconnected = new StatusDto { State = ConnectionState.Disconnected, Intent = Intent.Off };
        var polls = 0;
        using var service = new ServiceConnection((r, _) => r is GetStatusRequest && ++polls == 1 ? oldPoll.Task : Task.FromResult(IpcResponse.Success(disconnected)));
        using var main = new MainViewModel(service, new UiPreferences());
        var polling = main.RefreshAsync();
        await main.RunCommandAsync(new DisconnectRequest(false));
        Assert.Equal(Intent.Off, main.Status!.Intent);
        oldPoll.SetResult(IpcResponse.Success(new StatusDto { State = ConnectionState.Connected, Intent = Intent.Connected }));
        await polling;
        Assert.Equal(Intent.Off, main.Status.Intent);
        Assert.Equal(2, polls);
    });

    [Fact]
    public Task RoutingSaveMustNotAdoptUnseenExternalBaseline() => RunStaAsync(async () =>
    {
        var store = new MemoryService();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Routing;
        await page.OnOpenedAsync();
        var direct = page.Columns.Single(c => c.Target == RouteTarget.Direct);
        direct.NewValue = "203.0.113.0/24";
        direct.AddCommand.Execute(null);
        store.AfterSave = () => { store.Settings = store.Settings with { DefaultTarget = RouteTarget.Blocked }; return Task.CompletedTask; };
        await page.SaveCommand.ExecuteAsync(null);
        store.AfterSave = null;
        direct.NewValue = "198.51.100.0/24";
        direct.AddCommand.Execute(null);
        await page.SaveCommand.ExecuteAsync(null);
        Assert.Equal(RouteTarget.Blocked, store.Settings.DefaultTarget);
    });
    private sealed class MemoryService
    {
        public AppSettings Settings { get; set; } = new();
        public Func<Task>? AfterSave { get; set; }
        public SaveConnectionRequest? LastConnection { get; private set; }
        public async Task<IpcResponse> SendAsync(IpcRequest request, CancellationToken cancellationToken)
        {
            switch (request)
            {
                case GetSettingsRequest: return IpcResponse.Success(Settings);
                case GetAdaptersRequest: return IpcResponse.Success(new List<AdapterDto>());
                case SaveSettingsRequest save: Settings = save.Settings; break;
                case SaveConnectionRequest save: Settings = save.Settings; LastConnection = save; break;
                default: throw new InvalidOperationException("Неожиданный запрос " + request.GetType().Name);
            }

            if (AfterSave is { } after) { await after(); }
            return IpcResponse.Success();
        }
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
        return completion.Task.WaitAsync(TimeSpan.FromSeconds(15), TestContext.Current.CancellationToken);
    }
}
