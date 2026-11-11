using System.Windows.Threading;
using SplitVpn.App.Services;
using SplitVpn.App.ViewModels;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;

namespace SplitVpn.App.Tests;

/// <summary>Настоящие модели WPF с изолированным IPC, без службы и записи настроек пользователя.</summary>
public sealed class SettingsSaveTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public Task SavedFieldDoesNotOverwriteAnotherWindow(bool protection) => RunStaAsync(async () =>
    {
        var store = new MemoryService();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        if (protection)
        {
            var page = main.Protection;
            await page.OnOpenedAsync();
            page.LocalAccess = false;
            await page.SaveCommand.ExecuteAsync(null);
            Assert.False(page.Dirty);
            store.Settings = store.Settings with { LocalAccess = true };
            page.LocalDnsServer = "10.0.0.53";
            await page.SaveCommand.ExecuteAsync(null);
            Assert.True(store.Settings.LocalAccess);
        }
        else
        {
            var page = main.Settings;
            await page.OnOpenedAsync();
            page.AutoConnect = !page.AutoConnect;
            await page.SaveCommand.ExecuteAsync(null);
            Assert.False(page.Dirty);
            var external = !page.AutoConnect;
            store.Settings = store.Settings with { AutoConnect = external };
            page.SequentialDial = !page.SequentialDial;
            await page.SaveCommand.ExecuteAsync(null);
            Assert.Equal(external, store.Settings.AutoConnect);
        }
    });

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public Task EditsMadeDuringSaveRemainPending(bool protection) => RunStaAsync(async () =>
    {
        var store = new MemoryService();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        if (protection)
        {
            var page = main.Protection;
            await page.OnOpenedAsync();
            page.LocalDnsServer = "10.0.0.53";
            store.AfterSave = async () => { await Task.Yield(); page.LocalDnsServer = "10.0.0.54"; };
            await page.SaveCommand.ExecuteAsync(null);
            Assert.True(page.Dirty);
            Assert.Equal("10.0.0.53", store.Settings.LocalDnsServer);
            store.AfterSave = null;
            await page.SaveCommand.ExecuteAsync(null);
            Assert.Equal("10.0.0.54", store.Settings.LocalDnsServer);
            Assert.False(page.Dirty);
        }
        else
        {
            var page = main.Settings;
            await page.OnOpenedAsync();
            page.GeoInterval = 3;
            store.AfterSave = async () => { await Task.Yield(); page.GeoInterval = 7; };
            await page.SaveCommand.ExecuteAsync(null);
            Assert.True(page.Dirty);
            Assert.Equal(3, store.Settings.GeoUpdate.IntervalDays);
            store.AfterSave = null;
            await page.SaveCommand.ExecuteAsync(null);
            Assert.Equal(7, store.Settings.GeoUpdate.IntervalDays);
            Assert.False(page.Dirty);
        }
    });

    [Fact]
    public Task ProtectionConfirmationPreservesChangesFromAnotherWindow() => RunStaAsync(async () =>
    {
        var store = new MemoryService();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        await main.Protection.OnOpenedAsync();
        main.Protection.OutageMode = OutageMode.AllowAll;
        var added = new ConnectionProfile { Name = "Новое подключение", Server = "vpn.example", UserName = "user" };
        main.Confirm = async (_, _, _) =>
        {
            await Task.Yield();
            store.Settings = store.Settings with { Profiles = [added] };
            return true;
        };
        await main.Protection.SaveCommand.ExecuteAsync(null);
        Assert.Equal(OutageMode.AllowAll, store.Settings.OutageMode);
        Assert.Equal(added.Id, Assert.Single(store.Settings.Profiles).Id);
    });

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public Task NewPskEditSurvivesSaveCompletion(bool clearKey) => RunStaAsync(async () =>
    {
        var profile = new ConnectionProfile { Name = "L2TP", Server = "vpn.example", UserName = "user", Protocol = VpnProtocol.L2tpIpsec, Role = ProfileRole.Primary };
        var store = new MemoryService { Settings = new AppSettings { Profiles = [profile], DefaultTarget = RouteTarget.Tunnel(profile.Id) } };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        await main.Connections.LoadAsync();
        var item = main.Connections.Selected!;
        item.Security.PreSharedKey = "submitted";
        store.AfterSave = async () =>
        {
            await Task.Yield();
            if (clearKey) { item.Security.ClearPreSharedKey = true; }
            else { item.Security.PreSharedKey = "edited-during-save"; }
        };
        await main.Connections.SaveCommand.ExecuteAsync(null);
        Assert.Equal("submitted", store.LastConnection!.PreSharedKey);
        Assert.True(item.IsDirty);
        Assert.Same(item, main.Connections.Selected);
        if (clearKey) { Assert.True(item.Security.ClearPreSharedKey); }
        else { Assert.Equal("edited-during-save", item.Security.PreSharedKey); }
        store.AfterSave = null;
        await main.Connections.SaveCommand.ExecuteAsync(null);
        Assert.Equal(clearKey ? "" : "edited-during-save", store.LastConnection.PreSharedKey);
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
