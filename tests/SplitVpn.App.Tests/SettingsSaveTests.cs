using System.IO;
using System.Windows.Threading;
using SplitVpn.Core.Diagnostics;
using SplitVpn.App.Services;
using SplitVpn.App.ViewModels;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;

namespace SplitVpn.App.Tests;

/// <summary>Настоящие модели WPF с изолированным IPC, без службы и записи настроек пользователя.</summary>
public sealed partial class SettingsSaveTests
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

    [Fact]
    public Task AmbiguousCreateCannotBeDiscardedOffline() => RunStaAsync(async () =>
    {
        var online = true;
        Task<IpcResponse> Send(IpcRequest request, CancellationToken token)
        {
            if (request is SaveConnectionRequest) { online = false; }
            if (!online) { throw new ServiceUnavailableException("Нет связи."); }
            return Task.FromResult(request is GetAdaptersRequest ? IpcResponse.Success(new List<AdapterDto>()) : IpcResponse.Success(new AppSettings()));
        }

        using var service = new ServiceConnection(Send);
        using var main = new MainViewModel(service, new UiPreferences());
        var editor = main.Connections;
        await editor.LoadAsync();
        editor.AddCommand.Execute(null);
        var item = editor.Selected!;
        item.Server = "vpn.example";
        item.UserName = "user";
        await editor.SaveCommand.ExecuteAsync(null);
        Assert.True(item.SaveAttempted);
        await editor.DeleteCommand.ExecuteAsync(null);
        Assert.Same(item, Assert.Single(editor.Profiles));
        Assert.True(editor.MessageIsError);
    });

    [Fact]
    public Task MirrorsPreservePunctuationAndChangesAffectOnlyGeoMetering() => RunStaAsync(async () =>
    {
        var store = new MemoryService();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Settings;
        await page.OnOpenedAsync();
        var metered = !page.DeferOnMetered;
        string[] mirrors = ["https://mirror.example/list;a,b", "https://mirror.example/other"];
        page.GeoMirrors = string.Join(Environment.NewLine, mirrors);
        page.DeferOnMetered = metered;
        var before = store.Settings;
        await page.SaveCommand.ExecuteAsync(null);
        Assert.Equal(mirrors, store.Settings.GeoUpdate.Mirrors);
        Assert.Equal(metered, store.Settings.GeoUpdate.DeferOnMetered);
        Assert.Equal(before.AppUpdate.DeferOnMetered, store.Settings.AppUpdate.DeferOnMetered);
        Assert.Equal(before.BypassUpdate.DeferOnMetered, store.Settings.BypassUpdate.DeferOnMetered);
    });

    [Fact]
    public Task RouteBoardRejectsEquivalentPrefixAndRetainsColumnDraft() => RunStaAsync(async () =>
    {
        var store = new MemoryService();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Routing;
        await page.OnOpenedAsync();
        var direct = page.Columns.Single(c => c.Target == RouteTarget.Direct);
        direct.NewValue = "192.0.2.0/24";
        direct.AddCommand.Execute(null);
        var blocked = page.Columns.Single(c => c.Target == RouteTarget.Blocked);
        blocked.NewValue = "192.0.2.0/024";
        blocked.AddCommand.Execute(null);
        Assert.True(page.MessageIsError);
        page.AddGroupCommand.Execute(null);
        Assert.Equal("192.0.2.0/024", page.Columns.Single(c => c.Target == RouteTarget.Blocked).NewValue);
    });

    [Fact]
    public async Task GatewayProxyIsRestoredOnlyByLastSession()
    {
        var directory = Directory.CreateTempSubdirectory("SplitVpn.ProxyTest.");
        try
        {
            const string gateway = "https://gateway.example/proxy.pac";
            var proxy = new MemoryProxy();
            var initial = proxy.Read();
            var status = new StatusDto { Tunnels = [new TunnelStatusDto { State = SplitVpn.Core.State.ConnectionState.Connected, ServerNetworks = new ServerNetworksDto { ApplyProxy = true, ProxyPac = gateway } }] };
            using var first = new ProxyService(proxy, directory.FullName);
            using var second = new ProxyService(proxy, directory.FullName);
            Assert.Null(await first.UpdateAsync(status, false));
            Assert.Null(await second.UpdateAsync(status, false));
            first.Dispose();
            Assert.True(proxy.Read().Uses(gateway));
            second.Dispose();
            Assert.Equal(initial, proxy.Read());
        }
        finally { directory.Delete(recursive: true); }
    }

    private sealed class MemoryProxy : IProxySettings
    {
        private ProxyState _state = new(1, null);
        public ProxyState Read() => _state;
        public void Write(ProxyState state) => _state = state;
    }

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

    /// <summary>Ключ сервера SSH нужного вида (ssh-ed25519) с произвольным содержимым.</summary>
    private static string Ed25519HostKey()
    {
        var name = "ssh-ed25519"u8.ToArray();
        var blob = new byte[4 + name.Length + 4 + 32];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(blob, (uint)name.Length);
        name.CopyTo(blob, 4);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(blob.AsSpan(4 + name.Length), 32);
        blob.AsSpan(8 + name.Length).Fill(7);
        return "ssh-ed25519 " + Convert.ToBase64String(blob);
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
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public Task ConcurrentProfileChangePreservesRemoteServerOrDeletion(bool deleted) => RunStaAsync(async () =>
    {
        // Ключ сервера задан: форма проверяет профиль SSH так же, как служба, и без ключа не отправила бы его.
        var profile = new ConnectionProfile { Name = "SSH", Protocol = VpnProtocol.SshVpn, AuthMethod = AuthMethod.SshKey, Server = "old.example", UserName = "admin", Role = ProfileRole.Primary,
            SshVpn = new SshVpnSettings { HostKey = Ed25519HostKey() } };
        var store = new MemoryService { Settings = new AppSettings { Profiles = [profile], DefaultTarget = RouteTarget.Tunnel(profile.Id) } };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var editor = main.Connections;
        await editor.LoadAsync();
        editor.Selected!.Name = "Другое имя";
        store.Settings = store.Settings with { Profiles = deleted ? [] : [profile with { Server = "new.example" }] };
        var revision = SettingsSerializer.Revision(store.Settings);
        await editor.SaveCommand.ExecuteAsync(null);
        if (deleted)
        {
            Assert.Empty(store.Settings.Profiles);
            Assert.Null(store.LastConnection);
            Assert.True(editor.MessageIsError);
        }
        else
        {
            Assert.Equal("new.example", Assert.Single(store.Settings.Profiles).Server);
            Assert.Equal(revision, store.LastConnection?.ExpectedRevision);
        }
    });
}
