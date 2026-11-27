using System.Windows.Threading;
using SplitVpn.App.Services;
using SplitVpn.App.ViewModels;
using SplitVpn.App.Views;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;

namespace SplitVpn.App.Tests;

/// <summary>
/// Итерация 9: перечитывание доски, не загруженной при открытии; «Выше»/«Ниже» по выбранной строке; переход до первого
/// показа окна и отложенный запрос фокуса; повторное «Добавить подключение»; «восстановлен» после подавленного «оборвался».
/// </summary>
public sealed class Iteration9AppTests
{
    // ---------- Доска маршрутизации без службы при открытии ----------

    [Fact]
    public Task BoardNotLoadedAtOpenCanBeReloadedAndLoadsWhenServiceReturns() => RunStaAsync(async () =>
    {
        var store = new FakeService { Unavailable = true };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Routing;
        var raised = 0;
        page.PropertyChanged += (_, e) => raised += e.PropertyName == nameof(RoutingViewModel.CanReloadBoard) ? 1 : 0;

        await main.RefreshAsync();
        await page.OnOpenedAsync();

        // Правок нет, но доска пустая: перечитать её можно, добавить группу — нельзя.
        Assert.False(page.Dirty);
        Assert.True(page.CanReloadBoard);
        Assert.False(page.AddGroupCommand.CanExecute(null));

        // Служба появилась: доска догружается сама, кнопка без правок снова недоступна.
        store.Unavailable = false;
        await main.RefreshAsync();
        await WaitUntil(() => page.AddGroupCommand.CanExecute(null));
        Assert.False(page.CanReloadBoard);
        Assert.True(raised > 0);

        // С правками кнопка доступна.
        page.MarkDirty();
        Assert.True(page.CanReloadBoard);
    });

    [Fact]
    public Task BoardWithEditsIsNotReloadedAutomatically() => RunStaAsync(async () =>
    {
        var store = new FakeService { Unavailable = true };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Routing;
        await main.RefreshAsync();
        await page.OnOpenedAsync();
        page.MarkDirty();

        store.Unavailable = false;
        await main.RefreshAsync();
        await Task.Delay(50, TestContext.Current.CancellationToken);

        Assert.True(page.Dirty);
        Assert.False(page.AddGroupCommand.CanExecute(null));
        Assert.True(page.CanReloadBoard);
    });

    [Fact]
    public Task BoardOpenedNeverIsNotLoadedByStatus() => RunStaAsync(async () =>
    {
        var store = new FakeService();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());

        await main.RefreshAsync();
        await Task.Delay(50, TestContext.Current.CancellationToken);

        // Страницу не открывали: опрос состояния доску не грузит.
        Assert.False(main.Routing.AddGroupCommand.CanExecute(null));
    });

    // ---------- «Выше» и «Ниже» по выбранной строке ----------

    [Fact]
    public Task MoveCommandsAreEvaluatedAgainstNewSelection() => RunStaAsync(async () =>
    {
        var store = new FakeService { Settings = new AppSettings { Profiles = [Profile("Первое"), Profile("Второе"), Profile("Третье")] } };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();
        Assert.Same(page.Profiles[0], page.Selected);

        // Доступность, прочитанная в момент уведомления, относится уже к новой строке.
        bool? up = null, down = null;
        page.MoveUpCommand.CanExecuteChanged += (_, _) => up = page.MoveUpCommand.CanExecute(null);
        page.MoveDownCommand.CanExecuteChanged += (_, _) => down = page.MoveDownCommand.CanExecute(null);

        page.Selected = page.Profiles[2];
        Assert.True(up);
        Assert.False(down);

        page.Selected = page.Profiles[0];
        Assert.False(up);
        Assert.True(down);

        // Команда без параметра переставляет выбранную строку.
        var first = page.Profiles[0];
        await page.MoveDownCommand.ExecuteAsync(null);
        Assert.Same(first, page.Profiles[1]);
        Assert.Same(first, page.Selected);
        Assert.Contains(store.Requests, r => r is SetProfileOrderRequest);
    });

    // ---------- Переход до первого показа окна и отложенный фокус ----------

    [Fact]
    public Task NavigationBeforeWindowIsReadyOnlyRecordsThePage() => RunStaAsync(async () =>
    {
        var store = new FakeService();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var requested = new List<PageViewModel>();
        main.NavigationRequested += requested.Add;

        main.OpenNotificationTarget(new AppNotification("Неполное применение", "", NotificationKind.Error, main.Diagnostics));
        Assert.Empty(requested);
        Assert.Same(main.Diagnostics, main.CurrentPage);

        main.NavigationReady = true;
        main.NavigateTo(main.Settings);
        Assert.Same(main.Settings, Assert.Single(requested));
        await Task.CompletedTask;
    });

    [Fact]
    public void FocusRequestKeepsRequestMadeBeforeElementExists()
    {
        var source = new object();

        // Нулевой счётчик — начальное значение, не запрос.
        Assert.False(FocusRequest.IsPendingRequest(source, "Token", 0));
        Assert.False(FocusRequest.IsPendingRequest(source, "Token", null));

        // Счётчик уже сдвинут до появления элемента: первое значение привязки — запрос.
        Assert.True(FocusRequest.IsPendingRequest(source, "Token", 1));
        FocusRequest.Remember(source, "Token", 1);

        // Пересозданный элемент по тому же обслуженному значению фокус не забирает, по новому — забирает.
        Assert.False(FocusRequest.IsPendingRequest(source, "Token", 1));
        Assert.True(FocusRequest.IsPendingRequest(source, "Token", 2));
        Assert.True(FocusRequest.IsPendingRequest(source, "Other", 1));

        // Источник неизвестен — как раньше, первое значение не запрос.
        Assert.False(FocusRequest.IsPendingRequest(null, "Token", 3));
    }

    // ---------- «Добавить подключение» с главной ----------

    [Fact]
    public Task RepeatedAddFromHomeOpensTheSameDraft() => RunStaAsync(async () =>
    {
        var store = new FakeService();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences()) { ServiceAvailable = true };
        var home = main.Home;
        await main.RefreshAsync();
        await home.OnOpenedAsync();
        Assert.Equal(HomeSetupAction.AddConnection, home.SetupAction);
        var focus = main.Connections.EditorFocusToken;

        await home.PrimaryActionCommand.ExecuteAsync(null);
        await WaitUntil(() => main.Connections.Loaded);
        var draft = Assert.Single(main.Connections.Profiles, p => p.IsNew);

        // Пользователь ушёл на главную, выбрал другое и снова нажал «Добавить подключение».
        main.NavigateTo(main.Home);
        main.Connections.Selected = null;
        await home.PrimaryActionCommand.ExecuteAsync(null);
        await Task.Delay(50, TestContext.Current.CancellationToken);

        Assert.Same(draft, Assert.Single(main.Connections.Profiles, p => p.IsNew));
        Assert.Same(draft, main.Connections.Selected);
        Assert.Same(main.Connections, main.CurrentPage);
        Assert.Equal(focus + 2, main.Connections.EditorFocusToken);
    });

    // ---------- Уведомления об обрыве ----------

    [Fact]
    public Task SuppressedOutageNoticeStillLeadsToRestoredNotice() => RunStaAsync(async () =>
    {
        var store = new FakeService();
        var time = new ManualTime();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences(), time);
        var shown = new List<string>();
        main.Notify += n => shown.Add(n.Title);

        async Task Status(ConnectionState state, int seconds)
        {
            store.Status = new StatusDto { State = state, Intent = Intent.Connected, ProfileName = "Основное" };
            time.Now = DateTimeOffset.UnixEpoch.AddHours(1).AddSeconds(seconds);
            await main.RefreshAsync();
        }

        await Status(ConnectionState.Connected, 0);
        await Status(ConnectionState.Reconnecting, 1);
        await Status(ConnectionState.Reconnecting, 32);
        await Status(ConnectionState.Connected, 40);
        Assert.Equal(new[] { "VPN оборвался", "VPN восстановлен" }, shown);

        // Второй долгий обрыв: после показанного «восстановлен» «оборвался» снова новость (ревью 27.11), а повтор
        // «восстановлен» подавлен пределом (прошло меньше 5 минут) — последним остаётся «оборвался».
        await Status(ConnectionState.Reconnecting, 50);
        await Status(ConnectionState.Reconnecting, 81);
        await Status(ConnectionState.Connected, 90);
        Assert.Equal(new[] { "VPN оборвался", "VPN восстановлен", "VPN оборвался" }, shown);

        // Третий долгий обрыв: «оборвался» подавлен пределом повторов (восстановления между ними показано не было), но
        // восстановление после него — «восстановлен», а не «ненадолго прерывалась».
        await Status(ConnectionState.Reconnecting, 300);
        await Status(ConnectionState.Reconnecting, 331);
        Assert.Equal(3, shown.Count);
        await Status(ConnectionState.Connected, 345);
        Assert.Equal(new[] { "VPN оборвался", "VPN восстановлен", "VPN оборвался", "VPN восстановлен" }, shown);
    });

    // ---------- Вспомогательное ----------

    private static ConnectionProfile Profile(string name) =>
        new() { Name = name, Server = "vpn.example", UserName = "user", Role = ProfileRole.Off };

    private static async Task WaitUntil(Func<bool> condition)
    {
        for (var i = 0; i < 200 && !condition(); i++)
        {
            await Task.Delay(10, TestContext.Current.CancellationToken);
        }

        Assert.True(condition());
    }

    private sealed class ManualTime : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UnixEpoch;

        public override DateTimeOffset GetUtcNow() => Now;
    }

    /// <summary>Подставная служба: настройки и состояние в памяти, все запросы записываются.</summary>
    private sealed class FakeService
    {
        public AppSettings Settings { get; set; } = new();

        public StatusDto Status { get; set; } = new() { Intent = Intent.Off };

        public bool Unavailable { get; set; }

        public List<IpcRequest> Requests { get; } = [];

        public Task<IpcResponse> SendAsync(IpcRequest request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            if (Unavailable)
            {
                throw new ServiceUnavailableException("Служба не запущена.");
            }

            return Task.FromResult(request switch
            {
                GetSettingsRequest => IpcResponse.Success(Settings),
                GetAdaptersRequest => IpcResponse.Success(new List<AdapterDto>()),
                GetStatusRequest => IpcResponse.Success(Status),
                GetEventsRequest => IpcResponse.Success(new List<ServiceEvent>()),
                SaveSettingsRequest save => Save(save.Settings),
                _ => IpcResponse.Success(),
            });
        }

        private IpcResponse Save(AppSettings settings)
        {
            Settings = settings;
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
