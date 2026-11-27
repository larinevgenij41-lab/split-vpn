using System.Windows.Threading;
using SplitVpn.App.Services;
using SplitVpn.App.ViewModels;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;

namespace SplitVpn.App.Tests;

/// <summary>
/// Пустые состояния по снимкам самопроверки 25.11: подсказка главной кнопки только по полученному от службы списку
/// подключений, доступность кнопок под пустым списком «Подключений».
/// </summary>
public sealed class ReviewNov25EmptyStateTests
{
    // ---------- Главная: «Добавить подключение» только по полученным настройкам ----------

    [Fact]
    public Task HomeWithoutServiceShowsPlainConnectButton() => RunStaAsync(async () =>
    {
        var store = new FakeService { Unavailable = true };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var home = main.Home;

        await home.OnOpenedAsync();
        await main.RefreshAsync();

        Assert.False(main.ServiceAvailable);
        Assert.Equal(HomeSetupAction.None, home.SetupAction);
        Assert.Equal("Подключить", home.ButtonText);
        Assert.Null(home.SetupHint);
    });

    [Fact]
    public Task HomeForgetsConnectionListWhenServiceIsLost() => RunStaAsync(async () =>
    {
        var store = new FakeService();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var home = main.Home;
        await main.RefreshAsync();
        await home.OnOpenedAsync();
        Assert.Equal("Добавить подключение", home.ButtonText);

        // Служба пропала: пустой список больше не ответ службы, подсказки нет.
        store.Unavailable = true;
        await main.RefreshAsync();
        Assert.False(main.ServiceAvailable);
        Assert.Equal(HomeSetupAction.None, home.SetupAction);
        Assert.Equal("Подключить", home.ButtonText);
        Assert.Null(home.SetupHint);

        // Служба вернулась, а список ещё не прочитан: до ответа кнопка обычная, после — снова подсказка.
        var reply = new TaskCompletionSource<IpcResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        store.Unavailable = false;
        store.Override = request => request is GetSettingsRequest ? reply.Task : null;
        var before = store.Requests.OfType<GetSettingsRequest>().Count();
        await main.RefreshAsync();
        Assert.True(main.ServiceAvailable);
        Assert.Equal(HomeSetupAction.None, home.SetupAction);
        Assert.Equal("Подключить", home.ButtonText);
        Assert.Null(home.SetupHint);

        // Следующий опрос до ответа не отправляет второй запрос.
        await main.RefreshAsync();
        Assert.Equal(before + 1, store.Requests.OfType<GetSettingsRequest>().Count());

        reply.SetResult(IpcResponse.Success(new AppSettings()));
        await WaitUntil(() => home.SetupAction == HomeSetupAction.AddConnection);
        Assert.Equal("Добавить подключение", home.ButtonText);
        Assert.NotNull(home.SetupHint);
    });

    [Fact]
    public Task HomeStatusBeforeSettingsKeepsPlainButton() => RunStaAsync(async () =>
    {
        // Служба отвечает на опрос состояния, но настройки не отдаёт: список подключений не получен.
        var store = new FakeService();
        store.Override = request => request is GetSettingsRequest
            ? Task.FromResult(IpcResponse.Failure(IpcErrorCodes.Failed, "Настройки недоступны."))
            : null;
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences()) { ServiceAvailable = true };
        var home = main.Home;

        await home.OnOpenedAsync();
        await main.RefreshAsync();
        await main.RefreshAsync();

        Assert.True(main.ServiceAvailable);
        Assert.Equal(HomeSetupAction.None, home.SetupAction);
        Assert.Equal("Подключить", home.ButtonText);
        Assert.Null(home.SetupHint);
    });

    [Fact]
    public Task HomeWithoutConnectionsOffersToAddOne() => RunStaAsync(async () =>
    {
        var store = new FakeService();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences()) { ServiceAvailable = true };
        var home = main.Home;
        // Первый опрос — до ответа на чтение настроек: список подключений ещё не получен.
        var reply = new TaskCompletionSource<IpcResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        store.Override = request => request is GetSettingsRequest ? reply.Task : null;
        await main.RefreshAsync();
        Assert.Equal("Подключить", home.ButtonText);
        Assert.Null(home.SetupHint);

        store.Override = null;
        await home.OnOpenedAsync();

        // Подсказка и надпись кнопки меняются вместе — и по открытию главной, без ожидания следующего опроса.
        Assert.Equal(HomeSetupAction.AddConnection, home.SetupAction);
        Assert.Equal("Добавить подключение", home.ButtonText);
        Assert.StartsWith("Подключений пока нет", home.SetupHint, StringComparison.Ordinal);
    });

    [Fact]
    public Task HomeWithOnlyDisabledConnectionsOpensConnections() => RunStaAsync(async () =>
    {
        var store = new FakeService { Settings = new AppSettings { Profiles = [Profile("Запасное", ProfileRole.Off)] } };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences()) { ServiceAvailable = true };
        var home = main.Home;
        await home.OnOpenedAsync();
        home.OnStatus(new StatusDto { Intent = Intent.Off });

        Assert.Equal(HomeSetupAction.OpenConnections, home.SetupAction);
        Assert.Equal("Открыть «Подключения»", home.ButtonText);
        Assert.StartsWith("Все подключения выключены", home.SetupHint, StringComparison.Ordinal);
    });

    [Fact]
    public Task HomeWithEnabledConnectionShowsPlainButton() => RunStaAsync(async () =>
    {
        var store = new FakeService { Settings = new AppSettings { Profiles = [Profile("Запасное", ProfileRole.Off), Profile("Основное", ProfileRole.Primary)] } };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences()) { ServiceAvailable = true };
        var home = main.Home;
        await home.OnOpenedAsync();
        home.OnStatus(new StatusDto { Intent = Intent.Off });

        Assert.Equal(HomeSetupAction.None, home.SetupAction);
        Assert.Equal("Подключить", home.ButtonText);
        Assert.Null(home.SetupHint);
    });

    // ---------- «Подключения»: кнопки под списком ----------

    [Fact]
    public Task EmptyConnectionListAllowsOnlyAddAndImport() => RunStaAsync(async () =>
    {
        var store = new FakeService();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();

        Assert.Empty(page.Profiles);
        Assert.False(page.MoveUpCommand.CanExecute(null));
        Assert.False(page.MoveDownCommand.CanExecute(null));
        Assert.False(page.CopyCommand.CanExecute(null));
        Assert.False(page.DeleteCommand.CanExecute(null));
        Assert.False(page.ExportCommand.CanExecute(null));
        Assert.True(page.AddCommand.CanExecute(null));
        Assert.True(page.ImportCommand.CanExecute(null));
    });

    [Fact]
    public Task ListCommandsFollowSelectionAndEdges() => RunStaAsync(async () =>
    {
        var store = new FakeService { Settings = new AppSettings { Profiles = [Profile("Первое", ProfileRole.Primary), Profile("Второе", ProfileRole.Off), Profile("Третье", ProfileRole.Off)] } };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();
        var changed = new HashSet<string>();
        page.MoveUpCommand.CanExecuteChanged += (_, _) => changed.Add("up");
        page.CopyCommand.CanExecuteChanged += (_, _) => changed.Add("copy");
        page.DeleteCommand.CanExecuteChanged += (_, _) => changed.Add("delete");

        // Первая строка: выше некуда.
        Assert.Same(page.Profiles[0], page.Selected);
        Assert.False(page.MoveUpCommand.CanExecute(null));
        Assert.True(page.MoveDownCommand.CanExecute(null));
        Assert.True(page.CopyCommand.CanExecute(null));
        Assert.True(page.DeleteCommand.CanExecute(null));
        Assert.True(page.ExportCommand.CanExecute(null));

        page.Selected = page.Profiles[1];
        Assert.True(page.MoveUpCommand.CanExecute(null));
        Assert.True(page.MoveDownCommand.CanExecute(null));

        // Последняя строка: ниже некуда.
        page.Selected = page.Profiles[2];
        Assert.True(page.MoveUpCommand.CanExecute(null));
        Assert.False(page.MoveDownCommand.CanExecute(null));

        // Выбор снят: кнопки строки недоступны и сообщили об этом кнопкам на экране.
        changed.Clear();
        page.Selected = null;
        Assert.Equal(new HashSet<string> { "up", "copy", "delete" }, changed);
        Assert.False(page.MoveUpCommand.CanExecute(null));
        Assert.False(page.MoveDownCommand.CanExecute(null));
        Assert.False(page.CopyCommand.CanExecute(null));
        Assert.False(page.DeleteCommand.CanExecute(null));
        Assert.True(page.ExportCommand.CanExecute(null));
        Assert.True(page.AddCommand.CanExecute(null));
        Assert.True(page.ImportCommand.CanExecute(null));

        // Перестановка меняет края: бывшая первая строка, сдвинутая вниз, снова может подняться.
        var first = page.Profiles[0];
        await page.MoveAsync(first, +1);
        Assert.True(page.MoveUpCommand.CanExecute(null));
        Assert.True(page.MoveDownCommand.CanExecute(null));
    });

    [Fact]
    public Task ExportBecomesAvailableWhenListFills() => RunStaAsync(async () =>
    {
        var store = new FakeService();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();
        var raised = 0;
        page.ExportCommand.CanExecuteChanged += (_, _) => raised++;

        page.AddCommand.Execute(null);

        Assert.True(raised > 0);
        Assert.True(page.ExportCommand.CanExecute(null));
        Assert.True(page.CopyCommand.CanExecute(null));
        Assert.True(page.DeleteCommand.CanExecute(null));
        // Единственная строка — сразу оба края.
        Assert.False(page.MoveUpCommand.CanExecute(null));
        Assert.False(page.MoveDownCommand.CanExecute(null));
    });

    /// <summary>
    /// Первый запуск без мастера: первое подключение, добавленное в пустой список, сразу опорное, и после сохранения
    /// на него переходит «Остальной интернет». Следующие подключения создаются выключенными.
    /// </summary>
    [Fact]
    public Task FirstAddedConnectionIsPrimary() => RunStaAsync(async () =>
    {
        var store = new FakeService();
        SaveConnectionRequest? saved = null;
        store.Override = request =>
        {
            if (request is not SaveConnectionRequest save)
            {
                return null;
            }

            saved = save;
            store.Settings = save.Settings;
            return Task.FromResult(IpcResponse.Success());
        };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();

        page.AddCommand.Execute(null);
        var first = page.Selected!;
        Assert.Equal(ProfileRole.Primary, first.Role);
        first.Server = "vpn.example";
        first.UserName = "user";
        page.Password = "secret";
        await page.SaveCommand.ExecuteAsync(null);

        Assert.False(page.MessageIsError, page.Message);
        Assert.NotNull(saved);
        Assert.Equal(ProfileRole.Primary, saved.Settings.Profile(first.Id)!.Role);
        Assert.Equal(RouteTarget.Tunnel(first.Id), saved.Settings.DefaultTarget);

        page.AddCommand.Execute(null);
        Assert.Equal(ProfileRole.Off, page.Selected!.Role);
    });

    /// <summary>Список ещё не получен от службы: новое подключение выключено — неизвестно, есть ли уже опорное.</summary>
    [Fact]
    public Task AddBeforeListLoadedIsOff() => RunStaAsync(() =>
    {
        using var service = new ServiceConnection(new FakeService { Unavailable = true }.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());

        main.Connections.AddCommand.Execute(null);

        Assert.Equal(ProfileRole.Off, main.Connections.Selected!.Role);
        return Task.CompletedTask;
    });

    // ---------- Вспомогательное ----------

    private static ConnectionProfile Profile(string name, ProfileRole role) =>
        new() { Name = name, Server = "vpn.example", UserName = "user", Role = role };

    private static async Task WaitUntil(Func<bool> condition)
    {
        for (var i = 0; i < 100 && !condition(); i++)
        {
            await Task.Delay(10, TestContext.Current.CancellationToken);
        }

        Assert.True(condition());
    }

    /// <summary>Подставная служба: настройки и состояние в памяти, все запросы записываются.</summary>
    private sealed class FakeService
    {
        public AppSettings Settings { get; set; } = new();

        public bool Unavailable { get; set; }

        public List<IpcRequest> Requests { get; } = [];

        public Func<IpcRequest, Task<IpcResponse>?>? Override { get; set; }

        public async Task<IpcResponse> SendAsync(IpcRequest request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            if (Unavailable)
            {
                throw new ServiceUnavailableException("Служба не запущена.");
            }

            if (Override?.Invoke(request) is { } custom)
            {
                return await custom;
            }

            return request switch
            {
                GetSettingsRequest => IpcResponse.Success(Settings),
                GetAdaptersRequest => IpcResponse.Success(new List<AdapterDto>()),
                GetStatusRequest => IpcResponse.Success(new StatusDto { Intent = Intent.Off }),
                GetEventsRequest => IpcResponse.Success(new List<ServiceEvent>()),
                SaveSettingsRequest save => Save(save.Settings),
                _ => IpcResponse.Success(),
            };
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
