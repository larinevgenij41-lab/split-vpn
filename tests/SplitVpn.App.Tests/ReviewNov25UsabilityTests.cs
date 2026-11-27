using System.IO;
using System.Windows.Threading;
using Microsoft.Web.WebView2.Core;
using SplitVpn.App.Services;
using SplitVpn.App.ViewModels;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;

namespace SplitVpn.App.Tests;

/// <summary>Ревью удобства 25.11: подтверждения, несохранённые правки, уведомления, журнал, тексты ошибок.</summary>
public sealed class ReviewNov25UsabilityTests
{
    // ---------- T-1: «Отменить изменения» на доске ----------

    [Fact]
    public Task BoardRevertAsksBeforeDiscardingEdits() => RunStaAsync(async () =>
    {
        var store = new FakeService();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Routing;
        await page.OnOpenedAsync();
        var prompts = new List<(string Title, string Action)>();
        var answer = false;
        main.Confirm = (title, _, action) => { prompts.Add((title, action)); return Task.FromResult(answer); };

        Add(page, RouteTarget.Direct, "203.0.113.0/24");
        Assert.True(page.Dirty);
        await page.ReloadCommand.ExecuteAsync(null);
        var prompt = Assert.Single(prompts);
        Assert.Equal("Отменить изменения доски?", prompt.Title);
        Assert.Equal("Отменить изменения", prompt.Action);
        Assert.True(page.Dirty);
        Assert.Contains(page.Columns.Single(c => c.Target == RouteTarget.Direct).Cards, c => c.Title == "203.0.113.0/24");

        answer = true;
        await page.ReloadCommand.ExecuteAsync(null);
        Assert.False(page.Dirty);
        Assert.DoesNotContain(page.Columns.Single(c => c.Target == RouteTarget.Direct).Cards, c => c.Title == "203.0.113.0/24");

        // Без правок отменять нечего: подтверждение не нужно.
        main.Confirm = (_, _, _) => throw new InvalidOperationException("Неожиданное подтверждение");
        await page.ReloadCommand.ExecuteAsync(null);
        Assert.False(page.MessageIsError, page.Message);
    });

    // ---------- T-11: переименование папки ----------

    [Fact]
    public Task FolderRenameMarksBoardWithoutRebuildingSearch() => RunStaAsync(async () =>
    {
        var store = new FakeService();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Routing;
        await page.OnOpenedAsync();
        var folder = page.CreateFolder(page.Columns.Single(c => c.Target == RouteTarget.Direct));
        await page.SaveCommand.ExecuteAsync(null);
        Assert.False(page.Dirty);

        page.Search = folder.Name;
        var searchRebuilt = 0;
        page.PropertyChanged += (_, e) => { if (e.PropertyName == nameof(RoutingViewModel.SearchResults)) { searchRebuilt++; } };
        folder.Name += " 2";

        Assert.True(page.Dirty);
        Assert.True(page.HasUnsavedChanges);
        Assert.Equal(0, searchRebuilt);
    });

    // ---------- T-2: несохранённые правки перед выходом и обновлением ----------

    [Fact]
    public Task UnsavedPagesListedInMenuOrder() => RunStaAsync(async () =>
    {
        var store = new FakeService();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        await main.Routing.OnOpenedAsync();
        await main.Connections.LoadAsync();
        Assert.Empty(main.PagesWithUnsavedChanges());

        var raised = new List<string>();
        foreach (var page in main.Pages)
        {
            page.PropertyChanged += (sender, e) => { if (e.PropertyName == nameof(PageViewModel.HasUnsavedChanges)) { raised.Add(((PageViewModel)sender!).Title); } };
        }

        main.Settings.AutoConnect = !main.Settings.AutoConnect;
        main.Protection.LocalAccess = !main.Protection.LocalAccess;
        Add(main.Routing, RouteTarget.Direct, "198.51.100.0/24");
        main.Connections.AddCommand.Execute(null);

        Assert.Equal(new PageViewModel[] { main.Connections, main.Routing, main.Protection, main.Settings }, main.PagesWithUnsavedChanges());
        Assert.Equal(new[] { "Настройки", "Защита и DNS", "Маршрутизация", "Подключения" }, raised);
    });

    [Fact]
    public Task ExistingProfileEditCountsAsUnsaved() => RunStaAsync(async () =>
    {
        var store = new FakeService { Settings = new AppSettings { Profiles = [Profile("Основное", ProfileRole.Primary)] } };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        await main.Connections.LoadAsync();
        Assert.Empty(main.PagesWithUnsavedChanges());

        main.Connections.Selected!.Server = "other.example";

        Assert.Equal(new PageViewModel[] { main.Connections }, main.PagesWithUnsavedChanges());
    });

    [Fact]
    public Task ExitWithUnsavedChangesAsksAndOpensFirstPageOnRefusal() => RunStaAsync(async () =>
    {
        var store = new FakeService();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        main.Confirm = (_, _, _) => throw new InvalidOperationException("Неожиданное подтверждение");
        Assert.True(await main.ConfirmDiscardUnsavedAsync());

        await main.Routing.OnOpenedAsync();
        Add(main.Routing, RouteTarget.Direct, "198.51.100.0/24");
        main.Settings.AutoConnect = !main.Settings.AutoConnect;
        string? text = null;
        string? action = null;
        var shown = 0;
        main.ShowWindow = () => shown++;
        main.Confirm = (title, body, button) => { text = title + " " + body; action = button; return Task.FromResult(false); };

        Assert.False(await main.ConfirmDiscardUnsavedAsync());
        Assert.Contains("Не сохранены: «Маршрутизация», «Настройки».", text, StringComparison.Ordinal);
        Assert.Equal("Закрыть без сохранения", action);
        Assert.Same(main.Routing, main.CurrentPage);
        Assert.Equal(1, shown);

        main.Confirm = (_, _, button) => { action = button; return Task.FromResult(true); };
        Assert.True(await main.ConfirmDiscardUnsavedAsync(forUpdate: true));
        Assert.Equal("Установить без сохранения", action);
    });

    // ---------- T-3: «Отключить и восстановить интернет» ----------

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public Task RestoreInternetIsConfirmed(bool confirmed) => RunStaAsync(async () =>
    {
        var store = new FakeService();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences()) { ServiceAvailable = true };
        string? action = null;
        main.Confirm = (title, _, button) => { action = title + "|" + button; return Task.FromResult(confirmed); };

        await main.DisconnectAndRestoreCommand.ExecuteAsync(null);

        Assert.Equal("Снять защиту?|Снять защиту", action);
        var disconnects = store.Requests.OfType<DisconnectRequest>().ToList();
        if (confirmed)
        {
            Assert.False(Assert.Single(disconnects).KeepProtection);
        }
        else
        {
            Assert.Empty(disconnects);
        }
    });

    // ---------- T-4: «Подключить» без включённых подключений ----------

    [Fact]
    public Task HomeButtonLeadsToConnectionsWhenNothingToConnect() => RunStaAsync(async () =>
    {
        var store = new FakeService();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences()) { ServiceAvailable = true };
        var home = main.Home;
        await home.OnOpenedAsync();
        home.OnStatus(new StatusDto { Intent = Intent.Off });

        Assert.Equal(HomeSetupAction.AddConnection, home.SetupAction);
        Assert.Equal("Добавить подключение", home.ButtonText);
        Assert.NotNull(home.SetupHint);
        await home.PrimaryActionCommand.ExecuteAsync(null);
        Assert.Same(main.Connections, main.CurrentPage);
        Assert.Contains(main.Connections.Profiles, p => p.IsNew);
        Assert.Empty(store.Requests.OfType<ConnectRequest>());
    });

    [Fact]
    public Task HomeButtonOpensConnectionsWhenAllAreOff() => RunStaAsync(async () =>
    {
        var store = new FakeService { Settings = new AppSettings { Profiles = [Profile("Запасное", ProfileRole.Off)] } };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences()) { ServiceAvailable = true };
        var home = main.Home;
        await home.OnOpenedAsync();
        home.OnStatus(new StatusDto { Intent = Intent.Off });

        Assert.Equal("Открыть «Подключения»", home.ButtonText);
        await home.PrimaryActionCommand.ExecuteAsync(null);
        Assert.Same(main.Connections, main.CurrentPage);
        Assert.Empty(store.Requests.OfType<ConnectRequest>());

        // Подключение включили: кнопка снова подключает.
        store.Settings = new AppSettings { Profiles = [Profile("Основное", ProfileRole.Primary)] };
        await home.OnOpenedAsync();
        home.OnStatus(new StatusDto { Intent = Intent.Off, ProfileName = "Основное" });
        Assert.Equal(HomeSetupAction.None, home.SetupAction);
        Assert.Equal("Подключить", home.ButtonText);
        Assert.Null(home.SetupHint);
        await home.PrimaryActionCommand.ExecuteAsync(null);
        Assert.Single(store.Requests.OfType<ConnectRequest>());
    });

    /// <summary>
    /// «Остановить службу»: главная кнопка недоступна сразу (уведомление о смене доступности, а не ожидание опроса),
    /// и даже вызов в обход доступности не отправляет «Подключить» останавливающейся службе.
    /// </summary>
    [Fact]
    public Task HomeButtonFollowsServiceStopping() => RunStaAsync(async () =>
    {
        var store = new FakeService { Settings = new AppSettings { Profiles = [Profile("Основное", ProfileRole.Primary)] } };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences()) { ServiceAvailable = true };
        var home = main.Home;
        await home.OnOpenedAsync();
        home.OnStatus(new StatusDto { Intent = Intent.Off, ProfileName = "Основное" });
        main.ServiceHost.Show(ServiceHostState.Running, "1.0.0");
        Assert.True(home.PrimaryActionCommand.CanExecute(null));

        var notified = 0;
        home.PrimaryActionCommand.CanExecuteChanged += (_, _) => notified++;
        main.ServiceHost.Show(ServiceHostState.StopPending, "1.0.0");
        Assert.True(notified > 0);
        Assert.False(home.PrimaryActionCommand.CanExecute(null));

        await home.PrimaryActionCommand.ExecuteAsync(null);
        Assert.Empty(store.Requests.OfType<ConnectRequest>());

        notified = 0;
        main.ServiceHost.Show(ServiceHostState.Running, "1.0.0");
        Assert.True(notified > 0);
        Assert.True(home.PrimaryActionCommand.CanExecute(null));
    });

    // ---------- T-5, T-12, T-19: уведомления ----------

    [Fact]
    public Task NotificationsTargetThePageThatNeedsAction() => RunStaAsync(async () =>
    {
        var store = new FakeService();
        var time = new ManualTime();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences(), time);
        var shown = new List<AppNotification>();
        main.Notify += shown.Add;

        async Task Status(ConnectionState state, int seconds)
        {
            store.Status = new StatusDto { State = state, Intent = Intent.Connected, ProfileName = "Основное", ErrorText = "Причина" };
            time.Now = DateTimeOffset.UnixEpoch.AddHours(1).AddSeconds(seconds);
            await main.RefreshAsync();
        }

        await Status(ConnectionState.Connected, 0);
        await Status(ConnectionState.PasswordRequired, 1);
        await Status(ConnectionState.PartiallyApplied, 2);
        await Status(ConnectionState.Error, 3);

        Assert.Equal(new[] { "Требуется пароль", "Неполное применение", "Ошибка подключения" }, shown.Select(n => n.Title));
        Assert.Same(main.Home, shown[0].Target);
        Assert.True(shown[0].FocusPassword);
        Assert.Same(main.Diagnostics, shown[1].Target);
        Assert.Same(main.Home, shown[2].Target);
        Assert.Equal(NotificationKind.Error, shown[2].Kind);
        Assert.Equal(H.NotifyIcon.Core.NotificationIcon.Error, TrayIcon.IconFor(shown[2].Kind));
        Assert.Equal(H.NotifyIcon.Core.NotificationIcon.Warning, TrayIcon.IconFor(shown[0].Kind));

        // Щелчок по уведомлению о пароле: главная и фокус в поле пароля.
        main.NavigateTo(main.Settings);
        var token = main.Home.PasswordFocusToken;
        main.OpenNotificationTarget(shown[0]);
        Assert.Same(main.Home, main.CurrentPage);
        Assert.Equal(token + 1, main.Home.PasswordFocusToken);

        main.OpenNotificationTarget(shown[1]);
        Assert.Same(main.Diagnostics, main.CurrentPage);
    });

    [Fact]
    public Task FailedCommandNotificationOpensItsPage() => RunStaAsync(async () =>
    {
        var store = new FakeService { Status = new StatusDto { State = ConnectionState.Disconnected, ProfileName = "Основное" } };
        store.Override = request => request is ConnectRequest ? Task.FromResult(IpcResponse.Failure(IpcErrorCodes.Failed, "Сервер не ответил.")) : null;
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences()) { ServiceAvailable = true };
        var shown = new List<AppNotification>();
        main.Notify += shown.Add;
        main.NavigateTo(main.Connections);

        await main.RunCommandAsync(new ConnectRequest(null, null));

        var notice = Assert.Single(shown);
        Assert.Equal("Команда не выполнена", notice.Title);
        Assert.Same(main.Connections, notice.Target);
    });

    [Fact]
    public Task FlappingVpnDoesNotFloodNotifications() => RunStaAsync(async () =>
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
        await Status(ConnectionState.Connected, 10);
        Assert.Equal(new[] { "VPN переподключился" }, shown);

        // Ещё одно короткое переподключение в пределах 5 минут — без уведомлений.
        await Status(ConnectionState.Reconnecting, 20);
        await Status(ConnectionState.Connected, 25);
        Assert.Single(shown);

        // Долгий обрыв: «оборвался» через 30 с и «восстановлен» по возвращении.
        await Status(ConnectionState.Reconnecting, 40);
        await Status(ConnectionState.Reconnecting, 55);
        Assert.Single(shown);
        await Status(ConnectionState.Reconnecting, 71);
        await Status(ConnectionState.Connected, 80);
        Assert.Equal(new[] { "VPN переподключился", "VPN оборвался", "VPN восстановлен" }, shown);

        // Уведомления, требующие действия, ограничены коротким пределом: первое показывается, повтор того же самого в
        // течение минуты (аудит 27.11) подавлен — если между ними не было показано «снова подключён» (ревью 27.11).
        await Status(ConnectionState.PasswordRequired, 90);
        await Status(ConnectionState.Connected, 95);
        await Status(ConnectionState.PasswordRequired, 100);
        await Status(ConnectionState.Connected, 105);
        await Status(ConnectionState.PasswordRequired, 110);
        await Status(ConnectionState.Connected, 115);
        Assert.Equal(2, shown.Count(t => t == "Требуется пароль"));
        Assert.Equal(1, shown.Count(t => t == "VPN снова подключён"));
        await Status(ConnectionState.PasswordRequired, 170);
        await Status(ConnectionState.Connected, 175);
        Assert.Equal(3, shown.Count(t => t == "Требуется пароль"));

        // Через 5 минут то же уведомление снова показывается.
        await Status(ConnectionState.Reconnecting, 400);
        await Status(ConnectionState.Connected, 405);
        Assert.Equal(2, shown.Count(t => t == "VPN переподключился"));
    });

    [Fact]
    public Task TunnelInterruptionsAreLimitedPerTunnel() => RunStaAsync(async () =>
    {
        var store = new FakeService();
        var time = new ManualTime();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences(), time);
        var shown = new List<string>();
        main.Notify += n => shown.Add(n.Title);
        var tunnel = Guid.NewGuid();

        async Task Tunnel(ConnectionState state, int seconds)
        {
            store.Status = new StatusDto
            {
                State = ConnectionState.Connected, Intent = Intent.Connected, ProfileName = "Основное",
                Tunnels = [new TunnelStatusDto { ProfileId = tunnel, Name = "Работа", State = state }],
            };
            time.Now = DateTimeOffset.UnixEpoch.AddHours(1).AddSeconds(seconds);
            await main.RefreshAsync();
        }

        for (var i = 0; i < 5; i++)
        {
            await Tunnel(ConnectionState.Connected, i * 20);
            await Tunnel(ConnectionState.Reconnecting, i * 20 + 10);
        }

        Assert.Equal(new[] { "Прервалось подключение «Работа»" }, shown);
    });

    [Fact]
    public void TrayTooltipNamesSignInAndRestOfInternet()
    {
        var status = new StatusDto
        {
            State = ConnectionState.PasswordRequired,
            GeoTargetName = "напрямую",
            DefaultTargetName = "через «Офис»",
            Tunnels = [new TunnelStatusDto { Name = "Офис", State = ConnectionState.PasswordRequired, SignIn = new SignInPromptDto { GatewayHost = "vpn.example.org" } }],
        };

        var text = TrayIcon.Tooltip("Требуется пароль", status);

        Assert.StartsWith("Раздельный VPN: Требуется вход", text, StringComparison.Ordinal);
        Assert.Contains("Остальной интернет → через «Офис»", text, StringComparison.Ordinal);
        Assert.Equal("Раздельный VPN: Служба недоступна", TrayIcon.Tooltip("Служба недоступна", null));
    }

    // ---------- T-6, T-17: журнал событий ----------

    [Fact]
    public void JournalPrependsIntoSameListAndKeepsLimit()
    {
        var journal = new EventJournal();
        var visible = journal.Visible;
        journal.Prepend([Event(2, "Сведения"), Event(1, "Ошибка")]);
        journal.Prepend([Event(4, "Предупреждение"), Event(3, "Сведения")]);

        Assert.Same(visible, journal.Visible);
        Assert.Equal(new long[] { 4, 3, 2, 1 }, visible.Select(e => e.Id));

        journal.Prepend([.. Enumerable.Range(5, EventJournal.Limit).Reverse().Select(id => Event(id, "Сведения"))]);
        Assert.Equal(EventJournal.Limit, journal.Count);
        Assert.Equal(EventJournal.Limit, visible.Count);
        Assert.Equal(EventJournal.Limit + 4L, visible[0].Id);
        Assert.Equal(5L, visible[^1].Id);
    }

    [Fact]
    public void JournalFiltersErrorsAndWarnings()
    {
        var journal = new EventJournal();
        journal.Prepend([Event(3, "Сведения"), Event(2, "Предупреждение"), Event(1, "Ошибка")]);

        journal.OnlyProblems = true;
        Assert.Equal(new long[] { 2, 1 }, journal.Visible.Select(e => e.Id));

        journal.Prepend([Event(5, "Ошибка"), Event(4, "Сведения")]);
        Assert.Equal(new long[] { 5, 2, 1 }, journal.Visible.Select(e => e.Id));
        Assert.Equal(5, journal.Count);

        journal.OnlyProblems = false;
        Assert.Equal(new long[] { 5, 4, 3, 2, 1 }, journal.Visible.Select(e => e.Id));

        var line = EventJournal.Format(Event(9, "Ошибка", "Текст события"));
        Assert.EndsWith("  Текст события", line, StringComparison.Ordinal);
        Assert.Contains(DateTimeOffset.UnixEpoch.AddHours(1).ToLocalTime().ToString("HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture), line, StringComparison.Ordinal);
    }

    // ---------- T-7: тексты ошибок ----------

    [Theory]
    [InlineData(CoreWebView2WebErrorStatus.HostNameNotResolved, "адрес сайта не найден")]
    [InlineData(CoreWebView2WebErrorStatus.Timeout, "сайт не ответил")]
    [InlineData(CoreWebView2WebErrorStatus.ConnectionAborted, "соединение прервано")]
    [InlineData(CoreWebView2WebErrorStatus.ConnectionReset, "соединение прервано")]
    [InlineData(CoreWebView2WebErrorStatus.Disconnected, "соединение прервано")]
    [InlineData(CoreWebView2WebErrorStatus.CertificateCommonNameIsIncorrect, "сертификат сайта недействителен")]
    [InlineData(CoreWebView2WebErrorStatus.CertificateExpired, "сертификат сайта недействителен")]
    [InlineData(CoreWebView2WebErrorStatus.CertificateRevoked, "сертификат сайта недействителен")]
    [InlineData(CoreWebView2WebErrorStatus.CertificateIsInvalid, "сертификат сайта недействителен")]
    [InlineData(CoreWebView2WebErrorStatus.CannotConnect, "не удалось подключиться к сайту")]
    [InlineData(CoreWebView2WebErrorStatus.Unknown, "ошибка сети")]
    [InlineData(CoreWebView2WebErrorStatus.ServerUnreachable, "ошибка сети")]
    public void WebErrorsAreTranslated(CoreWebView2WebErrorStatus status, string expected) =>
        Assert.Equal(expected, UiText.WebError(status));

    [Fact]
    public void FileErrorsAreRussianAndNameTheFile()
    {
        var io = new IOException("The process cannot access the file because it is being used by another process.");

        var write = UiText.FileError(io, @"C:\Users\user\Desktop\подключения.json", writing: true);
        Assert.Equal("Не удалось записать файл «подключения.json»: нет доступа или файл занят другой программой. Выберите другую папку.", write);
        Assert.Equal("Файл «ru.txt» не читается или повреждён.", UiText.FileError(io, @"D:\ru.txt"));
        Assert.Equal("Файл «export.json» не читается или повреждён.", UiText.FileError(new System.Text.Json.JsonException("bad"), "export.json", writing: true));
        Assert.DoesNotContain("process", UiText.FileError(io), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public Task PageShowsRussianTextForSystemFileErrors() => RunStaAsync(async () =>
    {
        using var service = new ServiceConnection(new FakeService().SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = new ProbePage(main);

        await page.Run(() => Task.FromException<string?>(new UnauthorizedAccessException("Access to the path 'C:\\x.json' is denied.")));

        Assert.True(page.MessageIsError);
        Assert.DoesNotContain("Access", page.Message, StringComparison.Ordinal);
        Assert.Contains("нет доступа", page.Message, StringComparison.Ordinal);
    });

    [Fact]
    public void RawCodesAndEnumNamesAreNotShown()
    {
        Assert.Equal("Служба отклонила запрос.", UiText.ServiceRejected(new IpcResponse(false, "E_SOMETHING", null, null)));
        Assert.Equal("Текст службы", UiText.ServiceRejected(new IpcResponse(false, "E_SOMETHING", "Текст службы", null)));
        Assert.Equal("Неизвестное состояние", StatusText.StateName((ConnectionState)999));
        Assert.Equal("Неизвестное решение", CheckAddressViewModel.DecisionText("SomethingNew"));
        Assert.Equal("Напрямую", CheckAddressViewModel.DecisionText("Direct"));
    }

    [Fact]
    public void SummarySaysRestOfInternet()
    {
        var status = new StatusDto { GeoTargetName = "напрямую", DefaultTargetName = "блокировать", ProtectionActive = true };
        Assert.Contains("Остальной интернет →", UiText.StatusSummary(status), StringComparison.Ordinal);
        Assert.DoesNotContain("Остальные адреса", UiText.StatusSummary(status), StringComparison.Ordinal);
    }

    // ---------- T-18: подчёркивание в меню ----------

    [Theory]
    [InlineData("work_vpn", "work__vpn")]
    [InlineData("a_b_c", "a__b__c")]
    [InlineData("Основное", "Основное")]
    [InlineData(null, "")]
    public void MenuHeaderKeepsUnderscores(string? name, string expected) => Assert.Equal(expected, UiText.MenuHeader(name));

    // ---------- T-10: ошибка поля переводит фокус ----------

    [Fact]
    public Task EditorServerErrorFocusesServerField() => RunStaAsync(async () =>
    {
        var store = new FakeService();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();
        page.AddCommand.Execute(null);
        page.Selected!.Server = "bad server name";

        await page.SaveCommand.ExecuteAsync(null);

        Assert.True(page.MessageIsError);
        Assert.StartsWith("Адрес VPN-сервера:", page.Message, StringComparison.Ordinal);
        Assert.Equal(1, page.ServerFocusToken);
        Assert.Empty(store.Requests.OfType<SaveConnectionRequest>());
    });

    // ---------- T-16: сообщения страниц устаревают ----------

    [Fact]
    public Task SuccessMessageHidesItselfAndErrorStays() => RunStaAsync(async () =>
    {
        using var service = new ServiceConnection(new FakeService().SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var scheduled = new List<(TimeSpan Delay, Action Action, Cancel Cancel)>();
        main.ScheduleUi = (delay, action) => { var cancel = new Cancel(); scheduled.Add((delay, action, cancel)); return cancel; };
        var page = new ProbePage(main);

        await page.Run(() => Task.FromResult<string?>("Сохранено."));
        Assert.Equal("Сохранено.", page.Message);
        var hide = scheduled.Last(s => !s.Cancel.Disposed);
        Assert.Equal(TimeSpan.FromSeconds(6), hide.Delay);
        hide.Action();
        Assert.Null(page.Message);

        await page.Run(() => Task.FromResult<string?>("Сохранено."));
        await page.Run(() => Task.FromException<string?>(new ServiceCommandException("Отказ.")));
        Assert.Equal("Отказ.", page.Message);
        Assert.All(scheduled, s => Assert.True(s.Cancel.Disposed || s.Action == hide.Action));

        // Повторное открытие страницы убирает прежнее сообщение об успехе, но не ошибку.
        main.NavigateTo(page);
        Assert.Equal("Отказ.", page.Message);
        await page.Run(() => Task.FromResult<string?>("Готово."));
        main.NavigateTo(main.Home);
        main.NavigateTo(page);
        Assert.Null(page.Message);
    });

    [Fact]
    public Task ConnectErrorClearsWhenVpnConnects() => RunStaAsync(async () =>
    {
        var store = new FakeService { Status = new StatusDto { State = ConnectionState.Disconnected, ProfileName = "Основное" } };
        store.Override = request => request is ConnectRequest ? Task.FromResult(IpcResponse.Failure(IpcErrorCodes.Failed, "Сервер не ответил.")) : null;
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences()) { ServiceAvailable = true };

        await main.RunCommandAsync(new ConnectRequest(null, null));
        Assert.Equal("Сервер не ответил.", main.Home.Message);

        store.Status = new StatusDto { State = ConnectionState.Connected, Intent = Intent.Connected, ProfileName = "Основное" };
        await main.RefreshAsync();
        Assert.Null(main.Home.Message);
    });

    // ---------- T-13: «Проверить» ----------

    [Fact]
    public Task ProfileTestShowsProgressAndKeepsResultUntilEdit() => RunStaAsync(async () =>
    {
        var reply = new TaskCompletionSource<IpcResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        var store = new FakeService { Settings = new AppSettings { Profiles = [Profile("Основное", ProfileRole.Primary)] } };
        store.Override = request => request is TestProfileRequest ? reply.Task : null;
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();
        var item = page.Selected!;

        var testing = page.TestCommand.ExecuteAsync(null);
        Assert.True(item.TestRunning);
        Assert.Contains("Пробное подключение к «Основное»", item.TestText, StringComparison.Ordinal);
        Assert.Contains("до минуты", item.TestText, StringComparison.Ordinal);

        reply.SetResult(IpcResponse.Success(new ProfileTestDto(false, "Сервер отклонил пароль.")));
        await testing;
        Assert.False(item.TestRunning);
        Assert.Equal("Сервер отклонил пароль.", item.TestText);
        Assert.True(item.TestFailed);
        Assert.False(item.IsDirty);

        item.UserName = "other";
        Assert.Null(item.TestText);
    });

    // ---------- T-20: удаление подключения ----------

    [Fact]
    public Task DraftWithInputIsDeletedOnlyAfterConfirmation() => RunStaAsync(async () =>
    {
        var store = new FakeService();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();
        page.AddCommand.Execute(null);
        var draft = page.Selected!;
        draft.Server = "vpn.example";
        var answer = false;
        string? action = null;
        main.Confirm = (_, _, button) => { action = button; return Task.FromResult(answer); };

        await page.DeleteCommand.ExecuteAsync(null);
        Assert.Equal("Удалить черновик", action);
        Assert.Contains(draft, page.Profiles);

        answer = true;
        await page.DeleteCommand.ExecuteAsync(null);
        Assert.DoesNotContain(draft, page.Profiles);

        // Пустой черновик убирается без вопросов.
        page.AddCommand.Execute(null);
        main.Confirm = (_, _, _) => throw new InvalidOperationException("Неожиданное подтверждение");
        await page.DeleteCommand.ExecuteAsync(null);
        Assert.Empty(page.Profiles);
    });

    [Fact]
    public Task EnabledConnectionIsTurnedOffAndDeleted() => RunStaAsync(async () =>
    {
        var profile = Profile("Основное", ProfileRole.Primary);
        var store = new FakeService { Settings = new AppSettings { Profiles = [profile], DefaultTarget = RouteTarget.Tunnel(profile.Id) } };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();
        string? text = null;
        string? action = null;
        main.Confirm = (_, body, button) => { text = body; action = button; return Task.FromResult(true); };

        await page.DeleteCommand.ExecuteAsync(null);

        Assert.Equal("Выключить и удалить", action);
        Assert.Contains("Остальной интернет", text, StringComparison.Ordinal);
        Assert.Null(store.Settings.Profile(profile.Id));
        Assert.Equal(2, store.Requests.OfType<SaveSettingsRequest>().Count());
        Assert.False(page.MessageIsError, page.Message);
    });

    // ---------- Вспомогательное ----------

    private static ConnectionProfile Profile(string name, ProfileRole role) =>
        new() { Name = name, Server = "vpn.example", UserName = "user", Role = role };

    private static ServiceEvent Event(long id, string level, string text = "событие") =>
        new(id, DateTimeOffset.UnixEpoch.AddHours(1), level, text);

    private static void Add(RoutingViewModel page, RouteTarget target, string text)
    {
        var column = page.Columns.Single(c => c.Target == target);
        column.NewValue = text;
        column.AddCommand.Execute(null);
    }

    private sealed class ProbePage(MainViewModel main) : PageViewModel(main, "Проба", Wpf.Ui.Controls.SymbolRegular.Beaker24)
    {
        public Task Run(Func<Task<string?>> action) => RunAsync(action);
    }

    private sealed class Cancel : IDisposable
    {
        public bool Disposed { get; private set; }

        public void Dispose() => Disposed = true;
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

        public StatusDto Status { get; set; } = new() { ProfileName = "Основное" };

        public List<IpcRequest> Requests { get; } = [];

        public Func<IpcRequest, Task<IpcResponse>?>? Override { get; set; }

        public async Task<IpcResponse> SendAsync(IpcRequest request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            if (Override?.Invoke(request) is { } custom)
            {
                return await custom;
            }

            switch (request)
            {
                case GetSettingsRequest:
                    return IpcResponse.Success(Settings);
                case GetAdaptersRequest:
                    return IpcResponse.Success(new List<AdapterDto>());
                case GetStatusRequest:
                    return IpcResponse.Success(Status);
                case GetEventsRequest:
                    return IpcResponse.Success(new List<ServiceEvent>());
                case SaveSettingsRequest save:
                    Settings = save.Settings;
                    return IpcResponse.Success();
                case SaveConnectionRequest save:
                    Settings = save.Settings;
                    return IpcResponse.Success(new List<string>());
                default:
                    return IpcResponse.Success();
            }
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
