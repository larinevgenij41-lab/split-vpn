using System.Collections.ObjectModel;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SplitVpn.App.Services;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;

namespace SplitVpn.App.ViewModels;

/// <summary>
/// Главное окно и трей: опрос состояния службы, основные команды, навигация по страницам.
/// Опрос идёт раз в 1,5 с по своему соединению (команды его не задерживают); пока предыдущий запрос
/// состояния не вернулся, следующий такт пропускается. UI не блокируется.
/// </summary>
public sealed partial class MainViewModel : ObservableObject, IDisposable
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(1500);

    /// <summary>Окно скрыто в трей: значку и уведомлениям хватает опроса раз в 5 секунд.</summary>
    private static readonly TimeSpan HiddenPollInterval = TimeSpan.FromSeconds(5);

    private readonly DispatcherTimer _timer;
    private readonly ServiceResponsiveness _responsiveness = new();
    private bool _polling;
    private int _failures;
    private DateTimeOffset _nextPollAt;
    private DateTimeOffset _lastPollAt;
    private bool _wizardChecked;
    private bool _lossExpected;
    private (DateTimeOffset Time, ulong Sent, ulong Received)? _lastBytes;

    public MainViewModel(ServiceConnection service, UiPreferences preferences)
    {
        Service = service;
        Preferences = preferences;
        Home = new HomeViewModel(this);
        Connections = new ConnectionsViewModel(this);
        Routing = new RoutingViewModel(this);
        CheckAddress = new CheckAddressViewModel(this);
        Protection = new ProtectionViewModel(this);
        Settings = new SettingsViewModel(this);
        Settings.LoadPreferences(preferences);
        Diagnostics = new DiagnosticsViewModel(this);
        About = new AboutViewModel(this);
        Pages = [Home, Connections, Routing, CheckAddress, Protection, Settings, Diagnostics, About];
        foreach (var page in Pages)
        {
            page.PropertyChanged += OnPageChanged;
        }

        _currentPage = Home;
        ServiceHost = new ServiceHostViewModel(this);
        _timer = new DispatcherTimer { Interval = PollInterval };
        _timer.Tick += async (_, _) => await PollAsync();
    }

    public ServiceConnection Service { get; }

    /// <summary>Блок «Служба» в меню: состояние службы Windows и её запуск, остановка, перезапуск.</summary>
    public ServiceHostViewModel ServiceHost { get; }

    public UiPreferences Preferences { get; private set; }

    public HomeViewModel Home { get; }

    public ConnectionsViewModel Connections { get; }

    public RoutingViewModel Routing { get; }

    public CheckAddressViewModel CheckAddress { get; }

    public ProtectionViewModel Protection { get; }

    public SettingsViewModel Settings { get; }

    public DiagnosticsViewModel Diagnostics { get; }

    public AboutViewModel About { get; }

    public ObservableCollection<PageViewModel> Pages { get; }

    /// <summary>Мастер первого запуска; null — не показывается.</summary>
    [ObservableProperty]
    private WizardViewModel? _wizard;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsWorking))]
    private PageViewModel _currentPage;

    [ObservableProperty]
    private StatusDto? _status;

    [ObservableProperty]
    private bool _serviceAvailable = true;

    [ObservableProperty]
    private string _serviceError = "";

    [ObservableProperty]
    private string _serviceErrorTitle = "Служба недоступна";

    /// <summary>Причина недоступности службы; null — служба отвечает.</summary>
    [ObservableProperty]
    private ServiceUnavailableReason? _unavailableReason;

    [ObservableProperty]
    private string _stateText = "Подключение к службе…";

    [ObservableProperty]
    private string _summaryText = "";

    [ObservableProperty]
    private string _speedText = "—";

    /// <summary>Идёт команда службе: остальные команды (в том числе из трея) недоступны, чтобы не было гонки.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ConnectCommand), nameof(DisconnectCommand), nameof(DisconnectAndRestoreCommand), nameof(ToggleConnectionCommand))]
    [NotifyPropertyChangedFor(nameof(IsWorking))]
    private bool _isBusy;

    /// <summary>Что делает идущая команда словами («Подключение…»): надпись главной кнопки. null — команды нет.</summary>
    [ObservableProperty]
    private string? _busyAction;

    /// <summary>Идёт команда службе или действие открытой страницы: в шапке окна виден индикатор ожидания.</summary>
    public bool IsWorking => IsBusy || CurrentPage.IsBusy;

    /// <summary>Окно на экране: иначе ошибка команды (например, из трея) показывается уведомлением.</summary>
    public bool IsWindowVisible { get; set; }

    /// <summary>Уведомление о значимом событии для трея (заголовок, текст).</summary>
    public event Action<string, string>? Notify;

    /// <summary>Окно переводит навигацию на страницу модели; без окна страница просто становится текущей.</summary>
    public event Action<PageViewModel>? NavigationRequested;

    public void NavigateTo(PageViewModel page)
    {
        if (NavigationRequested is { } handler)
        {
            handler(page);
        }
        else
        {
            CurrentPage = page;
        }
    }

    public event Action? StatusUpdated;

    /// <summary>
    /// Подтверждение необратимого или ослабляющего защиту действия: заголовок, текст, надпись кнопки действия.
    /// Окно подставляет диалог; без окна действие не подтверждается.
    /// </summary>
    public Func<string, string, string, Task<bool>> Confirm { get; set; } = (_, _, _) => Task.FromResult(false);

    /// <summary>VPN включён намерением пользователя и защита не приостановлена восстановлением сети.</summary>
    public static bool IsConnectedIntent(StatusDto? status) => status is { Intent: Intent.Connected, ProtectionSuspended: false };

    /// <summary>
    /// «Отключить и восстановить интернет» имеет смысл, пока защита включена или система в сбойном состоянии:
    /// при неполном применении фильтры могли остаться, даже если намерение уже «выключено».
    /// </summary>
    public static bool CanRestore(StatusDto? status) => status is not null
        && (status.ProtectionActive || status.State is ConnectionState.PartiallyApplied or ConnectionState.TrafficBlocked or ConnectionState.Error);

    public void Start()
    {
        _timer.Start();
        ServiceHost.Start();
        _ = PollAsync();
    }

    /// <summary>Опрос без ожидания отсрочки: пользователь открыл окно или дал команду.</summary>
    public Task RefreshAsync()
    {
        _nextPollAt = DateTimeOffset.MinValue;
        return PollAsync(force: true);
    }

    /// <summary>Пока идёт остановка или перезапуск службы по команде пользователя, потеря связи — без уведомления.</summary>
    public void ExpectServiceLoss(bool expected) => _lossExpected = expected;

    public void Dispose()
    {
        _timer.Stop();
        foreach (var page in Pages)
        {
            page.PropertyChanged -= OnPageChanged;
        }

        ServiceHost.Dispose();
    }

    /// <summary>Занятость открытой страницы — часть общей: индикатор в шапке один на окно.</summary>
    private void OnPageChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(PageViewModel.IsBusy) && ReferenceEquals(sender, CurrentPage))
        {
            OnPropertyChanged(nameof(IsWorking));
        }
    }

    public void SavePreferences(UiPreferences preferences)
    {
        Preferences = preferences;
        preferences.Save();
    }

    partial void OnCurrentPageChanged(PageViewModel value) => _ = value.OnOpenedAsync();

    [RelayCommand]
    private void Navigate(PageViewModel page) => NavigateTo(page);

    private bool CanRunCommand => !IsBusy;

    /// <summary>«Подключить» и «Повторить»: служба сбрасывает остановленные повторы и дозванивается заново.</summary>
    [RelayCommand(CanExecute = nameof(CanRunCommand))]
    private Task ConnectAsync() => RunCommandAsync(new ConnectRequest(null, null));

    /// <summary>«Отключить»: VPN разрывается, защита остаётся — трафик VPN заблокирован.</summary>
    [RelayCommand(CanExecute = nameof(CanRunCommand))]
    private Task DisconnectAsync() => RunCommandAsync(new DisconnectRequest(KeepProtection: true));

    /// <summary>«Отключить VPN и восстановить обычный интернет»: снимаются фильтры, маршруты, DNS.</summary>
    [RelayCommand(CanExecute = nameof(CanRunCommand))]
    private Task DisconnectAndRestoreAsync() => RunCommandAsync(new DisconnectRequest(KeepProtection: false));

    [RelayCommand(CanExecute = nameof(CanRunCommand))]
    private Task ToggleConnectionAsync() => RunCommandAsync(IsConnectedIntent(Status)
        ? new DisconnectRequest(KeepProtection: true)
        : new ConnectRequest(null, null));

    public async Task SetProfileRoleAsync(Guid profileId, ProfileRole role)
    {
        await RunCommandAsync(new SetProfileRoleRequest(profileId, role));
    }

    /// <summary>
    /// Выполнить команду службы и сразу обновить статус. Ошибка видна на открытой странице, а если окно
    /// скрыто (команда из трея) — уведомлением. Пока идёт одна команда, следующая не начинается.
    /// </summary>
    public async Task RunCommandAsync(IpcRequest request)
    {
        if (IsBusy)
        {
            return;
        }

        IsBusy = true;
        BusyAction = ActionText(request);
        try
        {
            var response = await Service.SendAsync(request);
            if (!response.Ok)
            {
                ShowCommandError(response.ErrorMessage ?? "Служба отклонила команду.");
            }
            else if (response.ResultAs<StatusDto>() is { } status)
            {
                ApplyStatus(status);
            }
        }
        catch (ServiceUnavailableException ex)
        {
            ShowCommandError(ex.Message);
        }
        finally
        {
            IsBusy = false;
            BusyAction = null;
        }

        await RefreshAsync();
    }

    /// <summary>Надпись главной кнопки на время команды: видно, что идёт, а не просто недоступная кнопка.</summary>
    private static string? ActionText(IpcRequest request) => request switch
    {
        ConnectRequest => "Подключение…",
        DisconnectRequest => "Отключение…",
        _ => null,
    };

    private void ShowCommandError(string text)
    {
        CurrentPage.ShowError(text);
        if (!IsWindowVisible)
        {
            // Ответ на действие пользователя: уведомление показывается независимо от настройки уведомлений о сбоях.
            Notify?.Invoke("Команда не выполнена", text);
        }
    }

    private async Task PollAsync(bool force = false)
    {
        var now = DateTimeOffset.UtcNow;
        if (_polling || now < _nextPollAt || (!force && !IsWindowVisible && now - _lastPollAt < HiddenPollInterval))
        {
            return;
        }

        _polling = true;
        _lastPollAt = now;
        try
        {
            ApplyStatus(await Service.RequestAsync<StatusDto>(new GetStatusRequest()));
        }
        catch (ServiceUnavailableException ex)
        {
            if (_responsiveness.OnFailure(ex.Reason, DateTimeOffset.UtcNow))
            {
                ApplyUnavailable(ex);
            }
        }
        catch (ServiceCommandException ex)
        {
            // Отказ на запрос состояния возможен только от службы другой версии.
            ApplyUnavailable(new ServiceUnavailableException(ex.Message, ex, ServiceUnavailableReason.VersionMismatch));
        }
        finally
        {
            _polling = false;
        }
    }

    private void ApplyStatus(StatusDto status)
    {
        var previous = Status;
        _responsiveness.OnSuccess(DateTimeOffset.UtcNow);
        _failures = 0;
        _nextPollAt = DateTimeOffset.MinValue;
        ServiceAvailable = true;
        ServiceError = "";
        UnavailableReason = null;
        Status = status;
        StateText = StatusText.StateName(status.State);
        SummaryText = StatusText.Format(status);
        SpeedText = Speed(status);
        NotifyTransitions(previous, status);
        foreach (var page in Pages)
        {
            page.OnStatus(status);
        }

        StatusUpdated?.Invoke();
        _ = ShowWizardIfNeededAsync();
    }

    private void ApplyUnavailable(ServiceUnavailableException error)
    {
        // Уведомление — только о потере уже работавшей службы: при входе в Windows она может стартовать позже интерфейса.
        // Остановку или перезапуск из блока «Служба» пользователь сделал сам — о ней не уведомляем.
        var lost = ServiceAvailable && Status is not null && !_lossExpected;
        _failures++;
        _nextPollAt = DateTimeOffset.UtcNow + Backoff(error.Reason, _failures);
        var (title, text, advice) = Describe(error.Reason);
        if (lost && Preferences.Notifications)
        {
            Notify?.Invoke(title, advice);
        }

        ServiceAvailable = false;
        UnavailableReason = error.Reason;
        ServiceErrorTitle = title;
        ServiceError = $"{text} {advice}";
        Status = null;
        StateText = title;
        SummaryText = text;
        SpeedText = "—";
        _lastBytes = null;
        foreach (var page in Pages)
        {
            page.OnStatus(null);
        }

        StatusUpdated?.Invoke();
    }

    /// <summary>Заголовок, состояние и совет по причине недоступности. Восстановление сети советуется только там, где оно поможет.</summary>
    internal static (string Title, string Text, string Advice) Describe(ServiceUnavailableReason reason) => reason switch
    {
        ServiceUnavailableReason.Timeout => (
            "Служба не отвечает",
            "Состояние могло устареть; команды не выполняются.",
            "Если служба не отвечает дольше минуты, нажмите «Перезапустить» в блоке «Служба» внизу меню или откройте «Диагностика» → «Восстановить сеть»."),
        ServiceUnavailableReason.Denied => (
            "Нужны права администратора",
            "Управлять службой может только администратор компьютера; защита работает как прежде.",
            "Войдите в Windows под учётной записью администратора."),
        ServiceUnavailableReason.VersionMismatch => (
            "Версии не совпадают",
            "Приложение и служба разных версий; защита работает как прежде.",
            "Перезапустите приложение после обновления или переустановите программу."),
        ServiceUnavailableReason.Untrusted => (
            "Канал управления подменён",
            "Имя канала службы занято посторонним процессом; команды ему не отправляются.",
            "Проверьте компьютер на вредоносные программы. Защиту не снимайте."),
        _ => (
            "Служба недоступна",
            "Команды не выполняются; защита, если была включена, сохраняется.",
            "Запустите службу кнопкой «Запустить» в блоке «Служба» внизу меню. «Диагностика» → «Восстановить сеть» снимет защиту с правами администратора."),
    };

    /// <summary>Отсрочка следующего опроса: неработающую службу не дёргать каждые 1,5 с, зависшую — проверять чаще.</summary>
    internal static TimeSpan Backoff(ServiceUnavailableReason reason, int failures) => reason switch
    {
        ServiceUnavailableReason.Timeout => TimeSpan.FromSeconds(5),
        ServiceUnavailableReason.Denied or ServiceUnavailableReason.VersionMismatch or ServiceUnavailableReason.Untrusted => TimeSpan.FromSeconds(60),
        _ => TimeSpan.FromSeconds(Math.Min(30, 1.5 * Math.Pow(2, Math.Max(0, failures - 1)))),
    };

    private string Speed(StatusDto status)
    {
        var now = DateTimeOffset.UtcNow;
        var text = "—";
        if (_lastBytes is { } last && status.State == ConnectionState.Connected && status.BytesSent >= last.Sent && status.BytesReceived >= last.Received)
        {
            var seconds = Math.Max(0.5, (now - last.Time).TotalSeconds);
            text = $"↑ {Format.Bytes((status.BytesSent - last.Sent) / seconds)}/с   ↓ {Format.Bytes((status.BytesReceived - last.Received) / seconds)}/с";
        }

        _lastBytes = (now, status.BytesSent, status.BytesReceived);
        return text;
    }

    /// <summary>Уведомления только о значимых сбоях и восстановлении (PLAN §6).</summary>
    private void NotifyTransitions(StatusDto? previous, StatusDto current)
    {
        if (previous is null || previous.State == current.State || !Preferences.Notifications)
        {
            return;
        }

        var text = (previous.State, current.State) switch
        {
            (ConnectionState.Connected, ConnectionState.Reconnecting) => ("VPN оборвался", current.OutageMode == OutageMode.AllowAll
                ? "До переподключения трафик идёт напрямую, без VPN."
                : "Трафик через VPN заблокирован до переподключения."),
            (ConnectionState.Reconnecting, ConnectionState.Connected) => ("VPN восстановлен", StatusText.Format(current)),
            (ConnectionState.Error or ConnectionState.TrafficBlocked or ConnectionState.PasswordRequired or ConnectionState.PartiallyApplied, ConnectionState.Connected)
                => ("VPN снова подключён", StatusText.Format(current)),
            (_, ConnectionState.DisconnectedExternally) => ("VPN отключён извне", "Защита сохранена. «Подключить» — чтобы подключиться снова."),
            (_, ConnectionState.Error) => ("Ошибка подключения", current.ErrorText ?? "Подробности на главной странице."),
            (_, ConnectionState.PasswordRequired) when current.Tunnels.FirstOrDefault(t => t.SignIn is not null) is { } signIn
                => ("Требуется вход", $"Войдите в «{signIn.Name}»: окно входа откроется само или по кнопке «Войти» на главной."),
            (_, ConnectionState.PasswordRequired) => ("Требуется пароль", "Введите пароль на главной странице."),
            (_, ConnectionState.PartiallyApplied) => ("Неполное применение", current.ErrorText ?? "Откройте «Диагностика»."),
            (_, ConnectionState.TrafficBlocked) => ("Трафик заблокирован", "Основной адаптер недоступен."),
            _ => default,
        };
        if (text != default)
        {
            Notify?.Invoke(text.Item1, text.Item2);
        }
    }

    /// <summary>Мастер предлагается один раз за запуск, если подключений нет: настройки не запрашиваются на каждом опросе.</summary>
    private async Task ShowWizardIfNeededAsync()
    {
        if (_wizardChecked || Wizard is not null || Preferences.WizardDismissed || Status?.ProfileName is not null)
        {
            return;
        }

        _wizardChecked = true;
        try
        {
            var settings = await Service.RequestAsync<AppSettings>(new GetSettingsRequest());
            if (settings.Profiles.Count == 0 && Wizard is null)
            {
                Wizard = new WizardViewModel(this);
            }
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or ServiceCommandException)
        {
            // Мастер покажем, когда служба станет доступна.
            _wizardChecked = false;
        }
    }

    [RelayCommand]
    public void OpenWizard() => Wizard = new WizardViewModel(this);

    /// <summary>Окно закрыто крестиком и спрятано в трей: один раз объясняем, где теперь пульт.</summary>
    public void OnHiddenToTray()
    {
        if (Preferences.TrayHintShown)
        {
            return;
        }

        Notify?.Invoke("«Раздельный VPN» работает в трее", "VPN и защита продолжают работать. Открыть окно — щелчок по значку; закрыть пульт — пункт меню значка.");
        SavePreferences(Preferences with { TrayHintShown = true });
    }

    public void CloseWizard(bool dismissForever)
    {
        Wizard = null;
        if (dismissForever)
        {
            SavePreferences(Preferences with { WizardDismissed = true });
        }
    }
}
