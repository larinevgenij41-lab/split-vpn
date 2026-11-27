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
    private long _statusGeneration;
    private bool _refreshPending;
    private int _failures;
    private readonly System.Diagnostics.Stopwatch _elapsed = System.Diagnostics.Stopwatch.StartNew();
    private TimeSpan _nextPollAt;
    private TimeSpan _lastPollAt = -HiddenPollInterval;
    private bool _wizardChecked;
    private bool _lossExpected;
    private (TimeSpan Time, ulong Sent, ulong Received)? _lastBytes;

    /// <summary>Одно и то же уведомление (вид и туннель) — не чаще раза в 5 минут: «мигающий» VPN не засыпает ими экран.</summary>
    internal static readonly TimeSpan NotificationRepeatInterval = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Предел повтора уведомлений о сбоях и о нужном действии (ошибка, вход, пароль, блокировка трафика, потеря службы):
    /// первое показывается всегда, повтор того же самого (вид и подключение) в течение минуты — нет. Мигающий Wi-Fi или
    /// служба, падающая по кругу, иначе выдавали бы уведомление на каждый круг.
    /// </summary>
    internal static readonly TimeSpan UrgentRepeatInterval = TimeSpan.FromMinutes(1);

    /// <summary>Обрыв короче этого — переподключение, а не сбой: пара «оборвался» и «восстановлен» не показывается.</summary>
    internal static readonly TimeSpan OutageNoticeDelay = TimeSpan.FromSeconds(30);

    private readonly TimeProvider _time;
    private readonly Dictionary<string, DateTimeOffset> _notifiedAt = [];

    /// <summary>Когда начался обрыв опорного VPN (Подключено → Переподключение); null — обрыва нет.</summary>
    private DateTimeOffset? _outageSince;

    /// <summary>Об идущем обрыве уже сообщено: о восстановлении тогда тоже сообщается.</summary>
    private bool _outageAnnounced;

    /// <summary>Ошибка команды подключения, показанная на странице: снимается, когда VPN подключился.</summary>
    private (PageViewModel Page, string Text)? _commandError;

    public MainViewModel(ServiceConnection service, UiPreferences preferences, TimeProvider? time = null)
    {
        _time = time ?? TimeProvider.System;
        _ui = SynchronizationContext.Current;
        Service = service;
        Emergency = new EmergencyViewModel(this);
        Emergency.PropertyChanged += OnEmergencyChanged;
        Service.EmergencyOffRefused += OnEmergencyOffRefused;
        Service.WaitingForDial += OnWaitingForDial;
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

    public Func<Guid, bool>? ActivateSignIn { get; set; }

    public ServiceConnection Service { get; }

    /// <summary>Экстренное выключение: состояние «выключена», команды выключения и включения, итог.</summary>
    public EmergencyViewModel Emergency { get; }

    /// <summary>Поток интерфейса: отказ «emergency-off» может прийти из фонового запроса.</summary>
    private readonly SynchronizationContext? _ui;

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

    /// <summary>«Подробный журнал до ЧЧ:ММ» в шапке; пусто — режим выключен.</summary>
    [ObservableProperty]
    private string _verboseBadge = "";

    [ObservableProperty]
    private string? _proxyError;

    /// <summary>Мастер первого запуска; null — не показывается.</summary>
    [ObservableProperty]
    private WizardViewModel? _wizard;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsWorking))]
    [NotifyPropertyChangedFor(nameof(ShowCommandProgress))]
    private PageViewModel _currentPage;

    [ObservableProperty]
    private StatusDto? _status;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowServiceRecovery), nameof(ShowServiceError), nameof(CanSendCommands), nameof(CanDisconnect))]
    [NotifyCanExecuteChangedFor(nameof(ConnectCommand), nameof(DisconnectCommand), nameof(DisconnectAndRestoreCommand), nameof(ToggleConnectionCommand))]
    private bool _serviceAvailable;

    [ObservableProperty]
    private string _serviceError = "";

    [ObservableProperty]
    private string _serviceErrorTitle = "Служба недоступна";

    /// <summary>Причина недоступности службы; null — служба отвечает.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowServiceRecovery), nameof(ShowServiceError))]
    private ServiceUnavailableReason? _unavailableReason;

    /// <summary>
    /// «Запустить службу» и «Перезапустить службу» рядом с ошибкой. После экстренного выключения не предлагаются: служба
    /// запустилась бы «пустой», а включает программу «Включить программу».
    /// </summary>
    public bool ShowServiceRecovery => !ServiceAvailable && !Emergency.IsOff
        && UnavailableReason is ServiceUnavailableReason.NotRunning or ServiceUnavailableReason.Timeout;

    /// <summary>
    /// Красная плашка «Служба недоступна»; после экстренного выключения вместо неё спокойный баннер. Только после
    /// неудачного опроса (известна причина): до первого ответа службы окно показывает «Подключение к службе…», а не ошибку
    /// рядом с блоком «Служба», где она «Работает».
    /// </summary>
    public bool ShowServiceError => !ServiceAvailable && UnavailableReason is not null && !Emergency.IsOff;

    [ObservableProperty]
    private string _stateText = "Подключение к службе…";

    [ObservableProperty]
    private string _summaryText = "";

    [ObservableProperty]
    private string _speedText = "—";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowCommandProgress))]
    private bool _showServiceProgress;

    [ObservableProperty]
    private string _serviceProgressStage = "";

    [ObservableProperty]
    private string _serviceProgressDetail = "";

    [ObservableProperty]
    private double _serviceProgressPercent;

    [ObservableProperty]
    private bool _serviceProgressIndeterminate;

    internal void ApplyProgress(ServiceProgressDto? progress)
    {
        ShowServiceProgress = progress is not null;
        ServiceProgressStage = progress is { Completed: { } done, Total: { } total }
            ? $"{progress.Stage}: {done} из {total}" : progress?.Stage ?? "";
        ServiceProgressPercent = Math.Clamp(progress?.Percent ?? 0, 0, 100);
        ServiceProgressIndeterminate = progress?.Percent is null;
        ServiceProgressDetail = progress is null ? "" :
            (progress.Percent is { } percent && progress.Total is null ? $"Примерно {Math.Clamp(percent, 0, 100)}% · " : "")
            + (progress.StartedUtc is null ? "Ожидание действия пользователя" : $"Этап выполняется {progress.ElapsedSeconds} с");
    }

    /// <summary>Идёт команда службе: остальные команды (в том числе из трея) недоступны, чтобы не было гонки.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ConnectCommand), nameof(DisconnectCommand), nameof(DisconnectAndRestoreCommand), nameof(ToggleConnectionCommand))]
    [NotifyPropertyChangedFor(nameof(IsWorking))]
    [NotifyPropertyChangedFor(nameof(ShowCommandProgress))]
    [NotifyPropertyChangedFor(nameof(CanDisconnect))]
    private bool _isBusy;

    /// <summary>
    /// Идущая команда отложена службой до конца дозвона и повторяется сама (до полутора минут). Отключение её не ждёт:
    /// «Отключить» и «Отключить и восстановить интернет» доступны, прекращают ожидание и выполняются сразу.
    /// </summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(DisconnectCommand), nameof(DisconnectAndRestoreCommand), nameof(ToggleConnectionCommand))]
    [NotifyPropertyChangedFor(nameof(CanDisconnect))]
    private bool _commandWaitingForDial;

    /// <summary>Ожидание дозвона идущей команды: «Отключить» прекращает его.</summary>
    private CancellationTokenSource? _commandDialWait;

    /// <summary>Завершается, когда идущая команда сняла <see cref="IsBusy"/>.</summary>
    private Task _commandDone = Task.CompletedTask;

    /// <summary>Что делает идущая команда словами («Подключение…»): надпись главной кнопки. null — команды нет.</summary>
    [ObservableProperty]
    private string? _busyAction;

    /// <summary>Идёт команда службе или действие открытой страницы: в шапке окна виден индикатор ожидания.</summary>
    public bool IsWorking => IsBusy || CurrentPage.IsBusy;

    public bool ShowCommandProgress => IsWorking && !ShowServiceProgress;

    /// <summary>Окно на экране: иначе ошибка команды (например, из трея) показывается уведомлением.</summary>
    public bool IsWindowVisible { get; set; }

    /// <summary>Уведомление о значимом событии для трея: текст, вид значка и страница, где нужно действие.</summary>
    public event Action<AppNotification>? Notify;

    /// <summary>Окно переводит навигацию на страницу модели; без окна страница просто становится текущей.</summary>
    public event Action<PageViewModel>? NavigationRequested;

    /// <summary>Показать главное окно (из трея оно может быть скрыто): подтверждение и итог должны быть видны.</summary>
    public Action? ShowWindow { get; set; }

    /// <summary>
    /// Отложенное действие в потоке интерфейса (скрытие сообщения об успехе). Возвращает отмену.
    /// По умолчанию — таймер диспетчера; тесты подставляют свой планировщик и не ждут реального времени.
    /// </summary>
    public Func<TimeSpan, Action, IDisposable> ScheduleUi { get; set; } = DispatcherDelay.Schedule;

    /// <summary>Щелчок по уведомлению: окно открывается там, где нужно действие, а для пароля — сразу в поле ввода.</summary>
    public void OpenNotificationTarget(AppNotification notification)
    {
        ArgumentNullException.ThrowIfNull(notification);
        ShowWindow?.Invoke();
        if (notification.Target is { } page)
        {
            NavigateTo(page);
        }

        if (notification.FocusPassword)
        {
            Home.PasswordFocusToken++;
        }
    }

    /// <summary>Страницы с несохранёнными правками в порядке меню: о них спрашивают перед выходом и установкой обновления.</summary>
    public IReadOnlyList<PageViewModel> PagesWithUnsavedChanges() => Pages.Where(p => p.HasUnsavedChanges).ToList();

    /// <summary>
    /// Перед выходом или установкой обновления: есть несохранённые правки — подтверждение со списком страниц.
    /// Отказ открывает окно на первой такой странице. true — можно продолжать.
    /// </summary>
    public async Task<bool> ConfirmDiscardUnsavedAsync(bool forUpdate = false)
    {
        var pages = PagesWithUnsavedChanges();
        if (pages.Count == 0)
        {
            return true;
        }

        ShowWindow?.Invoke();
        var names = string.Join(", ", pages.Select(p => "«" + p.Title + "»"));
        if (await Confirm("Есть несохранённые изменения",
                $"Не сохранены: {names}. " + (forUpdate
                    ? "При установке обновления приложение закроется, и они будут потеряны."
                    : "При закрытии они будут потеряны."),
                forUpdate ? "Установить без сохранения" : "Закрыть без сохранения"))
        {
            return true;
        }

        NavigateTo(pages[0]);
        return false;
    }

    /// <summary>
    /// Окно загружено и его меню может переходить по страницам. До первого показа (запуск в трей) переход только
    /// запоминается в <see cref="CurrentPage"/>: окно откроется на ней, а не на главной.
    /// </summary>
    public bool NavigationReady { get; set; }

    public void NavigateTo(PageViewModel page)
    {
        if (NavigationReady && NavigationRequested is { } handler)
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
        // Первая страница (главная) выбрана в конструкторе: смены страницы не было, и её загрузка при открытии
        // иначе не выполнилась бы до первого перехода на другую страницу и обратно.
        _ = CurrentPage.OnOpenedAsync();
    }

    /// <summary>Опрос без ожидания отсрочки: пользователь открыл окно или дал команду.</summary>
    public Task RefreshAsync()
    {
        _nextPollAt = TimeSpan.Zero;
        return PollAsync(force: true);
    }

    /// <summary>Пока идёт остановка или перезапуск службы по команде пользователя, потеря связи — без уведомления.</summary>
    public void ExpectServiceLoss(bool expected) => _lossExpected = expected;

    internal bool ServiceLossExpected => _lossExpected;

    public void Dispose()
    {
        _timer.Stop();
        foreach (var page in Pages)
        {
            page.PropertyChanged -= OnPageChanged;
        }

        Service.EmergencyOffRefused -= OnEmergencyOffRefused;
        Service.WaitingForDial -= OnWaitingForDial;
        Emergency.PropertyChanged -= OnEmergencyChanged;

        ServiceHost.Dispose();
    }

    /// <summary>Занятость открытой страницы — часть общей: индикатор в шапке один на окно.</summary>
    private void OnPageChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(PageViewModel.IsBusy) && ReferenceEquals(sender, CurrentPage))
        {
            OnPropertyChanged(nameof(IsWorking));
            OnPropertyChanged(nameof(ShowCommandProgress));
        }
    }

    /// <summary>Запись настроек интерфейса: (новые, исходные) → записанные с учётом правок другой копии приложения.</summary>
    internal Func<UiPreferences, UiPreferences, UiPreferences> WritePreferences { get; set; } = static (preferences, baseline) => preferences.SaveChanges(baseline);

    /// <summary>Применение темы; тесты подставляют своё — без окна приложения тему применять некуда.</summary>
    internal Action<ThemeChoice> ApplyTheme { get; set; } = ThemeService.Apply;

    /// <summary>Неожиданная ошибка, уже показанная пользователю, — в журнал ошибок интерфейса; тесты подставляют своё.</summary>
    internal Action<Exception> RecordError { get; set; } = App.RecordHandled;

    /// <summary>Настройки интерфейса в том виде, в каком последними записаны (или прочитаны): от них считаются правки.</summary>
    private UiPreferences? _savedPreferences;

    private bool _preferencesWriting;
    private bool _preferencesWritePending;

    /// <summary>Завершается, когда записаны все изменения настроек интерфейса (для проверок и выхода).</summary>
    internal Task PreferencesWritten { get; private set; } = Task.CompletedTask;

    /// <summary>
    /// Дождаться записи настроек интерфейса не дольше <paramref name="limit"/> (перед выходом); false — не дождались.
    /// Только асинхронно: продолжение записи возвращается в поток интерфейса, блокирующее ожидание его не пустило бы.
    /// </summary>
    internal async Task<bool> WaitPreferencesWrittenAsync(TimeSpan limit)
    {
        var written = PreferencesWritten;
        if (written.IsCompleted)
        {
            return true;
        }

        using var timeout = new CancellationTokenSource();
        var finished = await Task.WhenAny(written, Task.Delay(limit, timeout.Token)) == written;
        await timeout.CancelAsync();
        return finished;
    }

    /// <summary>Идущая запись настроек интерфейса на диск (вне потока интерфейса), без её продолжения в нём.</summary>
    private Task _preferencesDiskWrite = Task.CompletedTask;

    /// <summary>
    /// Блокирующее ожидание идущей записи настроек на диск не дольше <paramref name="limit"/> — для выхода из Windows,
    /// где обработчик синхронный. Ждётся только сама фоновая запись: потока интерфейса ей не нужно, взаимоблокировки
    /// нет. Запись, ждущая очереди (повторное переключение во время записи), так не выполнится. false — не дождались.
    /// </summary>
    internal bool WaitPreferencesDiskWrite(TimeSpan limit)
    {
        try
        {
            return _preferencesDiskWrite.Wait(limit);
        }
        catch (AggregateException)
        {
            // Запись закончилась сбоем: ждать больше нечего, сбой разбирает её продолжение.
            return true;
        }
    }

    /// <summary>
    /// Изменение настроек интерфейса действует сразу, а запись идёт вне потока интерфейса: межпроцессные замки
    /// (<see cref="UiPreferences.SaveChanges"/>) ждутся до нескольких секунд, и окно не должно замирать. Записи идут по
    /// одной и по порядку: быстрые повторные переключения не обгоняют друг друга, а записывается последнее состояние.
    /// Сбой записи возвращает последнее записанное, как прежде, и показывает ошибку.
    /// </summary>
    public void SavePreferences(UiPreferences preferences)
    {
        ArgumentNullException.ThrowIfNull(preferences);
        _savedPreferences ??= Preferences;
        ShowPreferences(preferences);
        _preferencesWritePending = true;
        if (!_preferencesWriting)
        {
            PreferencesWritten = WritePreferencesAsync();
        }
    }

    private void ShowPreferences(UiPreferences preferences)
    {
        Preferences = preferences;
        Settings.LoadPreferences(preferences);
        ApplyTheme(preferences.Theme);
    }

    private async Task WritePreferencesAsync()
    {
        _preferencesWriting = true;
        try
        {
            while (_preferencesWritePending)
            {
                _preferencesWritePending = false;
                var desired = Preferences;
                // От последнего записанного, а не от промежуточного: правка, запись которой не удалась, войдёт в следующую.
                var baseline = _savedPreferences!;
                var write = WritePreferences;
                try
                {
                    var diskWrite = Task.Run(() => write(desired, baseline));
                    _preferencesDiskWrite = diskWrite;
                    var merged = await diskWrite;
                    _savedPreferences = merged;
                    // Другая копия приложения могла поменять другие настройки: показывается записанное. Переключения,
                    // сделанные здесь во время записи, переносятся поверх него — иначе следующая запись вернула бы
                    // на диск прежнее значение настройки, которую поменяла другая копия.
                    var shown = _preferencesWritePending ? Preferences.ChangesOnto(desired, merged) : merged;
                    if (shown != Preferences)
                    {
                        ShowPreferences(shown);
                    }
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    var busy = ex is System.IO.IOException or UnauthorizedAccessException;
                    SplitVpn.Core.Diagnostics.Verbose.Write("Ui", "настройки интерфейса не сохранены: " + ex.GetType().Name + " «" + ex.Message + "»");
                    if (!busy)
                    {
                        // Неожиданный сбой (в том числе применения темы) не должен обрывать запись молча.
                        RecordError(ex);
                    }

                    if (!_preferencesWritePending)
                    {
                        CurrentPage.ShowError(busy
                            ? "Не удалось сохранить настройки интерфейса: файл настроек занят другой копией приложения или недоступен. Повторите через несколько секунд."
                            : "Не удалось сохранить настройки интерфейса из-за внутренней ошибки. Повторите; подробности — в журнале ошибок интерфейса.");
                        RevertPreferences();
                    }
                }
            }
        }
        finally
        {
            _preferencesWriting = false;
        }
    }

    /// <summary>Вернуть последнее записанное; сбой показа здесь — тоже в журнал, запись настроек продолжается.</summary>
    private void RevertPreferences()
    {
        try
        {
            ShowPreferences(_savedPreferences!);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            RecordError(ex);
        }
    }

    partial void OnCurrentPageChanged(PageViewModel value)
    {
        value.ClearSuccessMessage();
        _ = value.OnOpenedAsync();
    }

    [RelayCommand]
    private void Navigate(PageViewModel page) => NavigateTo(page);

    /// <summary>
    /// Команды службе недоступны, пока идёт другая, служба не отвечает или останавливается, или программа экстренно выключена.
    /// </summary>
    private bool CanRunCommand => !IsBusy && CanSendCommands && !Emergency.IsOff;

    /// <summary>Служба отвечает и не останавливается: главной кнопке есть кому отправить команду.</summary>
    public bool CanSendCommands => ServiceAvailable && !ServiceHost.IsStopping;

    /// <summary>
    /// «Отключить» и «Отключить и восстановить интернет» доступны и тогда, когда идущая команда только ждёт конца дозвона
    /// (<see cref="CommandWaitingForDial"/>): отключение прекращает это ожидание.
    /// </summary>
    public bool CanDisconnect => (!IsBusy || CommandWaitingForDial) && CanSendCommands && !Emergency.IsOff;

    /// <summary>Главная кнопка: как прочие команды, но отключение доступно и во время ожидания дозвона.</summary>
    private bool CanToggleConnection => CanRunCommand || (CanDisconnect && IsConnectedIntent(Status));

    /// <summary>
    /// Главная команда во время ожидания дозвона зависит от намерения в статусе (например, другая копия отключила VPN).
    /// Уведомление — только при смене намерения: статус приходит с каждым опросом.
    /// </summary>
    partial void OnStatusChanged(StatusDto? oldValue, StatusDto? newValue)
    {
        if (IsConnectedIntent(oldValue) != IsConnectedIntent(newValue))
        {
            ToggleConnectionCommand.NotifyCanExecuteChanged();
        }
    }

    /// <summary>Состояние службы Windows сменилось: «Подключить» недоступна, пока служба останавливается.</summary>
    internal void OnServiceHostChanged()
    {
        OnPropertyChanged(nameof(CanSendCommands));
        OnPropertyChanged(nameof(CanDisconnect));
        ConnectCommand.NotifyCanExecuteChanged();
        DisconnectCommand.NotifyCanExecuteChanged();
        DisconnectAndRestoreCommand.NotifyCanExecuteChanged();
        ToggleConnectionCommand.NotifyCanExecuteChanged();
        // Диспетчер служб мог сообщить «не установлена» уже после неудачного опроса: баннер и «Запустить службу» — по нему.
        if (!ServiceAvailable && UnavailableReason == ServiceUnavailableReason.NotRunning)
        {
            var (title, text, advice) = Describe(ServiceUnavailableReason.NotRunning, ServiceHost.IsNotInstalled);
            ServiceErrorTitle = title;
            ServiceError = $"{text} {advice}";
            StateText = title;
            SummaryText = text;
            ApplyEmergencyText();
        }

        Diagnostics.OnEmergencyChanged();
    }

    /// <summary>«Подключить» и «Повторить»: служба сбрасывает остановленные повторы и дозванивается заново.</summary>
    [RelayCommand(CanExecute = nameof(CanRunCommand))]
    private Task<bool> ConnectAsync() => RunCommandAsync(new ConnectRequest(null, null));

    /// <summary>«Отключить»: VPN разрывается, защита остаётся — трафик VPN заблокирован.</summary>
    [RelayCommand(CanExecute = nameof(CanDisconnect))]
    private Task<bool> DisconnectAsync() => RunCommandAsync(new DisconnectRequest(KeepProtection: true));

    /// <summary>
    /// «Отключить и восстановить интернет»: снимаются фильтры, маршруты, DNS. Защита ослабляется — как и «Восстановить
    /// сеть» в «Диагностике», действие подтверждается.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanDisconnect))]
    private async Task<bool> DisconnectAndRestoreAsync()
    {
        if (!await Confirm("Снять защиту?",
                "VPN отключится, а маршруты, фильтры и DNS вернутся к исходным — весь трафик пойдёт напрямую через провайдера. "
                + "Вернуть защиту можно кнопкой «Подключить».",
                "Снять защиту"))
        {
            return false;
        }

        return await RunCommandAsync(new DisconnectRequest(KeepProtection: false));
    }

    [RelayCommand(CanExecute = nameof(CanToggleConnection))]
    private Task<bool> ToggleConnectionAsync() => RunCommandAsync(IsConnectedIntent(Status)
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
    public async Task<bool> RunCommandAsync(IpcRequest request)
    {
        var origin = CurrentPage;
        if (IsBusy && request is DisconnectRequest && CommandWaitingForDial && _commandDialWait is { } wait)
        {
            // Идущая команда лишь ждёт конца дозвона (служба её ещё не выполнила): ожидание прекращается, и отключение
            // начинается, как только та команда сняла занятость, — а не через полторы минуты повторов. Ждётся именно
            // она: пока шла отмена, могла начаться следующая команда.
            var waited = _commandDone;
            CommandWaitingForDial = false;
            await wait.CancelAsync();
            await waited;
        }

        if (IsBusy)
        {
            origin.ShowError("Другая команда ещё выполняется. Повторите после её завершения.");
            return false;
        }

        IsBusy = true;
        BusyAction = ActionText(request);
        var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _commandDone = done.Task;
        using var dialWait = new CancellationTokenSource();
        _commandDialWait = dialWait;
        var accepted = false;
        try
        {
            var response = await Service.SendAsync(request, waiting => OnUi(() =>
            {
                // Поздний сигнал от уже завершённой команды не открывает отключение.
                if (ReferenceEquals(_commandDialWait, dialWait) && !dialWait.IsCancellationRequested)
                {
                    CommandWaitingForDial = waiting;
                }
            }), dialWait.Token);
            _statusGeneration++;
            accepted = response.Ok;
            // Отказ «программа экстренно выключена» показывает баннер (ServiceConnection.EmergencyOffRefused), а не ошибку.
            if (!response.Ok && response.ErrorCode == IpcErrorCodes.DialInProgress && dialWait.IsCancellationRequested)
            {
                ShowCommandError(origin, DialWaitCancelledText);
            }
            else if (!response.Ok && response.ErrorCode != IpcErrorCodes.EmergencyOff)
            {
                ShowCommandError(origin, UiText.ServiceRejected(response, "Служба отклонила команду."));
            }
            else if (Service.ResultOf<StatusDto>(response) is { } status)
            {
                ApplyStatus(status);
            }
        }
        catch (ServiceUnavailableException ex)
        {
            ShowCommandError(origin, ex.Message);
        }
        catch (ServiceCommandException ex)
        {
            // Запрос не отправлен (например, слишком большой): служба доступна, ошибка относится к команде.
            ShowCommandError(origin, ex.Message);
        }
        finally
        {
            _statusGeneration++;
            _commandDialWait = null;
            CommandWaitingForDial = false;
            IsBusy = false;
            BusyAction = null;
            done.TrySetResult();
        }

        await RefreshAsync();
        return accepted;
    }

    /// <summary>Надпись главной кнопки на время команды: видно, что идёт, а не просто недоступная кнопка.</summary>
    private static string? ActionText(IpcRequest request) => request switch
    {
        ConnectRequest => "Подключение…",
        DisconnectRequest => "Отключение…",
        _ => null,
    };

    private void ShowCommandError(PageViewModel origin, string text)
    {
        origin.ShowError(text);
        _commandError = (origin, text);
        if (!IsWindowVisible || CurrentPage != origin)
        {
            // Ответ на действие пользователя: уведомление показывается независимо от настройки уведомлений о сбоях.
            Notify?.Invoke(new AppNotification("Команда не выполнена", text, NotificationKind.Error, origin));
        }
    }

    /// <summary>VPN подключился: прежняя ошибка команды подключения больше не верна и снимается.</summary>
    private void ClearStaleCommandError(StatusDto? previous, StatusDto current)
    {
        if (current.State != ConnectionState.Connected || previous?.State == ConnectionState.Connected || _commandError is not { } error)
        {
            return;
        }

        if (error.Page.Message == error.Text && error.Page.MessageIsError)
        {
            error.Page.Message = null;
        }

        _commandError = null;
    }

    private async Task PollAsync(bool force = false)
    {
        var now = _elapsed.Elapsed;
        if (_polling && force) { _refreshPending = true; }
        if (_polling || (!force && now < _nextPollAt) || (!force && !IsWindowVisible && now - _lastPollAt < HiddenPollInterval))
        {
            return;
        }

        _polling = true;
        var generation = _statusGeneration;
        _lastPollAt = now;
        try
        {
            var status = await Service.RequestAsync<StatusDto>(new GetStatusRequest());
            if (generation == _statusGeneration) { ApplyStatus(status); }
        }
        catch (ServiceUnavailableException ex)
        {
            if (generation == _statusGeneration && _responsiveness.OnFailure(ex.Reason, DateTimeOffset.UnixEpoch + _elapsed.Elapsed))
            {
                ApplyUnavailable(ex);
            }
        }
        catch (ServiceCommandException ex)
        {
            // Неверный запрос — служба другой версии; иной отказ (ответ не передан, сбой) — ошибка службы той же версии.
            if (generation == _statusGeneration)
            {
                ApplyUnavailable(new ServiceUnavailableException(ex.Message, ex,
                    ex.ErrorCode == IpcErrorCodes.BadRequest ? ServiceUnavailableReason.VersionMismatch : ServiceUnavailableReason.Faulted));
            }
        }
        finally
        {
            _polling = false;
        }
        if (_refreshPending)
        {
            _refreshPending = false;
            await PollAsync(force: true);
        }
    }

    private void ApplyStatus(StatusDto status)
    {
        var previous = Status;
        _responsiveness.OnSuccess(DateTimeOffset.UnixEpoch + _elapsed.Elapsed);
        _failures = 0;
        _nextPollAt = TimeSpan.Zero;
        Emergency.ApplyStatus(status);
        ServiceAvailable = true;
        ServiceError = "";
        UnavailableReason = null;
        UiVerbose.Apply(status.VerboseUntilUtc);
        UpdateVerboseBadge();
        Status = status;
        ApplyProgress(status.Progress);
        StateText = StatusText.StateName(status.State);
        SummaryText = UiText.StatusSummary(status);
        ApplyEmergencyText();
        SpeedText = Speed(status);
        ClearStaleCommandError(previous, status);
        NotifyTransitions(previous, status);
        foreach (var page in Pages)
        {
            page.OnStatus(status);
        }

        StatusUpdated?.Invoke();
        _ = ShowWizardIfNeededAsync();
        _ = PruneSignInProfilesOnceAsync();
    }

    private bool _signInProfilesPruned;

    /// <summary>
    /// Один раз за запуск, после того как служба отдала настройки: профили встроенного браузера (cookie и вход SSO)
    /// подключений, которых в настройках больше нет, удаляются вне потока интерфейса. Настройки не получены — ничего
    /// не удаляется, попытка повторится при следующем опросе.
    /// </summary>
    private async Task PruneSignInProfilesOnceAsync()
    {
        if (_signInProfilesPruned)
        {
            return;
        }

        _signInProfilesPruned = true;
        try
        {
            var settings = await Service.RequestAsync<AppSettings>(new GetSettingsRequest());
            var ids = settings.Profiles.Select(p => p.Id).ToHashSet();
            await SignInProfileWork.RunAsync(profiles => profiles.PruneOrphans(ids));
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or ServiceCommandException)
        {
            _signInProfilesPruned = false;
        }
    }

    private void UpdateVerboseBadge() =>
        VerboseBadge = UiVerbose.Until is { } until ? $"Подробный журнал до {until.ToLocalTime():HH:mm}" : "";

    /// <summary>Программа экстренно выключена: в шапке меню, на главной и в трее — это, а не «Служба недоступна».</summary>
    private void ApplyEmergencyText()
    {
        if (Emergency.IsOff)
        {
            StateText = UiText.EmergencyStateText;
            SummaryText = UiText.EmergencySummaryText;
        }
    }

    private void OnEmergencyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(EmergencyViewModel.IsOff))
        {
            return;
        }

        OnPropertyChanged(nameof(ShowServiceRecovery));
        OnPropertyChanged(nameof(ShowServiceError));
        OnPropertyChanged(nameof(CanDisconnect));
        ConnectCommand.NotifyCanExecuteChanged();
        DisconnectCommand.NotifyCanExecuteChanged();
        DisconnectAndRestoreCommand.NotifyCanExecuteChanged();
        ToggleConnectionCommand.NotifyCanExecuteChanged();
        ServiceHost.OnEmergencyChanged();
        ApplyEmergencyText();
        Home.ApplyEmergency();
        Diagnostics.OnEmergencyChanged();
    }

    /// <summary>Длиннее предела автоскрытия: ожидание дозвона длится до полутора минут, и сообщение не должно пропасть раньше.</summary>
    internal const string SavingAfterDialText = "Сохраняю после завершения дозвона… Изменения будут приняты, как только подключение завершится (до полутора минут).";

    /// <summary>Отложенную до конца дозвона команду прервало отключение: служба её не выполнила.</summary>
    internal const string DialWaitCancelledText = "Изменение не сохранено: ожидание конца дозвона прервано отключением. Повторите его после отключения.";

    /// <summary>Действие в потоке интерфейса: сразу, если вызвано в нём, иначе — следом в его очереди.</summary>
    private void OnUi(Action action)
    {
        if (_ui is null || SynchronizationContext.Current == _ui)
        {
            action();
        }
        else
        {
            _ui.Post(_ => action(), null);
        }
    }

    /// <summary>
    /// Служба отложила изменение настроек до конца дозвона, а приложение повторяет команду само: вместо ошибки
    /// открытая страница (или мастер) показывает, что сохранение ждёт. Итог команды потом заменит это сообщение.
    /// </summary>
    private void OnWaitingForDial(bool waiting)
    {
        void Show()
        {
            if (Wizard is { } wizard)
            {
                if (waiting) { wizard.Progress = SavingAfterDialText; }
                return;
            }

            if (waiting)
            {
                CurrentPage.ShowInfo(SavingAfterDialText);
            }
            else if (CurrentPage.Message == SavingAfterDialText)
            {
                CurrentPage.ClearSuccessMessage();
            }
        }

        if (_ui is null || SynchronizationContext.Current == _ui)
        {
            Show();
        }
        else
        {
            _ui.Post(_ => Show(), null);
        }
    }

    /// <summary>Служба отказала с кодом «emergency-off»: показываем состояние «выключена», а не ошибку.</summary>
    private void OnEmergencyOffRefused()
    {
        if (_ui is null || SynchronizationContext.Current == _ui)
        {
            Emergency.OnRefused();
        }
        else
        {
            _ui.Post(_ => Emergency.OnRefused(), null);
        }
    }

    private void ApplyUnavailable(ServiceUnavailableException error)
    {
        // Уведомление — только о потере уже работавшей службы: при входе в Windows она может стартовать позже интерфейса.
        // Остановку или перезапуск из блока «Служба» пользователь сделал сам — о ней не уведомляем.
        // После экстренного выключения служба остановлена намеренно: о «потере» не уведомляем, вместо ошибки — баннер.
        Emergency.ApplyUnavailable();
        var lost = ServiceAvailable && Status is not null && !_lossExpected && !Emergency.IsOff;
        UiVerbose.RefreshFromRegistry();
        UpdateVerboseBadge();
        _failures++;
        _nextPollAt = _elapsed.Elapsed + Backoff(error.Reason, _failures);
        var (title, text, advice) = Describe(error.Reason, ServiceHost.IsNotInstalled);
        if (lost && Preferences.Notifications)
        {
            // Служба, падающая по кругу, теряется на каждом круге: одно уведомление о той же причине в минуту.
            Emit(ServiceLostKey + error.Reason, new AppNotification(title, advice, NotificationKind.Warning, null), _time.GetUtcNow(), UrgentRepeatInterval);
        }

        ServiceAvailable = false;
        UnavailableReason = error.Reason;
        ServiceErrorTitle = title;
        ServiceError = error.Reason == ServiceUnavailableReason.Faulted ? $"{text} {error.Message} {advice}" : $"{text} {advice}";
        Status = null;
        ApplyProgress(null);
        StateText = title;
        SummaryText = text;
        ApplyEmergencyText();
        SpeedText = "—";
        _lastBytes = null;
        foreach (var page in Pages)
        {
            page.OnStatus(null);
        }

        StatusUpdated?.Invoke();
    }

    /// <summary>Заголовок, состояние и совет по причине недоступности. Восстановление сети советуется только там, где оно поможет.</summary>
    /// <param name="notInstalled">
    /// Служба Windows не установлена (по диспетчеру служб): канал так же не открывается, как у остановленной, но
    /// «Запустить службу» здесь бесполезна — нужна переустановка программы.
    /// </param>
    internal static (string Title, string Text, string Advice) Describe(ServiceUnavailableReason reason, bool notInstalled = false) => reason switch
    {
        ServiceUnavailableReason.NotRunning when notInstalled => (
            "Служба не установлена",
            "Служба «Раздельный VPN» не установлена на этом компьютере; команды не выполняются.",
            "Переустановите программу: установщик установит и запустит службу."),
        ServiceUnavailableReason.Timeout => (
            "Служба не отвечает",
            "Состояние могло устареть; команды не выполняются.",
            "Если служба не отвечает дольше минуты, нажмите «Перезапустить службу» ниже. Подробности доступны в «Диагностике»."),
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
        ServiceUnavailableReason.Faulted => (
            "Служба ответила ошибкой",
            "Служба работает, но не передала состояние; защита работает как прежде.",
            "Если ошибка повторяется, соберите архив в «Диагностике» и перезапустите службу."),
        _ => (
            "Служба недоступна",
            "Команды не выполняются; защита, если была включена, сохраняется.",
            "Если служба остановлена, нажмите «Запустить службу» ниже. Для этого Windows запросит права администратора."),
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
        var now = _elapsed.Elapsed;
        var text = "—";
        if (_lastBytes is { } last && status.State == ConnectionState.Connected && status.BytesSent >= last.Sent && status.BytesReceived >= last.Received)
        {
            var seconds = Math.Max(TimeSpan.FromTicks(1).TotalSeconds, (now - last.Time).TotalSeconds);
            text = $"↑ {Format.Bytes((status.BytesSent - last.Sent) / seconds)}/с   ↓ {Format.Bytes((status.BytesReceived - last.Received) / seconds)}/с";
        }

        _lastBytes = (now, status.BytesSent, status.BytesReceived);
        return text;
    }

    /// <summary>
    /// Уведомления только о значимых сбоях и восстановлении (PLAN §6). Короткий обрыв опорного VPN (до
    /// <see cref="OutageNoticeDelay"/>) — одно «VPN переподключился», а не пара «оборвался»/«восстановлен». Одно и то же
    /// уведомление повторяется не чаще <see cref="NotificationRepeatInterval"/>. Уведомления, требующие действия
    /// (пароль, вход, ошибка, заблокированный трафик, неполное применение), ограничены коротким
    /// <see cref="UrgentRepeatInterval"/>: первое показывается всегда, подавляется только повтор того же самого.
    /// </summary>
    private void NotifyTransitions(StatusDto? previous, StatusDto current)
    {
        var now = _time.GetUtcNow();
        if (previous is null)
        {
            _outageSince = null;
            _outageAnnounced = false;
            return;
        }

        var outageAnnounced = _outageAnnounced;
        if (previous.State == ConnectionState.Connected && current.State == ConnectionState.Reconnecting)
        {
            _outageSince = now;
            _outageAnnounced = false;
        }
        else if (current.State != ConnectionState.Reconnecting)
        {
            _outageSince = null;
            _outageAnnounced = false;
        }

        if (!Preferences.Notifications)
        {
            return;
        }

        // Обрыв затянулся: теперь это сбой, о нём стоит знать.
        if (current.State == ConnectionState.Reconnecting && _outageSince is { } since && !_outageAnnounced && now - since >= OutageNoticeDelay)
        {
            Emit("outage", new AppNotification("VPN оборвался", current.OutageMode == OutageMode.AllowAll
                ? "До переподключения трафик идёт напрямую, без VPN."
                : "Трафик через VPN заблокирован до переподключения.", NotificationKind.Warning, Home), now);
            // Обрыв затянулся, даже если повтор уведомления подавлен пределом: восстановление — «VPN восстановлен»,
            // а не «ненадолго прерывалась», и попытка не повторяется на каждом опросе.
            _outageAnnounced = true;
        }

        if (previous.State == current.State)
        {
            var connected = previous.Tunnels.Where(t => t.State == ConnectionState.Connected).Select(t => t.ProfileId).ToHashSet();
            foreach (var tunnel in current.Tunnels.Where(t => connected.Contains(t.ProfileId) && !t.Paused && t.State is ConnectionState.Error or ConnectionState.Reconnecting or ConnectionState.DisconnectedExternally))
            {
                var notification = new AppNotification($"Прервалось подключение «{tunnel.Name}»", StatusText.StateName(tunnel.State),
                    tunnel.State == ConnectionState.Error ? NotificationKind.Error : NotificationKind.Warning, Home);
                if (tunnel.State == ConnectionState.Error)
                {
                    // Ошибка мигающего дополнительного туннеля — не на каждый переход: одна в минуту на подключение.
                    Emit("tunnel-error:" + tunnel.ProfileId, notification, now, UrgentRepeatInterval);
                }
                else
                {
                    Emit("tunnel:" + tunnel.ProfileId, notification, now);
                }
            }

            return;
        }

        (string? Key, AppNotification? Notice) choice = (previous.State, current.State) switch
        {
            // Об обрыве — позже и только если он затянулся (см. выше).
            (ConnectionState.Connected, ConnectionState.Reconnecting) => (null, null),
            (ConnectionState.Reconnecting, ConnectionState.Connected) when outageAnnounced
                => ("restored", new AppNotification("VPN восстановлен", UiText.StatusSummary(current), NotificationKind.Info, Home)),
            (ConnectionState.Reconnecting, ConnectionState.Connected)
                => ("reconnected", new AppNotification("VPN переподключился", "Связь ненадолго прерывалась и восстановилась сама.", NotificationKind.Info, Home)),
            (ConnectionState.Error or ConnectionState.TrafficBlocked or ConnectionState.PasswordRequired or ConnectionState.PartiallyApplied, ConnectionState.Connected)
                => ("connected-again", new AppNotification("VPN снова подключён", UiText.StatusSummary(current), NotificationKind.Info, Home)),
            (_, ConnectionState.DisconnectedExternally)
                => ("external", new AppNotification("VPN отключён извне", "Защита сохранена. «Подключить» — чтобы подключиться снова.", NotificationKind.Warning, Home)),
            // Сбои и нужные действия — с коротким пределом (UrgentRepeatInterval): ключ — вид и подключение (и текст
            // ошибки), поэтому подавляется только повтор того же самого, а вход в другое подключение или новая ошибка
            // показываются сразу.
            (_, ConnectionState.Error)
                => ($"error:{current.ProfileName}:{current.ErrorText}", new AppNotification("Ошибка подключения", current.ErrorText ?? "Подробности на главной странице.", NotificationKind.Error, Home)),
            (_, ConnectionState.PasswordRequired) when current.Tunnels.FirstOrDefault(t => t.SignIn is not null) is { } signIn
                => ("signin:" + signIn.ProfileId, new AppNotification("Требуется вход", $"Войдите в «{signIn.Name}»: окно входа откроется само или по кнопке «Войти» на главной.", NotificationKind.Warning, Home)),
            (_, ConnectionState.PasswordRequired)
                => ("password:" + (current.Tunnels.FirstOrDefault(t => t.State == ConnectionState.PasswordRequired)?.ProfileId.ToString() ?? current.ProfileName),
                    new AppNotification("Требуется пароль", "Введите пароль на главной странице.", NotificationKind.Warning, Home, FocusPassword: true)),
            (_, ConnectionState.PartiallyApplied)
                => ("partial:" + current.ErrorText, new AppNotification("Неполное применение", current.ErrorText ?? "Откройте «Диагностику».", NotificationKind.Error, Diagnostics)),
            (_, ConnectionState.TrafficBlocked)
                => ("blocked", new AppNotification("Трафик заблокирован", "Основной адаптер недоступен.", NotificationKind.Error, Home)),
            _ => (null, null),
        };
        if (choice.Notice is { } notice)
        {
            Emit(choice.Key, notice, now, current.State is ConnectionState.Error or ConnectionState.PasswordRequired
                or ConnectionState.PartiallyApplied or ConnectionState.TrafficBlocked ? UrgentRepeatInterval : NotificationRepeatInterval);
        }
    }

    /// <summary>Уведомления о восстановлении опорного VPN: после показанного такого повтор сбоя уже не «тот же самый».</summary>
    private static readonly string[] RecoveryKeys = ["connected-again", "restored", "reconnected"];

    /// <summary>Ключи (префиксы) сбоев опорного VPN, которые снимает показанное уведомление о восстановлении.</summary>
    private static readonly string[] RecoverableKeys = ["blocked", "error:", "partial:", "password:", "signin:", "outage"];

    private const string ServiceLostKey = "service-lost:";

    private static readonly string[] ServiceLostKeys = [ServiceLostKey];

    /// <summary>
    /// Показывает уведомление, если такое же (тот же ключ) не показывалось в течение <paramref name="window"/> (по
    /// умолчанию <see cref="NotificationRepeatInterval"/>). null — без предела.
    /// Подавляется только повтор, после которого пользователь не видел противоположного: показанное «снова подключён»
    /// («восстановлен», «переподключился») снимает ключи сбоев опорного VPN, и следующая блокировка или ошибка
    /// показывается сразу, — иначе последним осталось бы «снова подключён» при заблокированном трафике. Само уведомление
    /// о восстановлении ограничено своим пределом (5 минут): пока оно подавлено, ключи не снимаются, и при мигании
    /// пользователь видит «сбой → восстановлен → сбой», а не пару на каждом круге; последним остаётся сбой — сторона
    /// осторожности. Любое уведомление о состоянии значит, что служба отвечала: потеря службы после него — снова новость.
    /// </summary>
    private bool Emit(string? key, AppNotification notification, DateTimeOffset now, TimeSpan? window = null)
    {
        if (key is not null)
        {
            if (_notifiedAt.TryGetValue(key, out var shown) && now - shown < (window ?? NotificationRepeatInterval))
            {
                return false;
            }

            if (RecoveryKeys.Contains(key, StringComparer.Ordinal))
            {
                ForgetKeys(RecoverableKeys);
            }

            if (!key.StartsWith(ServiceLostKey, StringComparison.Ordinal))
            {
                ForgetKeys(ServiceLostKeys);
            }

            _notifiedAt[key] = now;
        }

        Notify?.Invoke(notification);
        return true;
    }

    private void ForgetKeys(string[] prefixes)
    {
        foreach (var stale in _notifiedAt.Keys.Where(k => prefixes.Any(p => k.StartsWith(p, StringComparison.Ordinal))).ToList())
        {
            _notifiedAt.Remove(stale);
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

        Notify?.Invoke(new AppNotification("«Раздельный VPN» работает в трее",
            "VPN и защита продолжают работать. Открыть окно — щелчок по значку; закрыть пульт — пункт меню значка.", NotificationKind.Info, null));
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

/// <summary>Вид всплывающего уведомления: значок сообщает, насколько оно важно.</summary>
public enum NotificationKind
{
    Info,
    Warning,
    Error,
}

/// <summary>
/// Уведомление трея. <paramref name="Target"/> — страница, где нужно действие (null — окно открывается как есть),
/// <paramref name="FocusPassword"/> — по щелчку фокус сразу в поле пароля на главной.
/// </summary>
public sealed record AppNotification(string Title, string Text, NotificationKind Kind, PageViewModel? Target, bool FocusPassword = false);

/// <summary>Отложенное действие на таймере диспетчера; отмена — Dispose.</summary>
internal sealed class DispatcherDelay : IDisposable
{
    private readonly DispatcherTimer _timer;

    private DispatcherDelay(TimeSpan delay, Action action)
    {
        _timer = new DispatcherTimer { Interval = delay };
        _timer.Tick += (_, _) =>
        {
            _timer.Stop();
            action();
        };
        _timer.Start();
    }

    public static IDisposable Schedule(TimeSpan delay, Action action) => new DispatcherDelay(delay, action);

    public void Dispose() => _timer.Stop();
}
