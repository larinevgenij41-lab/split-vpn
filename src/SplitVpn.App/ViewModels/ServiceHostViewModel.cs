using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SplitVpn.App.Services;
using SplitVpn.App.Views;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.State;

namespace SplitVpn.App.ViewModels;

/// <summary>
/// Блок «Служба» внизу меню: состояние службы Windows по диспетчеру служб, признак «не отвечает» из опроса
/// главного окна и кнопки «Запустить», «Остановить», «Перезапустить». Состояние перечитывается раз в 2 с,
/// пока окно на экране, и сразу после действия.
/// </summary>
public sealed partial class ServiceHostViewModel : ObservableObject, IDisposable
{
    private static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(2);

    private readonly MainViewModel _main;
    private readonly DispatcherTimer _timer;
    private ServiceHostState _state = ServiceHostState.Unknown;
    private ServiceHostAction? _pending;

    public ServiceHostViewModel(MainViewModel main)
    {
        _main = main;
        _timer = new DispatcherTimer { Interval = RefreshInterval };
        _timer.Tick += (_, _) => OnTick();
        _main.StatusUpdated += Update;
        _view = ServiceHostView.From(_state, notResponding: false, pending: null);
    }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Text), nameof(Tone), nameof(Description))]
    [NotifyCanExecuteChangedFor(nameof(StartCommand), nameof(StopCommand), nameof(RestartCommand))]
    private ServiceHostView _view;

    /// <summary>Версия установленной службы; пусто — не установлена или не прочитана.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Description))]
    private string _version = "";

    public string Text => View.Text;

    public StateTone Tone => View.Tone switch
    {
        ServiceHostTone.Good => StateTone.Success,
        ServiceHostTone.Warning => StateTone.Caution,
        ServiceHostTone.Bad => StateTone.Critical,
        ServiceHostTone.Progress => StateTone.Accent,
        _ => StateTone.Neutral,
    };

    /// <summary>Подсказка и имя для экранного диктора: состояние целиком, с версией.</summary>
    public string Description => Version.Length > 0 ? $"Служба «Раздельный VPN» {Version}: {Text}" : $"Служба «Раздельный VPN»: {Text}";

    public void Start()
    {
        _timer.Start();
        Update();
    }

    public void Dispose()
    {
        _timer.Stop();
        _main.StatusUpdated -= Update;
    }

    /// <summary>Показать заданное состояние без обращения к диспетчеру служб (самопроверка разметки).</summary>
    internal void Show(ServiceHostState state, string version)
    {
        _state = state;
        Version = version;
        View = ServiceHostView.From(state, NotResponding, _pending);
    }

    private bool NotResponding => _main.UnavailableReason == ServiceUnavailableReason.Timeout;

    private void OnTick()
    {
        if (!_main.IsWindowVisible)
        {
            return;
        }

        Update();
        if (_state == ServiceHostState.Running && _main.UnavailableReason == ServiceUnavailableReason.NotRunning)
        {
            // Служба запущена (например, из «Служб» Windows), а опрос ещё ждёт отсрочку после её остановки: подключаемся сразу.
            _ = _main.RefreshAsync();
        }
    }

    private void Update()
    {
        var state = WindowsServiceHost.Query();
        if (state != _state || (Version.Length == 0 && state != ServiceHostState.NotInstalled))
        {
            // Версию файла перечитываем только при смене состояния: после переустановки она могла измениться.
            Version = state == ServiceHostState.NotInstalled ? "" : WindowsServiceHost.Version() ?? "";
        }

        _state = state;
        View = ServiceHostView.From(state, NotResponding, _pending);
    }

    [RelayCommand(CanExecute = nameof(CanStart))]
    private Task StartAsync() => RunAsync(ServiceHostAction.Start);

    [RelayCommand(CanExecute = nameof(CanStop))]
    private async Task StopAsync()
    {
        if (await _main.Confirm("Остановить службу?",
                "Защита не снимается: фильтры и маршруты останутся. Пока служба остановлена, не работают DNS-посредник, переподключение VPN и команды приложения — при включённой защите сайты могут не открываться. "
                + "Сеансы AnyConnect закроются: сети шлюза будут заблокированы до запуска службы и нового входа.",
                "Остановить"))
        {
            await RunAsync(ServiceHostAction.Stop);
        }
    }

    [RelayCommand(CanExecute = nameof(CanRestart))]
    private async Task RestartAsync()
    {
        if (await _main.Confirm("Перезапустить службу?",
                "Защита и подключения SSTP, L2TP, IKEv2 сохранятся — новая служба их подхватит. Сеансы AnyConnect закроются: после перезапуска потребуется войти заново.",
                "Перезапустить"))
        {
            await RunAsync(ServiceHostAction.Restart);
        }
    }

    private bool CanStart() => View.CanStart;

    private bool CanStop() => View.CanStop;

    private bool CanRestart() => View.CanRestart;

    private async Task RunAsync(ServiceHostAction action)
    {
        if (_pending is not null)
        {
            return;
        }

        _pending = action;
        View = ServiceHostView.From(_state, NotResponding, _pending);
        _main.ExpectServiceLoss(action != ServiceHostAction.Start);
        try
        {
            if (await WindowsServiceHost.RunElevatedAsync(action) is { } error)
            {
                _main.CurrentPage.ShowError(error);
            }

            // Опрос не ждёт отсрочку: баннер «Служба недоступна» сменяется, как только служба откроет канал.
            _pending = null;
            Update();
            await _main.RefreshAsync();
        }
        finally
        {
            _pending = null;
            _main.ExpectServiceLoss(false);
            Update();
        }
    }
}
