using System.IO;
using System.IO.Pipes;
using System.Windows;
using SplitVpn.App.Services;
using SplitVpn.App.ViewModels;
using SplitVpn.App.Views;
using SplitVpn.Core.Diagnostics;

namespace SplitVpn.App;

/// <summary>
/// Интерфейс «Раздельный VPN». Один экземпляр на сеанс: повторный запуск показывает окно первого.
/// Интерфейс ничего не меняет в системе сам — только команды службе через канал IPC.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1001", Justification = "Ресурсы освобождаются в OnExit — жизненный цикл WPF-приложения.")]
public partial class App : Application
{
    /// <summary>
    /// Канал активации — свой на каждый сеанс Windows, как и мьютекс единственного экземпляра: при быстром
    /// переключении пользователей и RDP ярлык открывает окно в своём сеансе, а не у другого пользователя.
    /// </summary>
    private static readonly string ActivationPipe = "SplitVpn.App.Activate." + System.Diagnostics.Process.GetCurrentProcess().SessionId;

    private Mutex? _singleInstance;
    private MainViewModel? _main;
    private TrayIcon? _tray;
    private ProxyService? _proxy;
    private CancellationTokenSource? _activation;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        if (e.Args.Contains("--selftest", StringComparer.OrdinalIgnoreCase))
        {
            // Проверка разметки: окно создаётся за пределами экрана, к службе приложение не обращается.
            // Выход через Environment.Exit: у окна отменяется закрытие (оно прячется в трей).
            // Обработчик ошибок не ставится: исключение самопроверки должно завершить процесс с ошибкой.
            Environment.Exit(SelfTest.Run());
            return;
        }

        DispatcherUnhandledException += (_, args) =>
        {
            // Ошибка интерфейса не должна закрывать приложение: служба и защита от него не зависят.
            // Лавина одинаковых ошибок — исключение: интерфейс завершается, чтобы не занимать процессор и диск.
            args.Handled = ErrorLog.Record(args.Exception);
        };
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            if (args.ExceptionObject is Exception exception)
            {
                ErrorLog.Record(exception);
            }
        };
        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            ErrorLog.Record(args.Exception);
            args.SetObserved();
        };

        _singleInstance = new Mutex(true, @"Local\SplitVpn.App", out var first);
        if (!first)
        {
            SignalFirstInstance();
            Shutdown();
            return;
        }

        var preferences = UiPreferences.Load();
        ThemeService.Apply(preferences.Theme);

        var connection = new ServiceConnection();
        _main = new MainViewModel(connection, preferences) { Confirm = ConfirmAsync };
        var window = new MainWindow { DataContext = _main };
        MainWindow = window;
        _tray = new TrayIcon(_main, ShowMainWindow, ExitApplication);
        var signIn = new SignInCoordinator(connection);
        _proxy = new ProxyService(new WinInetProxySettings());
        var main = _main;
        main.StatusUpdated += () =>
        {
            // Обработчики независимы: сбой окна входа не должен оставлять прокси шлюза без обновления, и наоборот.
            Isolate(() => signIn.OnStatus(main.Status));
            Isolate(() => _proxy.OnStatus(main.Status));
        };

        var startHidden = e.Args.Contains("--tray", StringComparer.OrdinalIgnoreCase);
        if (!startHidden)
        {
            window.Show();
        }

        // Выход из Windows и Restart Manager установщика (обновление при запущенном интерфейсе) закрывают
        // интерфейс по-настоящему, а не прячут окно в трей: иначе файлы заменяются только после перезагрузки.
        SessionEnding += (_, _) => ExitApplication();

        _main.Start();
        _activation = new CancellationTokenSource();
        _ = ListenForActivationAsync(_activation.Token);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _activation?.Cancel();
        // Прокси шлюза ставит интерфейс: без него некому снять прокси при отключении туннеля.
        _proxy?.Restore();
        _tray?.Dispose();
        _main?.Dispose();
        _singleInstance?.Dispose();
        base.OnExit(e);
    }

    public void ShowMainWindow()
    {
        if (MainWindow is null)
        {
            return;
        }

        MainWindow.Show();
        if (MainWindow.WindowState == WindowState.Minimized)
        {
            MainWindow.WindowState = WindowState.Normal;
        }

        MainWindow.Activate();
        _ = _main?.RefreshAsync();
    }

    public void ExitApplication()
    {
        if (MainWindow is MainWindow window)
        {
            window.AllowClose = true;
        }

        Shutdown();
    }

    /// <summary>
    /// Обработчик обновления состояния: ошибка пишется в журнал интерфейса и не мешает остальным.
    /// Лавина одинаковых ошибок, как и везде, завершает приложение — служба и защита от него не зависят.
    /// </summary>
    private static void Isolate(Action handler)
    {
        try
        {
            handler();
        }
        catch (Exception ex) when (ErrorLog.Record(ex))
        {
            // Записано в журнал интерфейса.
        }
    }

    /// <summary>Диалог подтверждения поверх главного окна (или без владельца, если окно скрыто в трее).</summary>
    private async Task<bool> ConfirmAsync(string title, string text, string action)
    {
        var box = new Wpf.Ui.Controls.MessageBox
        {
            Title = title,
            Content = new System.Windows.Controls.TextBlock { Text = text, TextWrapping = TextWrapping.Wrap, MaxWidth = 440 },
            PrimaryButtonText = action,
            CloseButtonText = "Отмена",
            Owner = MainWindow is { IsVisible: true } owner ? owner : null,
        };
        return await box.ShowDialogAsync() == Wpf.Ui.Controls.MessageBoxResult.Primary;
    }

    private static readonly ErrorLogWriter ErrorLog = new(
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SplitVpn", "ui-errors.log"),
        TimeProvider.System);

    private static void SignalFirstInstance()
    {
        try
        {
            using var client = new NamedPipeClientStream(".", ActivationPipe, PipeDirection.Out, PipeOptions.CurrentUserOnly);
            client.Connect(1000);
            client.WriteByte(1);
        }
        catch (Exception ex) when (ex is IOException or TimeoutException or UnauthorizedAccessException)
        {
            // Первый экземпляр не отвечает — окно не показать, но и второй экземпляр не нужен.
        }
    }

    private async Task ListenForActivationAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await using var server = new NamedPipeServerStream(ActivationPipe, PipeDirection.In, 1, PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                await server.WaitForConnectionAsync(cancellationToken);
                Dispatcher.Invoke(ShowMainWindow);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
            {
                // Слушатель не должен умирать молча: без него ярлык перестанет открывать окно.
                ErrorLog.Record(ex);
                await Task.Delay(1000, CancellationToken.None);
            }
        }
    }
}
