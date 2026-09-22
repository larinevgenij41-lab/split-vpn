using System.IO;
using System.Windows;
using System.Windows.Controls;
using CommunityToolkit.Mvvm.Input;
using H.NotifyIcon;
using H.NotifyIcon.Core;
using SplitVpn.App.ViewModels;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;

namespace SplitVpn.App.Services;

/// <summary>
/// Значок в трее: состояние цветом значка и текстом подсказки (не только цветом), основные команды,
/// включение и выключение подключений, уведомления о значимых сбоях.
/// </summary>
public sealed class TrayIcon : IDisposable
{
    private readonly MainViewModel _main;
    private readonly TaskbarIcon _icon;
    private readonly MenuItem _state = new() { IsEnabled = false };
    private readonly MenuItem _connect = new() { Header = "Подключить" };
    private readonly MenuItem _disconnect = new() { Header = "Отключить (защита остаётся)" };
    private readonly MenuItem _restore = new() { Header = "Отключить и восстановить обычный интернет" };
    private readonly MenuItem _profiles = new() { Header = "Включить или выключить подключение" };
    private string _currentIcon = "";
    private bool _filling;

    public TrayIcon(MainViewModel main, Action showWindow, Action exit)
    {
        _main = main;
        _connect.Click += async (_, _) => await RunAsync(_main.ConnectCommand);
        _disconnect.Click += async (_, _) => await RunAsync(_main.DisconnectCommand);
        _restore.Click += async (_, _) => await RunAsync(_main.DisconnectAndRestoreCommand);
        _profiles.SubmenuOpened += async (_, e) =>
        {
            if (e.OriginalSource == _profiles)
            {
                await FillProfilesAsync();
            }
        };
        _profiles.Items.Add(new MenuItem { Header = "…", IsEnabled = false });

        var open = new MenuItem { Header = "Открыть «Раздельный VPN»", FontWeight = FontWeights.SemiBold };
        open.Click += (_, _) => showWindow();
        var quit = new MenuItem { Header = "Закрыть окно и значок (VPN и защита продолжат работать)" };
        quit.Click += (_, _) => exit();

        var menu = new ContextMenu();
        foreach (var item in new object[] { _state, new Separator(), _connect, _disconnect, _restore, _profiles, new Separator(), open, quit })
        {
            menu.Items.Add(item);
        }

        _icon = new TaskbarIcon
        {
            ToolTipText = "Раздельный VPN",
            Icon = LoadIcon("app"),
            ContextMenu = menu,
            MenuActivation = PopupActivationMode.RightClick,
            NoLeftClickDelay = true,
            LeftClickCommand = new RelayCommand(showWindow),
        };
        _icon.TrayBalloonTipClicked += (_, _) => showWindow();
        _icon.ForceCreate(false);

        _main.StatusUpdated += Update;
        _main.PropertyChanged += OnMainChanged;
        _main.Notify += ShowNotification;
        Update();
    }

    public void Dispose()
    {
        _main.StatusUpdated -= Update;
        _main.PropertyChanged -= OnMainChanged;
        _main.Notify -= ShowNotification;
        _icon.Dispose();
    }

    private void OnMainChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainViewModel.IsBusy))
        {
            Update();
        }
    }

    /// <summary>Команда из меню — те же правила, что у кнопок окна: пока идёт другая команда, не выполняется.</summary>
    private static Task RunAsync(IAsyncRelayCommand command) =>
        command.CanExecute(null) ? command.ExecuteAsync(null) : Task.CompletedTask;

    private void Update()
    {
        var status = _main.Status;
        var iconName = status switch
        {
            null => "blocked",
            { State: ConnectionState.Connected } => "connected",
            { State: ConnectionState.Error or ConnectionState.PartiallyApplied or ConnectionState.TrafficBlocked or ConnectionState.PasswordRequired } => "blocked",
            { Intent: Intent.Off } => "off",
            _ => "app",
        };
        if (iconName != _currentIcon)
        {
            // TaskbarIcon освобождает предыдущий значок при замене: каждый раз новый экземпляр.
            _icon.Icon = LoadIcon(iconName);
            _currentIcon = iconName;
        }

        _icon.ToolTipText = Tooltip(_main.StateText, status);
        _state.Header = _main.StateText;
        var ready = _main.ServiceAvailable && !_main.IsBusy;
        var connected = MainViewModel.IsConnectedIntent(status);
        var error = status?.State == ConnectionState.Error;
        _connect.Header = error && connected ? "Повторить подключение" : "Подключить";
        _connect.IsEnabled = ready && (!connected || error);
        _disconnect.IsEnabled = ready && connected;
        _restore.IsEnabled = ready && MainViewModel.CanRestore(status);
        _profiles.IsEnabled = ready;
    }

    /// <summary>
    /// Подсказка значка ограничена 127 символами: состояние защиты ставится сразу после состояния,
    /// чтобы при обрезке терялись подробности маршрутов, а не главное.
    /// </summary>
    internal static string Tooltip(string stateText, StatusDto? status)
    {
        var protection = status is null ? "" : status.ProtectionSuspended ? "защита снята" : status.ProtectionActive ? "защита включена" : "защита выключена";
        var text = "Раздельный VPN: " + stateText + (protection.Length > 0 ? ", " + protection : "");
        if (status is not null)
        {
            text += "\nРоссия → " + status.GeoTargetName + "\nОстальное → " + status.DefaultTargetName;
        }

        return text.Length > 127 ? text[..126] + "…" : text;
    }

    /// <summary>
    /// Подменю подключений: отмечены включённые. Щелчок включает выключенное (дополнительным) или выключает
    /// дополнительное; опорное выключается на странице «Подключения», где видно, куда уйдёт его трафик.
    /// Отметка меняется только по ответу службы: список перечитывается при каждом открытии.
    /// </summary>
    private async Task FillProfilesAsync()
    {
        if (_filling)
        {
            return;
        }

        _filling = true;
        var items = new List<MenuItem>();
        try
        {
            var settings = await _main.Service.RequestAsync<AppSettings>(new GetSettingsRequest());
            foreach (var profile in settings.Profiles)
            {
                var item = new MenuItem
                {
                    Header = profile.Name + profile.Role switch { ProfileRole.Primary => " (опорное)", ProfileRole.Secondary => " (дополнительное)", _ => "" },
                    IsChecked = profile.Role != ProfileRole.Off,
                    IsEnabled = profile.Role != ProfileRole.Primary,
                };
                var id = profile.Id;
                var next = profile.Role == ProfileRole.Off ? ProfileRole.Secondary : ProfileRole.Off;
                item.Click += async (_, _) => await _main.SetProfileRoleAsync(id, next);
                items.Add(item);
            }

            if (items.Count == 0)
            {
                items.Add(new MenuItem { Header = "Подключений нет", IsEnabled = false });
            }
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or ServiceCommandException or IOException)
        {
            items = [new MenuItem { Header = "Служба недоступна", IsEnabled = false }];
        }
        finally
        {
            _filling = false;
        }

        // Замена списка — одним шагом после ответа: повторное открытие не удваивает пункты.
        _profiles.Items.Clear();
        foreach (var item in items)
        {
            _profiles.Items.Add(item);
        }
    }

    /// <summary>Значок нужного для трея размера: при масштабе 200 % это 32×32, а не растянутые 16×16.</summary>
    private static System.Drawing.Icon LoadIcon(string name)
    {
        using var stream = Application.GetResourceStream(new Uri($"pack://application:,,,/Assets/{name}.ico")).Stream;
        var scale = Application.Current.MainWindow is { } window ? System.Windows.Media.VisualTreeHelper.GetDpi(window).DpiScaleX : 1;
        var size = Math.Max(16, (int)Math.Round(SystemParameters.SmallIconWidth * scale));
        return new System.Drawing.Icon(stream, size, size);
    }

    private void ShowNotification(string title, string message) =>
        _icon.ShowNotification(title, message, NotificationIcon.Info);
}
