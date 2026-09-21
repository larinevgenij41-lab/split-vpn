using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using SplitVpn.App.Services;
using SplitVpn.App.ViewModels;
using SplitVpn.App.Views;

namespace SplitVpn.App;

/// <summary>
/// Проверка разметки без участия человека: каждая страница создаётся и раскладывается, ошибки привязок
/// собираются из трассировки WPF. Запуск — «SplitVpn.exe --selftest»; к службе приложение не обращается.
/// </summary>
internal static class SelfTest
{
    /// <summary>Ход проверки пишется в файл: у оконного приложения нет консоли.</summary>
    private static readonly string LogPath = Path.Combine(Path.GetTempPath(), "splitvpn-selftest.log");

    public static int Run()
    {
        File.WriteAllText(LogPath, "");
        var errors = new StringBuilder();
        var listener = new CollectingListener(errors);
        PresentationTraceSources.Refresh();
        PresentationTraceSources.DataBindingSource.Listeners.Add(listener);
        PresentationTraceSources.DataBindingSource.Switch.Level = SourceLevels.Error | SourceLevels.Warning;

        Log("Старт самопроверки.");
        // Как при обычном запуске: без темы нет цветов акцента, и шаблоны основных кнопок не создаются.
        // SPLITVPN_SELFTEST_THEME=Light|Dark — проверить разметку в нужной теме; SPLITVPN_SELFTEST_SHOTS — папка для снимков страниц.
        var preferences = UiPreferences.Load();
        if (Enum.TryParse<ThemeChoice>(Environment.GetEnvironmentVariable("SPLITVPN_SELFTEST_THEME"), out var theme))
        {
            preferences = preferences with { Theme = theme };
        }

        ThemeService.Apply(preferences.Theme);
        var shots = Environment.GetEnvironmentVariable("SPLITVPN_SELFTEST_SHOTS");
        var main = new MainViewModel(new ServiceConnection(), preferences);
        Log("Модель создана.");
        var window = new MainWindow
        {
            DataContext = main,
            Left = -20000,
            Top = -20000,
            ShowActivated = false,
        };
        Log("Окно создано.");
        window.Show();
        Log("Окно показано.");
        window.UpdateLayout();
        Log("Раскладка выполнена.");
        MainWindow.NameUnlabeledButtons(window);
        CheckAccessibility(window, errors);

        // Блок «Служба» внизу меню: состояния с разным набором доступных кнопок, раскрытое и свёрнутое меню.
        var root = (FrameworkElement)window.Content;
        main.ServiceHost.Show(Core.State.ServiceHostState.Running, "0.3.9");
        Settle(root);
        Shot(root, shots, "window-service-running");
        var block = window.ServiceBlock.TransformToAncestor(root).TransformBounds(new Rect(window.ServiceBlock.RenderSize));
        Log($"Блок «Служба»: {block}, окно {root.ActualWidth}×{root.ActualHeight}");
        if (block.Bottom > root.ActualHeight || block.Right > root.ActualWidth)
        {
            errors.AppendLine("Блок «Служба» не помещается в окно: " + block);
        }

        main.UnavailableReason = Core.Ipc.ServiceUnavailableReason.Timeout;
        main.ServiceHost.Show(Core.State.ServiceHostState.Running, "0.3.9");
        Settle(root);
        Shot(root, shots, "window-service-not-responding");
        main.UnavailableReason = null;
        main.ServiceHost.Show(Core.State.ServiceHostState.Stopped, "0.3.9");
        Settle(root);
        Shot(root, shots, "window-service-stopped");
        if (!main.ServiceHost.StartCommand.CanExecute(null) || main.ServiceHost.StopCommand.CanExecute(null))
        {
            errors.AppendLine("Блок «Служба»: у остановленной службы доступность кнопок не соответствует состоянию.");
        }

        main.ServiceHost.Show(Core.State.ServiceHostState.StopPending, "0.3.9");
        Settle(root);
        Shot(root, shots, "window-service-stopping");
        var (width, height) = (window.Width, window.Height);
        window.Height = window.MinHeight;
        Settle(root);
        Shot(root, shots, "window-service-min-height");
        block = window.ServiceBlock.TransformToAncestor(root).TransformBounds(new Rect(window.ServiceBlock.RenderSize));
        Log($"Блок «Служба» при минимальной высоте: {block}, окно {root.ActualWidth}×{root.ActualHeight}");
        window.Height = height;
        window.Width = 760;
        Settle(root);
        Shot(root, shots, "window-service-compact");
        window.Width = width;
        Settle(root);
        Log("Блок «Служба» отрисован.");

        // Страницы отрисовываются как модели в ContentControl: шаблоны из Pages.xaml те же,
        // а Page без навигационного узла в тесте не нужен.
        var host = new ContentControl { Width = 1180, Height = 760 };
        window.Content = host;
        foreach (var page in main.Pages)
        {
            host.Content = page;
            host.UpdateLayout();
            Log("Страница отрисована: " + page.Title);
        }

        // Шаблоны, которые применяются только с данными: строки туннелей и предупреждения главной, редактор подключения, мастер.
        main.Home.Tunnels.Add(TunnelRow.From(
            new Core.Ipc.TunnelStatusDto
            {
                Name = "Основное",
                Role = Core.Settings.ProfileRole.Primary,
                Protocol = Core.Settings.VpnProtocol.Sstp,
                State = Core.State.ConnectionState.Connected,
                VpnAddress = "10.0.0.2",
                SessionStartedUtc = DateTimeOffset.UtcNow - TimeSpan.FromHours(4),
            },
            "↑ 338 КБ/с ↓ 21 КБ/с",
            nothingRouted: false));
        main.Home.Tunnels.Add(TunnelRow.From(
            new Core.Ipc.TunnelStatusDto
            {
                Name = "Работа",
                Role = Core.Settings.ProfileRole.Secondary,
                Protocol = Core.Settings.VpnProtocol.AnyConnect,
                State = Core.State.ConnectionState.Connected,
                VpnAddress = "10.0.7.188",
                SessionStartedUtc = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(12),
                ServerNetworks = new Core.Ipc.ServerNetworksDto
                {
                    Networks = [.. Enumerable.Range(1, 69).Select(i => $"10.{i}.0.0/16")],
                    DtlsActive = true,
                    Mtu = 1278,
                    SessionExpiresUtc = DateTimeOffset.UtcNow + TimeSpan.FromHours(5),
                },
            },
            "↑ 12 КБ/с ↓ 3 КБ/с",
            nothingRouted: true));
        main.Home.Warnings.Add(WarningRow.From(new Core.Ipc.StatusWarning("no-geo", "Проверка предупреждения с действием службы", "geo-update")));
        main.Home.Warnings.Add(WarningRow.From(new Core.Ipc.StatusWarning("foreign-vpn", "Активно другое VPN-подключение «Работа (IKEv2)»: его маршруты и DNS могут перехватывать трафик.", null)));
        main.Home.SignInRequired = true;
        main.Home.SignInError = "Проверка ошибки входа";
        main.Home.HasErrorAction = true;
        main.Home.ErrorActionText = "Открыть «Диагностику»";
        main.Home.ErrorText = "Основной адаптер недоступен — проверьте Wi-Fi или кабель.";
        main.Home.HasErrorDetails = true;
        main.Home.ErrorSummary = "Windows не смогла проверить, не отозван ли сертификат сервера";
        main.Home.ErrorMeaning = "Сам сертификат может быть полностью исправен: Windows отдельно обращается за списком отзыва (CRL) по адресу, записанному в сертификате, и этот адрес не ответил.";
        main.Home.ErrorCertificateText = "Сертификат сервера: vpn.example.org, выдал Let's Encrypt, действует до 27.09.2026 11:42 (осталось 6 дней).";
        main.Home.ErrorCodeText = "Код 0x80092013 (-2146885613, CryptoAPI)";
        main.Home.ErrorSteps.Add("1. Подождите повтора: программа открывает адрес проверки отзыва через защиту и подключается снова сама (ye1.c.lencr.org).");
        main.Home.ErrorSteps.Add("2. Если повтор не помогает — снимите защиту, подключитесь напрямую и нажмите «Повторить».");
        main.Home.Note = "IPv6 ограничен: публичный IPv6 блокируется, пока включена защита. Браузеры с включённым DNS-over-HTTPS разрешают имена сами: такие запросы идут через VPN, если адрес DoH-сервера не российский.";
        host.Content = null;
        host.Content = main.Home;
        host.UpdateLayout();
        Shot(host, shots, "home");

        // Идёт команда: индикатор в шапке окна и надпись «Подключение…» на главной кнопке.
        main.IsBusy = true;
        main.BusyAction = "Подключение…";
        Settle(host);
        Shot(host, shots, "home-busy");
        if (!main.IsWorking || main.Home.ButtonText != "Подключение…")
        {
            errors.AppendLine("Во время команды индикатор занятости или надпись главной кнопки не обновились.");
        }

        main.IsBusy = false;
        main.BusyAction = null;
        main.Connections.Profiles.Add(ProfileItem.From(new Core.Settings.ConnectionProfile { Name = "Проверка", Server = "vpn.example.org", PrimaryAdapter = Core.Settings.AdapterSelection.Pinned, PinnedInterfaceGuid = Guid.NewGuid(), AuthMethod = Core.Settings.AuthMethod.PeapMsChapV2, Role = Core.Settings.ProfileRole.Primary }));
        main.Connections.Selected = main.Connections.Profiles[0];
        host.Content = null;
        host.Content = main.Connections;
        host.UpdateLayout();
        if (main.Connections.Selected.IsDirty)
        {
            // Привязки редактора не должны сами менять профиль: иначе он считается изменённым и не обновляется из службы.
            errors.AppendLine("Редактор подключения пометил профиль изменённым без правок пользователя.");
        }

        var anyConnect = ProfileItem.From(new Core.Settings.ConnectionProfile { Name = "Шлюз", Server = "vpn.example.org", Protocol = Core.Settings.VpnProtocol.AnyConnect, AuthMethod = Core.Settings.AuthMethod.GatewayForm, Role = Core.Settings.ProfileRole.Secondary });
        main.Connections.Profiles.Add(anyConnect);
        main.Connections.Selected = anyConnect;
        host.Content = null;
        host.Content = main.Connections;
        host.UpdateLayout();
        Shot(host, shots, "connections-anyconnect");
        if (anyConnect.IsDirty)
        {
            errors.AppendLine("Редактор подключения AnyConnect пометил профиль изменённым без правок пользователя.");
        }

        // Обратно на RAS-профиль: списки способов входа и ролей у протоколов разные, выбранное не должно потеряться.
        main.Connections.Selected = main.Connections.Profiles[0];
        Settle(host);
        Shot(host, shots, "connections-back-to-ras");
        if (FindComboBox(host, "Способ входа") is { SelectedItem: null })
        {
            errors.AppendLine("После переключения профиля поле «Способ входа» осталось пустым.");
        }
        if (FindComboBox(host, "Роль подключения") is { SelectedItem: null })
        {
            // У AnyConnect в списке ролей нет «Опорного»: после возврата к опорному профилю поле не должно опустеть.
            errors.AppendLine("После переключения профиля поле «Роль» осталось пустым.");
        }
        if (main.Connections.Profiles.Any(p => p.IsDirty))
        {
            errors.AppendLine("Переключение между профилями AnyConnect и RAS пометило профиль изменённым.");
        }

        main.Diagnostics.GatewaySessions.Add(new GatewaySessionRow("Шлюз · 10.0.0.2", "DTLS (UDP) · MTU 1230 · 69 сетей"));
        host.Content = null;
        host.Content = main.Diagnostics;
        host.UpdateLayout();
        Shot(host, shots, "diagnostics");

        // Форма шлюза строится кодом: проверяется, что поля всех видов создаются и окно раскладывается.
        var form = new SignInFormWindow(new ServiceConnection(), Guid.NewGuid(), "Шлюз", new Core.Ipc.SignInPromptDto
        {
            RequestId = Guid.NewGuid(),
            Kind = Core.Ipc.SignInKind.Form,
            GatewayHost = "vpn.example.org",
            Title = "Вход",
            Error = "Неверный пароль",
            Fields =
            [
                new Core.Ipc.AuthFieldDto("group", "Группа", Core.Ipc.AuthFieldKind.Select, [new Core.Ipc.AuthChoiceDto("staff", "Сотрудники")], null),
                new Core.Ipc.AuthFieldDto("username", "Логин", Core.Ipc.AuthFieldKind.Text, [], "user"),
                new Core.Ipc.AuthFieldDto("password", "Пароль", Core.Ipc.AuthFieldKind.Password, [], null),
            ],
        }) { Left = -20000, Top = -20000, ShowActivated = false };
        form.Show();
        form.UpdateLayout();
        Shot((FrameworkElement)form.Content, shots, "gateway-form");
        form.CloseByService();

        Log("Главная, редакторы подключений, диагностика и форма шлюза отрисованы.");
        var wizard = new WizardViewModel(main, loadAdapters: false);
        for (var step = 0; step <= WizardViewModel.LastStep; step++)
        {
            wizard.Step = step;
            host.Content = null;
            host.Content = wizard;
            host.UpdateLayout();
        }

        Log("Мастер отрисован: шагов " + (WizardViewModel.LastStep + 1));

        // Доска маршрутизации с карточками: шаблоны колонок и карточек применяются только при наличии данных.
        var column = new BoardColumn(main.Routing, Core.Policy.RouteTarget.Direct, "Напрямую", "проверка", StateTone.Success);
        column.Cards.Add(new BoardCard(main.Routing, CardKind.Default, "Остальной интернет", "проверка", Core.Policy.RouteTarget.Direct));
        column.Cards.Add(new BoardCard(main.Routing, CardKind.Domain, "example.org", null, Core.Policy.RouteTarget.Direct));
        column.Cards.Add(new BoardCard(main.Routing, CardKind.ServerNetworks, "Сети шлюза «Шлюз»", "69 сетей", Core.Policy.RouteTarget.Direct) { ProfileId = Guid.NewGuid() });
        main.Routing.Columns.Add(column);
        main.Routing.Groups.Add(ViewModels.GroupItem.From(new Core.Settings.TunnelGroupSetting { Name = "Проверка" }, [], () => { }));
        host.Content = null;
        host.Content = main.Routing;
        host.UpdateLayout();
        Shot(host, shots, "routing");
        Log("Доска отрисована: колонок " + main.Routing.Columns.Count + ", карточек " + column.Cards.Count);

        window.AllowClose = true;
        window.Close();
        main.Dispose();
        if (errors.Length == 0)
        {
            Log("Самопроверка разметки пройдена.");
            return 0;
        }

        Log("Ошибки самопроверки:");
        Log(errors.ToString());
        return 1;
    }

    /// <summary>
    /// Дерево автоматизации (то же, что видит экранный диктор): пункты меню доступны по именам, у кнопок
    /// заголовка окна есть имена.
    /// </summary>
    private static void CheckAccessibility(Window window, StringBuilder errors)
    {
        var names = new List<string>();
        var unnamedButtons = 0;
        Collect(System.Windows.Automation.Peers.UIElementAutomationPeer.CreatePeerForElement(window), 0);
        foreach (var expected in new[] { "Главная", "Подключения", "Маршрутизация", "Настройки", "Свернуть", "Закрыть в трей", "Запустить службу", "Перезапустить службу" })
        {
            if (!names.Contains(expected))
            {
                errors.AppendLine("Доступность: в дереве автоматизации нет элемента «" + expected + "».");
            }
        }

        Log("Дерево автоматизации: элементов с именем " + names.Count + ", видимых кнопок без имени " + unnamedButtons);

        void Collect(System.Windows.Automation.Peers.AutomationPeer? peer, int depth)
        {
            if (peer is null || depth > 40)
            {
                return;
            }

            var name = peer.GetName();
            if (!string.IsNullOrEmpty(name))
            {
                names.Add(name);
            }
            else if (peer.GetAutomationControlType() == System.Windows.Automation.Peers.AutomationControlType.Button && !peer.IsOffscreen())
            {
                unnamedButtons++;
                Log("Кнопка без имени: " + ((peer as System.Windows.Automation.Peers.UIElementAutomationPeer)?.Owner is FrameworkElement { } owner ? owner.GetType().Name + " " + owner.Name + " " + owner.ToolTip : "?"));
            }

            foreach (var child in peer.GetChildren() ?? [])
            {
                Collect(child, depth + 1);
            }
        }
    }

    /// <summary>Асинхронные привязки и отложенные операции диспетчера успевают выполниться.</summary>
    private static void Settle(FrameworkElement element)
    {
        for (var i = 0; i < 20; i++)
        {
            element.Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.ContextIdle);
            Thread.Sleep(10);
        }

        element.UpdateLayout();
    }

    /// <summary>Видимый список выбора по имени для экранного диктора: так же его находит пользователь.</summary>
    private static ComboBox? FindComboBox(DependencyObject root, string name)
    {
        for (var i = 0; i < System.Windows.Media.VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = System.Windows.Media.VisualTreeHelper.GetChild(root, i);
            if (child is ComboBox box && System.Windows.Automation.AutomationProperties.GetName(box) == name && box.IsVisible)
            {
                return box;
            }

            if (FindComboBox(child, name) is { } found)
            {
                return found;
            }
        }

        return null;
    }

    /// <summary>Снимок отрисованного элемента в PNG — чтобы посмотреть разметку глазами без запуска службы.</summary>
    private static void Shot(FrameworkElement element, string? folder, string name)
    {
        if (string.IsNullOrEmpty(folder))
        {
            return;
        }

        Directory.CreateDirectory(folder);
        var width = (int)Math.Ceiling(element.ActualWidth);
        var height = (int)Math.Ceiling(Math.Max(element.ActualHeight, element.DesiredSize.Height));
        var bitmap = new System.Windows.Media.Imaging.RenderTargetBitmap(Math.Max(1, width), Math.Max(1, height), 96, 96, System.Windows.Media.PixelFormats.Pbgra32);
        var background = new System.Windows.Shapes.Rectangle
        {
            Width = width,
            Height = height,
            Fill = (System.Windows.Media.Brush)Application.Current.FindResource("ApplicationBackgroundBrush"),
        };
        background.Measure(new Size(width, height));
        background.Arrange(new Rect(0, 0, width, height));
        bitmap.Render(background);
        bitmap.Render(element);
        var encoder = new System.Windows.Media.Imaging.PngBitmapEncoder();
        encoder.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(bitmap));
        using var file = File.Create(Path.Combine(folder, name + ".png"));
        encoder.Save(file);
    }

    private static void Log(string text)
    {
        Console.WriteLine(text);
        File.AppendAllText(LogPath, text + Environment.NewLine);
    }

    /// <summary>Трассировка пишет сообщение частями (заголовок через Write, текст через WriteLine): собираем целиком.</summary>
    private sealed class CollectingListener(StringBuilder errors) : TraceListener
    {
        private readonly StringBuilder _line = new();

        public override void Write(string? message) => _line.Append(message);

        public override void WriteLine(string? message)
        {
            _line.Append(message);
            var text = _line.ToString();
            _line.Clear();
            if (text.Contains("System.Windows.Data Error", StringComparison.Ordinal))
            {
                errors.AppendLine(text);
            }
        }
    }
}
