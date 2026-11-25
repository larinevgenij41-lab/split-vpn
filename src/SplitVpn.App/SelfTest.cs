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
        // Даже проверка перестановки списка не должна обращаться к установленной службе.
        using var connection = new ServiceConnection((request, _) => Task.FromResult(request is Core.Ipc.SetProfileOrderRequest
            ? Core.Ipc.IpcResponse.Success()
            : Core.Ipc.IpcResponse.Failure(Core.Ipc.IpcErrorCodes.Failed, "Изолированная проверка интерфейса.")));
        var main = new MainViewModel(connection, preferences);
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
        main.ApplyProgress(new Core.Ipc.ServiceProgressDto
        {
            Stage = "Обновление маршрутов", Percent = 35, Completed = 128, Total = 356,
            StartedUtc = DateTimeOffset.UtcNow.AddSeconds(-18), ElapsedSeconds = 18,
        });
        Settle(root);
        Shot(root, shots, "window-service-progress");
        if (main.ServiceProgressStage != "Обновление маршрутов: 128 из 356" || main.ServiceProgressPercent != 35)
        {
            errors.AppendLine("Счётчик обновления маршрутов не отображается в индикаторе службы.");
        }
        main.ApplyProgress(new Core.Ipc.ServiceProgressDto { Stage = "Ожидание входа: Lamoda" });
        Settle(root);
        Shot(root, shots, "window-service-progress-waiting");
        if (!main.ShowServiceProgress || !main.ServiceProgressIndeterminate)
        {
            errors.AppendLine("Ожидание входа не отображается в индикаторе службы.");
        }
        main.ApplyProgress(null);
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
        main.ServiceAvailable = false;
        (main.ServiceErrorTitle, _, main.ServiceError) = MainViewModel.Describe(main.UnavailableReason.Value);
        main.ServiceHost.Show(Core.State.ServiceHostState.Running, "0.3.9");
        Settle(root);
        if (!window.ServiceRecoveryActions.IsVisible || !main.ServiceHost.RestartCommand.CanExecute(null))
        {
            errors.AppendLine("Перезапуск недоступен рядом с сообщением о неотвечающей службе.");
        }
        Shot(root, shots, "window-service-not-responding");
        main.UnavailableReason = Core.Ipc.ServiceUnavailableReason.NotRunning;
        (main.ServiceErrorTitle, _, main.ServiceError) = MainViewModel.Describe(main.UnavailableReason.Value);
        main.ServiceHost.Show(Core.State.ServiceHostState.Stopped, "0.3.9");
        Settle(root);
        Shot(root, shots, "window-service-stopped");
        if (!main.ServiceHost.StartCommand.CanExecute(null) || main.ServiceHost.StopCommand.CanExecute(null))
        {
            errors.AppendLine("Блок «Служба»: у остановленной службы доступность кнопок не соответствует состоянию.");
        }

        main.UnavailableReason = Core.Ipc.ServiceUnavailableReason.Denied;
        Settle(root);
        if (window.ServiceRecoveryActions.IsVisible)
        {
            errors.AppendLine("При отказе в доступе предлагается перезапуск службы.");
        }
        main.UnavailableReason = null;
        main.ServiceAvailable = true;

        main.ServiceHost.Show(Core.State.ServiceHostState.StopPending, "0.3.9");
        Settle(root);
        Shot(root, shots, "window-service-stopping");
        var (width, height) = (window.Width, window.Height);
        window.Height = window.MinHeight;
        Settle(root);
        Shot(root, shots, "window-service-min-height");
        block = window.ServiceBlock.TransformToAncestor(root).TransformBounds(new Rect(window.ServiceBlock.RenderSize));
        Log($"Блок «Служба» при минимальной высоте: {block}, окно {root.ActualWidth}×{root.ActualHeight}");

        // Низкое окно и все сообщения шапки сразу (ход службы, прокси, служба не отвечает, сообщение страницы):
        // шапка над страницей не выше 40 % окна и прокручивается сама, странице остаётся место.
        main.ApplyProgress(new Core.Ipc.ServiceProgressDto
        {
            Stage = "Обновление маршрутов", Percent = 60, Completed = 214, Total = 356,
            StartedUtc = DateTimeOffset.UtcNow.AddSeconds(-30), ElapsedSeconds = 30,
        });
        main.ProxyError = "Не удалось вернуть прежние настройки прокси Windows: проверьте их в параметрах сети.";
        main.UnavailableReason = Core.Ipc.ServiceUnavailableReason.Timeout;
        main.ServiceAvailable = false;
        (main.ServiceErrorTitle, _, main.ServiceError) = MainViewModel.Describe(main.UnavailableReason.Value);
        main.ServiceHost.Show(Core.State.ServiceHostState.Running, "0.3.9");
        var pageWithMessage = main.CurrentPage ?? main.Home;
        pageWithMessage.ShowError("Проверка сообщения страницы в шапке окна.");
        Settle(root);
        Shot(root, shots, "window-header-min-height");
        var headerShare = window.HeaderScroll.ActualHeight / window.ActualHeight;
        Log($"Шапка при минимальной высоте: {window.HeaderScroll.ActualHeight:0} из {window.ActualHeight:0}, прокрутка {window.HeaderScroll.ScrollableHeight:0}");
        if (headerShare > 0.41)
        {
            errors.AppendLine(System.Globalization.CultureInfo.InvariantCulture, $"Шапка окна при минимальной высоте занимает {headerShare:P0} высоты окна.");
        }

        pageWithMessage.Message = null;
        main.ApplyProgress(null);
        main.ProxyError = null;
        main.UnavailableReason = null;
        main.ServiceAvailable = true;
        main.ServiceHost.Show(Core.State.ServiceHostState.StopPending, "0.3.9");
        window.Height = height;
        window.Width = 760;
        Settle(root);
        Shot(root, shots, "window-service-compact");
        window.Width = width;
        Settle(root);
        Log("Блок «Служба» отрисован.");
        CheckEmergencyWindow(main, window, root, shots, errors);
        CheckTrayWindow(main, root, errors);

        // Доска маршрутизации узнаёт об изменениях маршрутизации в другом месте по снимку её части настроек.
        var routing = new Core.Settings.AppSettings();
        if (RoutingViewModel.RoutingPart(routing) != RoutingViewModel.RoutingPart(routing with { })
            || RoutingViewModel.RoutingPart(routing) == RoutingViewModel.RoutingPart(routing with { DefaultTarget = Core.Policy.RouteTarget.Tunnel(Guid.NewGuid()) }))
        {
            errors.AppendLine("Снимок маршрутизации доски не отличает изменённые настройки от прежних.");
        }

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

        CheckHomeSetup(main, host, shots, errors);

        // Главная после экстренного выключения: вместо «Подключить» — «Включить программу» и пояснение.
        var (homeTone, homeSymbol, homeState, homeSummary) = (main.Home.Tone, main.Home.StateSymbol, main.StateText, main.SummaryText);
        main.Emergency.Show(new Core.Recovery.EmergencyFlag(DateTimeOffset.UtcNow.AddHours(-3)));
        host.Content = null;
        host.Content = main.Home;
        Settle(host);
        Shot(host, shots, "home-emergency");
        if (!HasVisibleText(host, "Включить программу") || HasVisibleText(host, "Подключить"))
        {
            errors.AppendLine("Главная после экстренного выключения: нет «Включить программу» или видна «Подключить».");
        }

        main.Emergency.Show(null);
        (main.Home.Tone, main.Home.StateSymbol, main.StateText, main.SummaryText) = (homeTone, homeSymbol, homeState, homeSummary);

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
        // Положенный пользователем туннель: у его выключателя должно быть своё имя для диктора.
        main.Home.Tunnels.Add(TunnelRow.From(
            new Core.Ipc.TunnelStatusDto
            {
                Name = "Запасное",
                Role = Core.Settings.ProfileRole.Secondary,
                Protocol = Core.Settings.VpnProtocol.Sstp,
                State = Core.State.ConnectionState.Disconnected,
                Paused = true,
            },
            null,
            nothingRouted: false));
        main.Home.Warnings.Add(WarningRow.From(new Core.Ipc.StatusWarning("no-geo", "Проверка предупреждения с действием службы", "geo-update")));
        main.Home.Warnings.Add(WarningRow.From(new Core.Ipc.StatusWarning("update-ready", "Готово обновление до версии 9.9.9: установка займёт около минуты.", "update-install")));
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
        main.Home.Note = "IPv6 ограничен: публичный IPv6 блокируется, пока включена защита. При DNS-over-HTTPS в браузере правила для доменов могут не сработать: браузер разрешает имена сам. Путь трафика определяют правила для IP-адресов.";
        host.Content = null;
        host.Content = main.Home;
        host.UpdateLayout();
        Shot(host, shots, "home");
        // Строки туннелей ниже края снимка страницы: снимаются отдельно, в широком и в узком окне
        // (примечание «ничего не направлено» с кнопкой переносится, строка состояния — одна, с многоточием).
        var tunnels = Descendants(host).OfType<ItemsControl>().First(c => ReferenceEquals(c.ItemsSource, main.Home.Tunnels));
        Shot(tunnels, shots, "home-tunnels");
        host.Width = 640;
        Settle(host);
        Shot(tunnels, shots, "home-tunnels-narrow");
        if (Descendants(tunnels).OfType<FrameworkElement>().Any(e => e.IsVisible && e is TextBlock or Button
            && e.TransformToAncestor(tunnels).TransformBounds(new Rect(e.RenderSize)).Right > tunnels.ActualWidth + 1))
        {
            errors.AppendLine("В узком окне текст или кнопка строки туннеля выходит за край.");
        }

        host.Width = 1180;
        Settle(host);
        var details =Descendants(host).OfType<Expander>().Single(e => Equals(e.Header, "Технические подробности"));
        details.IsExpanded = true;
        Settle(host);
        Shot(host, shots, "home-error-details");
        details.IsExpanded = false;
        CheckTunnelMenu(host, errors);

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
        main.Protection.Adapters.Add(new TrustedAdapterItem(
            new Core.Ipc.AdapterDto(Guid.NewGuid(), "Radmin VPN", "Famatech Radmin VPN Ethernet Adapter", "Ethernet", true, false, "26.0.0.1", false, IsOverlay: true, IsTrusted: true),
            isTrusted: false));
        host.Content = main.Protection;
        host.UpdateLayout();
        Shot(host, shots, "protection-trusted-adapters");
        if (main.Protection.Dirty)
        {
            errors.AppendLine("Список доверенных адаптеров пометил страницу защиты изменённой без правок пользователя.");
        }

        // Самый длинный вариант свёртки списка обхода виден в поле целиком (поле не фиксированной ширины).
        main.Settings.BypassAggregatePrefix = 18;
        host.Content = main.Settings;
        Settle(host);
        var aggregate = Descendants(host).OfType<CardRow>().First(r => r.Title == "Объединять адреса в подсети");
        Shot(aggregate, shots, "settings-aggregate");
        if (FindComboBox(aggregate, "Свёртка списка обхода блокировок") is { } aggregateBox
            && Descendants(aggregateBox).OfType<TextBlock>().FirstOrDefault(t => t.IsVisible && t.Text.Contains("рекомендуется", StringComparison.Ordinal)) is { } chosen
            && aggregateBox.ActualWidth < chosen.DesiredSize.Width + 24)
        {
            errors.AppendLine("Выбранный вариант свёртки списка обхода обрезан.");
        }

        // Пустой список: до ответа службы - загрузка, после - подсказка, как добавить подключение.
        host.Content = main.Connections;
        host.UpdateLayout();
        if (!HasVisibleText(host, "Загрузка подключений"))
        {
            errors.AppendLine("Пустой список подключений до ответа службы не показывает загрузку.");
        }

        main.Connections.Loaded = true;
        host.UpdateLayout();
        Shot(host, shots, "connections-empty");
        if (!HasVisibleText(host, "Подключений пока нет"))
        {
            errors.AppendLine("Пустой список подключений не подсказывает, как добавить подключение.");
        }

        // Пустой список места не занимает, а кнопкам без выбранного подключения работать не с чем.
        if (Descendants(host).OfType<Wpf.Ui.Controls.ListView>().Any(l => ReferenceEquals(l.ItemsSource, main.Connections.Profiles) && l.IsVisible))
        {
            errors.AppendLine("Пустой список подключений занимает место между подсказкой и кнопками.");
        }

        var enabledButtons = Descendants(host).OfType<Wpf.Ui.Controls.Button>().Where(b => b.IsVisible && b.IsEnabled).Select(b => b.Content as string).ToHashSet();
        if (enabledButtons.Overlaps(["Выше", "Ниже", "Копировать", "Удалить", "Экспорт"]) || !enabledButtons.IsSupersetOf(["Добавить", "Импорт"]))
        {
            errors.AppendLine("При пустом списке подключений доступны не те кнопки: ожидаются только «Добавить» и «Импорт».");
        }

        main.Connections.Profiles.Add(ProfileItem.From(new Core.Settings.ConnectionProfile { Name = "Проверка", Server = "vpn.example.org", PrimaryAdapter = Core.Settings.AdapterSelection.Pinned, PinnedInterfaceGuid = Guid.NewGuid(), AuthMethod = Core.Settings.AuthMethod.PeapMsChapV2, Role = Core.Settings.ProfileRole.Primary }));
        main.Connections.Selected = main.Connections.Profiles[0];
        host.Content = null;
        host.Content = main.Connections;
        host.UpdateLayout();
        if (HasVisibleText(host, "Подключений пока нет"))
        {
            errors.AppendLine("Подсказка пустого списка подключений видна рядом с подключением.");
        }

        if (main.Connections.Selected.IsDirty)
        {
            // Привязки редактора не должны сами менять профиль: иначе он считается изменённым и не обновляется из службы.
            errors.AppendLine("Редактор подключения пометил профиль изменённым без правок пользователя.");
        }

        // Список адаптеров сменился под открытой формой (отмечен доверенный адаптер, новая сеть): выбранный адаптер
        // закреплённого профиля не теряется, и профиль не становится «не сохранено».
        var pinnedProfile = main.Connections.Selected;
        var pinnedGuid = pinnedProfile.PinnedInterfaceGuid!.Value;
        var wifi = new Core.Ipc.AdapterDto(pinnedGuid, "Беспроводная сеть", "Wi-Fi", "Wireless", true, true, "192.168.1.1", true);
        main.Connections.Adapters.Add(wifi);
        Settle(host);
        var dirtyBefore = pinnedProfile.IsDirty;
        pinnedProfile.PreserveAdapterChoice(() =>
        {
            main.Connections.Adapters.Clear();
            main.Connections.Adapters.Add(wifi with { IsTrusted = true });
        });
        Settle(host);
        if (pinnedProfile.PinnedInterfaceGuid != pinnedGuid || pinnedProfile.IsDirty != dirtyBefore)
        {
            errors.AppendLine("Смена списка адаптеров сбросила адаптер закреплённого профиля или пометила профиль изменённым.");
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

        // Перестановка и состояние из службы — не правка профиля: иначе опрос навсегда закроет обновление списка.
        var order = main.Connections.Profiles.Select(p => p.Id).ToList();
        _ = main.Connections.MoveAsync(main.Connections.Profiles[^1], -1);
        Settle(host);
        if (main.Connections.Profiles.Select(p => p.Id).SequenceEqual(order))
        {
            errors.AppendLine("Перестановка подключения не изменила порядок списка.");
        }

        main.Connections.OnStatus(new Core.Ipc.StatusDto
        {
            Tunnels = [.. main.Connections.Profiles.Select(p => new Core.Ipc.TunnelStatusDto { ProfileId = p.Id, Name = p.Name, Paused = true })],
        });
        Settle(host);
        if (main.Connections.Profiles.Any(p => p.IsDirty))
        {
            errors.AppendLine("Перестановка или состояние из службы пометили профиль изменённым.");
        }

        // Проверяем настоящую TwoWay-привязку PasswordBox: смена DataContext не переносит и не стирает пароль.
        main.Connections.Selected = pinnedProfile;
        Settle(host);
        Wpf.Ui.Controls.PasswordBox EditorPassword() => Descendants(host).OfType<Wpf.Ui.Controls.PasswordBox>()
            .Single(p => System.Windows.Automation.AutomationProperties.GetName(p) == "Пароль");
        EditorPassword().Password = "editor-draft-a";
        Settle(host);
        main.Connections.AddCommand.Execute(null);
        var newProfile = main.Connections.Selected!;
        Settle(host);
        if (EditorPassword().Password.Length != 0)
        {
            errors.AppendLine("Новое подключение получило пароль другого профиля.");
        }
        EditorPassword().Password = "editor-draft-b";
        newProfile.Server = "vpn.example.org";
        Settle(host);
        Shot(host, shots, "connections-new");
        main.Connections.Selected = pinnedProfile;
        Settle(host);
        if (EditorPassword().Password != "editor-draft-a" || newProfile.PasswordDraft != "editor-draft-b")
        {
            errors.AppendLine("Переключение редактора потеряло пароль или перенесло его другому подключению.");
        }
        pinnedProfile.PasswordDraft = "";
        pinnedProfile.IsDirty = false;
        main.Connections.Profiles.Remove(newProfile);

        main.Diagnostics.GatewaySessions.Add(new GatewaySessionRow("Шлюз · 10.0.0.2", "быстрый канал (UDP) · 69 сетей", "Канал DTLS (UDP) · MTU 1230"));
        // Строки журнала событий с меню «Копировать»: шаблон строки применяется только с данными.
        main.Diagnostics.Journal.Prepend(
        [
            new Core.Ipc.ServiceEvent(3, DateTimeOffset.UtcNow, "Ошибка", "Проверка строки ошибки"),
            new Core.Ipc.ServiceEvent(2, DateTimeOffset.UtcNow.AddMinutes(-1), "Предупреждение", "Проверка строки предупреждения"),
            new Core.Ipc.ServiceEvent(1, DateTimeOffset.UtcNow.AddMinutes(-2), "Сведения", "Проверка строки сведений"),
        ]);
        // Ход пробного подключения у кнопки «Проверить».
        pinnedProfile.TestRunning = true;
        pinnedProfile.TestText = "Пробное подключение к «Проверка»… Может занять до минуты.";
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

        // Последний шаг в узком окне мастера: длинная строка «Готово. …» переносится, а не уходит за край.
        wizard.Progress = "Готово. Подключено «Основное»: российские адреса идут напрямую, остальной интернет — через VPN; защита при обрыве включена.";
        wizard.Finished = true;
        host.Width = 640;
        host.Content = null;
        host.Content = wizard;
        Settle(host);
        Shot(host, shots, "wizard-done-narrow");
        var done = Descendants(host).OfType<TextBlock>().FirstOrDefault(t => t.IsVisible && t.Text == wizard.Progress);
        if (done is null || done.ActualWidth > host.ActualWidth)
        {
            errors.AppendLine("Строка «Готово. …» последнего шага мастера не видна или шире окна мастера.");
        }

        host.Width = 1180;
        Log("Мастер отрисован: шагов " + (WizardViewModel.LastStep + 1));

        // Доска с отдельными карточками и папкой: проверяются обе разметки и сокращение списка.
        var column = new BoardColumn(main.Routing, Core.Policy.RouteTarget.Direct, "Напрямую", "проверка", StateTone.Success);
        var vpnColumn = new BoardColumn(main.Routing, Core.Policy.RouteTarget.Tunnel(Guid.NewGuid()), "Основное подключение", "VPN", StateTone.Success);
        column.Cards.Add(new BoardCard(main.Routing, CardKind.Default, "Остальной интернет", "проверка", Core.Policy.RouteTarget.Direct));
        column.Cards.Add(new BoardCard(main.Routing, CardKind.Geo, "Россия (RU-база)", "проверка", Core.Policy.RouteTarget.Direct));
        var domains = new List<string> { "www.kimi.com", "kimi.com", "kimi.ai", "moonshot.cn", "moonshot.ai", "kimi.moonshot.cn", "api.moonshot.ai" }
            .Select(name => new BoardCard(main.Routing, CardKind.Domain, name, null, Core.Policy.RouteTarget.Direct)).ToArray();
        foreach (var card in domains)
        {
            column.Cards.Add(card);
        }

        column.Cards.Add(new BoardCard(main.Routing, CardKind.ServerNetworks, "Сети шлюза «Шлюз»", "69 сетей", Core.Policy.RouteTarget.Direct) { ProfileId = Guid.NewGuid() });
        main.Routing.Columns.Add(column);
        main.Routing.Columns.Add(vpnColumn);
        main.Routing.Columns.Add(new BoardColumn(main.Routing, Core.Policy.RouteTarget.Tunnel(Guid.NewGuid()), "Дополнительное подключение с длинным названием", "VPN", StateTone.Success));
        main.Routing.Columns.Add(new BoardColumn(main.Routing, Core.Policy.RouteTarget.Blocked, "Блокировать", "Нет доступа к сети", StateTone.Success));
        main.Routing.Groups.Add(ViewModels.GroupItem.From(new Core.Settings.TunnelGroupSetting { Name = "Проверка" }, [], () => { }));

        var temporary = main.Routing.CreateFolder(column);
        main.Routing.MoveToFolder(domains[0], temporary);
        main.Routing.RemoveFolder(temporary);
        if (domains[0].IsInFolder || !column.Cards.Contains(domains[0]))
        {
            errors.AppendLine("Удаление папки не оставило её правило отдельной карточкой.");
        }

        var ungroupedCount = column.Cards.Count;
        var folder = main.Routing.CreateFolder(column);
        folder.Name = "Kimi и Moonshot";
        foreach (var card in domains)
        {
            main.Routing.MoveToFolder(card, folder);
        }

        if (folder.Cards.Count != domains.Length || column.Cards.Count != ungroupedCount - domains.Length + 1)
        {
            errors.AppendLine("Папка не сократила список карточек ожидаемым образом.");
        }

        main.Routing.Move(folder, vpnColumn);
        if (folder.Target != vpnColumn.Target || folder.Cards.Any(card => card.Target != vpnColumn.Target))
        {
            errors.AppendLine("Перенос папки не изменил маршрут всех её правил.");
        }

        main.Routing.Move(folder, column);
        main.Routing.Extract(domains[0]);
        if (domains[0].IsInFolder || !column.Cards.Contains(domains[0]))
        {
            errors.AppendLine("Правило не вынимается из папки.");
        }

        main.Routing.MoveToFolder(domains[0], folder);
        folder.IsExpanded = false;
        host.Content = null;
        host.Content = main.Routing;
        Settle(host);
        Shot(host, shots, "routing");
        folder.IsExpanded = true;
        Settle(host);
        Shot(host, shots, "routing-folder-expanded");
        folder.IsExpanded = false;
        Settle(host);
        Log("Доска отрисована: колонок " + main.Routing.Columns.Count + ", карточек верхнего уровня " + column.Cards.Count + ", правил в папке " + folder.Cards.Count);

        // Папка с сотнями правил (списки доменов сервисов). В 0.17.5 раскрытие такой папки создавало карточку
        // на каждое правило разом, и окно программы падало. Раскрытая папка строит только видимые карточки.
        const int manyRules = 900;
        var largeRules = new List<BoardCard>();
        var large = main.Routing.CreateFolder(vpnColumn);
        large.Name = "Большая папка";
        for (var i = 0; i < manyRules; i++)
        {
            var rule = new BoardCard(main.Routing, CardKind.Domain, $"host{i}.example.org", null, vpnColumn.Target);
            largeRules.Add(rule);
            vpnColumn.Cards.Add(rule);
            main.Routing.MoveToFolder(rule, large);
        }

        large.IsExpanded = false;
        Settle(host);
        var expandTimer = System.Diagnostics.Stopwatch.StartNew();
        large.IsExpanded = true;
        Settle(host);
        expandTimer.Stop();
        var realized = Descendants(host).OfType<FrameworkElement>().Count(e => e.DataContext is BoardCard { IsInFolder: true } card && large.Cards.Contains(card) && e is Wpf.Ui.Controls.Card);
        Shot(host, shots, "routing-large-folder");
        Log($"Большая папка: правил {large.Cards.Count}, построено карточек {realized}, раскрытие {expandTimer.ElapsedMilliseconds} мс");
        if (large.Cards.Count != manyRules)
        {
            errors.AppendLine("В большую папку попали не все правила.");
        }

        if (realized == 0 || realized > 80)
        {
            errors.AppendLine("Раскрытая папка из " + manyRules + " правил построила " + realized + " карточек: ожидаются только видимые.");
        }

        if (expandTimer.Elapsed > TimeSpan.FromSeconds(5))
        {
            errors.AppendLine("Папка из " + manyRules + " правил раскрывалась " + expandTimer.ElapsedMilliseconds + " мс.");
        }

        large.IsExpanded = false;
        Settle(host);
        CheckLargeSearch(main.Routing, host, shots, manyRules, errors);
        main.Routing.RemoveFolder(large);
        foreach (var rule in largeRules)
        {
            vpnColumn.Cards.Remove(rule);
        }

        Settle(host);

        // Реальные размеры области NavigationView: отдельный широкий ContentControl не выявляет
        // обрезку редактора и кнопок в узком окне. Проверяем также повторное расширение окна.
        window.Content = root;
        // Сохраняем данные шапки, но убираем MainViewModel из окна: обработчик Navigated
        // иначе вызовет OnOpenedAsync и заменит тестовые данные настройками рабочей службы.
        window.DataContext = new
        {
            main.Home, main.StateText, main.Status, main.ServiceHost, main.IsWorking,
            main.ShowCommandProgress, main.ShowServiceProgress, main.ServiceProgressStage,
            main.ServiceProgressDetail, main.ServiceProgressPercent, main.ServiceProgressIndeterminate,
            main.ProxyError, main.ServiceAvailable, main.ShowServiceRecovery, main.ServiceErrorTitle, main.ServiceError, main.CurrentPage, main.Wizard, main.VerboseBadge,
            main.Emergency, main.ShowServiceError,
        };
        // Несохранённая правка настроек службы: у пункта меню «Настройки» видна отметка, у блока «Работа VPN» — бейдж.
        main.Settings.AutoConnect = !main.Settings.AutoConnect;
        if (!main.PagesWithUnsavedChanges().Contains(main.Settings))
        {
            errors.AppendLine("Правка настроек службы не отмечена как несохранённая.");
        }

        foreach (var viewportWidth in new[] { 1080d, 760d, 640d, 1440d })
        {
            window.Width = viewportWidth;
            foreach (var pageType in PageProvider.Factories.Keys)
            {
                window.Navigation.Navigate(pageType);
                Settle(root);
                CheckColumns(root, errors);
                Shot(root, shots, $"viewport-{viewportWidth}-{pageType.Name}");
            }
        }

        Log("Адаптивная компоновка: 8 страниц при ширине 1080, 760, 640 и 1440.");
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
    /// Экстренно выключена, служба остановлена: спокойный баннер с «Включить программу» вместо красной «Служба недоступна»,
    /// без «Запустить службу»; затем итог команды со списком шагов — при обычной и минимальной высоте окна.
    /// </summary>
    private static void CheckEmergencyWindow(MainViewModel main, MainWindow window, FrameworkElement root, string? shots, StringBuilder errors)
    {
        var (stateText, summaryText) = (main.StateText, main.SummaryText);
        main.UnavailableReason = Core.Ipc.ServiceUnavailableReason.NotRunning;
        main.ServiceAvailable = false;
        (main.ServiceErrorTitle, _, main.ServiceError) = MainViewModel.Describe(main.UnavailableReason.Value);
        main.ServiceHost.Show(Core.State.ServiceHostState.Stopped, "0.3.9");
        main.Emergency.Show(new Core.Recovery.EmergencyFlag(DateTimeOffset.UtcNow.AddMinutes(-42)));
        Settle(root);
        Shot(root, shots, "window-emergency-off");
        if (!window.EmergencyBanner.IsVisible || window.ServiceRecoveryActions.IsVisible || main.ShowServiceError
            || main.ServiceHost.StartCommand.CanExecute(null) || main.ConnectCommand.CanExecute(null) || !main.Emergency.TurnOnCommand.CanExecute(null))
        {
            errors.AppendLine("Экстренно выключена: нет баннера с «Включить программу» или видны ошибка службы и её запуск.");
        }

        if (main.StateText != UiText.EmergencyStateText || main.Home.Tone != Views.StateTone.Caution)
        {
            errors.AppendLine("Экстренно выключена: состояние в шапке меню или тон главной не «экстренно выключен».");
        }

        var report = new Core.Recovery.EmergencyReport
        {
            Command = Core.Recovery.EmergencyCommands.Off,
            StartedUtc = DateTimeOffset.UtcNow.AddMinutes(-1),
            FinishedUtc = DateTimeOffset.UtcNow,
            ExitCode = 3,
            Summary = "Сеть возвращена не полностью.",
            Steps =
            [
                new("flag", "Отметка отключения", Core.Recovery.EmergencyStepOutcome.Done, @"HKLM\Software\SplitVpn: EmergencyOff = 1", 12),
                new("start-type", "Ручной запуск службы", Core.Recovery.EmergencyStepOutcome.Done, "был тип запуска auto", 30),
                new("service", "Остановка службы", Core.Recovery.EmergencyStepOutcome.Done, "служба остановлена штатно", 2100),
                new("wfp", "Фильтры защиты (WFP)", Core.Recovery.EmergencyStepOutcome.Timeout, "не завершился за 120 с", 120000),
                new("routes", "Маршруты программы", Core.Recovery.EmergencyStepOutcome.Already, "своих маршрутов нет", 40),
                new("flush-dns", "Кеш DNS", Core.Recovery.EmergencyStepOutcome.Failed, "ipconfig /flushdns: код 1", 900, Required: false),
            ],
        };
        main.Emergency.Result = EmergencyRunResult.FromExitCode(on: false, 3, report, Core.Recovery.EmergencyReportFiles.LastPath);
        Settle(root);
        Shot(root, shots, "window-emergency-result");
        if (!window.EmergencyResult.IsVisible || !main.Emergency.Result.Advice.Contains("Перезагрузите", StringComparison.Ordinal))
        {
            errors.AppendLine("Итог экстренного выключения не показан или без совета перезагрузить компьютер.");
        }

        var height = window.Height;
        window.Height = window.MinHeight;
        Settle(root);
        Shot(root, shots, "window-emergency-result-min-height");
        if (window.HeaderScroll.ActualHeight / window.ActualHeight > 0.41)
        {
            errors.AppendLine("Итог экстренного выключения при минимальной высоте занимает больше 40 % окна.");
        }

        window.Height = height;
        main.Emergency.Result = null;
        main.Emergency.Show(null);
        main.UnavailableReason = null;
        main.ServiceAvailable = true;
        (main.StateText, main.SummaryText) = (stateText, summaryText);
        main.ServiceHost.Show(Core.State.ServiceHostState.Running, "0.3.9");
        Settle(root);
        Log("Экстренное выключение в окне проверено.");
    }

    /// <summary>
    /// Главная кнопка, когда подключать нечего: подсказка «Подключений пока нет» и надпись «Добавить подключение»
    /// появляются только вместе и только по списку, полученному от службы. Пока служба недоступна — обычная
    /// кнопка «Подключить» без подсказки. Опрос не запускается: имя подключения в состоянии не меняется.
    /// </summary>
    private static void CheckHomeSetup(MainViewModel main, ContentControl host, string? shots, StringBuilder errors)
    {
        var home = main.Home;
        host.Content = null;
        host.Content = home;

        // Список был получен, а служба затем пропала: подсказки нет.
        home.SetProfileCounts(new Core.Settings.AppSettings());
        home.OnStatus(null);
        Settle(host);
        if (home.ButtonText != "Подключить" || home.SetupHint is not null || HasVisibleText(host, "Подключений пока нет"))
        {
            errors.AppendLine("При недоступной службе главная кнопка подсказывает добавить подключение.");
        }

        // Список получен, подключений нет: надпись кнопки и подсказка согласованы.
        home.SetProfileCounts(new Core.Settings.AppSettings());
        home.OnStatus(new Core.Ipc.StatusDto { Intent = Core.State.Intent.Off });
        Settle(host);
        Shot(host, shots, "home-no-connections");
        if (home.ButtonText != "Добавить подключение" || !HasVisibleText(host, "Подключений пока нет"))
        {
            errors.AppendLine("Без подключений главная кнопка не называется «Добавить подключение» или подсказка не видна.");
        }

        // Обратно к состоянию «служба не ответила»: так страница выглядит в остальных снимках.
        home.OnStatus(null);
        home.Tone = StateTone.Neutral;
        home.StateSymbol = Wpf.Ui.Controls.SymbolRegular.PlugDisconnected24;
        host.Content = null;
    }

    /// <summary>
    /// Поиск по доске с сотнями правил: запрос, которому подходят все правила большой папки, показывает не больше
    /// 200 карточек, строит только видимые и не пересоздаёт строки при отметке правки (фокус не теряется).
    /// </summary>
    private static void CheckLargeSearch(RoutingViewModel routing, FrameworkElement host, string? shots, int rules, StringBuilder errors)
    {
        var timer = Stopwatch.StartNew();
        routing.Search = "example.org";
        Settle(host);
        timer.Stop();
        var list = Descendants(host).OfType<ItemsControl>().FirstOrDefault(c => System.Windows.Automation.AutomationProperties.GetName(c) == "Найденные маршруты" && c.IsVisible);
        var realized = list is null ? 0 : Descendants(list).OfType<Wpf.Ui.Controls.Card>().Count(c => c.DataContext is BoardCard);
        Shot(host, shots, "routing-search-large");
        Log($"Поиск по {rules} правилам: найдено показано {routing.SearchResults.Count}, есть ещё {routing.SearchHasMore}, построено карточек {realized}, {timer.ElapsedMilliseconds} мс");
        if (routing.SearchResults.Count != RoutingViewModel.SearchLimit || !routing.SearchHasMore)
        {
            errors.AppendLine("Поиск по большой папке показал " + routing.SearchResults.Count + " результатов без отметки «есть ещё»: ожидается " + RoutingViewModel.SearchLimit + ".");
        }

        if (list is null || realized == 0 || realized > 60)
        {
            errors.AppendLine("Результаты поиска построили " + realized + " карточек: ожидаются только видимые.");
        }

        if (timer.Elapsed > TimeSpan.FromSeconds(5))
        {
            errors.AppendLine("Поиск по " + rules + " правилам занял " + timer.ElapsedMilliseconds + " мс.");
        }

        if (!HasVisibleText(host, "Показаны первые " + RoutingViewModel.SearchLimit))
        {
            errors.AppendLine("Нет строки «Показаны первые 200 — уточните запрос».");
        }

        // Отметка правки при открытом поиске не пересоздаёт строки: тот же объект и та же разметка строки.
        var first = routing.SearchResults[0];
        var container = list?.ItemContainerGenerator.ContainerFromItem(first);
        routing.MarkDirty();
        Settle(host);
        if (!ReferenceEquals(routing.SearchResults[0], first) || (container is not null && !ReferenceEquals(list!.ItemContainerGenerator.ContainerFromItem(first), container)))
        {
            errors.AppendLine("Отметка правки пересоздала результаты поиска: фокус клавиатуры терялся бы.");
        }

        routing.Search = "";
        Settle(host);
    }

    private static void CheckColumns(DependencyObject root, StringBuilder errors)
    {
        if (root is Panel panel && root is ResponsiveColumns or EvenWrapPanel)
        {
            Rect? previous = null;
            foreach (UIElement child in panel.Children)
            {
                if (child.Visibility == Visibility.Collapsed)
                {
                    continue;
                }

                var bounds = child.TransformToAncestor(panel).TransformBounds(new Rect(child.RenderSize));
                if (bounds.Left < -1 || bounds.Right > panel.ActualWidth + 1)
                {
                    errors.AppendLine(System.Globalization.CultureInfo.InvariantCulture, $"Колонка выходит за границы панели: {bounds}, ширина {panel.ActualWidth}.");
                }

                if (previous is { } other && other.IntersectsWith(bounds))
                {
                    errors.AppendLine(System.Globalization.CultureInfo.InvariantCulture, $"Колонки перекрываются: {other} и {bounds}.");
                }

                previous = bounds;
            }
        }

        for (var i = 0; i < System.Windows.Media.VisualTreeHelper.GetChildrenCount(root); i++)
        {
            CheckColumns(System.Windows.Media.VisualTreeHelper.GetChild(root, i), errors);
        }
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

    /// <summary>
    /// Запуск в трей: окно создаётся скрытым и показывается позже. Шапка и подвал меню WPF-UI вне логического
    /// дерева окна, и привязки с поиском источника к показу уже сдавались: блок "Служба" оставался без данных,
    /// а развёрнутый и свёрнутый виды были на экране одновременно.
    /// </summary>
    private static void CheckTrayWindow(MainViewModel main, FrameworkElement root, StringBuilder errors)
    {
        var window = new MainWindow { DataContext = main, Left = -20000, Top = -20000, ShowActivated = false };
        // Очередь окна обрабатывается, пока оно скрыто: здесь WPF и разрешает привязки шапки и подвала.
        Settle(root);
        window.Show();
        var content = (FrameworkElement)window.Content;
        Settle(content);
        if (!ReferenceEquals(window.ServiceFooter.DataContext, main.ServiceHost)
            || window.ServiceBlock.Visibility != Visibility.Visible || window.ServiceIcon.Visibility != Visibility.Collapsed)
        {
            errors.AppendLine("Окно, открытое из трея: блок \"Служба\" без данных или виден вместе со значком свёрнутого меню.");
        }

        window.Navigation.IsPaneOpen = false;
        Settle(content);
        if (window.StatusCard.Visibility != Visibility.Collapsed || window.ServiceBlock.Visibility != Visibility.Collapsed
            || window.ServiceIcon.Visibility != Visibility.Visible)
        {
            errors.AppendLine("Окно, открытое из трея: в свёрнутом меню видны карточки развёрнутого.");
        }

        // В свёрнутом меню состояние службы — значок с цветной точкой: диктор должен прочитать его словами.
        var peer = System.Windows.Automation.Peers.UIElementAutomationPeer.CreatePeerForElement(window.ServiceIcon);
        var spoken = peer?.GetName() ?? "";
        Log("Значок службы в свёрнутом меню для диктора: " + (spoken.Length > 0 ? spoken : "(нет имени)"));
        if (!spoken.StartsWith("Служба «Раздельный VPN»", StringComparison.Ordinal))
        {
            errors.AppendLine("Значок службы в свёрнутом меню не озвучивает состояние службы.");
        }

        window.AllowClose = true;
        window.Close();
        Log("Окно, открытое из трея, проверено.");
    }

    /// <summary>
    /// Меню строки туннеля на главной открывается во всплывающем окне вне дерева страницы: пункт «Выключить совсем»
    /// должен найти команду модели главной (поиск ItemsControl из меню находил само меню, и пункт ничего не делал).
    /// </summary>
    private static void CheckTunnelMenu(FrameworkElement host, StringBuilder errors)
    {
        var button = Descendants(host).OfType<Wpf.Ui.Controls.DropDownButton>().FirstOrDefault();
        if (button?.Flyout is not ContextMenu menu)
        {
            errors.AppendLine("На главной нет меню строки туннеля.");
            return;
        }

        menu.PlacementTarget = button;
        menu.IsOpen = true;
        Settle(host);
        var item = menu.Items.OfType<MenuItem>().FirstOrDefault(i => i.Header as string == "Выключить совсем");
        if (item?.Command is null || !item.Command.CanExecute(item.CommandParameter))
        {
            errors.AppendLine("Пункт «Выключить совсем» в меню строки туннеля не связан с командой главной.");
        }

        menu.IsOpen = false;
        Log("Меню строки туннеля проверено.");
    }

    private static IEnumerable<DependencyObject> Descendants(DependencyObject root)
    {
        for (var i = 0; i < System.Windows.Media.VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = System.Windows.Media.VisualTreeHelper.GetChild(root, i);
            yield return child;
            foreach (var nested in Descendants(child))
            {
                yield return nested;
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

    /// <summary>Видимый текст, начинающийся с заданных слов: подписи пустых состояний и загрузки.</summary>
    private static bool HasVisibleText(DependencyObject root, string prefix)
    {
        for (var i = 0; i < System.Windows.Media.VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = System.Windows.Media.VisualTreeHelper.GetChild(root, i);
            if (child is TextBlock text && text.IsVisible && text.Text.StartsWith(prefix, StringComparison.Ordinal))
            {
                return true;
            }

            if (HasVisibleText(child, prefix))
            {
                return true;
            }
        }

        return false;
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
        // Через VisualBrush: элемент рисуется от своего левого верхнего угла, а не со сдвигом внутри родителя
        // (узкий элемент по центру широкого окна иначе выходил на снимке обрезанным справа).
        var content = new System.Windows.Media.DrawingVisual();
        using (var context = content.RenderOpen())
        {
            context.DrawRectangle(new System.Windows.Media.VisualBrush(element)
            {
                Stretch = System.Windows.Media.Stretch.None,
                ViewboxUnits = System.Windows.Media.BrushMappingMode.Absolute,
                // VisualBrush учитывает сдвиг элемента внутри родителя: окно снимка начинается с этого сдвига.
                Viewbox = new Rect((Point)System.Windows.Media.VisualTreeHelper.GetOffset(element), new Size(width, height)),
                ViewportUnits = System.Windows.Media.BrushMappingMode.Absolute,
                Viewport = new Rect(0, 0, width, height),
            },
                null, new Rect(0, 0, width, height));
        }

        bitmap.Render(content);
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
