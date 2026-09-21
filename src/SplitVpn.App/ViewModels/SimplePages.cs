using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using SplitVpn.App.Services;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;
using Wpf.Ui.Controls;

namespace SplitVpn.App.ViewModels;

/// <summary>Проверить адрес: решение политики, источник, ожидаемый и фактический интерфейс.</summary>
public sealed partial class CheckAddressViewModel(MainViewModel main) : PageViewModel(main, "Проверить адрес", SymbolRegular.Search24)
{
    public ObservableCollection<AddressCheckItem> Results { get; } = [];

    [ObservableProperty]
    private string _query = "";

    [ObservableProperty]
    private string? _note;

    [RelayCommand]
    private Task CheckAsync() => RunAsync(async () =>
    {
        if (string.IsNullOrWhiteSpace(Query))
        {
            return;
        }

        var result = await Service.RequestAsync<AddressCheckDto>(new CheckAddressRequest(Query.Trim()));
        Results.Clear();
        foreach (var item in result.Items)
        {
            Results.Add(item);
        }

        Note = result.Note;
    });

    public static string DecisionText(string decision) => decision switch
    {
        "Direct" => "Напрямую",
        "Vpn" => "Через VPN",
        "Block" => "Заблокировано",
        "Local" => "Локальная сеть",
        "Server" => "Сервер VPN",
        _ => decision,
    };
}

/// <summary>Защита и DNS: режим при обрыве, прямой DNS при обрыве, локальный доступ и суффиксы.</summary>
public sealed partial class ProtectionViewModel(MainViewModel main) : PageViewModel(main, "Защита и DNS", SymbolRegular.ShieldCheckmark24)
{
    private static readonly HashSet<string> Edited =
        [nameof(OutageMode), nameof(DnsDirectOnOutage), nameof(LocalAccess), nameof(LocalSuffixes), nameof(LocalDnsServer), nameof(UpstreamDns)];

    private bool _loading;

    /// <summary>Есть несохранённые правки: при возврате на страницу они не перезаписываются настройками службы.</summary>
    [ObservableProperty]
    private bool _dirty;

    [ObservableProperty]
    private OutageMode _outageMode;

    [ObservableProperty]
    private bool _dnsDirectOnOutage;

    [ObservableProperty]
    private bool _localAccess = true;

    [ObservableProperty]
    private string _localSuffixes = "";

    [ObservableProperty]
    private string _localDnsServer = "";

    [ObservableProperty]
    private string _upstreamDns = "";

    public bool BlockVpnTraffic
    {
        get => OutageMode == OutageMode.BlockVpnTraffic;
        set { if (value) { OutageMode = OutageMode.BlockVpnTraffic; } }
    }

    public bool BlockAllPublic
    {
        get => OutageMode == OutageMode.BlockAllPublic;
        set { if (value) { OutageMode = OutageMode.BlockAllPublic; } }
    }

    public bool AllowAll
    {
        get => OutageMode == OutageMode.AllowAll;
        set { if (value) { OutageMode = OutageMode.AllowAll; } }
    }

    partial void OnOutageModeChanged(OutageMode value)
    {
        OnPropertyChanged(nameof(BlockVpnTraffic));
        OnPropertyChanged(nameof(BlockAllPublic));
        OnPropertyChanged(nameof(AllowAll));
    }

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (!_loading && e.PropertyName is { } name && Edited.Contains(name))
        {
            Dirty = true;
        }
    }

    public override Task OnOpenedAsync() => Dirty ? Task.CompletedTask : RunAsync(async () =>
    {
        var s = await Service.RequestAsync<AppSettings>(new GetSettingsRequest());
        _loading = true;
        try
        {
            OutageMode = s.OutageMode;
            DnsDirectOnOutage = s.DnsDirectOnOutage;
            LocalAccess = s.LocalAccess;
            LocalSuffixes = string.Join(", ", s.LocalDnsSuffixes);
            LocalDnsServer = s.LocalDnsServer ?? "";
            UpstreamDns = string.Join(", ", s.UpstreamDns);
        }
        finally
        {
            _loading = false;
        }
    });

    [RelayCommand]
    private Task SaveAsync() => RunAsync(async () =>
    {
        var fresh = await Service.RequestAsync<AppSettings>(new GetSettingsRequest());

        // Переход к «Разрешить всё напрямую» ослабляет защиту: при обрыве трафик пойдёт мимо туннеля.
        if (OutageMode == OutageMode.AllowAll && fresh.OutageMode != OutageMode.AllowAll
            && !await Main.Confirm("Отключить защиту при обрыве?",
                "При обрыве VPN весь трафик пойдёт напрямую через провайдера, без защиты: иностранные адреса перестанут блокироваться.",
                "Отключить защиту"))
        {
            return null;
        }

        await Service.CommandAsync(new SaveSettingsRequest(fresh with
        {
            OutageMode = OutageMode,
            DnsDirectOnOutage = DnsDirectOnOutage,
            LocalAccess = LocalAccess,
            LocalDnsSuffixes = SplitList(LocalSuffixes),
            LocalDnsServer = string.IsNullOrWhiteSpace(LocalDnsServer) ? null : LocalDnsServer.Trim(),
            UpstreamDns = SplitList(UpstreamDns),
        }));
        Dirty = false;
        return "Сохранено и применено.";
    });

    internal static List<string> SplitList(string text) =>
        text.Split([',', ';', ' ', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
}

/// <summary>Настройки: автозапуск, автоподключение, тема, уведомления, обновление базы.</summary>
public sealed partial class SettingsViewModel(MainViewModel main) : PageViewModel(main, "Настройки", SymbolRegular.Settings24)
{
    public static IReadOnlyList<ChoiceItem<ThemeChoice>> Themes { get; } =
        [new(ThemeChoice.System, "Как в системе"), new(ThemeChoice.Light, "Светлая"), new(ThemeChoice.Dark, "Тёмная")];

    public static IReadOnlyList<ChoiceItem<int>> Intervals { get; } = [new(1, "Каждый день"), new(3, "Раз в 3 дня"), new(7, "Раз в неделю")];

    public static IReadOnlyList<ChoiceItem<GeoSourceKind>> Sources { get; } =
        [new(GeoSourceKind.Loyalsoldier, "Loyalsoldier (GeoLite2, страна использования)"), new(GeoSourceKind.Ipverse, "ipverse (страна регистрации)"), new(GeoSourceKind.CustomUrl, "Свой адрес (HTTPS)")];

    private static readonly HashSet<string> Edited =
        [nameof(AutoConnect), nameof(GeoAutoUpdate), nameof(GeoInterval), nameof(GeoSource), nameof(GeoCustomUrl), nameof(DeferOnMetered), nameof(GeoMirrors),
            nameof(BypassAutoUpdate), nameof(BypassInterval)];

    private bool _loading;

    /// <summary>Есть несохранённые правки настроек службы (настройки интерфейса сохраняются сразу).</summary>
    [ObservableProperty]
    private bool _dirty;

    [ObservableProperty]
    private bool _autostart;

    /// <summary>Есть включённое подключение Cisco AnyConnect: без автозапуска интерфейса его вход после перезагрузки не начнётся.</summary>
    [ObservableProperty]
    private bool _anyConnectNeedsAutostart;

    private bool _hasActiveAnyConnect;

    [ObservableProperty]
    private bool _autoConnect;

    [ObservableProperty]
    private ThemeChoice _theme;

    [ObservableProperty]
    private bool _notifications;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowCustomUrl))]
    private bool _showAdvanced;

    [ObservableProperty]
    private bool _geoAutoUpdate;

    [ObservableProperty]
    private int _geoInterval = 1;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowCustomUrl))]
    private GeoSourceKind _geoSource;

    /// <summary>Поле своего адреса видно и тогда, когда выбран источник «Свой адрес»: иначе его негде заполнить.</summary>
    public bool ShowCustomUrl => ShowAdvanced || GeoSource == GeoSourceKind.CustomUrl;

    [ObservableProperty]
    private string _geoCustomUrl = "";

    [ObservableProperty]
    private bool _deferOnMetered;

    /// <summary>Обновление списка обхода блокировок: источник у него один, настраиваются срок и автообновление.</summary>
    [ObservableProperty]
    private bool _bypassAutoUpdate;

    [ObservableProperty]
    private int _bypassInterval = 1;

    [ObservableProperty]
    private string _geoMirrors = "";

    /// <summary>Значения интерфейса из настроек пользователя без повторного сохранения и применения.</summary>
    public void LoadPreferences(UiPreferences preferences)
    {
        _loading = true;
        try
        {
            Autostart = Services.Autostart.IsEnabled;
            Theme = preferences.Theme;
            Notifications = preferences.Notifications;
            ShowAdvanced = preferences.ShowAdvanced;
        }
        finally
        {
            _loading = false;
        }
    }

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (!_loading && e.PropertyName is { } name && Edited.Contains(name))
        {
            Dirty = true;
        }
    }

    public override Task OnOpenedAsync() => RunAsync(async () =>
    {
        LoadPreferences(Main.Preferences);
        if (Dirty)
        {
            return;
        }

        var s = await Service.RequestAsync<AppSettings>(new GetSettingsRequest());
        _loading = true;
        try
        {
            AutoConnect = s.AutoConnect;
            GeoAutoUpdate = s.GeoUpdate.AutoUpdate;
            GeoInterval = s.GeoUpdate.IntervalDays;
            GeoSource = s.GeoUpdate.Source;
            GeoCustomUrl = s.GeoUpdate.CustomUrl ?? "";
            DeferOnMetered = s.GeoUpdate.DeferOnMetered;
            GeoMirrors = string.Join(", ", s.GeoUpdate.Mirrors);
            BypassAutoUpdate = s.BypassUpdate.AutoUpdate;
            BypassInterval = s.BypassUpdate.IntervalDays;
            _hasActiveAnyConnect = s.Profiles.Any(p => p.Protocol == VpnProtocol.AnyConnect && p.Role != ProfileRole.Off);
            AnyConnectNeedsAutostart = _hasActiveAnyConnect && !Autostart;
        }
        finally
        {
            _loading = false;
        }
    });

    partial void OnThemeChanged(ThemeChoice value)
    {
        if (_loading)
        {
            return;
        }

        ThemeService.Apply(value);
        Main.SavePreferences(Main.Preferences with { Theme = value });
    }

    partial void OnAutostartChanged(bool value)
    {
        AnyConnectNeedsAutostart = _hasActiveAnyConnect && !value;
        if (_loading)
        {
            return;
        }

        try
        {
            Services.Autostart.Set(value);
        }
        catch (IOException ex)
        {
            ShowMessage(ex.Message, isError: true);
            // Переключатель возвращается к фактическому состоянию реестра.
            _loading = true;
            try
            {
                Autostart = Services.Autostart.IsEnabled;
            }
            finally
            {
                _loading = false;
            }
        }
    }

    partial void OnNotificationsChanged(bool value)
    {
        if (!_loading)
        {
            Main.SavePreferences(Main.Preferences with { Notifications = value });
        }
    }

    partial void OnShowAdvancedChanged(bool value)
    {
        if (!_loading)
        {
            Main.SavePreferences(Main.Preferences with { ShowAdvanced = value });
        }
    }

    [RelayCommand]
    private Task SaveAsync() => RunAsync(async () =>
    {
        var fresh = await Service.RequestAsync<AppSettings>(new GetSettingsRequest());
        await Service.CommandAsync(new SaveSettingsRequest(fresh with
        {
            AutoConnect = AutoConnect,
            GeoUpdate = fresh.GeoUpdate with
            {
                AutoUpdate = GeoAutoUpdate,
                IntervalDays = GeoInterval,
                Source = GeoSource,
                CustomUrl = string.IsNullOrWhiteSpace(GeoCustomUrl) ? null : GeoCustomUrl.Trim(),
                DeferOnMetered = DeferOnMetered,
                Mirrors = ProtectionViewModel.SplitList(GeoMirrors),
            },
            BypassUpdate = fresh.BypassUpdate with
            {
                AutoUpdate = BypassAutoUpdate,
                IntervalDays = BypassInterval,
                DeferOnMetered = DeferOnMetered,
            },
        }));
        Dirty = false;
    }, "Сохранено.");
}

/// <summary>Диагностика: события службы, отчёт с маскированием, восстановление сети.</summary>
public sealed partial class DiagnosticsViewModel(MainViewModel main) : PageViewModel(main, "Диагностика", SymbolRegular.Pulse24)
{
    private readonly HashSet<long> _ids = [];
    private long _lastEventId;
    private bool _loadingEvents;

    public ObservableCollection<ServiceEvent> Events { get; } = [];

    [ObservableProperty]
    private bool _maskReport = true;

    /// <summary>При открытии журнал читается целиком: служба могла перезапуститься и нумеровать события заново.</summary>
    public override Task OnOpenedAsync() => RunAsync(() =>
    {
        _lastEventId = 0;
        _ids.Clear();
        Events.Clear();
        return LoadEventsAsync();
    });

    /// <summary>Пока предыдущая подгрузка не вернулась, новая не начинается: иначе список чистится посреди вставки.</summary>
    private async Task LoadEventsAsync()
    {
        if (_loadingEvents)
        {
            return;
        }

        _loadingEvents = true;
        try
        {
            var events = await Service.RequestAsync<List<ServiceEvent>>(new GetEventsRequest(_lastEventId));
            if (events.Count > 0 && events[0].Id <= _lastEventId)
            {
                // Служба перезапущена: журнал нумеруется заново.
                Events.Clear();
                _ids.Clear();
                _lastEventId = 0;
            }

            foreach (var e in events.Where(e => _ids.Add(e.Id)))
            {
                Events.Insert(0, e);
                _lastEventId = Math.Max(_lastEventId, e.Id);
            }

            while (Events.Count > 500)
            {
                _ids.Remove(Events[^1].Id);
                Events.RemoveAt(Events.Count - 1);
            }
        }
        finally
        {
            _loadingEvents = false;
        }
    }

    /// <summary>
    /// Подгрузка на каждом опросе: недоступность службы видна баннером в шапке, сообщение страницы она не занимает
    /// и брошенную задачу с исключением не оставляет.
    /// </summary>
    private async Task LoadEventsQuietlyAsync()
    {
        try
        {
            await LoadEventsAsync();
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or ServiceCommandException)
        {
            // Журнал догрузится на следующем опросе.
        }
    }

    [RelayCommand]
    private Task ExportReportAsync() => RunAsync(async () =>
    {
        var dialog = new SaveFileDialog { FileName = $"splitvpn-отчёт-{DateTime.Now:yyyyMMdd-HHmm}.json", Filter = "JSON|*.json" };
        if (dialog.ShowDialog() != true)
        {
            return null;
        }

        var report = await Service.RequestAsync<string>(new ExportReportRequest(MaskReport));
        await File.WriteAllTextAsync(dialog.FileName, report);
        return "Отчёт сохранён.";
    });

    /// <summary>Восстановить сеть: через службу, а если она недоступна — «recover» с правами администратора.</summary>
    [RelayCommand]
    private Task RecoverNetworkAsync() => RunAsync(async () =>
    {
        if (!await Main.Confirm("Восстановить сеть?",
                "Защита будет снята: VPN разорвётся, фильтры, маршруты и DNS приложения вернутся к исходным, трафик пойдёт напрямую. Вернуть защиту — «Подключить».",
                "Восстановить сеть"))
        {
            return;
        }

        if (Main.UnavailableReason == ServiceUnavailableReason.Untrusted)
        {
            // Имя канала занял посторонний процесс: снимать защиту по его вине нельзя.
            ShowMessage(Main.ServiceError, isError: true);
            return;
        }

        if (Main.ServiceAvailable || Main.UnavailableReason == ServiceUnavailableReason.Timeout)
        {
            try
            {
                // Запрос идёт по своему соединению и ждёт не дольше RequestTimeouts.Recover: очередь команд
                // («Подключить») аварийный путь не задерживает.
                await Service.CommandAsync(new RecoverNetworkRequest());
                ShowMessage("Защита снята, обычный интернет восстановлен.", isError: false);
                return;
            }
            catch (ServiceUnavailableException ex) when (ex.Reason == ServiceUnavailableReason.Timeout)
            {
                // Служба, скорее всего, занята применением настроек и сама снимет защиту через несколько секунд.
                // Аварийный путь останавливает службу до перезагрузки — молча туда не уходим.
                if (!await Main.Confirm("Служба не ответила",
                        "Служба не ответила: вероятно, применяет настройки. Восстановить сеть с правами администратора? "
                        + "Служба будет остановлена и сама не запустится до перезагрузки.",
                        "Восстановить с правами администратора"))
                {
                    ShowMessage("Повторите через несколько секунд.", isError: false);
                    return;
                }
            }
            catch (ServiceUnavailableException)
            {
                // Служба пропала (остановлена, канал закрыт) — аварийный путь ниже.
            }
        }

        ShowMessage(await NetworkRecovery.RunElevatedAsync(), isError: false);
    });

    /// <summary>Кнопка «Запустить службу» видна, когда канал службы не открывается (например, после аварийного восстановления).</summary>
    public bool CanStartService => Main.UnavailableReason == ServiceUnavailableReason.NotRunning;

    /// <summary>Сеансы AnyConnect: транспорт, MTU, срок сеанса, сети и DNS шлюза. Cookie и токены сюда не попадают.</summary>
    public ObservableCollection<GatewaySessionRow> GatewaySessions { get; } = [];

    public override void OnStatus(StatusDto? status)
    {
        OnPropertyChanged(nameof(CanStartService));
        var rows = (status?.Tunnels ?? []).Where(t => t.ServerNetworks is not null).Select(GatewaySessionRow.From).ToList();
        if (!rows.SequenceEqual(GatewaySessions))
        {
            GatewaySessions.Clear();
            foreach (var row in rows)
            {
                GatewaySessions.Add(row);
            }
        }

        if (Main.CurrentPage == this && status is not null && !IsBusy)
        {
            _ = LoadEventsQuietlyAsync();
        }
    }

    [RelayCommand]
    private Task StartServiceAsync() => RunAsync(async () =>
    {
        var (success, text) = await NetworkRecovery.StartServiceElevatedAsync();
        ShowMessage(text, isError: !success);
        await Main.RefreshAsync();
        return null;
    });

    [RelayCommand]
    private static void OpenLogs()
    {
        var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SplitVpn", "logs");
        Process.Start(new ProcessStartInfo("explorer.exe", $"\"{folder}\"") { UseShellExecute = true });
    }
}

public sealed class AboutViewModel(MainViewModel main) : PageViewModel(main, "О программе", SymbolRegular.Info24)
{
    public string Version { get; } = typeof(AboutViewModel).Assembly.GetName().Version?.ToString(3) ?? "0.1.0";

    public string CheckTargets { get; private set; } = "";

    public override async Task OnOpenedAsync()
    {
        try
        {
            var s = await Service.RequestAsync<AppSettings>(new GetSettingsRequest());
            CheckTargets = $"Проверка подключения: иностранная цель {s.CheckTargets.Foreign}, российская {s.CheckTargets.Russian}.";
            OnPropertyChanged(nameof(CheckTargets));
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or ServiceCommandException)
        {
            CheckTargets = "";
        }
    }
}

/// <summary>Строка диагностики о сеансе шлюза AnyConnect.</summary>
public sealed record GatewaySessionRow(string Title, string Description)
{
    public override string ToString() => $"{Title}: {Description}";

    public static GatewaySessionRow From(TunnelStatusDto tunnel)
    {
        var n = tunnel.ServerNetworks!;
        var parts = new List<string>
        {
            n.DtlsActive ? "DTLS (UDP)" : "TLS (TCP)",
            "MTU " + n.Mtu.ToString(System.Globalization.CultureInfo.InvariantCulture),
            Format.Count(n.Networks.Count, "сеть", "сети", "сетей"),
        };
        if (n.Dns.Count > 0)
        {
            parts.Add("DNS " + string.Join(", ", n.Dns));
        }

        if (n.DnsSuffixes.Count > 0)
        {
            parts.Add("суффиксы " + string.Join(", ", n.DnsSuffixes));
        }

        if (n.SessionExpiresUtc is { } expires)
        {
            parts.Add("сеанс до " + Format.Local(expires));
        }

        if (n.ProxyPac is { } pac)
        {
            parts.Add((n.ApplyProxy ? "прокси применяется: " : "прокси шлюза не применяется: ") + pac);
        }

        if (n.ClientVersion is { } version)
        {
            parts.Add("libopenconnect " + version);
        }

        return new GatewaySessionRow(tunnel.Name + (tunnel.VpnAddress is { } address ? " · " + address : ""), string.Join(" · ", parts));
    }
}
