using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SplitVpn.App.Services;
using SplitVpn.App.Views;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Policy;
using SplitVpn.Core.State;
using SplitVpn.Core.Settings;
using Wpf.Ui.Controls;

namespace SplitVpn.App.ViewModels;

/// <summary>Главная: одна большая кнопка, фактическое состояние словами, сеанс, предупреждения с действием.</summary>
public sealed partial class HomeViewModel : PageViewModel
{
    /// <summary>Предупреждение службы о постоянном ограничении: показывается строкой, а не жёлтой карточкой.</summary>
    private const string Ipv6WarningCode = "ipv6-restricted";

    private const string DohNote = "Браузеры с включённым DNS-over-HTTPS разрешают имена сами: такие запросы идут через VPN, если адрес DoH-сервера не российский.";

    private const string Ipv6Note = "IPv6 ограничен: публичный IPv6 блокируется, пока включена защита.";

    /// <summary>Байты туннелей на прошлом опросе: по ним считается скорость каждого туннеля.</summary>
    private readonly Dictionary<Guid, (DateTimeOffset Time, ulong Sent, ulong Received)> _tunnelBytes = [];

    /// <summary>Доска маршрутизации из настроек: по ней видно, назначено ли туннелю хоть что-нибудь. null — не прочитана.</summary>
    private AppSettings? _board;

    public HomeViewModel(MainViewModel main)
        : base(main, "Главная", SymbolRegular.Home24)
    {
        // Пока идёт «Подключить» или «Отключить», главная кнопка говорит, что происходит.
        main.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(MainViewModel.BusyAction))
            {
                UpdateButtonText();
            }
        };
    }

    public ObservableCollection<WarningRow> Warnings { get; } = [];

    /// <summary>Что сделать по ошибке, по шагам и по порядку.</summary>
    public ObservableCollection<string> ErrorSteps { get; } = [];

    /// <summary>Состояние каждого поднимаемого туннеля: опорный первым.</summary>
    public ObservableCollection<TunnelRow> Tunnels { get; } = [];

    [ObservableProperty]
    private string _buttonText = "Подключить";

    [ObservableProperty]
    private bool _isConnectedIntent;

    [ObservableProperty]
    private string _profile = "—";

    [ObservableProperty]
    private string _adapter = "—";

    [ObservableProperty]
    private string _vpnAddress = "—";

    [ObservableProperty]
    private string _duration = "—";

    [ObservableProperty]
    private string _sent = "—";

    [ObservableProperty]
    private string _received = "—";

    [ObservableProperty]
    private string? _errorText;

    /// <summary>Постоянные пояснения (IPv6, DNS-over-HTTPS) — одной серой строкой внизу страницы.</summary>
    [ObservableProperty]
    private string _note = DohNote;

    /// <summary>Состояние «Ошибка»: повторы остановлены до действия пользователя — показывается «Повторить».</summary>
    [ObservableProperty]
    private bool _canRetry;

    /// <summary>Сбойное состояние, у которого есть следующий шаг: «Проверить данные входа», «Открыть «Диагностику»».</summary>
    [ObservableProperty]
    private bool _hasErrorAction;

    /// <summary>Что делать по причине сбоя: «Проверить подключение», «Открыть диагностику».</summary>
    [ObservableProperty]
    private string _errorActionText = "";

    /// <summary>Есть подробная расшифровка ошибки: показывается отдельной карточкой под состоянием.</summary>
    [ObservableProperty]
    private bool _hasErrorDetails;

    /// <summary>Что произошло — одной фразой, без кода.</summary>
    [ObservableProperty]
    private string _errorSummary = "";

    /// <summary>Почему так вышло: механика отказа.</summary>
    [ObservableProperty]
    private string _errorMeaning = "";

    /// <summary>Код ошибки словами; null — кода нет (например, таймаут).</summary>
    [ObservableProperty]
    private string? _errorCodeText;

    /// <summary>Сертификат сервера, если его удалось посмотреть.</summary>
    [ObservableProperty]
    private string? _errorCertificateText;

    /// <summary>Защиту можно снять: она включена или система в сбойном состоянии.</summary>
    [ObservableProperty]
    private bool _canRestore;

    [ObservableProperty]
    private StateTone _tone = StateTone.Neutral;

    [ObservableProperty]
    private SymbolRegular _stateSymbol = SymbolRegular.PlugDisconnected24;

    /// <summary>Идёт подключение или переподключение: вместо значка — кольцо ожидания.</summary>
    [ObservableProperty]
    private bool _isTransitioning;

    [ObservableProperty]
    private bool _passwordRequired;

    /// <summary>Подключение, которому нужен пароль: пароль уходит именно ему, а не опорному.</summary>
    [ObservableProperty]
    private string _passwordTitle = "Требуется пароль";

    private Guid? _passwordProfileId;

    [ObservableProperty]
    private string _password = "";

    /// <summary>Туннель AnyConnect ждёт входа: карточка с кнопкой «Войти».</summary>
    [ObservableProperty]
    private bool _signInRequired;

    [ObservableProperty]
    private string _signInTitle = "Требуется вход";

    [ObservableProperty]
    private string? _signInError;

    private Guid? _signInProfileId;

    /// <summary>
    /// Доска маршрутизации читается один раз при открытии страницы: по ней видно, что туннель поднят, но ничего
    /// не несёт. Опрос состояния настройки не запрашивает. Без ответа службы подсказки просто нет.
    /// </summary>
    public override async Task OnOpenedAsync()
    {
        try
        {
            _board = await Service.RequestAsync<AppSettings>(new GetSettingsRequest());
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or ServiceCommandException)
        {
            _board = null;
            return;
        }

        if (Main.Status is { } status)
        {
            SyncTunnels(status);
        }
    }

    public override void OnStatus(StatusDto? status)
    {
        if (status is null)
        {
            IsConnectedIntent = false;
            UpdateButtonText();
            Warnings.Clear();
            Note = DohNote;
            Tone = StateTone.Critical;
            StateSymbol = SymbolRegular.ErrorCircle24;
            IsTransitioning = false;
            ErrorText = null;
            SyncErrorDetails(null);
            CanRetry = false;
            HasErrorAction = false;
            CanRestore = false;
            PasswordRequired = false;
            _passwordProfileId = null;
            SignInRequired = false;
            _signInProfileId = null;
            Tunnels.Clear();
            _tunnelBytes.Clear();
            Profile = Adapter = VpnAddress = Duration = Sent = Received = "—";
            return;
        }

        IsConnectedIntent = MainViewModel.IsConnectedIntent(status);
        UpdateButtonText();
        Profile = status.ProfileName ?? "не выбрано";
        if (status.Protocol is { } protocol) { Profile += " · " + VpnProtocols.Name(protocol); }
        Adapter = status.PrimaryAdapterName ?? "недоступен";
        // Адрес и длительность — туннеля из плитки «Подключение»; при нескольких туннелях это видно по подписи.
        var owner = status.Tunnels.Count > 1 && status.ProfileName is { } name ? $" · «{name}»" : "";
        VpnAddress = status.VpnAddress is { } address ? address + owner : "—";
        Duration = status.SessionStartedUtc is { } started ? Format.Duration(DateTimeOffset.UtcNow - started) + owner : "—";
        Sent = status.State == ConnectionState.Connected ? Format.Bytes(status.BytesSent) : "—";
        Received = status.State == ConnectionState.Connected ? Format.Bytes(status.BytesReceived) : "—";
        // У «Трафик заблокирован» своего текста ошибки нет: причина всегда одна — нет основного адаптера.
        ErrorText = status.ErrorText ?? (status.State == ConnectionState.TrafficBlocked
            ? "Основной адаптер недоступен — проверьте Wi-Fi или кабель."
            : null);
        SyncErrorDetails(ErrorText is null ? null : status.ErrorHelp);
        CanRetry = status.State == ConnectionState.Error && IsConnectedIntent;
        HasErrorAction = status.State is ConnectionState.Error or ConnectionState.TrafficBlocked or ConnectionState.PartiallyApplied;
        ErrorActionText = ErrorActionFor(status).Text;
        CanRestore = MainViewModel.CanRestore(status);
        SyncPassword(status);
        SyncSignIn(status);
        (Tone, StateSymbol, IsTransitioning) = status.State switch
        {
            ConnectionState.Connected => (StateTone.Success, SymbolRegular.ShieldCheckmark24, false),
            ConnectionState.Error or ConnectionState.PartiallyApplied or ConnectionState.TrafficBlocked => (StateTone.Critical, SymbolRegular.ShieldError24, false),
            ConnectionState.Reconnecting or ConnectionState.Connecting or ConnectionState.ApplyingRoutes or ConnectionState.PreparingProtection => (StateTone.Accent, SymbolRegular.ArrowSync24, true),
            ConnectionState.PasswordRequired => (StateTone.Caution, SymbolRegular.Password24, false),
            ConnectionState.DisconnectedExternally => (StateTone.Caution, SymbolRegular.PlugDisconnected24, false),
            _ when status.ProtectionSuspended => (StateTone.Caution, SymbolRegular.ShieldDismiss24, false),
            _ when status.ProtectionActive => (StateTone.Caution, SymbolRegular.ShieldLock24, false),
            _ => (StateTone.Neutral, SymbolRegular.PlugDisconnected24, false),
        };
        SyncTunnels(status);
        SyncWarnings(status.Warnings);
    }

    /// <summary>Надпись кнопки: во время команды — что идёт, иначе — что произойдёт по нажатию.</summary>
    private void UpdateButtonText() => ButtonText = Main.BusyAction ?? (IsConnectedIntent ? "Отключить" : "Подключить");

    private void SyncTunnels(StatusDto status)
    {
        var rows = status.Tunnels.Select(t => TunnelRow.From(t, Speed(t), NothingRouted(t))).ToList();
        foreach (var gone in _tunnelBytes.Keys.Where(id => status.Tunnels.All(t => t.ProfileId != id)).ToList())
        {
            _tunnelBytes.Remove(gone);
        }

        if (rows.SequenceEqual(Tunnels))
        {
            return;
        }

        Tunnels.Clear();
        foreach (var row in rows)
        {
            Tunnels.Add(row);
        }
    }

    /// <summary>Скорость по байтам самого туннеля: разница с прошлым опросом. null — считать пока не по чему.</summary>
    private string? Speed(TunnelStatusDto tunnel)
    {
        var now = DateTimeOffset.UtcNow;
        string? text = null;
        if (_tunnelBytes.TryGetValue(tunnel.ProfileId, out var last) && tunnel.State == ConnectionState.Connected
            && tunnel.BytesSent >= last.Sent && tunnel.BytesReceived >= last.Received)
        {
            var seconds = Math.Max(0.5, (now - last.Time).TotalSeconds);
            text = $"↑ {Format.Bytes((tunnel.BytesSent - last.Sent) / seconds)}/с ↓ {Format.Bytes((tunnel.BytesReceived - last.Received) / seconds)}/с";
        }

        _tunnelBytes[tunnel.ProfileId] = (now, tunnel.BytesSent, tunnel.BytesReceived);
        return text;
    }

    /// <summary>
    /// Туннель поднят, а на доске ему ничего не назначено: ни правил, ни «остального интернета», ни группы,
    /// ни сетей шлюза. Такое подключение работает вхолостую, и это стоит показать.
    /// </summary>
    private bool NothingRouted(TunnelStatusDto tunnel)
    {
        if (_board is not { } settings || tunnel.State != ConnectionState.Connected)
        {
            return false;
        }

        var groups = settings.Groups.Where(g => g.Members.Contains(tunnel.ProfileId)).Select(g => g.Id).ToHashSet();
        return !settings.AllTargets.Any(t =>
            (t.Target.IsTunnel(out var id) && id == tunnel.ProfileId)
            || (t.Target.IsGroup(out var group) && groups.Contains(group)));
    }

    /// <summary>
    /// Карточка пароля видна, пока пароль нужен хотя бы одному туннелю — даже если общее состояние другое
    /// (например, «Ошибка» соседнего туннеля): иначе опрос закрывал бы карточку посреди набора.
    /// </summary>
    private void SyncPassword(StatusDto status)
    {
        // Туннелю AnyConnect нужен вход на шлюзе, а не пароль: для него своя карточка.
        var tunnel = status.Tunnels.FirstOrDefault(t => t is { State: ConnectionState.PasswordRequired, SignIn: null });
        _passwordProfileId = tunnel?.ProfileId;
        PasswordRequired = tunnel is not null || (status.State == ConnectionState.PasswordRequired && status.Tunnels.All(t => t.SignIn is null));
        PasswordTitle = tunnel is null ? "Требуется пароль" : $"Требуется пароль для «{tunnel.Name}»";
    }

    /// <summary>
    /// Вход в AnyConnect: окно ждёт, пока шлюз попросит данные, — кнопка есть только у туннеля, который ждёт
    /// действия пользователя; открытое окно входа служба закроет сама.
    /// </summary>
    private void SyncSignIn(StatusDto status)
    {
        var tunnel = status.Tunnels.FirstOrDefault(t => t.SignIn is { Kind: SignInKind.Required });
        _signInProfileId = tunnel?.ProfileId;
        SignInRequired = tunnel is not null;
        SignInTitle = tunnel is null ? "Требуется вход" : $"Требуется вход в «{tunnel.Name}»";
        SignInError = tunnel?.SignIn?.Error;
    }

    [RelayCommand]
    private Task SignInAsync() => _signInProfileId is { } id ? Main.RunCommandAsync(new BeginSignInRequest(id)) : Task.CompletedTask;

    [RelayCommand]
    private Task ConnectWithPasswordAsync()
    {
        var password = Password;
        Password = "";
        return string.IsNullOrEmpty(password) ? Task.CompletedTask : Main.RunCommandAsync(new ConnectRequest(_passwordProfileId, password));
    }

    [RelayCommand]
    private void OpenRouting() => Main.NavigateTo(Main.Routing);

    /// <summary>
    /// Куда вести пользователя по сбойному состоянию: данные входа, сертификат и адрес — в «Подключения»,
    /// остальное (в том числе заблокированный трафик и неполное применение) — в «Диагностику».
    /// </summary>
    private static (string Text, bool ToConnections) ErrorActionFor(StatusDto? status) => status?.State switch
    {
        ConnectionState.TrafficBlocked or ConnectionState.PartiallyApplied => ("Открыть «Диагностику»", false),
        _ => (status?.ErrorCategory ?? ErrorCategory.Other) switch
        {
            ErrorCategory.Authentication => ("Проверить данные входа", true),
            ErrorCategory.Certificate => ("Проверить сертификаты", true),
            ErrorCategory.NameResolution or ErrorCategory.ServerUnreachable => ("Проверить адрес сервера", true),
            _ => ("Открыть «Диагностику»", false),
        },
    };

    [RelayCommand]
    private void ErrorAction() => Main.NavigateTo(ErrorActionFor(Main.Status).ToConnections ? Main.Connections : Main.Diagnostics);

    /// <summary>
    /// Подробности отказа: что значит код и что делать. Шаги нумеруются здесь — в таком виде их читает
    /// и экранный диктор, и буфер обмена.
    /// </summary>
    private void SyncErrorDetails(ConnectionErrorHelp? help)
    {
        HasErrorDetails = help is not null;
        ErrorSummary = help?.Summary ?? "";
        ErrorMeaning = help?.Meaning ?? "";
        ErrorCodeText = help?.CodeText;
        ErrorCertificateText = help?.CertificateText;
        var steps = help is null
            ? []
            : help.Steps.Select((step, index) => string.Create(CultureInfo.InvariantCulture, $"{index + 1}. {step}")).ToList();
        if (steps.SequenceEqual(ErrorSteps))
        {
            return;
        }

        ErrorSteps.Clear();
        foreach (var step in steps)
        {
            ErrorSteps.Add(step);
        }
    }

    /// <summary>Сведения об ошибке одним куском: их удобно приложить к обращению за помощью.</summary>
    [RelayCommand]
    private void CopyError()
    {
        var lines = new List<string> { ErrorSummary, ErrorText ?? "", ErrorMeaning, ErrorCertificateText ?? "", ErrorCodeText ?? "" };
        lines.AddRange(ErrorSteps);
        try
        {
            Clipboard.SetText(string.Join(Environment.NewLine, lines.Where(line => line.Length > 0)));
            ShowMessage("Сведения об ошибке скопированы в буфер обмена.", isError: false);
        }
        catch (ExternalException ex)
        {
            // Буфером обмена владеет другая программа: копирование просто не состоялось.
            ShowError("Не удалось скопировать сведения: " + ex.Message);
        }
    }

    /// <summary>
    /// Включает или отключает один туннель прямо сейчас, не трогая настройки. Про опорное подключение
    /// спрашиваем: его отключение включает защиту при обрыве и оставляет без интернета вообще.
    /// </summary>
    [RelayCommand]
    private async Task ToggleTunnelAsync(TunnelRow row)
    {
        ArgumentNullException.ThrowIfNull(row);
        if (!row.Paused && row.IsAnchor && !await ConfirmAnchorOffAsync(row.Name))
        {
            return;
        }

        await Main.RunCommandAsync(new SetTunnelPausedRequest(row.ProfileId, !row.Paused));
    }

    private Task<bool> ConfirmAnchorOffAsync(string name) => Main.Confirm(
        "Отключить опорное подключение?",
        $"Через «{name}» идёт остальной интернет. " + (Main.Status?.OutageMode == OutageMode.AllowAll
            ? "Пока оно отключено, этот трафик пойдёт напрямую, мимо VPN."
            : "Пока оно отключено, защита блокирует этот трафик: интернета не будет, пока вы не включите подключение обратно."),
        "Отключить");

    /// <summary>
    /// Выключить подключение совсем: это уже правка настроек, она переживает перезапуск. Цели, назначенные
    /// на него, служба иначе не пропустит — поэтому сначала переводим их на прямой выход и говорим об этом.
    /// </summary>
    [RelayCommand]
    private Task TurnOffTunnelAsync(TunnelRow row) => RunAsync(async () =>
    {
        ArgumentNullException.ThrowIfNull(row);
        var fresh = await Service.RequestAsync<AppSettings>(new GetSettingsRequest());
        if (fresh.Profile(row.ProfileId) is not { } profile)
        {
            return null;
        }

        var updated = ConnectionEdits.SaveProfile(fresh, profile with { Role = ProfileRole.Off });
        var direct = ConnectionEdits.NewlyDirect(fresh, updated);
        var consequence = direct.Count > 0
            ? $" Напрямую, мимо VPN, пойдут: {string.Join(", ", direct)}."
            : "";
        if (!await Main.Confirm("Выключить подключение совсем?",
            $"«{row.Name}» не будет подниматься, пока вы не включите его на странице «Подключения»." + consequence,
            "Выключить"))
        {
            return null;
        }

        await Service.CommandAsync(new SaveSettingsRequest(updated));
        return $"«{row.Name}» выключено.";
    });

    /// <summary>Действие предупреждения: переход на нужную страницу, окно Windows или команда службе.</summary>
    [RelayCommand]
    private async Task WarningActionAsync(WarningRow warning)
    {
        ArgumentNullException.ThrowIfNull(warning);
        switch (warning.ActionCode ?? warning.Code)
        {
            case "geo-update":
                Main.NavigateTo(Main.Routing);
                await Main.Routing.UpdateGeoCommand.ExecuteAsync(null);
                break;
            case "geo-review":
            case "group-degraded":
                Main.NavigateTo(Main.Routing);
                break;
            case "update-install":
                Main.NavigateTo(Main.About);
                await Main.About.InstallUpdateCommand.ExecuteAsync(null);
                break;
            case "update-open":
                Main.NavigateTo(Main.About);
                break;
            case "enter-password":
                PasswordRequired = true;
                break;
            case "sign-in":
                await SignInAsync();
                break;
            case "foreign-vpn":
            case "foreign-routes":
                OpenNetworkConnections();
                break;
            case "public-onlink":
                Main.NavigateTo(Main.Protection);
                break;
            default:
                Main.NavigateTo(Main.Diagnostics);
                break;
        }
    }

    /// <summary>«Сетевые подключения» Windows: там видно и отключается чужое VPN-подключение.</summary>
    private void OpenNetworkConnections()
    {
        try
        {
            Process.Start(new ProcessStartInfo("control.exe", "ncpa.cpl") { UseShellExecute = true });
        }
        catch (Win32Exception ex)
        {
            ShowError("Не удалось открыть «Сетевые подключения»: " + ex.Message);
        }
    }

    private void SyncWarnings(IReadOnlyList<StatusWarning> warnings)
    {
        // Постоянное ограничение IPv6 — не повод для жёлтой карточки на каждом опросе: оно уходит в серую строку
        // вместе с пояснением про DNS-over-HTTPS, чтобы одно и то же не висело на нескольких страницах.
        Note = warnings.Any(w => w.Code == Ipv6WarningCode) ? Ipv6Note + " " + DohNote : DohNote;
        var rows = warnings.Where(w => w.Code != Ipv6WarningCode).Select(WarningRow.From).ToList();
        if (rows.SequenceEqual(Warnings))
        {
            return;
        }

        Warnings.Clear();
        foreach (var row in rows)
        {
            Warnings.Add(row);
        }
    }
}

/// <summary>
/// Предупреждение с кнопкой следующего шага. Часть кодов служба присылает без действия — куда с ними идти,
/// знает интерфейс: чужое VPN-подключение отключают в «Сетевых подключениях», группу правят в «Маршрутизации».
/// </summary>
public sealed record WarningRow(string Code, string Text, string? ActionCode, string? ActionText)
{
    /// <summary>Имя строки для экранного диктора.</summary>
    public override string ToString() => ActionText is null ? Text : $"{Text} Действие: {ActionText}.";

    public static WarningRow From(StatusWarning warning)
    {
        ArgumentNullException.ThrowIfNull(warning);
        return new WarningRow(warning.Code, warning.Text, warning.ActionCode, ActionTextFor(warning));
    }

    private static string? ActionTextFor(StatusWarning warning) => warning.ActionCode switch
    {
        "geo-update" => "Загрузить базу",
        "geo-review" => "Рассмотреть",
        "update-install" => "Обновить",
        "update-open" => "Посмотреть",
        "enter-password" => "Ввести пароль",
        "sign-in" => "Войти",
        not null => "Подробнее",
        null => warning.Code switch
        {
            "foreign-vpn" or "foreign-routes" => "Сетевые подключения",
            "public-onlink" => "Защита и DNS",
            "group-degraded" => "Маршрутизация",
            "wfp-hard-permit" => "Диагностика",
            _ => null,
        },
    };
}

/// <summary>Строка о туннеле на главной: чем он поднят, что несёт и с какой скоростью.</summary>
public sealed record TunnelRow(
    Guid ProfileId, string Name, ProfileRole Role, string RoleText, string Protocol, string State, string Detail,
    string? Note, StateTone Tone, bool Paused, bool IsAnchor)
{
    /// <summary>Переключатель включён, когда туннель не положен вручную.</summary>
    public bool Enabled => !Paused;

    /// <summary>Имя переключателя для экранного диктора: у каждой строки своё.</summary>
    public string ToggleName => (Paused ? "Включить " : "Отключить ") + Name;

    /// <summary>Значок показывает, что произойдёт по нажатию. Оба имени уже используются в проекте.</summary>
    public SymbolRegular ToggleSymbol => Paused ? SymbolRegular.PlugDisconnected24 : SymbolRegular.PlugConnected24;

    /// <summary>Имя строки для экранного диктора.</summary>
    public override string ToString() =>
        $"{Name}, {RoleText}, {Protocol}: {State}, {Detail}" + (Note is null ? "" : ". " + Note);

    public static TunnelRow From(TunnelStatusDto tunnel, string? speed, bool nothingRouted)
    {
        ArgumentNullException.ThrowIfNull(tunnel);
        var tone = tunnel.State switch
        {
            ConnectionState.Connected => StateTone.Success,
            ConnectionState.Error or ConnectionState.TrafficBlocked or ConnectionState.PartiallyApplied => StateTone.Critical,
            ConnectionState.Disconnected or ConnectionState.DisconnectedExternally => StateTone.Neutral,
            _ => StateTone.Caution,
        };

        var parts = new List<string>();
        if (tunnel.Paused)
        {
            // Положено пользователем — это не ошибка и не сбой: говорим, как вернуть.
            parts.Add("отключено вами; «Подключить» поднимет снова");
        }
        else if (tunnel.ErrorText is { } error)
        {
            parts.Add(error);
        }
        else if (tunnel.SignIn is { Kind: SignInKind.Required })
        {
            parts.Add("нужен вход");
        }
        else
        {
            parts.Add(tunnel.VpnAddress is { } address ? "адрес " + address : "адрес не получен");
        }

        if (tunnel.State == ConnectionState.Connected && tunnel.SessionStartedUtc is { } started)
        {
            parts.Add(Format.Duration(DateTimeOffset.UtcNow - started));
        }

        if (tunnel.ServerNetworks is { } gateway)
        {
            parts.Add(gateway.DtlsActive ? "DTLS" : "TLS");
            parts.Add(Format.Count(gateway.Networks.Count, "сеть", "сети", "сетей") + " шлюза");
            if (gateway.SessionExpiresUtc is { } expires)
            {
                parts.Add("сеанс до " + Format.Time(expires));
            }
        }

        if (speed is { } rate)
        {
            parts.Add(rate);
        }

        return new TunnelRow(
            tunnel.ProfileId,
            tunnel.Name,
            tunnel.Role,
            RoleName(tunnel.Role),
            VpnProtocols.Name(tunnel.Protocol),
            tunnel.Paused ? "Отключено" : StatusText.StateName(tunnel.State),
            string.Join(" · ", parts),
            nothingRouted && !tunnel.Paused ? "на это подключение ничего не направлено" : null,
            tunnel.Paused ? StateTone.Neutral : tone,
            tunnel.Paused,
            tunnel.IsAnchor);
    }

    private static string RoleName(ProfileRole role) => role switch
    {
        ProfileRole.Primary => "опорное",
        ProfileRole.Secondary => "дополнительное",
        _ => "выключено",
    };
}
