using System.Collections.ObjectModel;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;

namespace SplitVpn.App.ViewModels;

public enum GeoStartOption
{
    DownloadNow,
    ViaTunnel,
    ImportFile,
}

/// <summary>Поле мастера с ошибкой ввода: в него переводится фокус.</summary>
public enum WizardField
{
    None,
    Name,
    Server,
    UserName,
    Password,

    /// <summary>Поля блока «Параметры входа и безопасности»: блок раскрывается.</summary>
    Security,

    ImportFile,
}

/// <summary>
/// Мастер первого запуска: сервер и вход → основной адаптер → режим → RU-база → проверка.
/// Мастер можно прервать и запустить снова; до шага «Готово» в системе ничего не меняется.
/// </summary>
public sealed partial class WizardViewModel : ObservableObject
{
    public ConnectionSecurityViewModel Security { get; } = new() { CanClearSavedKey = false, AllowAnyConnect = false, AllowSshVpn = false };
    public const int LastStep = 4;

    private readonly MainViewModel _main;
    private readonly Guid _profileId = Guid.NewGuid();
    private ConnectionProfile? _acceptedProfile;
    private Task? _adapterLoad;

    /// <summary>«Готово» отправило службе ConnectRequest: намерение «подключено» и защита уже у службы.</summary>
    private bool _connectSent;

    /// <summary>Снимок настроек сделан (при первом сохранении профиля мастером).</summary>
    private bool _settingsCaptured;

    /// <summary>
    /// Мастер отправил службе сохранение профиля. Ставится до отправки: служба могла записать настройки, даже если
    /// ответ не дошёл или не записался пароль. С этого момента «Отмена» возвращает то, что мастер поменял.
    /// </summary>
    private bool _profileSaved;

    /// <summary>Цель RU-базы, которую записал мастер: «Отмена» возвращает прежнюю, только если она такой и осталась.</summary>
    private RouteTarget _wizardGeo = RouteTarget.Direct;

    /// <summary>
    /// Настройки до первого сохранения профиля мастером. Мастер делает новое подключение опорным, понижает прежнее
    /// опорное и забирает «Остальной интернет» и RU-базу: после неудачи любого следующего шага «Отмена» возвращает
    /// эти поля (новое подключение остаётся выключенным), а не рвёт все туннели.
    /// </summary>
    private AppSettings? _settingsBefore;

    /// <summary>До мастера были другие включённые подключения: их работу «Отмена» должна сохранить.</summary>
    private bool OtherProfilesWereEnabled => _settingsBefore?.Profiles.Any(p => p.Id != _profileId && p.Role != ProfileRole.Off) == true;

    /// <param name="main">Главная модель.</param>
    /// <param name="loadAdapters">Запросить адаптеры у службы; самопроверка разметки обходится без службы.</param>
    public WizardViewModel(MainViewModel main, bool loadAdapters = true)
    {
        _main = main;
        Security.ResetDetailsExpanded();
        if (loadAdapters)
        {
            _adapterLoad = LoadAdaptersAsync();
        }
    }

    public ObservableCollection<AdapterDto> Adapters { get; } = [];

    public static IReadOnlyList<string> StepTitles { get; } = ["Сервер и вход", "Основной адаптер", "Режим", "RU-база", "Проверка"];

    /// <summary>Шаг «RU-база»: при режиме «Весь интернет через VPN» база не используется, и шаг пропускается.</summary>
    private const int GeoStep = 3;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StepTitle), nameof(CanGoBack), nameof(NextText))]
    private int _step;

    /// <summary>Шаг показывается: «RU-база» — только в режиме «Россия напрямую».</summary>
    public bool IsStepShown(int step) => step != GeoStep || RussiaDirect;

    /// <summary>Последний шаг с вводом: после него «Готово: подключить».</summary>
    public int LastInputStep => RussiaDirect ? GeoStep : GeoStep - 1;

    private int ShownStepCount => Enumerable.Range(0, LastStep + 1).Count(IsStepShown);

    private int ShownStepNumber => Enumerable.Range(0, Math.Clamp(Step, 0, LastStep) + 1).Count(IsStepShown);

    // Запросы фокуса на поле с ошибкой: представление переводит курсор в поле при каждом изменении.
    [ObservableProperty]
    private int _nameFocusToken;

    [ObservableProperty]
    private int _serverFocusToken;

    [ObservableProperty]
    private int _userNameFocusToken;

    [ObservableProperty]
    private int _passwordFocusToken;

    [ObservableProperty]
    private int _importFocusToken;

    [ObservableProperty]
    private string _name = "Основное";

    [ObservableProperty]
    private string _server = "";

    [ObservableProperty]
    private string _userName = "";

    [ObservableProperty]
    private string _password = "";

    [ObservableProperty]
    private bool _savePassword = true;

    [ObservableProperty]
    private bool _pinAdapter;

    [ObservableProperty]
    private AdapterDto? _pinnedAdapter;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StepTitle), nameof(NextText), nameof(LastInputStep))]
    private bool _russiaDirect = true;

    [ObservableProperty]
    private GeoStartOption _geoOption = GeoStartOption.DownloadNow;

    [ObservableProperty]
    private string? _importPath;

    [ObservableProperty]
    private string? _error;

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private string _progress = "";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanGoBack), nameof(CanCancel), nameof(NextText))]
    private bool _finished;

    public string StepTitle => $"Шаг {ShownStepNumber} из {ShownStepCount}. {StepTitles[Math.Clamp(Step, 0, LastStep)]}";

    public bool CanGoBack => Step > 0 && !Finished && !IsBusy;

    public bool CanCancel => !Finished && !IsBusy;

    partial void OnIsBusyChanged(bool value)
    {
        OnPropertyChanged(nameof(CanGoBack));
        OnPropertyChanged(nameof(CanCancel));
        NextCommand.NotifyCanExecuteChanged();
    }

    public string NextText => Finished ? "Закрыть" : Step == LastInputStep ? "Готово: подключить" : "Далее";

    public bool GeoDownloadNow
    {
        get => GeoOption == GeoStartOption.DownloadNow;
        set { if (value) { GeoOption = GeoStartOption.DownloadNow; } }
    }

    public bool GeoViaTunnel
    {
        get => GeoOption == GeoStartOption.ViaTunnel;
        set { if (value) { GeoOption = GeoStartOption.ViaTunnel; } }
    }

    public bool GeoImport
    {
        get => GeoOption == GeoStartOption.ImportFile;
        set { if (value) { GeoOption = GeoStartOption.ImportFile; } }
    }

    partial void OnGeoOptionChanged(GeoStartOption value)
    {
        OnPropertyChanged(nameof(GeoDownloadNow));
        OnPropertyChanged(nameof(GeoViaTunnel));
        OnPropertyChanged(nameof(GeoImport));
    }

    [RelayCommand]
    private void Back()
    {
        Error = null;
        var step = Math.Min(Step, LastStep) - 1;
        while (step > 0 && !IsStepShown(step))
        {
            step--;
        }

        Step = Math.Max(0, step);
    }

    private bool CanGoNext => !IsBusy;

    [RelayCommand(CanExecute = nameof(CanGoNext))]
    private async Task NextAsync()
    {
        if (Finished)
        {
            _main.CloseWizard(dismissForever: false);
            return;
        }

        if (Step >= LastStep)
        {
            // Шаг проверки идёт сам; повторное нажатие до конца применения ничего не делает.
            return;
        }

        var (error, field) = ValidateStep();
        Error = error;
        if (Error is not null)
        {
            FocusField(field);
            return;
        }

        if (Step == 0)
        {
            // Занятое название выясняется сразу, а не после «Готово» на последнем шаге.
            Error = await NameProblemAsync();
            if (Error is not null)
            {
                FocusField(WizardField.Name);
                return;
            }
        }

        if (Step >= LastInputStep)
        {
            Step = LastStep;
            await ApplyAsync();
            return;
        }

        var next = Step + 1;
        while (next < LastStep && !IsStepShown(next))
        {
            next++;
        }

        Step = next;
        if (Step == 1 && Adapters.Count == 0)
        {
            await (_adapterLoad is { IsCompleted: false } ? _adapterLoad : _adapterLoad = LoadAdaptersAsync());
        }
    }

    /// <summary>
    /// «Отмена». Профиль уже сохранён (дальше не удались RU-база, смена её цели или подключение) — возвращаются
    /// поля, которые поменял мастер (роли, «Остальной интернет», RU-база), если их с тех пор не меняли в другом
    /// месте; новое подключение остаётся выключенным, работающие туннели не рвутся. Если «Готово» уже отправило
    /// подключение, а других включённых подключений до мастера не было, служба держит намерение «подключено» и
    /// защиту — тогда VPN отключается со снятием защиты. Профиль остаётся, его можно исправить в «Подключениях».
    /// Пока возврат или отключение не прошли, мастер не закрывается.
    /// </summary>
    [RelayCommand]
    private async Task CancelAsync()
    {
        Password = "";
        Security.ClearSecrets();
        // Профиль сохранён, а дальше что-то не удалось (RU-база, подключение): «Отмена» возвращает роли и цели,
        // которые поменял мастер. Исключение — подключение уже отправлено, а других включённых подключений не было:
        // тогда ниже VPN отключается со снятием защиты.
        if (_profileSaved && _settingsBefore is { } before && (OtherProfilesWereEnabled || !_connectSent))
        {
            IsBusy = true;
            Progress = "Возврат прежних настроек подключений…";
            try
            {
                var fresh = await _main.Service.RequestAsync<AppSettings>(new GetSettingsRequest());
                // Возвращаются только поля, которые менял мастер, и только если их с тех пор не поменяли в другом месте;
                // ревизия свежих настроек: если их изменят и сейчас, служба откажет, и «Отмена» повторится.
                if (Rollback(before, fresh, _profileId, _wizardGeo) is { } restored)
                {
                    await _main.Service.CommandAsync(new SaveSettingsRequest(restored, SettingsSerializer.Revision(fresh)));
                }

                _connectSent = false;
                _profileSaved = false;
            }
            catch (Exception ex) when (ex is ServiceUnavailableException or Services.ServiceCommandException)
            {
                Error = "Не удалось вернуть прежние настройки подключений: " + ex.Message
                    + " Повторите «Отмена» или верните роли подключений в «Подключениях».";
                return;
            }
            finally
            {
                IsBusy = false;
            }

            _main.CloseWizard(dismissForever: false);
            return;
        }

        if (_connectSent)
        {
            // Других включённых подключений не было: отключение VPN ничего работающего не рвёт.
            IsBusy = true;
            Progress = "Отключение VPN и снятие защиты…";
            try
            {
                if (!await _main.RunCommandAsync(new DisconnectRequest(KeepProtection: false)))
                {
                    Error = "Не удалось отключить VPN и снять защиту. Повторите «Отмена» или нажмите «Отключить и восстановить интернет» на главной странице.";
                    return;
                }

                _connectSent = false;
            }
            finally
            {
                IsBusy = false;
            }

            // Профиль уже сохранён: мастер сам больше не откроется, запоминать отказ от него не нужно.
            _main.CloseWizard(dismissForever: false);
            return;
        }

        _main.CloseWizard(dismissForever: true);
    }

    [RelayCommand]
    private void BrowseImport()
    {
        var dialog = new OpenFileDialog { Filter = "Список CIDR|*.txt;*.lst|Все файлы|*.*" };
        if (dialog.ShowDialog() == true)
        {
            ImportPath = dialog.FileName;
            GeoOption = GeoStartOption.ImportFile;
        }
    }

    /// <summary>Проверка шага: текст ошибки называет поле, а поле получает фокус (см. <see cref="FocusField"/>).</summary>
    internal (string? Error, WizardField Field) ValidateStep() => Step switch
    {
        0 when string.IsNullOrWhiteSpace(Name) => ("Название: введите название подключения, например «Основное».", WizardField.Name),
        0 when !VpnProtocols.TryParseServer(Server, Security.Protocol, out _) => (UiText.ServerFieldError(Security.Protocol, Server), WizardField.Server),
        0 when VpnProtocols.UnsupportedAuthText(Security.Protocol, Security.AuthMethod) is { } unsupported => (unsupported, WizardField.Security),
        0 when VpnProtocols.ValidateAuthentication(Security.Apply(new ConnectionProfile { UserName = UserName })) is [var error, ..]
            => (error, error.StartsWith("Имя пользователя", StringComparison.Ordinal) ? WizardField.UserName : WizardField.Security),
        0 when Security.NeedsPassword && string.IsNullOrWhiteSpace(UserName) => ("Имя пользователя: введите имя для входа в VPN.", WizardField.UserName),
        0 => MissingCredential(CanKeepCredentials(BuildProfile(null))),
        1 when PinAdapter && PinnedAdapter is null => ("Адаптер: выберите адаптер или оставьте автоматический выбор.", WizardField.None),
        3 when RussiaDirect && GeoOption == GeoStartOption.ImportFile && !File.Exists(ImportPath) => ("Файл базы: выберите файл со списком сетей.", WizardField.ImportFile),
        3 when RussiaDirect && GeoOption == GeoStartOption.ImportFile && new FileInfo(ImportPath!).Length > GeoImportFile.MaxBytes => (GeoImportFile.TooLarge, WizardField.ImportFile),
        _ => (null, WizardField.None),
    };

    private (string? Error, WizardField Field) MissingCredential(bool canKeep)
    {
        if (canKeep) { return (null, WizardField.None); }
        if (Security.NeedsPassword && Password.Length == 0) { return ("Пароль: введите пароль для входа в VPN.", WizardField.Password); }
        return Security.NeedsPsk && Security.PreSharedKey.Length == 0
            ? ("Общий ключ IPsec (PSK): введите ключ, который выдал администратор VPN.", WizardField.Security)
            : (null, WizardField.None);
    }

    /// <summary>Курсор — в поле с ошибкой; поля безопасности в свёрнутом блоке — блок раскрывается.</summary>
    private void FocusField(WizardField field)
    {
        switch (field)
        {
            case WizardField.Name: NameFocusToken++; break;
            case WizardField.Server: ServerFocusToken++; break;
            case WizardField.UserName: UserNameFocusToken++; break;
            case WizardField.Password: PasswordFocusToken++; break;
            case WizardField.ImportFile: ImportFocusToken++; break;
            case WizardField.Security: Security.DetailsExpanded = true; break;
        }
    }

    private string? MissingCredentialMessage(bool canKeep) => MissingCredential(canKeep).Error;

    private const string NameTaken = "Название уже занято. Укажите другое название подключения.";

    /// <summary>Названия сравниваются как в проверке настроек службы: без пробелов по краям и без учёта регистра.</summary>
    private static bool IsNameTaken(AppSettings settings, Guid profileId, string name) =>
        settings.Profiles.Any(p => p.Id != profileId && string.Equals(p.Name.Trim(), name.Trim(), StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Проверка названия на шаге «Сервер и вход»: null — название свободно или служба сейчас недоступна (окончательная
    /// проверка — при сохранении профиля, недоступная служба не должна запирать мастер на первом шаге).
    /// </summary>
    private async Task<string?> NameProblemAsync()
    {
        IsBusy = true;
        try
        {
            var settings = await _main.Service.RequestAsync<AppSettings>(new GetSettingsRequest());
            return IsNameTaken(settings, _profileId, Name) ? NameTaken : null;
        }
        catch (ServiceUnavailableException)
        {
            return null;
        }
        catch (Services.ServiceCommandException ex)
        {
            return ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private bool CanKeepCredentials(ConnectionProfile? profile) =>
        _acceptedProfile is { } accepted && profile is not null && accepted.SavePassword == profile.SavePassword
        && VpnProtocols.ConnectionKey(accepted) == VpnProtocols.ConnectionKey(profile);

    private async Task LoadAdaptersAsync()
    {
        try
        {
            foreach (var adapter in await _main.Service.RequestAsync<List<AdapterDto>>(new GetAdaptersRequest()))
            {
                Adapters.Add(adapter);
            }

            PinnedAdapter = Adapters.FirstOrDefault(a => a.IsPrimary);
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or Services.ServiceCommandException)
        {
            Error = ex.Message;
        }
    }

    /// <summary>
    /// Применение настроек. Любая ошибка возвращает мастер на шаг «RU-база» с текстом: мастер не должен
    /// застрять на шаге проверки. Пароль и ключ стираются только после того, как служба их приняла, —
    /// повторное «Готово» после ошибки не отправит пустой пароль.
    /// </summary>

    private async Task ApplyAsync()
    {
        IsBusy = true;
        Error = null;
        try
        {
            if (!await SaveProfileAsync()) { return; }
            Password = "";
            Security.ClearSecrets();
            if (RussiaDirect)
            {
                await PrepareGeoAsync();
            }
            var viaTunnel = RussiaDirect && GeoOption == GeoStartOption.ViaTunnel;
            try
            {
                if (viaTunnel)
                {
                    await ChangeGeoTargetAsync(RouteTarget.Direct, RouteTarget.Tunnel(_profileId));
                }

                Progress = "Подключение…";
                // Отметка ставится до отправки: служба могла принять команду, даже если ответ не дошёл.
                _connectSent = true;
                await _main.Service.CommandAsync(new ConnectRequest(_profileId, null));
                var status = await WaitConnectedAsync();
                if (status?.State != ConnectionState.Connected)
                {
                    if (status?.State == ConnectionState.PasswordRequired || status?.ErrorCategory == ErrorCategory.Authentication)
                    {
                        _acceptedProfile = null;
                    }
                    Error = $"Подключение не завершено: {StatusText.StateName(status?.State ?? ConnectionState.Error)}. {status?.ErrorText} "
                        + (!OtherProfilesWereEnabled
                            ?"Исправьте данные и нажмите «Далее» — или «Отмена»: VPN отключится, защита снимется, подключение останется в «Подключениях»."
                            : "Исправьте данные и нажмите «Далее» — или «Отмена»: вернутся прежние настройки подключений, работающие подключения не разорвутся, а новое останется выключенным в «Подключениях».");
                    Step = 0;
                    if (status?.State == ConnectionState.PasswordRequired || status?.ErrorCategory == ErrorCategory.Authentication)
                    {
                        PasswordFocusToken++;
                    }

                    return;
                }

                // Подключение работает: «Отмена» после следующей ошибки его не разрывает.
                _connectSent = false;
                if (viaTunnel)
                {
                    Progress = "Загрузка RU-базы через VPN…";
                    await _main.Service.CommandAsync(new GeoUpdateNowRequest());
                }

                Progress = "Готово. " + UiText.StatusSummary(status);
            }
            finally
            {
                if (viaTunnel)
                {
                    await ChangeGeoTargetAsync(RouteTarget.Tunnel(_profileId), RouteTarget.Direct);
                }
            }
            Finished = true;
        }
        catch (Exception ex)
        {
            // Сообщения службы и самого приложения русские; системные (.NET) — английские и пользователю не показываются.
            Error = ex is ServiceUnavailableException or Services.ServiceCommandException or FormatException or UserFacingException
                ? ex.Message
                : ex is IOException or UnauthorizedAccessException ? UiText.FileError(ex, ImportPath)
                : "Не удалось применить настройки. Повторите «Готово: подключить»; если ошибка повторится, соберите архив в «Диагностике».";
            if (Error.StartsWith("Не удалось применить", StringComparison.Ordinal))
            {
                SplitVpn.Core.Diagnostics.Verbose.Write("Ui", "мастер: ошибка применения " + ex);
            }

            Step = LastInputStep;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task<bool> SaveProfileAsync()
    {
        Progress = "Сохранение подключения…";
        var settings = await _main.Service.RequestAsync<AppSettings>(new GetSettingsRequest());
        var existing = settings.Profiles.FirstOrDefault(p => p.Id == _profileId);
        if (IsNameTaken(settings, _profileId, Name))
        {
            // Название поменяли в другом месте после шага «Сервер и вход»: исправлять его там же.
            Error = NameTaken;
            Step = 0;
            return false;
        }

        var profile = BuildProfile(existing);
        if (MissingCredentialMessage(CanKeepCredentials(existing) && CanKeepCredentials(profile)) is { } problem)
        {
            _acceptedProfile = null;
            Error = problem;
            Step = 0;
            return false;
        }
        var updated = ConnectionEdits.SaveProfile(settings, profile) with
        {
            DefaultTarget = RouteTarget.Tunnel(profile.Id),
            GeoTarget = RussiaDirect ? RouteTarget.Direct : RouteTarget.Tunnel(profile.Id),
        };
        if (!_settingsCaptured)
        {
            // Мастер запущен повторно, а другие подключения уже работают: до сохранения видно, какое из них перестанет
            // быть опорным и что перейдёт на новое подключение.
            if (TakeoverText(settings, updated, _profileId) is { } takeover
                && !await _main.Confirm("Новое подключение станет опорным", takeover, "Продолжить"))
            {
                Error = "Сохранение отменено: прежние подключения не изменены. Нажмите «Готово: подключить», чтобы продолжить, или «Отмена».";
                Step = LastInputStep;
                return false;
            }

            // Снимок — до первого сохранения: повторное «Готово» видит настройки уже с новым подключением опорным.
            _settingsCaptured = true;
            _settingsBefore = settings;
        }

        // Отметка — до отправки: служба могла записать настройки, даже если не записала пароль или не ответила.
        _profileSaved = true;
        _wizardGeo = updated.GeoTarget;
        // Пустое значение — «не менять»: пароль уже мог быть принят службой при прошлой попытке.
        await _main.Service.CommandAsync(new SaveConnectionRequest(updated, profile.Id,
            Security.NeedsPassword && Password.Length > 0 ? Password : null,
            Security.NeedsPsk && Security.PreSharedKey.Length > 0 ? Security.PreSharedKey : null,
            ExpectedRevision: SettingsSerializer.Revision(settings)));
        _acceptedProfile = profile;
        return true;
    }

    private ConnectionProfile BuildProfile(ConnectionProfile? existing) => Security.Apply((existing ?? new ConnectionProfile { Id = _profileId }) with
    {
        Name = Name.Trim(),
        Server = Server.Trim(),
        UserName = UserName.Trim(),
        SavePassword = SavePassword,
        Role = ProfileRole.Primary,
        PrimaryAdapter = PinAdapter ? AdapterSelection.Pinned : AdapterSelection.Auto,
        PinnedInterfaceGuid = PinAdapter ? PinnedAdapter?.InterfaceGuid : null,
    });

    /// <summary>
    /// Что сохранение мастера отнимет у работающих подключений: какое опорное станет дополнительным и какие места
    /// назначения перейдут на новое подключение. null — других включённых подключений нет, спрашивать не о чем.
    /// </summary>
    internal static string? TakeoverText(AppSettings before, AppSettings after, Guid profileId)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);
        if (!before.Profiles.Any(p => p.Id != profileId && p.Role != ProfileRole.Off))
        {
            return null;
        }

        var name = after.Profile(profileId)?.Name ?? "Новое подключение";
        var lines = new List<string> { $"«{name}» станет опорным подключением." };
        if (before.PrimaryProfile is { } primary && primary.Id != profileId)
        {
            lines.Add($"«{primary.Name}» станет дополнительным: перестанет давать DNS по умолчанию и определять обрыв.");
        }

        foreach (var (where, was, will) in new[]
        {
            ("«Остальной интернет»", before.DefaultTarget, after.DefaultTarget),
            ("«Россия (RU-база)»", before.GeoTarget, after.GeoTarget),
        })
        {
            if (was != will)
            {
                lines.Add($"{where}: сейчас {TargetText(before, was)}, будет {TargetText(after, will)}.");
            }
        }

        lines.Add("Если дальше что-то не удастся, «Отмена» вернёт прежние роли и маршруты.");
        return string.Join("\n", lines);
    }

    private static string TargetText(AppSettings settings, RouteTarget target) => target.Kind switch
    {
        TargetKind.Direct => "напрямую",
        TargetKind.Block => "блокируется",
        _ => settings.TargetName(target),
    };

    /// <summary>
    /// Откат мастера поверх свежих настроек: новое подключение выключается, прежнее опорное снова опорное,
    /// «Остальной интернет» и RU-база возвращаются к прежним целям. Каждое поле возвращается, только если оно
    /// всё ещё такое, каким его сделал мастер: правки, сделанные в другом месте, остаются. null — возвращать нечего.
    /// </summary>
    /// <param name="before">Настройки до первого сохранения мастером.</param>
    /// <param name="fresh">Настройки службы сейчас.</param>
    /// <param name="profileId">Подключение мастера.</param>
    /// <param name="wizardGeo">Цель RU-базы, которую поставил мастер.</param>
    internal static AppSettings? Rollback(AppSettings before, AppSettings fresh, Guid profileId, RouteTarget wizardGeo)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(fresh);
        var wizardTunnel = RouteTarget.Tunnel(profileId);
        var restorePrimary = before.PrimaryProfile is { } oldPrimary && oldPrimary.Id != profileId
            && fresh.Profile(oldPrimary.Id) is { Role: ProfileRole.Secondary }
            && !fresh.Profiles.Any(p => p.Id != profileId && p.Role == ProfileRole.Primary)
                ? oldPrimary.Id : (Guid?)null;
        var wasNew = before.Profile(profileId) is null;
        var profiles = fresh.Profiles.Select(p =>
            p.Id == profileId && p.Role != ProfileRole.Off ? p with { Role = wasNew ? ProfileRole.Off : before.Profile(profileId)!.Role }
            : p.Id == restorePrimary ? p with { Role = ProfileRole.Primary }
            : p).ToList();
        var restored = fresh with
        {
            Profiles = profiles,
            DefaultTarget = fresh.DefaultTarget == wizardTunnel ? before.DefaultTarget : fresh.DefaultTarget,
            // Шаг «через VPN» временно направляет RU-базу в новое подключение; «Напрямую» мастер ставит сам.
            GeoTarget = fresh.GeoTarget == wizardTunnel || fresh.GeoTarget == wizardGeo ? before.GeoTarget : fresh.GeoTarget,
        };
        var changed = restored.DefaultTarget != fresh.DefaultTarget || restored.GeoTarget != fresh.GeoTarget
            || !profiles.Select(p => p.Role).SequenceEqual(fresh.Profiles.Select(p => p.Role));
        return changed ? ConnectionEdits.Retarget(restored) : null;
    }

    private async Task ChangeGeoTargetAsync(RouteTarget expected, RouteTarget target)
    {
        var fresh = await _main.Service.RequestAsync<AppSettings>(new GetSettingsRequest());
        if (fresh.GeoTarget == expected && fresh.DefaultTarget == RouteTarget.Tunnel(_profileId))
        {
            await _main.Service.CommandAsync(new SaveSettingsRequest(fresh with { GeoTarget = target }, SettingsSerializer.Revision(fresh)));
        }
    }

    private async Task PrepareGeoAsync()
    {
        switch (GeoOption)
        {
            case GeoStartOption.DownloadNow:
                Progress = "Загрузка RU-базы напрямую, через основной адаптер…";
                await _main.Service.CommandAsync(new GeoUpdateNowRequest());
                break;
            case GeoStartOption.ImportFile:
                Progress = "Импорт RU-базы…";
                await _main.Service.CommandAsync(await GeoImportFile.ReadAsync(ImportPath!));
                break;
            case GeoStartOption.ViaTunnel:
                break;
        }
    }

    private async Task<StatusDto?> WaitConnectedAsync()
    {
        StatusDto? status = null;
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(1));
        try
        {
            while (true)
            {
                status = await _main.Service.RequestAsync<StatusDto>(new GetStatusRequest(), deadline.Token);
                Progress = StatusText.StateName(status.State) + "…";
                if (status.State is ConnectionState.Connected or ConnectionState.Error or ConnectionState.PasswordRequired)
                {
                    return status;
                }

                await Task.Delay(1000, deadline.Token);
            }
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested)
        {
            return status;
        }
    }
}
