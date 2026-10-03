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

/// <summary>
/// Мастер первого запуска: сервер и вход → основной адаптер → режим → RU-база → проверка.
/// Мастер можно прервать и запустить снова; до шага «Готово» в системе ничего не меняется.
/// </summary>
public sealed partial class WizardViewModel : ObservableObject
{
    public ConnectionSecurityViewModel Security { get; } = new() { CanClearSavedKey = false, AllowAnyConnect = false };
    public const int LastStep = 4;

    private readonly MainViewModel _main;

    /// <param name="main">Главная модель.</param>
    /// <param name="loadAdapters">Запросить адаптеры у службы; самопроверка разметки обходится без службы.</param>
    public WizardViewModel(MainViewModel main, bool loadAdapters = true)
    {
        _main = main;
        if (loadAdapters)
        {
            _ = LoadAdaptersAsync();
        }
    }

    public ObservableCollection<AdapterDto> Adapters { get; } = [];

    public static IReadOnlyList<string> StepTitles { get; } = ["Сервер и вход", "Основной адаптер", "Режим", "RU-база", "Проверка"];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StepTitle), nameof(CanGoBack), nameof(NextText))]
    private int _step;

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

    public string StepTitle => $"Шаг {Step + 1} из {LastStep + 1}. {StepTitles[Math.Clamp(Step, 0, LastStep)]}";

    public bool CanGoBack => Step > 0 && !Finished && !IsBusy;

    public bool CanCancel => !Finished && !IsBusy;

    partial void OnIsBusyChanged(bool value)
    {
        OnPropertyChanged(nameof(CanGoBack));
        OnPropertyChanged(nameof(CanCancel));
        NextCommand.NotifyCanExecuteChanged();
    }

    public string NextText => Step == LastStep - 1 ? "Готово: подключить" : Finished ? "Закрыть" : "Далее";

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
        Step = Math.Max(0, Step - 1);
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

        Error = ValidateStep();
        if (Error is not null)
        {
            return;
        }

        if (Step == LastStep - 1)
        {
            Step = LastStep;
            await ApplyAsync();
            return;
        }

        Step++;
    }

    [RelayCommand]
    private void Cancel()
    {
        Password = "";
        Security.ClearSecrets();
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

    private string? ValidateStep() => Step switch
    {
        0 when string.IsNullOrWhiteSpace(Name) => "Введите название подключения.",
        0 when !VpnProtocols.TryParseServer(Server, Security.Protocol, out _) => VpnProtocols.ServerHint(Security.Protocol),
        0 when !VpnProtocols.Supports(Security.Protocol, Security.AuthMethod) => Security.CompatibilityHint,
        0 when VpnProtocols.ValidateAuthentication(Security.Apply(new ConnectionProfile { UserName = UserName })) is [var error, ..] => error,
        0 when Security.NeedsPassword && string.IsNullOrWhiteSpace(UserName) => "Введите имя пользователя.",
        0 when Security.NeedsPassword && string.IsNullOrEmpty(Password) => "Введите пароль.",
        0 when Security.NeedsPsk && string.IsNullOrEmpty(Security.PreSharedKey) => "Введите общий ключ IPsec (PSK).",
        1 when PinAdapter && PinnedAdapter is null => "Выберите адаптер или оставьте автоматический выбор.",
        3 when GeoOption == GeoStartOption.ImportFile && !File.Exists(ImportPath) => "Выберите файл базы.",
        3 when GeoOption == GeoStartOption.ImportFile && new FileInfo(ImportPath!).Length > Core.Geo.GeoValidationOptions.MaxImportBytes => "Файл слишком большой для списка сетей (больше 16 МБ).",
        _ => null,
    };

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
            await SaveProfileAsync();
            Password = "";
            Security.ClearSecrets();
            await PrepareGeoAsync();
            Progress = "Подключение…";
            await _main.Service.CommandAsync(new ConnectRequest(null, null));
            var status = await WaitConnectedAsync();
            if (status?.State == ConnectionState.Connected && GeoOption == GeoStartOption.ViaTunnel)
            {
                Progress = "Загрузка RU-базы через VPN…";
                await _main.Service.CommandAsync(new GeoUpdateNowRequest());
                status = await _main.Service.RequestAsync<StatusDto>(new GetStatusRequest());
            }

            Finished = true;
            Progress = status?.State == ConnectionState.Connected
                ? "Готово. " + StatusText.Format(status)
                : $"Подключение не завершено: {StatusText.StateName(status?.State ?? ConnectionState.Error)}. {status?.ErrorText}";
            OnPropertyChanged(nameof(NextText));
        }
        catch (Exception ex)
        {
            Error = ex.Message;
            Step = LastStep - 1;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task SaveProfileAsync()
    {
        Progress = "Сохранение подключения…";
        var settings = await _main.Service.RequestAsync<AppSettings>(new GetSettingsRequest());
        // Профиль с тем же названием — тот же профиль: его идентификатор сохраняется, и правила, группы
        // и сохранённый пароль, ссылающиеся на него, остаются в силе при повторном запуске мастера.
        var existing = settings.Profiles.FirstOrDefault(p => string.Equals(p.Name, Name.Trim(), StringComparison.OrdinalIgnoreCase));
        var profile = Security.Apply((existing ?? new ConnectionProfile()) with
        {
            Name = Name.Trim(),
            Server = Server.Trim(),
            UserName = UserName.Trim(),
            SavePassword = SavePassword,
            Role = ProfileRole.Primary,
            PrimaryAdapter = PinAdapter ? AdapterSelection.Pinned : AdapterSelection.Auto,
            PinnedInterfaceGuid = PinAdapter ? PinnedAdapter?.InterfaceGuid : null,
        });
        var updated = ConnectionEdits.SaveProfile(settings, profile) with
        {
            DefaultTarget = RouteTarget.Tunnel(profile.Id),
            GeoTarget = RussiaDirect ? RouteTarget.Direct : RouteTarget.Tunnel(profile.Id),
        };
        // Пустое значение — «не менять»: пароль уже мог быть принят службой при прошлой попытке.
        await _main.Service.CommandAsync(new SaveConnectionRequest(updated, profile.Id,
            Security.NeedsPassword && Password.Length > 0 ? Password : null,
            Security.NeedsPsk && Security.PreSharedKey.Length > 0 ? Security.PreSharedKey : null));
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
                await _main.Service.CommandAsync(new GeoImportRequest(await File.ReadAllTextAsync(ImportPath!)));
                break;
            case GeoStartOption.ViaTunnel:
                break;
        }
    }

    private async Task<StatusDto?> WaitConnectedAsync()
    {
        StatusDto? status = null;
        for (var i = 0; i < 60; i++)
        {
            status = await _main.Service.RequestAsync<StatusDto>(new GetStatusRequest());
            Progress = StatusText.StateName(status.State) + "…";
            if (status.State is ConnectionState.Connected or ConnectionState.Error or ConnectionState.PasswordRequired)
            {
                return status;
            }

            await Task.Delay(1000);
        }

        return status;
    }
}
