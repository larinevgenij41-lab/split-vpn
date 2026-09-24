using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using Wpf.Ui.Controls;

namespace SplitVpn.App.ViewModels;

/// <summary>Подключения: список профилей, редактирование, пароль, роль туннеля, импорт и экспорт без секретов.</summary>
public sealed partial class ConnectionsViewModel(MainViewModel main) : PageViewModel(main, "Подключения", SymbolRegular.PlugConnected24)
{
    public ObservableCollection<ProfileItem> Profiles { get; } = [];

    public ObservableCollection<AdapterDto> Adapters { get; } = [];

    /// <summary>Роли подключения: опорное даёт DNS по умолчанию и определяет обрыв.</summary>
    public static IReadOnlyList<ChoiceItem<ProfileRole>> Roles { get; } =
    [
        new(ProfileRole.Off, "Выключено"),
        new(ProfileRole.Primary, "Опорное"),
        new(ProfileRole.Secondary, "Дополнительное"),
    ];

    /// <summary>Идёт перезагрузка списка: выбор снимается и возвращается тому же профилю — набранное не стирается.</summary>
    private bool _reloading;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelection))]
    private ProfileItem? _selected;

    [ObservableProperty]
    private string _password = "";

    public bool HasSelection => Selected is not null;

    partial void OnSelectedChanged(ProfileItem? oldValue, ProfileItem? newValue)
    {
        if (_reloading)
        {
            return;
        }

        Password = "";
        oldValue?.Security.ClearSecrets();
    }

    partial void OnPasswordChanged(string value)
    {
        if (value.Length > 0 && Selected is { } item)
        {
            item.IsDirty = true;
        }
    }

    public override Task OnOpenedAsync() => RunAsync(LoadAsync);

    /// <summary>
    /// Перечитывает профили из службы. Несохранённые правки (новые и изменённые профили) остаются как есть:
    /// переход между страницами и сохранение другого профиля их не теряют. Набранный пароль и ключ IPsec
    /// сохраняются, пока выбран тот же профиль: список пересобирается, а выбор возвращается ему же.
    /// </summary>
    public async Task LoadAsync()
    {
        var settings = await Service.RequestAsync<AppSettings>(new GetSettingsRequest());
        var adapters = await Service.RequestAsync<List<AdapterDto>>(new GetAdaptersRequest());
        if (!adapters.SequenceEqual(Adapters))
        {
            // Список меняется только при реальном изменении: сброс списка сбросил бы выбранный адаптер в форме.
            Adapters.Clear();
            foreach (var adapter in adapters)
            {
                Adapters.Add(adapter);
            }
        }

        var selectedId = Selected?.Id;
        var edited = Profiles.Where(p => p.IsNew || p.IsDirty).ToDictionary(p => p.Id);
        var items = settings.Profiles.Select(p => edited.Remove(p.Id, out var kept) ? kept : ProfileItem.From(p)).ToList();
        items.AddRange(edited.Values.Where(p => p.IsNew));
        var previous = Selected;
        _reloading = true;
        try
        {
            Profiles.Clear();
            foreach (var item in items)
            {
                Profiles.Add(item);
            }

            RenumberProfiles();
            Selected = Profiles.FirstOrDefault(p => p.Id == selectedId) ?? Profiles.FirstOrDefault();
        }
        finally
        {
            _reloading = false;
        }

        OnStatus(Main.Status);

        if (Selected?.Id != selectedId)
        {
            // Профиль удалён или его ещё не было: набранное относится к прежнему выбору и не переносится.
            Password = "";
            previous?.Security.ClearSecrets();
        }
    }

    /// <summary>Состояние туннелей из службы: переключатель в строке показывает то же, что главная.</summary>
    public override void OnStatus(StatusDto? status)
    {
        foreach (var item in Profiles)
        {
            var tunnel = status?.Tunnels.FirstOrDefault(t => t.ProfileId == item.Id);
            item.Paused = tunnel?.Paused ?? false;
            item.CanToggle = tunnel is not null && status?.State != ConnectionState.Disconnected;
        }
    }

    /// <summary>Включает или отключает подключение прямо сейчас, не трогая настройки.</summary>
    [RelayCommand]
    private async Task ToggleAsync(ProfileItem item)
    {
        ArgumentNullException.ThrowIfNull(item);
        if (item.IsNew)
        {
            ShowMessage("Сначала сохраните подключение.", isError: true);
            return;
        }

        await Main.RunCommandAsync(new SetTunnelPausedRequest(item.Id, !item.Paused));
    }

    /// <summary>Поднимать раньше: порядок списка задаёт и вид на экране, и очерёдность подъёма.</summary>
    [RelayCommand]
    private Task MoveUpAsync(ProfileItem item) => MoveAsync(item, -1);

    [RelayCommand]
    private Task MoveDownAsync(ProfileItem item) => MoveAsync(item, +1);

    /// <summary>
    /// Переставляет строку и сразу сохраняет порядок. Перестановка идёт через <see cref="ObservableCollection{T}.Move"/>:
    /// экземпляры те же, ни одно свойство профиля не меняется, поэтому несохранённых правок не появляется.
    /// </summary>
    public Task MoveAsync(ProfileItem? item, int offset)
    {
        if (item is null)
        {
            return Task.CompletedTask;
        }

        var from = Profiles.IndexOf(item);
        var to = from + offset;
        return from < 0 || to < 0 || to >= Profiles.Count ? Task.CompletedTask : MoveToAsync(item, to);
    }

    public Task MoveToAsync(ProfileItem item, int to) => RunAsync(async () =>
    {
        ArgumentNullException.ThrowIfNull(item);
        var from = Profiles.IndexOf(item);
        if (from < 0 || to < 0 || to >= Profiles.Count || from == to)
        {
            return null;
        }

        Profiles.Move(from, to);
        RenumberProfiles();
        Selected = item;

        // Служба не знает несохранённых подключений: пока они есть, порядок сохранить нечем.
        if (Profiles.Any(p => p.IsNew))
        {
            return null;
        }

        await Service.CommandAsync(new SetProfileOrderRequest(Profiles.Select(p => p.Id).ToList()));
        return null;
    });

    private void RenumberProfiles()
    {
        for (var i = 0; i < Profiles.Count; i++)
        {
            Profiles[i].Position = i + 1;
        }
    }

    [RelayCommand]
    private void Add()
    {
        var item = ProfileItem.From(new ConnectionProfile { Name = UniqueName("Новое подключение") });
        item.IsNew = true;
        item.IsDirty = true;
        Profiles.Add(item);
        RenumberProfiles();
        Selected = item;
    }

    [RelayCommand]
    private void Copy()
    {
        if (Selected is null)
        {
            return;
        }

        var copy = ProfileItem.From(Selected.ToProfile() with { Id = Guid.NewGuid(), Name = UniqueName(Selected.Name + " (копия)"), Role = ProfileRole.Off });
        copy.IsNew = true;
        copy.IsDirty = true;
        Profiles.Add(copy);
        RenumberProfiles();
        Selected = copy;
    }

    [RelayCommand]
    private Task DeleteAsync() => RunAsync(async () =>
    {
        if (Selected is not { } item)
        {
            return null;
        }

        if (item.IsNew)
        {
            Profiles.Remove(item);
            Selected = Profiles.FirstOrDefault();
            return "Несохранённое подключение убрано.";
        }

        // Роль — сохранённая в службе, а не выбранная в форме: служба поднимает туннель по сохранённой.
        var fresh = await Service.RequestAsync<AppSettings>(new GetSettingsRequest());
        if (fresh.Profile(item.Id) is { Role: not ProfileRole.Off } saved)
        {
            ShowMessage($"Сначала выключите «{saved.Name}» и сохраните: на него может быть направлен трафик.", isError: true);
            return null;
        }

        if (!await Main.Confirm("Удалить подключение?", $"«{item.Name}» и его сохранённый пароль будут удалены. Отменить удаление нельзя.", "Удалить"))
        {
            return null;
        }

        await Service.CommandAsync(new SaveSettingsRequest(ConnectionEdits.RemoveProfile(fresh, item.Id)));
        Profiles.Remove(item);
        Selected = null;
        await LoadAsync();
        return "Подключение удалено.";
    });

    [RelayCommand]
    private Task SaveAsync() => RunAsync(async () =>
    {
        if (Selected is not { } item)
        {
            return null;
        }

        if (!VpnProtocols.TryParseServer(item.Server, item.Security.Protocol, out _))
        {
            throw new FormatException(VpnProtocols.ServerHint(item.Security.Protocol));
        }

        var fresh = await Service.RequestAsync<AppSettings>(new GetSettingsRequest());
        var profile = item.ToProfile();
        var security = item.Security;
        if (fresh.Profile(item.Id) is { } saved)
        {
            // Секреты привязаны к серверу и учётной записи: служба удалит прежние, без нового пароля подключение не поднимется.
            if (security.NeedsPassword && profile.SavePassword && Password.Length == 0 && ConnectionEdits.PasswordBindingChanged(saved, profile))
            {
                ShowMessage("Изменены сервер, протокол, способ входа или имя пользователя: введите пароль заново — прежний сохранённый пароль будет удалён.", isError: true);
                return null;
            }

            if (security.NeedsPsk && !security.ClearPreSharedKey && security.PreSharedKey.Length == 0 && ConnectionEdits.PreSharedKeyBindingChanged(saved, profile))
            {
                ShowMessage("Изменены сервер или протокол: введите общий ключ IPsec заново — прежний ключ будет удалён.", isError: true);
                return null;
            }
        }

        var updated = ConnectionEdits.SaveProfile(fresh, profile);
        if (ConnectionEdits.NewlyDirect(fresh, updated) is { Count: > 0 } direct
            && !await Main.Confirm("Трафик пойдёт мимо VPN",
                $"После сохранения напрямую, без VPN, пойдут: {string.Join(", ", direct)}. Сохранить?", "Сохранить"))
        {
            return null;
        }

        await Service.CommandAsync(new SaveConnectionRequest(
            updated,
            item.Id,
            security.NeedsPassword && Password.Length > 0 ? Password : null,
            security.NeedsPsk ? security.ClearPreSharedKey ? "" : security.PreSharedKey.Length > 0 ? security.PreSharedKey : null : null));
        Password = "";
        security.ClearSecrets();
        item.IsNew = false;
        item.IsDirty = false;

        await LoadAsync();
        return "Подключение сохранено.";
    });

    /// <summary>Проверка профиля: при снятой защите — пробный дозвон (до минуты), при подключении — отчёт по сеансу.</summary>
    [RelayCommand]
    private Task TestAsync() => RunAsync(async () =>
    {
        if (Selected is not { } item)
        {
            return null;
        }

        if (item.IsNew || item.IsDirty)
        {
            // Служба проверяет сохранённую версию профиля: несохранённые правки в проверку не попадут.
            ShowMessage("Сначала сохраните подключение: проверяется сохранённая версия.", isError: true);
            return null;
        }

        var result = await Service.RequestAsync<ProfileTestDto>(new TestProfileRequest(item.Id));
        ShowMessage(result.Text, isError: !result.Success);
        return null;
    });

    [RelayCommand]
    private Task ExportAsync() => RunAsync(async () =>
    {
        var dialog = new SaveFileDialog { FileName = "подключения.json", Filter = "JSON|*.json" };
        if (dialog.ShowDialog() != true)
        {
            return null;
        }

        // Пароли хранит только служба (DPAPI): в файл экспорта они не попадают.
        var settings = await Service.RequestAsync<AppSettings>(new GetSettingsRequest());
        var export = settings.Profiles.Select(p => p with { Id = Guid.NewGuid() }).ToList();
        await File.WriteAllTextAsync(dialog.FileName, JsonSerializer.Serialize(export, JsonDefaults.Options));
        return "Подключения экспортированы без паролей.";
    });

    [RelayCommand]
    private Task ImportAsync() => RunAsync(async () =>
    {
        var dialog = new OpenFileDialog { Filter = "JSON|*.json" };
        if (dialog.ShowDialog() != true)
        {
            return null;
        }

        if (new FileInfo(dialog.FileName).Length > ConnectionEdits.MaxImportBytes)
        {
            throw new FormatException("Файл слишком большой для списка подключений (больше 1 МБ).");
        }

        List<ConnectionProfile?> parsed;
        try
        {
            parsed = JsonSerializer.Deserialize<List<ConnectionProfile?>>(await File.ReadAllTextAsync(dialog.FileName), JsonDefaults.Options) ?? [];
        }
        catch (JsonException)
        {
            throw new FormatException("Файл не похож на экспорт подключений «Раздельного VPN»: ожидается список подключений в JSON.");
        }

        var fresh = await Service.RequestAsync<AppSettings>(new GetSettingsRequest());
        var added = ConnectionEdits.PrepareImport(fresh.Profiles.Select(p => p.Name), parsed);
        if (added.Count == 0)
        {
            ShowMessage("В файле нет подключений.", isError: true);
            return null;
        }

        var trust = added.Any(p => p.Eap.TrustedRootThumbprints.Count > 0)
            ? " Файл задаёт доверенные корневые сертификаты для проверки сервера — импортируйте только файл из надёжного источника."
            : "";
        if (!await Main.Confirm("Импортировать подключения?",
                $"Будут добавлены выключенными: {string.Join(", ", added.Select(p => "«" + p.Name + "»"))}. Пароли и ключи нужно ввести заново.{trust}", "Импортировать"))
        {
            return null;
        }

        await Service.CommandAsync(new SaveSettingsRequest(fresh with { Profiles = [.. fresh.Profiles, .. added] }));
        await LoadAsync();
        return "Подключения импортированы выключенными. Введите пароли и включите нужные.";
    });

    private string UniqueName(string name) =>
        ConnectionEdits.UniqueName(Profiles.Select(p => p.Name).ToHashSet(StringComparer.OrdinalIgnoreCase), name);
}

/// <summary>Редактируемая копия профиля.</summary>
public sealed partial class ProfileItem : ObservableObject
{
    public ConnectionSecurityViewModel Security { get; } = new();
    private ConnectionProfile _source = new();

    public Guid Id => _source.Id;

    /// <summary>Профиль ещё не сохранён в службе.</summary>
    public bool IsNew { get; set; }

    /// <summary>В форме есть несохранённые правки.</summary>
    [ObservableProperty]
    private bool _isDirty;

    /// <summary>
    /// Туннель положен пользователем «сейчас». Приходит из статуса службы, а не из формы: правкой
    /// профиля не является и <see cref="IsDirty"/> ставить не должен — см. список исключений в OnEdited.
    /// </summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ToggleName))]
    [NotifyPropertyChangedFor(nameof(ToggleSymbol))]
    private bool _paused;

    /// <summary>Туннель сейчас поднят службой: пока нет, переключать нечего.</summary>
    [ObservableProperty]
    private bool _canToggle;

    /// <summary>Номер в списке: он же очерёдность подъёма. Меняется перестановкой, а не правкой профиля.</summary>
    [ObservableProperty]
    private int _position;

    public string ToggleName => (Paused ? "Включить " : "Отключить ") + Name;

    /// <summary>Значок показывает, что произойдёт по нажатию.</summary>
    public SymbolRegular ToggleSymbol => Paused ? SymbolRegular.PlugDisconnected24 : SymbolRegular.PlugConnected24;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(RoleText))]
    private ProfileRole _role;

    public string RoleText => ConnectionsViewModel.Roles.First(r => r.Value == Role).Text;

    /// <summary>Роли, допустимые для протокола: AnyConnect не бывает опорным.</summary>
    public IReadOnlyList<ChoiceItem<ProfileRole>> RoleChoices => Security.IsAnyConnect
        ? ConnectionsViewModel.Roles.Where(r => r.Value != ProfileRole.Primary).ToList()
        : ConnectionsViewModel.Roles;

    public string UserNameLabel => Security.IsAnyConnect ? "Имя пользователя (необязательно — подставится в форму шлюза)" : "Имя пользователя";

    /// <summary>Закрепление адаптера относится к RAS: у AnyConnect соединение со шлюзом идёт по общим правилам.</summary>
    public bool ShowPinnedAdapter => PinAdapter && Security.IsRas;

    [ObservableProperty]
    private string _name = "";

    [ObservableProperty]
    private string _server = "";

    [ObservableProperty]
    private string _userName = "";

    [ObservableProperty]
    private bool _savePassword = true;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowPinnedAdapter))]
    private bool _pinAdapter;

    [ObservableProperty]
    private Guid? _pinnedInterfaceGuid;

    [ObservableProperty]
    private bool _allowFallback;

    /// <summary>Имя элемента списка для экранного диктора: номер задаёт очерёдность подъёма.</summary>
    public override string ToString() => $"{Position}. {Name}, {RoleText}" + (Paused ? ", отключено вами" : "");

    public static ProfileItem From(ConnectionProfile profile)
    {
        var item = new ProfileItem
        {
            _source = profile,
            Role = profile.Role,
            Name = profile.Name,
            Server = profile.Server,
            UserName = profile.UserName,
            SavePassword = profile.SavePassword,
            PinAdapter = profile.PrimaryAdapter == AdapterSelection.Pinned,
            PinnedInterfaceGuid = profile.PinnedInterfaceGuid,
            AllowFallback = profile.AllowFallbackWhenPinnedMissing,
        };
        item.Security.Load(profile);
        item.PropertyChanged += item.OnEdited;
        item.Security.PropertyChanged += item.OnEdited;
        return item;
    }

    private void OnEdited(object? sender, PropertyChangedEventArgs e)
    {
        if (sender == Security && e.PropertyName == nameof(ConnectionSecurityViewModel.IsAnyConnect))
        {
            OnPropertyChanged(nameof(RoleChoices));
            OnPropertyChanged(nameof(UserNameLabel));
            OnPropertyChanged(nameof(ShowPinnedAdapter));
            if (Security.IsAnyConnect && Role == ProfileRole.Primary)
            {
                Role = ProfileRole.Secondary;
            }
        }

        // Свойства из статуса службы и позиция в списке — не правка профиля: пометив их изменёнными,
        // опрос раз в полторы секунды навсегда закрыл бы обновление списка из службы.
        if (e.PropertyName is not (nameof(IsDirty) or nameof(RoleText) or nameof(RoleChoices) or nameof(UserNameLabel) or nameof(ShowPinnedAdapter)
            or nameof(Paused) or nameof(CanToggle) or nameof(Position) or nameof(ToggleName) or nameof(ToggleSymbol)))
        {
            IsDirty = true;
        }
    }

    public ConnectionProfile ToProfile() => Security.Apply(_source with
    {
        Name = Name.Trim(),
        Role = Role,
        Server = Server.Trim(),
        UserName = UserName.Trim(),
        SavePassword = SavePassword,
        PrimaryAdapter = ShowPinnedAdapter ? AdapterSelection.Pinned : AdapterSelection.Auto,
        PinnedInterfaceGuid = ShowPinnedAdapter ? PinnedInterfaceGuid : null,
        AllowFallbackWhenPinnedMissing = AllowFallback,
    });
}
