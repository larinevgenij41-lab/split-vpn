using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using SplitVpn.App.Services;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.OpenConnect;
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

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelection))]
    private ProfileItem? _selected;

    // Черновик принадлежит профилю, а не общему полю редактора. В настройки и экспорт он не попадает.
    public string Password
    {
        get => Selected?.PasswordDraft ?? "";
        set
        {
            if (Selected is { } item && item.PasswordDraft != value)
            {
                item.PasswordDraft = value;
                OnPropertyChanged();
            }
        }
    }

    [ObservableProperty]
    private int _editorFocusToken;

    /// <summary>
    /// Список хотя бы раз получен от службы. До этого пустой список - ещё не ответ, а загрузка: подпись
    /// "Подключений пока нет" показывается только после него.
    /// </summary>
    [ObservableProperty]
    private bool _loaded;

    [ObservableProperty]
    private string _initialLoadText = "Загрузка подключений…";

    public bool HasSelection => Selected is not null;

    partial void OnSelectedChanged(ProfileItem? oldValue, ProfileItem? newValue)
    {
        // Редактор один на все профили: блок параметров безопасности раскрывается по нуждам открытого профиля.
        newValue?.Security.ResetDetailsExpanded();
        OnPropertyChanged(nameof(Password));
    }

    public override Task OnOpenedAsync() => RunAsync(LoadAsync);

    /// <summary>
    /// Перечитывает профили из службы. Несохранённые правки (новые и изменённые профили) остаются как есть:
    /// переход между страницами и сохранение другого профиля их не теряют. Набранный пароль и ключ IPsec
    /// сохраняются отдельно у каждого изменённого профиля.
    /// </summary>
    public async Task LoadAsync()
    {
        InitialLoadText = "Загрузка подключений…";
        AppSettings settings;
        try { settings = await Service.RequestAsync<AppSettings>(new GetSettingsRequest()); }
        catch (Exception ex) when (ex is ServiceUnavailableException or ServiceCommandException)
        {
            InitialLoadText = "Не удалось загрузить подключения.";
            throw;
        }
        List<AdapterDto> adapters;
        try { adapters = await Service.RequestAsync<List<AdapterDto>>(new GetAdaptersRequest()); }
        catch (Exception ex) when (ex is ServiceUnavailableException or ServiceCommandException)
        {
            adapters = [.. Adapters];
            ShowMessage("Список адаптеров недоступен. " + ex.Message, isError: true);
        }
        if (!adapters.SequenceEqual(Adapters))
        {
            // Список меняется только при реальном изменении. Сброс списка сбрасывает выбор адаптера в форме,
            // и список выбора записал бы в открытый профиль пустое значение как правку пользователя.
            void Replace()
            {
                Adapters.Clear();
                foreach (var adapter in adapters)
                {
                    Adapters.Add(adapter);
                }
            }

            if (Selected is { } open)
            {
                open.PreserveAdapterChoice(Replace);
            }
            else
            {
                Replace();
            }
        }

        var selectedId = Selected?.Id;
        var edited = Profiles.Where(p => p.IsNew || p.IsDirty).ToDictionary(p => p.Id);
        var items = settings.Profiles.Select(p => edited.Remove(p.Id, out var kept) ? kept : ProfileItem.From(p)).ToList();
        items.AddRange(edited.Values);
        Profiles.Clear();
        foreach (var item in items)
        {
            Profiles.Add(item);
        }
        RenumberProfiles();
        Selected = Profiles.FirstOrDefault(p => p.Id == selectedId) ?? Profiles.FirstOrDefault();

        Loaded = true;
        OnStatus(Main.Status);

        OnPropertyChanged(nameof(Password));
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

        if (!item.Paused && Main.Status?.Tunnels.Any(t => t.ProfileId == item.Id && t.IsAnchor) == true
            && !await Main.Home.ConfirmAnchorOffAsync(item.Name)) { return; }
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

        // Служба не знает несохранённых подключений: пока они есть, порядок сохранить нечем, а перестановка
        // только на экране пропала бы при сохранении. Поэтому она не выполняется, пользователь видит почему.
        if (Profiles.Any(p => p.IsNew))
        {
            ShowMessage("Сохраните новое подключение, чтобы менять порядок: пока оно не сохранено, порядок сохранить нельзя.", isError: true);
            return null;
        }

        Profiles.Move(from, to);
        RenumberProfiles();
        Selected = item;

        try
        {
            await Service.CommandAsync(new SetProfileOrderRequest(Profiles.Select(p => p.Id).ToList()));
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or ServiceCommandException)
        {
            // Порядок на экране — порядок службы: после отказа список возвращается к сохранённому. Перечитываем
            // из службы (после таймаута она могла порядок и принять), а без связи — откатываем перестановку.
            try
            {
                await LoadAsync();
            }
            catch (Exception reload) when (reload is ServiceUnavailableException or ServiceCommandException)
            {
                if (Profiles.IndexOf(item) is var at && at >= 0 && from < Profiles.Count && at != from)
                {
                    Profiles.Move(at, from);
                    RenumberProfiles();
                }
            }

            throw;
        }

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
        EditorFocusToken++;
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
        EditorFocusToken++;
    }

    [RelayCommand]
    private Task RevertAsync() => RunAsync(async () =>
    {
        if (Selected is not { } item || (!item.IsNew && !item.IsDirty)) { return null; }
        var edits = item.Edits;
        if (!await Main.Confirm("Отменить изменения?",
                $"Несохранённые настройки, пароль и ключ IPsec подключения «{item.Name}» будут удалены из формы. Сохранённые данные останутся в службе.", "Отменить изменения")) { return null; }
        // После подтверждения перечитываем службу; при ошибке черновик остаётся в форме.
        var fresh = await Service.RequestAsync<AppSettings>(new GetSettingsRequest());
        if (item.Edits != edits) { ShowMessage("В форме появились новые изменения. Повторите отмену, если хотите их убрать.", isError: true); return null; }
        var replacement = fresh.Profile(item.Id) is { } saved ? ProfileItem.From(saved) : null;
        var index = Profiles.IndexOf(item);
        if (index < 0) { return null; }
        item.PasswordDraft = "";
        item.Security.ClearSecrets();
        if (replacement is null) { Profiles.RemoveAt(index); }
        else { Profiles[index] = replacement; }
        if (Selected == item || Selected is null) { Selected = replacement ?? Profiles.FirstOrDefault(); }
        RenumberProfiles();
        return "Несохранённые изменения отменены.";
    });

    [RelayCommand]
    private Task DeleteAsync() => RunAsync(async () =>
    {
        if (Selected is not { } item)
        {
            return null;
        }

        // Отметке "новый" одной верить нельзя: сохранение могло записать профиль и упасть на секрете или таймауте.
        // Поэтому сначала смотрим, есть ли профиль в службе; без связи со службой строка просто убирается.
        AppSettings? fresh = null;
        if (item.IsNew)
        {
            try
            {
                fresh = await Service.RequestAsync<AppSettings>(new GetSettingsRequest());
            }
            catch (Exception ex) when (ex is ServiceUnavailableException or ServiceCommandException)
            {
                // Служба недоступна, проверить нечем: убирается только строка.
            }

            if (fresh is null && item.SaveAttempted)
            {
                ShowMessage("Результат сохранения неизвестен. Восстановите связь со службой и повторите удаление.", isError: true);
                return null;
            }
            if (fresh?.Profile(item.Id) is null)
            {
                Profiles.Remove(item);
                RenumberProfiles();
                Selected = Profiles.FirstOrDefault();
                return "Несохранённое подключение убрано.";
            }

            item.IsNew = false;
        }

        // Роль — сохранённая в службе, а не выбранная в форме: служба поднимает туннель по сохранённой.
        fresh ??= await Service.RequestAsync<AppSettings>(new GetSettingsRequest());
        if (fresh.Profile(item.Id) is { Role: not ProfileRole.Off } saved)
        {
            ShowMessage($"Сначала выключите «{saved.Name}» и сохраните: на него может быть направлен трафик.", isError: true);
            return null;
        }

        if (!await Main.Confirm("Удалить подключение?", $"«{item.Name}» и его сохранённый пароль будут удалены. Отменить удаление нельзя.", "Удалить"))
        {
            return null;
        }

        // Пока окно подтверждения было открыто, настройки могли измениться (служба перенесла закрепление адаптера,
        // правка в другом окне): удаляем из свежих, иначе сохранение вернуло бы прочитанное до подтверждения.
        fresh = await Service.RequestAsync<AppSettings>(new GetSettingsRequest());
        if (fresh.Profile(item.Id) is { Role: not ProfileRole.Off } enabled)
        {
            ShowMessage($"Сначала выключите «{enabled.Name}» и сохраните: на него может быть направлен трафик.", isError: true);
            return null;
        }

        if (fresh.Profile(item.Id) is not null)
        {
            await Service.CommandAsync(new SaveSettingsRequest(ConnectionEdits.RemoveProfile(fresh, item.Id), SettingsSerializer.Revision(fresh)));
        }

        // Профиль встроенного браузера для входа AnyConnect хранит cookie и вход организации: без подключения он не нужен.
        SignInBrowserProfiles.Default.Delete(item.Id);
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

        // Пароль берётся вместе с профилем, до первого ожидания: пока идёт запрос, пользователь может выбрать
        // другой профиль и набрать его пароль в том же поле — он не должен уйти под этим профилем.
        var password = Password;
        // Профиль собирается из формы после ожидания ответа службы: если за это время изменили сервер, имя
        // пользователя или пароль, взятый выше пароль ушёл бы с новым сервером. Тогда сохранение не идёт.
        var startEdits = item.Edits;
        if (!VpnProtocols.TryParseServer(item.Server, item.Security.Protocol, out _))
        {
            throw new FormatException(VpnProtocols.ServerHint(item.Security.Protocol));
        }

        var fresh = await Service.RequestAsync<AppSettings>(new GetSettingsRequest());
        var security = item.Security;
        if (item.Edits != startEdits)
        {
            ShowMessage(EditedDuringSave, isError: true);
            return null;
        }

        var updated = PrepareSave(item, fresh);

        if (ConnectionEdits.NewlyDirect(fresh, updated) is { Count: > 0 } direct)
        {
            if (!await Main.Confirm("Трафик пойдёт мимо VPN",
                    $"После сохранения напрямую, без VPN, пойдут: {string.Join(", ", direct)}. Сохранить?", "Сохранить"))
            {
                return null;
            }

            // Пока окно подтверждения было открыто, настройки могли измениться (служба перенесла закрепление адаптера,
            // правка в другом окне): сохраняем поверх свежих, а не поверх прочитанных до подтверждения.
            fresh = await Service.RequestAsync<AppSettings>(new GetSettingsRequest());
            if (item.Edits != startEdits)
            {
                ShowMessage(EditedDuringSave, isError: true);
                return null;
            }

            var current = PrepareSave(item, fresh);

            if (ConnectionEdits.NewlyDirect(fresh, current).Except(direct).Any())
            {
                ShowMessage("Настройки изменились, пока было открыто подтверждение: сохраните подключение ещё раз.", isError: true);
                return null;
            }

            updated = current;
        }

        ConnectionProfile? reuseCredentialsFrom = null;
        var target = updated.Profile(item.Id)!;
        var saved = fresh.Profile(item.Id);
        var passwordRebound = saved is not null && security.NeedsPassword && password.Length == 0 && ConnectionEdits.PasswordBindingChanged(saved, target);
        var keyRebound = saved is not null && security.NeedsPsk && !security.ClearPreSharedKey && security.PreSharedKey.Length == 0
            && ConnectionEdits.PreSharedKeyBindingChanged(saved, target);
        // Использовать можно только то, что у сохранённого профиля было: у SSTP нет ключа IPsec, у входа
        // по сертификату нет пароля. Иначе профиль сохранился бы без них, и каждый дозвон заканчивался бы ошибкой.
        if (keyRebound && !VpnProtocols.NeedsPreSharedKey(saved!))
        {
            ShowMessage("Изменены сервер или протокол, а сохранённого ключа IPsec у подключения нет: введите общий ключ IPsec.", isError: true);
            return null;
        }

        if (passwordRebound && !VpnProtocols.NeedsPassword(saved!.AuthMethod) && target.SavePassword)
        {
            ShowMessage("Изменены сервер, протокол, способ входа или имя пользователя, а сохранённого пароля у подключения нет: введите пароль.", isError: true);
            return null;
        }

        var reusePassword = passwordRebound && VpnProtocols.NeedsPassword(saved!.AuthMethod);
        if (saved is not null && (reusePassword || keyRebound))
        {
            var reused = (reusePassword, keyRebound) switch
            {
                (true, true) => "сохранённый пароль и ключ IPsec",
                (true, false) => "сохранённый пароль",
                _ => "сохранённый ключ IPsec",
            };
            var confirmedDirect = ConnectionEdits.NewlyDirect(fresh, updated);
            if (!await Main.Confirm("Использовать прежние данные входа?",
                    $"Меняются сервер или параметры входа подключения «{item.Name}».\nБыло: {saved.Server}, {saved.UserName}\nБудет: {target.Server}, {target.UserName}\nИспользовать {reused} с новыми параметрами? Если нужны другие, отмените сохранение и заполните поля.", "Использовать и сохранить")) { return null; }
            fresh = await Service.RequestAsync<AppSettings>(new GetSettingsRequest());
            if (item.Edits != startEdits || fresh.Profile(item.Id) is not { } current || ConnectionEdits.PasswordBindingChanged(saved, current))
            { ShowMessage(EditedDuringSave, isError: true); return null; }
            updated = PrepareSave(item, fresh);
            if (ConnectionEdits.NewlyDirect(fresh, updated).Except(confirmedDirect).Any())
            { ShowMessage("Маршрутизация изменилась: проверьте поля и сохраните ещё раз.", isError: true); return null; }
            // Служба сверяет эту привязку с актуальной: чужие изменения не перенесут другой пароль.
            reuseCredentialsFrom = saved;
        }

        // Правки, сделанные после сборки запроса, в него не попали: профиль остаётся помеченным изменённым.
        var edits = item.Edits;
        var preSharedKey = security.PreSharedKey;
        var clearPreSharedKey = security.ClearPreSharedKey;
        var sshKey = security.IsSsh ? security.PendingSshKey : null;
        List<string> warnings;
        try
        {
            item.SaveAttempted = true;
            var response = await Service.CommandAsync(new SaveConnectionRequest(
                updated,
                item.Id,
                security.NeedsPassword && password.Length > 0 ? password : null,
                security.NeedsPsk ? clearPreSharedKey ? "" : preSharedKey.Length > 0 ? preSharedKey : null : null,
                reuseCredentialsFrom,
                sshKey, SettingsSerializer.Revision(fresh)));
            warnings = response.ResultAs<List<string>>() ?? [];
        }
        catch (Exception) when (item.IsNew)
        {
            // Новый профиль служба записывает раньше секрета: отказ при записи пароля или ключа и таймаут ответа
            // не значат, что профиля в службе нет. Без этой проверки "Удалить" убрал бы только строку, а профиль
            // и его трафик остались бы в службе. Черновики остаются в форме.
            await RefreshIsNewAsync(item);
            throw;
        }

        var clean = edits == item.Edits;
        // Сохранение подтверждено: набранное до запроса больше не черновик. Отправленное ушло в службу, а
        // ненужное сохранённому профилю (пароль при входе по сертификату, ключ IPsec вне L2TP/PSK) отброшено,
        // иначе профиль навсегда остался бы "Не сохранено". Набранное во время запроса остаётся.
        if (item.PasswordDraft == password)
        {
            item.PasswordDraft = "";
            if (ReferenceEquals(Selected, item)) { OnPropertyChanged(nameof(Password)); }
        }

        if (security.PreSharedKey == preSharedKey)
        {
            security.PreSharedKey = "";
        }

        if (security.ClearPreSharedKey == clearPreSharedKey)
        {
            security.ClearPreSharedKey = false;
        }

        security.SshKeySaved(sshKey);
        item.IsNew = false;
        if (clean && item.PasswordDraft.Length == 0 && security.PreSharedKey.Length == 0 && !security.ClearPreSharedKey
            && security.PendingSshKey is null)
        {
            item.IsDirty = false;
        }

        await LoadAsync();
        return warnings.Count == 0 ? "Подключение сохранено." : "Подключение сохранено. " + string.Join(" ", warnings);
    });

    /// <summary>
    /// Новый профиль после неудачного сохранения: перечитывает службу и снимает отметку "новый", если профиль
    /// в ней уже есть. Без связи со службой отметка остаётся: проверит удаление.
    /// </summary>
    private async Task RefreshIsNewAsync(ProfileItem item)
    {
        try
        {
            var fresh = await Service.RequestAsync<AppSettings>(new GetSettingsRequest());
            if (fresh.Profile(item.Id) is not null)
            {
                item.IsNew = false;
            }
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or ServiceCommandException)
        {
            // Пользователь увидит исходную ошибку сохранения, а не ошибку перечитывания.
        }
    }

    private const string EditedDuringSave ="Подключение изменено, пока шло сохранение: проверьте поля и сохраните ещё раз.";

    /// <summary>
    /// Настройки с профилем из формы поверх <paramref name="fresh"/>.
    /// Основа профиля - свежий профиль службы: изменённая форма хранит снимок, сделанный до правок в других местах.
    /// </summary>
    private static AppSettings PrepareSave(ProfileItem item, AppSettings fresh)
    {
        if (!item.IsNew && fresh.Profile(item.Id) is null)
        {
            throw new ServiceCommandException("Подключение удалено из другого окна. Можно скопировать черновик как новое подключение.");
        }
        if (fresh.Profile(item.Id) is { } current && item.HasDraftCredentials && item.BindingChanged(current))
        {
            throw new ServiceCommandException("Параметры входа изменились в другом окне. Перечитайте подключение перед отправкой новых данных входа.");
        }
        var profile = item.ToProfile(fresh.Profile(item.Id));
        return ConnectionEdits.SaveProfile(fresh, profile);
    }

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
        var export = ConnectionEdits.PrepareExport(settings.Profiles);
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

        // Пока окно подтверждения было открыто, настройки могли измениться (служба, другое окно): добавляем к свежим.
        // Названия подбираются заново по свежему списку; если они разошлись с показанными в подтверждении, импорт не выполняется.
        fresh = await Service.RequestAsync<AppSettings>(new GetSettingsRequest());
        var current = ConnectionEdits.PrepareImport(fresh.Profiles.Select(p => p.Name), parsed);
        if (!current.Select(p => p.Name).SequenceEqual(added.Select(p => p.Name), StringComparer.Ordinal))
        {
            ShowMessage("Список подключений изменился, пока было открыто подтверждение: импортируйте файл ещё раз.", isError: true);
            return null;
        }

        await Service.CommandAsync(new SaveSettingsRequest(fresh with { Profiles = [.. fresh.Profiles, .. current] }, SettingsSerializer.Revision(fresh)));
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
    internal bool SaveAttempted { get; set; }
    internal bool HasDraftCredentials => PasswordDraft.Length > 0 || Security.PreSharedKey.Length > 0 || Security.PendingSshKey is not null || Security.ClearPreSharedKey;
    internal bool BindingChanged(ConnectionProfile current) => VpnProtocols.ConnectionKey(_source) != VpnProtocols.ConnectionKey(current);

    /// <summary>Профиль ещё не сохранён в службе.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(EditorTitle))]
    [NotifyPropertyChangedFor(nameof(PasswordHint))]
    private bool _isNew;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PasswordHint))]
    private string _passwordDraft = "";

    public string EditorTitle => IsNew ? "Новое подключение" : "Параметры подключения";
    public string PasswordHint => PasswordDraft.Length > 0
        ? "Пароль введён. Он сохранится вместе с настройками; переключение между подключениями его не сотрёт."
        : IsNew ? "Введите пароль для входа в VPN."
        : "Оставьте поле пустым, чтобы использовать прежний пароль. Для замены введите новый.";

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

    public string UserNameLabel => Security.IsAnyConnect ? "Имя пользователя (необязательно — подставится в форму шлюза)"
        : Security.IsSsh ? "Имя пользователя на сервере SSH" : "Имя пользователя";

    /// <summary>Закрепление адаптера относится к RAS: у AnyConnect соединение со шлюзом идёт по общим правилам.</summary>
    public bool ShowPinnedAdapter => PinAdapter && Security.IsRas;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ToggleName))]
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
        if (sender == Security && e.PropertyName is nameof(ConnectionSecurityViewModel.IsAnyConnect) or nameof(ConnectionSecurityViewModel.IsSsh))
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
        if (e.PropertyName is not (nameof(IsDirty) or nameof(IsNew) or nameof(EditorTitle) or nameof(PasswordHint) or nameof(RoleText) or nameof(RoleChoices) or nameof(UserNameLabel) or nameof(ShowPinnedAdapter)
            or nameof(Paused) or nameof(CanToggle) or nameof(Position) or nameof(ToggleName) or nameof(ToggleSymbol)
            or nameof(ConnectionSecurityViewModel.DetailsExpanded)))
        {
            NoteEdit();
        }
    }

    /// <summary>
    /// Список адаптеров меняется под открытой формой (сменилась сеть, отмечен доверенный адаптер): список выбора
    /// теряет выбранный адаптер и записывает в профиль пустое значение. Это не правка пользователя: значение,
    /// счётчик правок и отметка «не сохранено» возвращаются как были.
    /// </summary>
    public void PreserveAdapterChoice(Action change)
    {
        ArgumentNullException.ThrowIfNull(change);
        var pinned = PinnedInterfaceGuid;
        var dirty = IsDirty;
        var edits = Edits;
        change();
        PinnedInterfaceGuid = pinned;
        Edits = edits;
        IsDirty = dirty;
    }

    /// <summary>Счётчик правок: сохранение снимает <see cref="IsDirty"/>, только если за время запроса правок не было.</summary>
    public int Edits { get; private set; }

    public void NoteEdit()
    {
        Edits++;
        IsDirty = true;
    }

    /// <summary>
    /// Профиль из полей формы. Основа — <paramref name="basis"/> (свежий профиль из службы): поля, которых
    /// в форме нет (цель сетей шлюза, повторы и прочие), берутся из неё, а не из снимка на момент загрузки.
    /// </summary>
    public ConnectionProfile ToProfile(ConnectionProfile? basis = null)
    {
        var fresh = basis ?? _source;
        // Адаптер сравнивается с тем, с которым открыта форма, а не со свежим: служба могла перенести закрепление
        // на новый идентификатор, пока форма была открыта, и прежний идентификатор не должен его отменить.
        var (pinned, description) = ConnectionEdits.MergePinnedAdapter(_source, fresh, PinnedInterfaceGuid);
        var clearPin = (!PinAdapter && _source.PrimaryAdapter == AdapterSelection.Pinned) || (Security.Protocol != _source.Protocol && !ShowPinnedAdapter);
        return Security.Apply(fresh with
        {
            Name = Name.Trim() == _source.Name ? fresh.Name : Name.Trim(),
            Role = Role == _source.Role ? fresh.Role : Role,
            Server = Server.Trim() == _source.Server ? fresh.Server : Server.Trim(),
            UserName = UserName.Trim() == _source.UserName ? fresh.UserName : UserName.Trim(),
            SavePassword = SavePassword == _source.SavePassword ? fresh.SavePassword : SavePassword,
            PrimaryAdapter = (PinAdapter == (_source.PrimaryAdapter == AdapterSelection.Pinned) && Security.Protocol == _source.Protocol) ? fresh.PrimaryAdapter : ShowPinnedAdapter ? AdapterSelection.Pinned : AdapterSelection.Auto,
            PinnedInterfaceGuid = clearPin ? null : pinned,
            PinnedAdapterDescription = clearPin ? null : description,
            AllowFallbackWhenPinnedMissing = AllowFallback == _source.AllowFallbackWhenPinnedMissing ? fresh.AllowFallbackWhenPinnedMissing : AllowFallback,
        }, _source);
    }
}
