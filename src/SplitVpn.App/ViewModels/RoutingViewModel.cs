using System.Collections.ObjectModel;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using SplitVpn.Core.Geo;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using Wpf.Ui.Controls;

namespace SplitVpn.App.ViewModels;

/// <summary>
/// Доска маршрутизации: колонки — куда идёт трафик (напрямую, в туннель, в группу туннелей, в блок),
/// карточки — что именно идёт (RU-база, остальной интернет, сети, домены). Карточки переносятся мышью
/// или через меню «Переместить в…».
/// </summary>
public sealed partial class RoutingViewModel : PageViewModel
{
    private readonly List<BoardCard> _cards = [];
    private readonly List<BoardFolder> _folders = [];
    private AppSettings _settings = new();

    public RoutingViewModel(MainViewModel main)
        : base(main, "Маршрутизация", SymbolRegular.Globe24)
    {
    }

    public ObservableCollection<BoardColumn> Columns { get; } = [];

    public ObservableCollection<GroupItem> Groups { get; } = [];

    [ObservableProperty]
    private bool _dirty;

    [ObservableProperty]
    private string _geoSummary = "—";

    [ObservableProperty]
    private string _geoChecks = "—";

    [ObservableProperty]
    private string? _geoPending;

    [ObservableProperty]
    private int _geoSkipped;

    [ObservableProperty]
    private string _bypassSummary = "—";

    [ObservableProperty]
    private string _bypassChecks = "—";

    [ObservableProperty]
    private string? _bypassPending;

    [ObservableProperty]
    private int _bypassSkipped;

    /// <summary>Несохранённая доска при возврате на страницу не перечитывается: правки не теряются.</summary>
    public override Task OnOpenedAsync() => Dirty ? Task.CompletedTask : RunAsync(LoadAsync);

    public override void OnStatus(StatusDto? status)
    {
        if (status is null)
        {
            return;
        }

        GeoSummary = status.GeoRevision is null
            ? "База не загружена — российские адреса идут туда же, куда остальной интернет."
            : $"IPv4: {Format.Number(status.GeoV4Count)} сетей, IPv6: {Format.Number(status.GeoV6Count)} (IPv6 пока ограничен). Загружена {Format.Local(status.GeoDownloadedUtc)}, версия {status.GeoRevision[..Math.Min(12, status.GeoRevision.Length)]}.";
        GeoChecks = $"Последняя проверка: {Format.Local(status.GeoLastCheckUtc)} — {status.GeoLastResult ?? "нет данных"}. Следующая: {Format.Local(status.GeoNextCheckUtc)}.";
        GeoPending = status.GeoPendingRevision is null ? null : $"Новая база ждёт подтверждения: {status.GeoPendingReason}";
        GeoSkipped = status.GeoSkippedCount;
        SyncBypass(status.Bypass);
        foreach (var card in _cards.Where(c => c.Kind == CardKind.ServerNetworks))
        {
            card.Subtitle = GatewaySummary(status.Tunnels.FirstOrDefault(t => t.ProfileId == card.ProfileId)?.ServerNetworks);
        }

        foreach (var tunnel in status.Tunnels)
        {
            if (Columns.FirstOrDefault(c => c.Target.IsTunnel(out var id) && id == tunnel.ProfileId) is { } column)
            {
                column.Subtitle = StatusText.StateName(tunnel.State) + (tunnel.VpnAddress is null ? "" : ", адрес " + tunnel.VpnAddress);
                column.Tone = tunnel.State == ConnectionState.Connected ? Views.StateTone.Success
                    : tunnel.State is ConnectionState.Error or ConnectionState.TrafficBlocked ? Views.StateTone.Critical
                    : Views.StateTone.Caution;
            }
        }
    }

    private async Task LoadAsync()
    {
        _settings = await Service.RequestAsync<AppSettings>(new GetSettingsRequest());
        _folders.Clear();
        foreach (var folder in _settings.RoutingFolders)
        {
            _folders.Add(new BoardFolder(this, folder.Id, folder.Name, folder.Target));
        }

        _cards.Clear();
        _cards.Add(new BoardCard(this, CardKind.Default, "Остальной интернет", "Всё, что не попало в другие карточки", _settings.DefaultTarget));
        _cards.Add(new BoardCard(this, CardKind.Geo, "Россия (RU-база)", "Адреса из автообновляемой базы", _settings.GeoTarget));
        // Список обхода блокировок перекрывает RU-базу: заблокированный ресурс на российском адресе
        // пойдёт туда, куда указывает эта карточка, а не «напрямую».
        _cards.Add(new BoardCard(this, CardKind.Bypass, "Обход блокировок",
            "Адреса заблокированных ресурсов; важнее RU-базы", _settings.BypassTarget ?? _settings.DefaultTarget));
        foreach (var rule in _settings.Rules)
        {
            _cards.Add(new BoardCard(this, CardKind.Network, rule.Cidr, rule.Comment, rule.Target) { FolderId = rule.FolderId });
        }

        foreach (var rule in _settings.DomainRules)
        {
            _cards.Add(new BoardCard(this, CardKind.Domain, rule.Suffix, rule.Comment, rule.Target) { FolderId = rule.FolderId });
        }

        foreach (var profile in _settings.Profiles.Where(p => p is { Protocol: VpnProtocol.AnyConnect } && p.Role != ProfileRole.Off))
        {
            var status = Main.Status?.Tunnels.FirstOrDefault(t => t.ProfileId == profile.Id)?.ServerNetworks;
            _cards.Add(new BoardCard(this, CardKind.ServerNetworks, $"Сети шлюза «{profile.Name}»", GatewaySummary(status),
                AppSettings.ServerNetworksTarget(profile), profile.AnyConnect.UserRulesOverrideServerNetworks)
            {
                ProfileId = profile.Id,
            });
        }

        Groups.Clear();
        foreach (var group in _settings.Groups)
        {
            Groups.Add(GroupItem.From(group, _settings.Profiles, MarkDirty));
        }

        RebuildColumns();
        Dirty = false;
    }

    /// <summary>Пересобирает колонки: напрямую, по одной на подключение и группу, блокировать.</summary>
    private void RebuildColumns()
    {
        var columns = new List<BoardColumn>
        {
            new(this, RouteTarget.Direct, "Напрямую", "Через основной адаптер, без VPN", Views.StateTone.Success),
        };
        columns.AddRange(_settings.Profiles
            .Where(p => p.Role != ProfileRole.Off)
            .Select(p => new BoardColumn(this, RouteTarget.Tunnel(p.Id), p.Name, p.Protocol == VpnProtocol.AnyConnect ? "Cisco AnyConnect" : RoleText(p.Role), Views.StateTone.Accent)
            {
                IsAnyConnect = p.Protocol == VpnProtocol.AnyConnect,
            }));
        columns.AddRange(Groups.Select(g => new BoardColumn(this, RouteTarget.Group(g.Id), g.Name, g.Summary, Views.StateTone.Accent)));
        columns.Add(new BoardColumn(this, RouteTarget.Blocked, "Блокировать", "Трафик не выпускается никуда", Views.StateTone.Critical));

        foreach (var folder in _folders)
        {
            folder.Cards.Clear();
            if (columns.All(c => c.Target != folder.Target))
            {
                folder.Target = RouteTarget.Direct;
                Dirty = true;
            }
        }

        foreach (var card in _cards)
        {
            if (FolderOf(card) is { } folder)
            {
                card.Target = folder.Target;
                folder.Cards.Add(card);
                continue;
            }

            if (card.FolderId is not null)
            {
                // Папка могла быть удалена из файла вручную: правило остаётся отдельной карточкой.
                card.FolderId = null;
                Dirty = true;
            }

            var column = columns.Find(c => c.Target == card.Target);
            if (column is null)
            {
                // Цель исчезла (подключение выключили или группу удалили) — карточка возвращается в «Напрямую».
                column = columns[0];
                card.Target = column.Target;
                Dirty = true;
            }

            column.Cards.Add(card);
        }

        foreach (var folder in _folders)
        {
            columns.Find(c => c.Target == folder.Target)!.Cards.Add(folder);
        }

        Columns.Clear();
        foreach (var column in columns)
        {
            Columns.Add(column);
        }
    }

    private static string RoleText(ProfileRole role) => role == ProfileRole.Primary ? "Опорное подключение" : "Дополнительное подключение";

    private static string GatewaySummary(ServerNetworksDto? networks) => networks is null
        ? "Шлюз назначит сети при входе"
        : Format.Count(networks.Networks.Count, "сеть", "сети", "сетей") + (networks.Dns.Count > 0 ? ", DNS " + string.Join(", ", networks.Dns) : "");

    /// <summary>
    /// Куда нельзя перенести карточку: «Остальной интернет» и RU-базу — в AnyConnect (он поднимается только после
    /// входа пользователя), сети шлюза — в группу. null — можно.
    /// </summary>
    internal static string? MoveRestriction(BoardCard card, BoardColumn target) => (card.Kind, target) switch
    {
        (CardKind.Default or CardKind.Geo or CardKind.Bypass, { IsAnyConnect: true }) => $"«{card.Title}» нельзя направить в AnyConnect: его сеанс поднимается только после входа пользователя.",
        (CardKind.ServerNetworks, _) when target.Target.Kind == TargetKind.Group => "Сети шлюза нельзя направить в группу подключений.",
        _ => null,
    };

    /// <summary>Правка группы: доска помечается изменённой, а колонка группы сразу показывает новое название и состав.</summary>
    internal void MarkDirty()
    {
        Dirty = true;
        foreach (var group in Groups)
        {
            if (Columns.FirstOrDefault(c => c.Target == RouteTarget.Group(group.Id)) is { } column)
            {
                column.Title = group.Name;
                column.Subtitle = group.Summary;
            }
        }
    }

    internal static bool CanMove(BoardEntry entry, BoardColumn target) => entry is not BoardCard card || MoveRestriction(card, target) is null;

    /// <summary>Переносит карточку или всю папку в другую колонку.</summary>
    internal void Move(BoardEntry entry, BoardColumn target)
    {
        if (entry is BoardFolder folder)
        {
            var source = Columns.FirstOrDefault(c => c.Cards.Contains(folder));
            if (source is null || source == target)
            {
                return;
            }

            source.Cards.Remove(folder);
            folder.Target = target.Target;
            foreach (var folderCard in folder.Cards)
            {
                folderCard.Target = target.Target;
            }

            folder.FocusOnLoad = true;
            target.Cards.Add(folder);
            Dirty = true;
            Message = null;
            return;
        }

        if (entry is not BoardCard card)
        {
            return;
        }

        var parent = FolderOf(card);
        var sourceColumn = parent is null
            ? Columns.FirstOrDefault(c => c.Cards.Contains(card))
            : Columns.FirstOrDefault(c => c.Cards.Contains(parent));
        if (sourceColumn is null || parent is null && sourceColumn == target)
        {
            return;
        }

        if (MoveRestriction(card, target) is { } restriction)
        {
            ShowMessage(restriction, isError: true);
            return;
        }

        if (parent is null)
        {
            sourceColumn.Cards.Remove(card);
        }
        else
        {
            // Перенос отдельного правила всегда вынимает его из прежней папки.
            parent.Cards.Remove(card);
            card.FolderId = null;
        }

        card.Target = target.Target;
        card.FocusOnLoad = true;
        target.Cards.Add(card);
        Dirty = true;
        Message = null;
    }

    internal void MoveToFolder(BoardCard card, BoardFolder destination)
    {
        if (card.FolderId == destination.Id || card.Kind is not (CardKind.Network or CardKind.Domain))
        {
            return;
        }

        var parent = FolderOf(card);
        var source = parent is null
            ? Columns.FirstOrDefault(c => c.Cards.Contains(card))
            : Columns.FirstOrDefault(c => c.Cards.Contains(parent));
        if (source is null)
        {
            return;
        }

        if (parent is null)
        {
            source.Cards.Remove(card);
        }
        else
        {
            parent.Cards.Remove(card);
        }

        card.FolderId = destination.Id;
        card.Target = destination.Target;
        destination.Cards.Add(card);
        destination.IsExpanded = true;
        Dirty = true;
        Message = null;
    }

    internal void Extract(BoardCard card)
    {
        if (FolderOf(card) is not { } parent)
        {
            return;
        }

        var column = Columns.FirstOrDefault(c => c.Cards.Contains(parent));
        if (column is null)
        {
            return;
        }

        parent.Cards.Remove(card);
        card.FolderId = null;
        card.Target = parent.Target;
        column.Cards.Insert(Math.Min(column.Cards.IndexOf(parent) + 1, column.Cards.Count), card);
        Dirty = true;
    }

    internal void Remove(BoardCard card)
    {
        FolderOf(card)?.Cards.Remove(card);
        foreach (var column in Columns)
        {
            column.Cards.Remove(card);
        }

        _cards.Remove(card);
        Dirty = true;
    }

    internal BoardFolder CreateFolder(BoardColumn column)
    {
        var folder = new BoardFolder(this, Guid.NewGuid(), UniqueFolderName("Новая папка"), column.Target) { IsExpanded = true };
        _folders.Add(folder);
        column.Cards.Add(folder);
        Dirty = true;
        Message = null;
        return folder;
    }

    internal void RemoveFolder(BoardFolder folder)
    {
        var column = Columns.FirstOrDefault(c => c.Cards.Contains(folder));
        if (column is null)
        {
            return;
        }

        var index = column.Cards.IndexOf(folder);
        var cards = folder.Cards.ToList();
        folder.Cards.Clear();
        column.Cards.Remove(folder);
        _folders.Remove(folder);
        foreach (var card in cards)
        {
            // «Удалить папку» означает только распустить её: правила остаются в той же колонке.
            card.FolderId = null;
            column.Cards.Insert(index++, card);
        }

        Dirty = true;
    }

    internal IReadOnlyList<BoardFolder> FolderTargetsFor(BoardCard card) => card.Kind is CardKind.Network or CardKind.Domain
        ? _folders.Where(f => f.Id != card.FolderId).ToList()
        : [];

    private BoardFolder? FolderOf(BoardCard card) => card.FolderId is { } id ? _folders.Find(f => f.Id == id) : null;

    private string UniqueFolderName(string name)
    {
        var candidate = name;
        for (var i = 2; _folders.Any(f => string.Equals(f.Name, candidate, StringComparison.OrdinalIgnoreCase)); i++)
        {
            candidate = $"{name} {i}";
        }

        return candidate;
    }

    /// <summary>Добавляет в колонку или папку сеть (если текст похож на CIDR) или домен.</summary>
    internal void Add(BoardColumn column, string text) => Add(column.Target, text, column, null);

    internal void Add(BoardFolder folder, string text) => Add(folder.Target, text, null, folder);

    private void Add(RouteTarget target, string text, BoardColumn? column, BoardFolder? folder)
    {
        var value = (text ?? "").Trim();
        if (value.Length == 0)
        {
            return;
        }

        if (value.Contains(':', StringComparison.Ordinal))
        {
            ShowMessage($"«{value}»: IPv6-адреса на доску не добавляются — публичный IPv6 блокируется, пока включена защита.", isError: true);
            return;
        }

        var kind = value.Contains('/', StringComparison.Ordinal) || Ipv4.TryParse(value, out _) ? CardKind.Network : CardKind.Domain;
        if (kind == CardKind.Network)
        {
            var cidr = value.Contains('/', StringComparison.Ordinal) ? value : value + "/32";
            var (_, errors) = SettingsSerializer.ParseRules([new UserRuleSetting { Cidr = cidr, Target = target }]);
            if (errors.Count > 0)
            {
                ShowMessage(string.Join(" ", errors), isError: true);
                return;
            }

            if (_cards.Exists(c => c.Kind == CardKind.Network && string.Equals(c.Title, cidr, StringComparison.OrdinalIgnoreCase)))
            {
                ShowMessage($"Сеть {cidr} уже есть на доске.", isError: true);
                return;
            }

            AddCard(new BoardCard(this, CardKind.Network, cidr, null, target), column, folder);
            return;
        }

        var suffix = SettingsSerializer.NormalizeSuffix(value);
        if (!SettingsSerializer.IsValidSuffix(suffix))
        {
            ShowMessage($"«{value}»: неверный домен. Укажите имя вида example.org.", isError: true);
            return;
        }

        if (_cards.Exists(c => c.Kind == CardKind.Domain && string.Equals(c.Title, suffix, StringComparison.OrdinalIgnoreCase)))
        {
            ShowMessage($"Домен «{suffix}» уже есть на доске.", isError: true);
            return;
        }

        AddCard(new BoardCard(this, CardKind.Domain, suffix, null, target), column, folder);
    }

    private void AddCard(BoardCard card, BoardColumn? column, BoardFolder? folder)
    {
        _cards.Add(card);
        if (folder is null)
        {
            column!.Cards.Add(card);
            column.NewValue = "";
        }
        else
        {
            card.FolderId = folder.Id;
            folder.Cards.Add(card);
            folder.NewValue = "";
            folder.IsExpanded = true;
        }

        Dirty = true;
        Message = null;
    }

    [RelayCommand]
    private void AddGroup()
    {
        var name = UniqueGroupName("Балансировка");
        Groups.Add(GroupItem.From(new TunnelGroupSetting { Name = name }, _settings.Profiles, MarkDirty));
        Dirty = true;
        RebuildColumns();
    }

    [RelayCommand]
    private async Task RemoveGroupAsync(GroupItem group)
    {
        var cards = Columns.FirstOrDefault(c => c.Target == RouteTarget.Group(group.Id))?.Cards.Count ?? 0;
        var detail = cards > 0 ? $" Карточки из её колонки ({cards}) перейдут в «Напрямую» — мимо VPN." : "";
        if (!await Main.Confirm("Удалить группу?", $"Группа «{group.Name}» будет удалена после сохранения доски.{detail}", "Удалить"))
        {
            return;
        }

        Groups.Remove(group);
        Dirty = true;
        RebuildColumns();
    }

    private string UniqueGroupName(string name)
    {
        var candidate = name;
        for (var i = 2; Groups.Any(g => string.Equals(g.Name, candidate, StringComparison.OrdinalIgnoreCase)); i++)
        {
            candidate = $"{name} {i}";
        }

        return candidate;
    }

    /// <summary>Сохранение с проверкой службой: конфликты правил объясняются текстом ошибки.</summary>
    [RelayCommand]
    private Task SaveAsync() => RunAsync(async () =>
    {
        var fresh = await Service.RequestAsync<AppSettings>(new GetSettingsRequest());
        var updated = fresh with
        {
            // Участники — только подключения, которые ещё существуют и включены: доска могла устареть.
            Groups = Groups.Select(g => g.ToSetting()).Select(g => g with { Members = g.Members.Where(m => fresh.Profile(m) is { Role: not ProfileRole.Off }).ToList() }).ToList(),
            RoutingFolders = _folders.Select(f => f.ToSetting()).ToList(),
            DefaultTarget = TargetOf(CardKind.Default),
            GeoTarget = TargetOf(CardKind.Geo),
            BypassTarget = TargetOf(CardKind.Bypass),
            Rules = _cards.Where(c => c.Kind == CardKind.Network)
                .Select(c => new UserRuleSetting { Cidr = c.Title, Target = FolderOf(c)?.Target ?? c.Target, Comment = c.Subtitle, FolderId = FolderOf(c)?.Id }).ToList(),
            DomainRules = _cards.Where(c => c.Kind == CardKind.Domain)
                .Select(c => new DomainRuleSetting { Suffix = c.Title, Target = FolderOf(c)?.Target ?? c.Target, Comment = c.Subtitle, FolderId = FolderOf(c)?.Id }).ToList(),
            Profiles = fresh.Profiles.Select(p => _cards.Find(c => c.Kind == CardKind.ServerNetworks && c.ProfileId == p.Id) is { } card
                ? p with
                {
                    AnyConnect = p.AnyConnect with
                    {
                        ServerNetworksTarget = card.Target == RouteTarget.Tunnel(p.Id) ? null : card.Target,
                        UserRulesOverrideServerNetworks = card.UserRulesWin,
                    },
                }
                : p).ToList(),
        };
        var response = await Service.CommandAsync(new SaveSettingsRequest(updated));
        _settings = updated;
        Dirty = false;
        var warnings = response.ResultAs<List<string>>() ?? [];
        return warnings.Count > 0 ? "Сохранено. " + string.Join(" ", warnings) : "Сохранено и применено.";
    });

    private RouteTarget TargetOf(CardKind kind) => _cards.Find(c => c.Kind == kind)?.Target ?? RouteTarget.Direct;

    [RelayCommand]
    private Task ReloadAsync() => RunAsync(LoadAsync, "Доска возвращена к сохранённому виду.");

    /// <summary>Сводка второго списка. Служба присылает её одной записью — плоские поля остались за RU-базой.</summary>
    private void SyncBypass(GeoListStatusDto? bypass)
    {
        if (bypass is null)
        {
            return;
        }

        BypassSummary = bypass.Revision is null
            ? "Список не загружен — заблокированные ресурсы идут по общим правилам."
            : $"IPv4: {Format.Number(bypass.V4Count)} сетей, IPv6: {Format.Number(bypass.V6Count)}. Загружен {Format.Local(bypass.DownloadedUtc)}, версия {bypass.Revision[..Math.Min(12, bypass.Revision.Length)]}.";
        BypassChecks = $"Последняя проверка: {Format.Local(bypass.LastCheckUtc)} — {bypass.LastResult ?? "нет данных"}. Следующая: {Format.Local(bypass.NextCheckUtc)}.";
        BypassPending = bypass.PendingRevision is null ? null : $"Новый список ждёт подтверждения: {bypass.PendingReason}";
        BypassSkipped = bypass.SkippedCount;
    }

    [RelayCommand]
    public Task UpdateGeoAsync() => RunAsync(() => Service.CommandAsync(new GeoUpdateNowRequest()), "Проверка базы выполнена.");

    [RelayCommand]
    public Task UpdateBypassAsync() => RunAsync(
        () => Service.CommandAsync(new GeoUpdateNowRequest { List = GeoListKind.Bypass }), "Проверка списка обхода блокировок выполнена.");

    [RelayCommand]
    private Task RollbackBypassAsync() => RunAsync(
        () => Service.CommandAsync(new GeoRollbackRequest { List = GeoListKind.Bypass }), "Возвращён предыдущий список; заменённая версия больше не предлагается.");

    [RelayCommand]
    private Task AcceptBypassAsync() => RunAsync(
        () => Service.CommandAsync(new GeoAcceptPendingRequest { List = GeoListKind.Bypass }), "Новый список принят.");

    [RelayCommand]
    private Task RejectBypassAsync() => RunAsync(
        () => Service.CommandAsync(new GeoRejectPendingRequest { List = GeoListKind.Bypass }), "Новый список отклонён.");

    [RelayCommand]
    private Task ClearBypassSkippedAsync() => RunAsync(
        () => Service.CommandAsync(new GeoClearSkippedRequest { List = GeoListKind.Bypass }), "Отклонённые версии списка снова будут предлагаться.");

    [RelayCommand]
    private Task RollbackGeoAsync() => RunAsync(() => Service.CommandAsync(new GeoRollbackRequest()), "Возвращена предыдущая база; заменённая версия больше не предлагается.");

    [RelayCommand]
    private Task AcceptGeoAsync() => RunAsync(() => Service.CommandAsync(new GeoAcceptPendingRequest()), "Новая база принята.");

    [RelayCommand]
    private Task RejectGeoAsync() => RunAsync(() => Service.CommandAsync(new GeoRejectPendingRequest()), "Новая база отклонена.");

    [RelayCommand]
    private Task ClearSkippedAsync() => RunAsync(() => Service.CommandAsync(new GeoClearSkippedRequest()), "Отклонённые версии базы снова будут предлагаться.");

    [RelayCommand]
    private Task ImportGeoAsync() => RunAsync(async () =>
    {
        var dialog = new OpenFileDialog { Filter = "Список CIDR|*.txt;*.lst|Все файлы|*.*" };
        if (dialog.ShowDialog() != true)
        {
            return null;
        }

        if (new FileInfo(dialog.FileName).Length > Core.Geo.GeoValidationOptions.MaxImportBytes)
        {
            throw new FormatException("Файл слишком большой для списка сетей (больше 16 МБ).");
        }

        if (!await Main.Confirm("Импортировать RU-базу?",
                $"Сети из файла «{Path.GetFileName(dialog.FileName)}» сразу заменят текущую базу и пойдут туда же, куда «Россия (RU-база)» — обычно напрямую, мимо VPN. "
                + "Проверка резких изменений для файла не выполняется. Импортируйте только список из надёжного источника.", "Импортировать"))
        {
            return null;
        }

        await Service.CommandAsync(new GeoImportRequest(await File.ReadAllTextAsync(dialog.FileName)));
        return "База импортирована.";
    });
}

public enum CardKind
{
    Default,
    Geo,

    /// <summary>Список адресов заблокированных ресурсов: слой поверх RU-базы.</summary>
    Bypass,

    Network,
    Domain,

    /// <summary>Сети, которые назначает шлюз AnyConnect: всегда на доске, пока подключение включено.</summary>
    ServerNetworks,
}

/// <summary>Колонка доски: одна цель маршрутизации.</summary>
public sealed partial class BoardColumn : ObservableObject
{
    private readonly RoutingViewModel _board;

    public BoardColumn(RoutingViewModel board, RouteTarget target, string title, string subtitle, Views.StateTone tone)
    {
        _board = board;
        Target = target;
        Title = title;
        Subtitle = subtitle;
        Tone = tone;
    }

    public RouteTarget Target { get; }

    /// <summary>Колонка подключения AnyConnect: «Остальной интернет» и RU-база сюда не переносятся.</summary>
    public bool IsAnyConnect { get; init; }

    [ObservableProperty]
    private string _title;

    /// <summary>Отдельные карточки и папки правил; правила внутри папок здесь не дублируются.</summary>
    public ObservableCollection<BoardEntry> Cards { get; } = [];

    /// <summary>Имя колонки для экранного диктора.</summary>
    public override string ToString() => Title;

    [ObservableProperty]
    private string _subtitle;

    [ObservableProperty]
    private Views.StateTone _tone;

    [ObservableProperty]
    private string _newValue = "";

    /// <summary>Принимает перенесённую карточку или папку.</summary>
    public void Accept(BoardEntry entry) => _board.Move(entry, this);

    [RelayCommand]
    private void Add() => _board.Add(this, NewValue);

    [RelayCommand]
    private void CreateFolder() => _board.CreateFolder(this);
}

/// <summary>Общие действия отдельной карточки и папки на доске.</summary>
public abstract partial class BoardEntry : ObservableObject
{
    protected BoardEntry(RoutingViewModel board, RouteTarget target)
    {
        Board = board;
        Target = target;
    }

    protected RoutingViewModel Board { get; }

    public abstract string Title { get; }

    public RouteTarget Target { get; set; }

    /// <summary>Перенесённому элементу фокус клавиатуры переходит в новую колонку.</summary>
    internal bool FocusOnLoad { get; set; }

    /// <summary>Колонки для меню «Переместить в…»: работает без мыши и с экранным диктором.</summary>
    public IReadOnlyList<BoardColumn> MoveTargets => Board.Columns.Where(c => !c.Cards.Contains(this) && RoutingViewModel.CanMove(this, c)).ToList();

    [RelayCommand]
    private void MoveTo(BoardColumn column) => Board.Move(this, column);
}

/// <summary>Сворачиваемая папка сетей и доменов с общей целью маршрутизации.</summary>
public sealed partial class BoardFolder : BoardEntry
{
    public BoardFolder(RoutingViewModel board, Guid id, string name, RouteTarget target)
        : base(board, target)
    {
        Id = id;
        _name = name;
        Cards.CollectionChanged += (_, _) => OnPropertyChanged(nameof(Summary));
    }

    public Guid Id { get; }

    [ObservableProperty]
    private string _name;

    public override string Title => Name;

    public ObservableCollection<BoardCard> Cards { get; } = [];

    public string Summary => Format.Count(Cards.Count, "правило", "правила", "правил");

    [ObservableProperty]
    private bool _isExpanded;

    public SymbolRegular ToggleSymbol => IsExpanded ? SymbolRegular.ChevronDown24 : SymbolRegular.ChevronRight24;

    [ObservableProperty]
    private string _newValue = "";

    public override string ToString() => $"{Name}, папка, {Summary}";

    partial void OnNameChanged(string value)
    {
        OnPropertyChanged(nameof(Title));
        Board.MarkDirty();
    }

    partial void OnIsExpandedChanged(bool value) => OnPropertyChanged(nameof(ToggleSymbol));

    public RoutingFolderSetting ToSetting() => new() { Id = Id, Name = Name.Trim(), Target = Target };

    [RelayCommand]
    private void Toggle() => IsExpanded = !IsExpanded;

    [RelayCommand]
    private void Add() => Board.Add(this, NewValue);

    [RelayCommand]
    private void Remove() => Board.RemoveFolder(this);
}

/// <summary>Карточка доски: что именно направляется в колонку.</summary>
public sealed partial class BoardCard : BoardEntry
{
    public BoardCard(RoutingViewModel board, CardKind kind, string title, string? subtitle, RouteTarget target, bool userRulesWin = true)
        : base(board, target)
    {
        _userRulesWin = userRulesWin;
        Kind = kind;
        Title = title;
        _subtitle = subtitle;
    }

    public CardKind Kind { get; }

    public override string Title { get; }

    /// <summary>Подключение AnyConnect, чьи сети несёт карточка.</summary>
    public Guid? ProfileId { get; init; }

    [ObservableProperty]
    private string? _subtitle;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsInFolder))]
    [NotifyPropertyChangedFor(nameof(ShowKind))]
    private Guid? _folderId;

    public bool IsInFolder => FolderId is not null;

    /// <summary>Внутри папки тип не повторяется в каждой строке; для диктора он остаётся в ToString().</summary>
    public bool ShowKind => !IsInFolder && KindText.Length > 0;

    public IReadOnlyList<BoardFolder> FolderTargets => Board.FolderTargetsFor(this);

    /// <summary>Для карточки сетей шлюза: ручные правила важнее этих сетей.</summary>
    [ObservableProperty]
    private bool _userRulesWin = true;

    public bool IsServerNetworks => Kind == CardKind.ServerNetworks;

    partial void OnUserRulesWinChanged(bool value) => Board.MarkDirty();

    /// <summary>Имя элемента для экранного диктора.</summary>
    public override string ToString() => KindText.Length > 0 ? $"{Title}, {KindText}" : Title;

    /// <summary>Сети и домены можно удалить; «Остальной интернет» и RU-база всегда есть на доске.</summary>
    public bool CanRemove => Kind is CardKind.Network or CardKind.Domain;

    public string KindText => Kind switch
    {
        // У «Остального интернета» и RU-базы вид уже ясен из названия: подпись не повторяется.
        CardKind.Default => "",
        CardKind.Geo => "",
        CardKind.Bypass => "",
        CardKind.Network => "Сеть",
        CardKind.ServerNetworks => "Назначает шлюз",
        _ => "Домен",
    };

    [RelayCommand]
    private void MoveToFolder(BoardFolder folder) => Board.MoveToFolder(this, folder);

    [RelayCommand]
    private void Extract() => Board.Extract(this);

    [RelayCommand]
    private void Remove() => Board.Remove(this);
}

/// <summary>Группа подключений с распределением нагрузки.</summary>
public sealed partial class GroupItem : ObservableObject
{
    private Action? _changed;

    public Guid Id { get; private init; } = Guid.NewGuid();

    public ObservableCollection<GroupMember> Members { get; } = [];

    [ObservableProperty]
    private string _name = "";

    [ObservableProperty]
    private bool _failover;

    public string Summary => (Failover ? "Резерв: " : "Балансировка: ") +
        (Members.Count(m => m.Included) is var count && count > 0 ? Format.Count(count, "подключение", "подключения", "подключений") : "участники не выбраны");

    public override string ToString() => $"{Name}, {Summary}";

    public static GroupItem From(TunnelGroupSetting setting, IReadOnlyList<ConnectionProfile> profiles, Action changed)
    {
        var item = new GroupItem
        {
            Id = setting.Id,
            Name = setting.Name,
            Failover = setting.Mode == BalanceMode.Failover,
        };
        // Порядок участников важен для резерва: сначала выбранные в сохранённом порядке, затем остальные.
        var order = setting.Members.Select((id, index) => (id, index)).DistinctBy(m => m.id).ToDictionary(m => m.id, m => m.index);
        // AnyConnect в группы не входит: его сеанс зависит от входа пользователя.
        foreach (var profile in profiles.Where(p => p.Role != ProfileRole.Off && p.Protocol != VpnProtocol.AnyConnect).OrderBy(p => order.GetValueOrDefault(p.Id, int.MaxValue)))
        {
            var member = new GroupMember(profile.Id, profile.Name) { Included = setting.Members.Contains(profile.Id) };
            member.PropertyChanged += (_, _) =>
            {
                changed();
                item.OnPropertyChanged(nameof(Summary));
            };
            item.Members.Add(member);
        }

        item._changed = changed;
        return item;
    }

    public TunnelGroupSetting ToSetting() => new()
    {
        Id = Id,
        Name = Name.Trim(),
        Mode = Failover ? BalanceMode.Failover : BalanceMode.Distribute,
        Members = Members.Where(m => m.Included).Select(m => m.ProfileId).ToList(),
    };

    partial void OnNameChanged(string value) => _changed?.Invoke();

    partial void OnFailoverChanged(bool value)
    {
        _changed?.Invoke();
        OnPropertyChanged(nameof(Summary));
    }
}

public sealed partial class GroupMember(Guid profileId, string name) : ObservableObject
{
    public Guid ProfileId { get; } = profileId;

    public string Name { get; } = name;

    [ObservableProperty]
    private bool _included;
}

public sealed record ChoiceItem<T>(T Value, string Text)
{
    public override string ToString() => Text;
}
