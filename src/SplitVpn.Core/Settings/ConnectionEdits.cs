using System.Globalization;
using SplitVpn.Core.Policy;

namespace SplitVpn.Core.Settings;

/// <summary>
/// Изменения списка подключений из интерфейса поверх свежих настроек службы: сохранение одного профиля,
/// удаление, импорт. Цели, группы и правила, которые ссылаются на выключенные или удалённые подключения,
/// возвращаются на прямой выход — иначе служба отклонит настройки.
/// </summary>
public static class ConnectionEdits
{
    /// <summary>Предел размера файла импорта: экспорт сотни подключений занимает десятки килобайт.</summary>
    public const int MaxImportBytes = 1024 * 1024;

    /// <summary>
    /// Сохраняет профиль на его месте в списке. Опорное подключение одно: прежнее становится дополнительным.
    /// «Остальной интернет» переходит на профиль только когда тот становится опорным, а трафик не идёт в VPN, —
    /// как при смене роли в службе; сознательный выбор «Напрямую» или «Блокировать» при правке не отменяется.
    /// </summary>
    public static AppSettings SaveProfile(AppSettings fresh, ConnectionProfile profile)
    {
        ArgumentNullException.ThrowIfNull(fresh);
        ArgumentNullException.ThrowIfNull(profile);
        var before = fresh.Profile(profile.Id);
        var profiles = fresh.Profiles
            .Select(p => p.Id == profile.Id ? profile : Demoted(p, profile))
            .ToList();
        if (before is null)
        {
            profiles.Add(profile);
        }

        var updated = fresh with { Profiles = profiles };
        if (profile.Role == ProfileRole.Primary && before?.Role != ProfileRole.Primary && updated.DefaultFollowsNewPrimary())
        {
            updated = updated with { DefaultTarget = RouteTarget.Tunnel(profile.Id) };
        }

        return Retarget(updated);
    }

    /// <summary>
    /// Сохранять ли пароль профиля при правке из командной строки: явный выбор, иначе прежнее значение профиля;
    /// новый профиль пароль сохраняет. Правка сервера или роли не должна молча включать запись пароля на диск.
    /// </summary>
    public static bool SavePasswordFor(ConnectionProfile? existing, bool? requested) =>
        requested ?? existing?.SavePassword ?? true;

    public static AppSettings RemoveProfile(AppSettings fresh, Guid profileId)
    {
        ArgumentNullException.ThrowIfNull(fresh);
        return Retarget(fresh with { Profiles = fresh.Profiles.Where(p => p.Id != profileId).ToList() });
    }

    /// <summary>
    /// Порядок подключений: он же вид списка на экране, он же очерёдность подъёма. Набор должен совпадать
    /// с нынешним — перестановка ничего не добавляет и не удаляет, поэтому цели трогать не нужно.
    /// </summary>
    public static AppSettings Reorder(AppSettings fresh, IReadOnlyList<Guid> order)
    {
        ArgumentNullException.ThrowIfNull(fresh);
        ArgumentNullException.ThrowIfNull(order);
        if (!IsSameSet(fresh.Profiles, order))
        {
            throw new ArgumentException("Порядок подключений не совпадает со списком.", nameof(order));
        }

        var byId = fresh.Profiles.ToDictionary(p => p.Id);
        return fresh with { Profiles = order.Select(id => byId[id]).ToList() };
    }

    /// <summary>Тот же набор подключений, что и в настройках: без пропусков, добавлений и повторов.</summary>
    public static bool IsSameSet(IReadOnlyList<ConnectionProfile> profiles, IReadOnlyList<Guid> order)
    {
        ArgumentNullException.ThrowIfNull(profiles);
        ArgumentNullException.ThrowIfNull(order);
        if (profiles.Count != order.Count)
        {
            return false;
        }

        var ids = profiles.Select(p => p.Id).ToHashSet();
        var seen = new HashSet<Guid>();
        return order.All(id => ids.Contains(id) && seen.Add(id));
    }

    /// <summary>
    /// Готовит профили из файла экспорта: новые идентификаторы, уникальные названия (в том числе внутри файла),
    /// роль «Выключено», автоматический выбор адаптера и повторы по умолчанию. Подключение из чужого файла
    /// не должно само дозваниваться, забирать опорную роль или ссылаться на адаптер другого компьютера.
    /// </summary>
    public static List<ConnectionProfile> PrepareImport(IEnumerable<string> existingNames, IEnumerable<ConnectionProfile?> imported)
    {
        ArgumentNullException.ThrowIfNull(existingNames);
        ArgumentNullException.ThrowIfNull(imported);
        // Занятые названия сравниваются так же, как в проверке настроек: без пробелов по краям и без учёта регистра.
        var names = existingNames.Select(n => (n ?? "").Trim()).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var result = new List<ConnectionProfile>();
        // Служебный раздел исходных значений (UnknownSettingValues.PreservedKey) из чужого файла не принимается:
        // при записи файла настроек он вернул бы на место непроверенные роль, протокол и способ входа.
        var profiles = imported.OfType<ConnectionProfile>().Select(p => UnknownSettingValues.WithoutPreserved(SettingsSerializer.NormalizeProfile(p))).ToList();
        // Прежний идентификатор из файла -> новый: ссылки между подключениями файла (цель сетей шлюза) переносятся вместе с ними.
        var newIds = new Dictionary<Guid, Guid>();
        foreach (var profile in profiles)
        {
            newIds.TryAdd(profile.Id, Guid.NewGuid());
        }

        var assigned = new HashSet<Guid>();
        foreach (var profile in profiles)
        {
            var importedId = newIds[profile.Id];
            if (!assigned.Add(importedId)) { importedId = Guid.NewGuid(); }
            var name = UniqueName(names, string.IsNullOrWhiteSpace(profile.Name) ? "Импортированное подключение" : profile.Name.Trim());
            names.Add(name);
            result.Add(profile with
            {
                Id = importedId,
                AnyConnect = profile.AnyConnect with { ServerNetworksTarget = profile.AnyConnect.ServerNetworksTarget == RouteTarget.Tunnel(profile.Id)
                    ? RouteTarget.Tunnel(importedId) : Remap(profile.AnyConnect.ServerNetworksTarget, newIds) },
                Name = name,
                Role = ProfileRole.Off,
                PrimaryAdapter = AdapterSelection.Auto,
                PinnedInterfaceGuid = null,
                PinnedAdapterDescription = null,
                AllowFallbackWhenPinnedMissing = false,
                Retry = new RetrySettings(),
            });
        }

        return result;
    }

    /// <summary>
    /// Готовит профили к записи в файл экспорта: новые идентификаторы, чтобы файл не нёс идентификаторов установки,
    /// перенос цели сетей шлюза AnyConnect на новые идентификаторы (иначе при импорте ссылка на другое подключение теряется)
    /// и без служебного раздела исходных значений.
    /// </summary>
    public static List<ConnectionProfile> PrepareExport(IEnumerable<ConnectionProfile> profiles)
    {
        ArgumentNullException.ThrowIfNull(profiles);
        var list = profiles.ToList();
        var newIds = new Dictionary<Guid, Guid>();
        foreach (var profile in list)
        {
            newIds.TryAdd(profile.Id, Guid.NewGuid());
        }

        // Служебный раздел исходных значений в файл экспорта не пишется: подключение уходит таким, каким его видит эта версия.
        return list.Select(p => UnknownSettingValues.WithoutPreserved(p) with
        {
            Id = newIds[p.Id],
            AnyConnect = p.AnyConnect with { ServerNetworksTarget = Remap(p.AnyConnect.ServerNetworksTarget, newIds) },
        }).ToList();
    }

    /// <summary>
    /// Цель-подключение переносится на новый идентификатор. Подключение, которого нет в наборе, и группа (группы
    /// не экспортируются) дают null — собственный туннель шлюза; «Напрямую» и «Блокировать» остаются как есть.
    /// </summary>
    private static RouteTarget? Remap(RouteTarget? target, Dictionary<Guid, Guid> newIds)
    {
        if (target is not { } value)
        {
            return null;
        }

        if (value.IsTunnel(out var tunnel))
        {
            return newIds.TryGetValue(tunnel, out var mapped) ? RouteTarget.Tunnel(mapped) : null;
        }

        return value.Kind == TargetKind.Group ? null : value;
    }

    /// <summary>
    /// Название, не совпадающее с занятыми: «Имя», «Имя 2», «Имя 3»… Сравнение то же, что у проверки настроек:
    /// без пробелов по краям и без учёта регистра, — иначе «Office» при занятом «Office » прошло бы здесь и было бы
    /// отклонено при сохранении. Результат не длиннее <see cref="SettingsValidator.MaxNameLength"/>.
    /// </summary>
    public static string UniqueName(IReadOnlySet<string> taken, string name)
    {
        ArgumentNullException.ThrowIfNull(taken);
        var used = taken.Select(t => (t ?? "").Trim()).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var basis = (name ?? "").Trim();
        var candidate = Fit(basis, SettingsValidator.MaxNameLength);
        for (var i = 2; used.Contains(candidate); i++)
        {
            var suffix = string.Create(CultureInfo.InvariantCulture, $" {i}");
            candidate = Fit(basis, SettingsValidator.MaxNameLength - suffix.Length) + suffix;
        }

        return candidate;
    }

    /// <summary>Начало названия длиной не больше <paramref name="length"/>, не разрезая суррогатную пару.</summary>
    private static string Fit(string name, int length)
    {
        if (name.Length <= length)
        {
            return name;
        }

        if (length > 0 && char.IsHighSurrogate(name[length - 1]))
        {
            length--;
        }

        return name[..length].TrimEnd();
    }

    /// <summary>
    /// Что после изменения уходит мимо VPN: места назначения («Остальной интернет», подсеть, домен), у которых
    /// цель была туннелем или группой, а стала прямым выходом. Нужно, чтобы предупредить до сохранения.
    /// Места сравниваются по названию, а не по позиции: удалённое подключение AnyConnect или появившаяся цель
    /// списка обхода сдвигают список, и сравнение по позиции сопоставило бы разные места.
    /// </summary>
    public static IReadOnlyList<string> NewlyDirect(AppSettings before, AppSettings after)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);
        var old = new Dictionary<string, RouteTarget>(StringComparer.Ordinal);
        foreach (var (where, target) in before.AllTargets)
        {
            old.TryAdd(where, target);
        }

        return after.AllTargets
            .Where(t => t.Target.Kind == TargetKind.Direct && old.TryGetValue(t.Where, out var was) && was.IsVpn)
            .Select(t => t.Where)
            .Distinct(StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>
    /// Сохранённый пароль привязан к серверу, протоколу, способу входа и учётной записи: после их смены служба
    /// не должна сама отдавать прежний пароль новому серверу (MS-CHAPv2 позволяет перебрать NT-хэш). Для способов
    /// EAP с проверкой сервера привязка включает и саму проверку: имена сервера и доверенные корневые CA. Иначе
    /// ослабленная проверка (чужой CA, другое имя) отдала бы прежний пароль подставному серверу.
    /// </summary>
    public static bool PasswordBindingChanged(ConnectionProfile before, ConnectionProfile after)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);
        return PreSharedKeyBindingChanged(before, after)
            || before.AuthMethod != after.AuthMethod
            || !SameText(before.UserName, after.UserName)
            || !SameText(before.Domain, after.Domain)
            || ServerValidationChanged(before, after);
    }

    /// <summary>
    /// Изменились имена сервера EAP (без учёта регистра и порядка) или набор отпечатков доверенных корневых CA
    /// (после нормализации). Учитывается, только если способ входа проверяет сервер.
    /// </summary>
    private static bool ServerValidationChanged(ConnectionProfile before, ConnectionProfile after)
    {
        if (!VpnProtocols.NeedsServerValidation(after.AuthMethod))
        {
            return false;
        }

        return !EapServerNames(before.Eap).SetEquals(EapServerNames(after.Eap))
            || !EapThumbprints(before.Eap).SetEquals(EapThumbprints(after.Eap));
    }

    // Профиль может прийти по каналу управления без нормализации: раздел или строка - null.
    private static HashSet<string> EapServerNames(EapSettings? eap) => new(
        (eap?.ServerNames ?? "").Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries),
        StringComparer.OrdinalIgnoreCase);

    private static HashSet<string> EapThumbprints(EapSettings? eap) => new(
        (eap?.TrustedRootThumbprints ?? []).Where(t => !string.IsNullOrWhiteSpace(t)).Select(VpnProtocols.NormalizeThumbprint),
        StringComparer.Ordinal);

    /// <summary>Общий ключ IPsec привязан к серверу и протоколу.</summary>
    public static bool PreSharedKeyBindingChanged(ConnectionProfile before, ConnectionProfile after)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);
        if (before.Protocol != after.Protocol) { return true; }
        if (before.Protocol == VpnProtocol.SshVpn
            && Net.ServerAddress.TryParse(before.Server, VpnProtocols.SshDefaultPort, out var first)
            && Net.ServerAddress.TryParse(after.Server, VpnProtocols.SshDefaultPort, out var second))
        {
            return first.Port != second.Port || !SameText(first.Host, second.Host);
        }
        return !SameText(before.Server, after.Server);
    }

    private static bool SameText(string? a, string? b) => string.Equals((a ?? "").Trim(), (b ?? "").Trim(), StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Закреплённый адаптер из формы поверх свежего профиля службы. Служба сама переносит закрепление на адаптер
    /// с новым идентификатором (после сброса сети Windows) и запоминает описание драйвера. Если адаптер в форме
    /// не меняли (тот же, с которым форма открыта, или выбор пуст, потому что прежнего адаптера уже нет в списке),
    /// идентификатор и описание берутся из службы: иначе сохранение формы вернуло бы исчезнувший адаптер без
    /// описания, и служба заблокировала бы трафик как при пропавшем закреплённом адаптере. Описание остаётся
    /// только у адаптера, которому принадлежит: для нового выбора служба запишет описание сама.
    /// </summary>
    /// <param name="loaded">Профиль, с которым открыта форма.</param>
    /// <param name="basis">Свежий профиль из службы.</param>
    /// <param name="selected">Адаптер, выбранный в форме.</param>
    public static (Guid? InterfaceGuid, string? Description) MergePinnedAdapter(ConnectionProfile loaded, ConnectionProfile basis, Guid? selected)
    {
        ArgumentNullException.ThrowIfNull(loaded);
        ArgumentNullException.ThrowIfNull(basis);
        var unchanged = selected is null || selected == loaded.PinnedInterfaceGuid;
        var guid = unchanged && basis.PinnedInterfaceGuid is not null ? basis.PinnedInterfaceGuid : selected;
        return (guid, guid is not null && guid == basis.PinnedInterfaceGuid ? basis.PinnedAdapterDescription : null);
    }

    /// <summary>
    /// Участники групп — только включённые подключения; пустые группы удаляются; цели на выключенные
    /// или удалённые подключения и группы возвращаются на прямой выход, сети шлюза AnyConnect — в свой туннель.
    /// </summary>
    public static AppSettings Retarget(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var withGroups = settings with
        {
            Groups = settings.Groups
                .Select(g => g with { Members = g.Members.Where(m => settings.Profile(m) is { Role: not ProfileRole.Off }).ToList() })
                .Where(g => g.Members.Count > 0)
                .ToList(),
        };
        return withGroups with
        {
            DefaultTarget = Usable(withGroups, withGroups.DefaultTarget),
            GeoTarget = Usable(withGroups, withGroups.GeoTarget),
            BypassTarget = withGroups.BypassTarget is { } bypass ? Usable(withGroups, bypass) : null,
            RoutingFolders = withGroups.RoutingFolders.Select(f => f with { Target = Usable(withGroups, f.Target) }).ToList(),
            Rules = withGroups.Rules.Select(r => r with { Target = Usable(withGroups, r.Target) }).ToList(),
            DomainRules = withGroups.DomainRules.Select(r => r with { Target = Usable(withGroups, r.Target) }).ToList(),
            Profiles = withGroups.Profiles.Select(p => WithUsableServerNetworks(withGroups, p)).ToList(),
        };
    }

    /// <summary>
    /// Сети шлюза AnyConnect, направленные в выключенное или удалённое подключение, возвращаются в свой туннель
    /// (null): это значение по умолчанию, и сети шлюза при этом не уходят мимо VPN.
    /// </summary>
    private static ConnectionProfile WithUsableServerNetworks(AppSettings settings, ConnectionProfile profile)
    {
        return profile.AnyConnect.ServerNetworksTarget is { } target && Usable(settings, target) != target
            ? profile with { AnyConnect = profile.AnyConnect with { ServerNetworksTarget = null } }
            : profile;
    }

    private static ConnectionProfile Demoted(ConnectionProfile other, ConnectionProfile saved) =>
        saved.Role == ProfileRole.Primary && other.Role == ProfileRole.Primary ? other with { Role = ProfileRole.Secondary } : other;

    private static RouteTarget Usable(AppSettings settings, RouteTarget target)
    {
        if (target.IsTunnel(out var tunnel))
        {
            return settings.Profile(tunnel) is { Role: not ProfileRole.Off } ? target : RouteTarget.Direct;
        }

        if (target.IsGroup(out var group))
        {
            return settings.Group(group) is null ? RouteTarget.Direct : target;
        }

        return target;
    }
}
