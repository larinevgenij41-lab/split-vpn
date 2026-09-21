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
        if (profile.Role == ProfileRole.Primary && before?.Role != ProfileRole.Primary && !updated.DefaultTarget.IsVpn)
        {
            updated = updated with { DefaultTarget = RouteTarget.Tunnel(profile.Id) };
        }

        return Retarget(updated);
    }

    public static AppSettings RemoveProfile(AppSettings fresh, Guid profileId)
    {
        ArgumentNullException.ThrowIfNull(fresh);
        return Retarget(fresh with { Profiles = fresh.Profiles.Where(p => p.Id != profileId).ToList() });
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
        var names = existingNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var result = new List<ConnectionProfile>();
        foreach (var profile in imported.OfType<ConnectionProfile>())
        {
            var name = UniqueName(names, string.IsNullOrWhiteSpace(profile.Name) ? "Импортированное подключение" : profile.Name.Trim());
            names.Add(name);
            result.Add(profile with
            {
                Id = Guid.NewGuid(),
                Name = name,
                Role = ProfileRole.Off,
                PrimaryAdapter = AdapterSelection.Auto,
                PinnedInterfaceGuid = null,
                AllowFallbackWhenPinnedMissing = false,
                Retry = new RetrySettings(),
            });
        }

        return result;
    }

    /// <summary>Название, не совпадающее с занятыми: «Имя», «Имя 2», «Имя 3»…</summary>
    public static string UniqueName(IReadOnlySet<string> taken, string name)
    {
        ArgumentNullException.ThrowIfNull(taken);
        var candidate = name;
        for (var i = 2; taken.Contains(candidate); i++)
        {
            candidate = $"{name} {i}";
        }

        return candidate;
    }

    /// <summary>
    /// Что после изменения уходит мимо VPN: места назначения («Остальной интернет», подсеть, домен), у которых
    /// цель была туннелем или группой, а стала прямым выходом. Нужно, чтобы предупредить до сохранения.
    /// </summary>
    public static IReadOnlyList<string> NewlyDirect(AppSettings before, AppSettings after)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);
        var old = before.AllTargets;
        var next = after.AllTargets;
        var result = new List<string>();
        for (var i = 0; i < Math.Min(old.Count, next.Count); i++)
        {
            if (old[i].Target.IsVpn && next[i].Target.Kind == TargetKind.Direct)
            {
                result.Add(next[i].Where);
            }
        }

        return result;
    }

    /// <summary>
    /// Сохранённый пароль привязан к серверу, протоколу, способу входа и учётной записи: после их смены служба
    /// не должна сама отдавать прежний пароль новому серверу (MS-CHAPv2 позволяет перебрать NT-хэш).
    /// </summary>
    public static bool PasswordBindingChanged(ConnectionProfile before, ConnectionProfile after)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);
        return PreSharedKeyBindingChanged(before, after)
            || before.AuthMethod != after.AuthMethod
            || !SameText(before.UserName, after.UserName)
            || !SameText(before.Domain, after.Domain);
    }

    /// <summary>Общий ключ IPsec привязан к серверу и протоколу.</summary>
    public static bool PreSharedKeyBindingChanged(ConnectionProfile before, ConnectionProfile after)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);
        return !SameText(before.Server, after.Server) || before.Protocol != after.Protocol;
    }

    private static bool SameText(string? a, string? b) => string.Equals((a ?? "").Trim(), (b ?? "").Trim(), StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Участники групп — только включённые подключения; пустые группы удаляются; цели на выключенные
    /// или удалённые подключения и группы возвращаются на прямой выход.
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
            Rules = withGroups.Rules.Select(r => r with { Target = Usable(withGroups, r.Target) }).ToList(),
            DomainRules = withGroups.DomainRules.Select(r => r with { Target = Usable(withGroups, r.Target) }).ToList(),
        };
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
