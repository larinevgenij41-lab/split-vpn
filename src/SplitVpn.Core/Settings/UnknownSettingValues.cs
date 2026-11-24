using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using SplitVpn.Core.Policy;

namespace SplitVpn.Core.Settings;

/// <summary>
/// Значения перечислений, которых эта версия не знает: файл настроек записан более новой версией программы
/// (откат после обновления) или исправлен вручную. Без обработки разбор такого значения бросает исключение,
/// весь файл считается нечитаемым, а первое же сохранение стирает все подключения и правила.
/// <para>
/// Схема. Перед разбором файла неизвестные значения обезвреживаются прямо в дереве JSON:
/// </para>
/// <list type="bullet">
/// <item>подключение с неизвестным протоколом, ролью, способом входа, проверкой IPsec или выбором адаптера
/// загружается выключенным (роль «Выключено»), неизвестное поле убирается (действует значение по умолчанию).
/// Исходные значения этих полей и исходная роль переносятся в раздел <see cref="PreservedKey"/> его
/// <see cref="ConnectionProfile.Extra"/>. Это отдельный ключ, а не исходные имена полей: в
/// <see cref="ConnectionProfile.Extra"/> попадают только поля, которых модель не знает, и запись «protocol» там
/// повторила бы известное поле дважды — такой JSON не разбирается ни этой версией, ни приложением по каналу
/// управления. При записи файла (<see cref="SettingsSerializer.Serialize"/>) сохранённые значения
/// возвращаются на свои места поверх подставленных, а сам раздел убирается: новая версия программы
/// читает подключение таким, каким его записала. По каналу управления раздел идёт как есть и возвращается
/// обратно при сохранении. Пока раздел есть, подключение остаётся выключенным: этих параметров эта версия
/// не понимает (см. проверку в <see cref="SettingsValidator"/>);</item>
/// <item>цель маршрутизации неизвестного вида становится блокировкой — ничего не уходит мимо VPN;</item>
/// <item>прочие неизвестные значения (режим защиты при обрыве, источник базы, способ распределения группы,
/// приоритет) заменяются значениями по умолчанию.</item>
/// </list>
/// Цели, направленные в выключенные так подключения (и в группы, где других участников не осталось),
/// блокируются: выключенное подключение служба не поднимает, а сохранение с такими целями отклонялось бы.
/// Всё изменённое перечисляется в предупреждении загрузки.
/// </summary>
public static class UnknownSettingValues
{
    /// <summary>Раздел подключения с исходными значениями полей, которых эта версия не знает.</summary>
    public const string PreservedKey = "preservedUnknownValues";

    private const string Role = "role";

    /// <summary>Поля подключения, неизвестное значение которых выключает подключение, и их JSON-имена.</summary>
    private static readonly (string Name, Func<JsonNode?, bool> IsKnown)[] ProfileFields =
    [
        ("protocol", IsKnownValue<VpnProtocol>),
        (Role, IsKnownValue<ProfileRole>),
        ("authMethod", IsKnownValue<AuthMethod>),
        ("ipsecAuthentication", IsKnownValue<IpsecAuthentication>),
        ("primaryAdapter", IsKnownValue<AdapterSelection>),
    ];

    /// <summary>Подключение несёт значения, которых эта версия не знает: включить его нельзя.</summary>
    public static bool HasPreservedValues(ConnectionProfile? profile) => profile?.Extra?.ContainsKey(PreservedKey) == true;

    /// <summary>
    /// Обезвреживает неизвестные значения в дереве файла настроек (см. описание класса). Возвращает, что изменено, —
    /// по строке на запись; пустой список, если ничего.
    /// </summary>
    public static List<string> Sanitize(JsonObject root)
    {
        ArgumentNullException.ThrowIfNull(root);
        var notes = new List<string>();
        ResetUnknown<OutageMode>(root, "outageMode", "режим защиты при обрыве VPN", notes);
        SanitizeTarget(root, "defaultTarget", "«Остальной интернет»", notes);
        SanitizeTarget(root, "geoTarget", "«Россия (RU-база)»", notes);
        SanitizeTarget(root, "bypassTarget", "«Обход блокировок»", notes);
        foreach (var (key, title) in new[] { ("geoUpdate", "источник RU-базы"), ("bypassUpdate", "источник списка обхода блокировок") })
        {
            if (Get(root, key) is JsonObject geo)
            {
                ResetUnknown<GeoSourceKind>(geo, "source", title, notes);
            }
        }

        foreach (var group in Objects(root, "groups"))
        {
            ResetUnknown<BalanceMode>(group, "mode", Text($"способ распределения группы «{Name(group, "name")}»"), notes);
        }

        foreach (var (key, kind, field) in new[] { ("routingFolders", "папки", "name"), ("rules", "подсети", "cidr"), ("domainRules", "домена", "suffix") })
        {
            foreach (var item in Objects(root, key))
            {
                var where = Text($"{kind} «{Name(item, field)}»");
                ResetUnknown<RoutePriority>(item, "priority", "приоритет " + where, notes);
                SanitizeTarget(item, "target", where, notes);
            }
        }

        foreach (var profile in Objects(root, "profiles"))
        {
            SanitizeProfile(profile, notes);
        }

        return notes;
    }

    /// <summary>
    /// Цели, направленные в подключения с сохранёнными неизвестными значениями, блокируются; такие подключения
    /// убираются из групп, а опустевшие из-за этого группы — из настроек (цели на них тоже блокируются).
    /// </summary>
    public static AppSettings BlockTargetsOfDisabled(AppSettings settings, List<string> notes)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(notes);
        var disabled = settings.Profiles.Where(HasPreservedValues).Select(p => p.Id).ToHashSet();
        if (disabled.Count == 0)
        {
            return settings;
        }

        var emptied = new HashSet<Guid>();
        var groups = new List<TunnelGroupSetting>();
        foreach (var group in settings.Groups)
        {
            var members = group.Members.Where(m => !disabled.Contains(m)).ToList();
            if (members.Count == group.Members.Count)
            {
                groups.Add(group);
            }
            else if (members.Count == 0)
            {
                emptied.Add(group.Id);
            }
            else
            {
                groups.Add(group with { Members = members });
            }
        }

        var blocked = new List<string>();
        RouteTarget Usable(RouteTarget target, string where)
        {
            if ((target.IsTunnel(out var tunnel) && disabled.Contains(tunnel)) || (target.IsGroup(out var group) && emptied.Contains(group)))
            {
                blocked.Add(where);
                return RouteTarget.Blocked;
            }

            return target;
        }

        var result = settings with
        {
            Groups = groups,
            DefaultTarget = Usable(settings.DefaultTarget, "«Остальной интернет»"),
            GeoTarget = Usable(settings.GeoTarget, "«Россия (RU-база)»"),
            BypassTarget = settings.BypassTarget is { } bypass ? Usable(bypass, "«Обход блокировок»") : null,
            RoutingFolders = settings.RoutingFolders.Select(f => f with { Target = Usable(f.Target, Text($"папка «{f.Name}»")) }).ToList(),
            Rules = settings.Rules.Select(r => r with { Target = Usable(r.Target, "подсеть " + r.Cidr) }).ToList(),
            DomainRules = settings.DomainRules.Select(r => r with { Target = Usable(r.Target, "домен " + r.Suffix) }).ToList(),
            Profiles = settings.Profiles.Select(p => p.AnyConnect.ServerNetworksTarget is { } networks
                ? p with { AnyConnect = p.AnyConnect with { ServerNetworksTarget = Usable(networks, Text($"сети шлюза «{p.Name}»")) } }
                : p).ToList(),
        };

        if (emptied.Count > 0)
        {
            notes.Add(Text($"группы подключений «{string.Join("», «", settings.Groups.Where(g => emptied.Contains(g.Id)).Select(g => g.Name))}» остались без участников и убраны"));
        }

        if (blocked.Count > 0)
        {
            const int Shown = 10;
            var list = string.Join(", ", blocked.Take(Shown)) + (blocked.Count > Shown ? Text($" и ещё {blocked.Count - Shown}") : "");
            notes.Add("направленное в выключенные подключения теперь блокируется: " + list);
        }

        return result;
    }

    /// <summary>
    /// Возвращает сохранённые значения подключений на их места в дереве записываемого файла и убирает раздел
    /// <see cref="PreservedKey"/>. Возвращаются только поля из списка <see cref="ProfileFields"/>.
    /// </summary>
    public static void Restore(JsonObject root)
    {
        ArgumentNullException.ThrowIfNull(root);
        foreach (var profile in Objects(root, "profiles"))
        {
            if (profile[PreservedKey] is not JsonObject preserved)
            {
                continue;
            }

            profile.Remove(PreservedKey);
            foreach (var (key, value) in preserved.ToList())
            {
                if (ProfileFields.FirstOrDefault(f => string.Equals(f.Name, key, StringComparison.OrdinalIgnoreCase)).Name is { } name)
                {
                    profile[name] = value?.DeepClone();
                }
            }
        }
    }

    private static void SanitizeProfile(JsonObject profile, List<string> notes)
    {
        var unknown = new List<string>();
        foreach (var (name, isKnown) in ProfileFields)
        {
            if (Find(profile, name) is { } key && !isKnown(profile[key]))
            {
                unknown.Add(Text($"{name} {Describe(profile[key])}"));
            }
        }

        if (unknown.Count == 0)
        {
            return;
        }

        if (profile[PreservedKey] is not JsonObject preserved)
        {
            preserved = new JsonObject();
            profile[PreservedKey] = preserved;
        }

        foreach (var (name, isKnown) in ProfileFields)
        {
            if (Find(profile, name) is not { } key)
            {
                continue;
            }

            var value = profile[key];
            if (name == Role || !isKnown(value))
            {
                // Исходная роль тоже сохраняется: новая версия получит подключение таким, каким его записала.
                preserved[name] = value?.DeepClone();
                profile.Remove(key);
            }
        }

        profile[Role] = nameof(ProfileRole.Off);
        notes.Add(Text($"подключение «{Name(profile, "name")}» ({string.Join(", ", unknown)}) выключено, исходные значения сохранятся в файле"));
    }

    /// <summary>Неизвестная цель становится блокировкой; цель без поля «kind» или пустая (null) не меняется.</summary>
    private static void SanitizeTarget(JsonObject parent, string field, string where, List<string> notes)
    {
        if (Find(parent, field) is not { } key || parent[key] is not JsonObject target || Find(target, "kind") is not { } kind
            || IsReadable<TargetKind>(target[kind]))
        {
            return;
        }

        notes.Add(Text($"для {where} задана неизвестная цель {Describe(target[kind])}, трафик блокируется"));
        parent[key] = new JsonObject { ["kind"] = nameof(TargetKind.Block) };
    }

    /// <summary>Неизвестное значение убирается: при разборе действует значение этого поля по умолчанию.</summary>
    private static void ResetUnknown<T>(JsonObject parent, string field, string title, List<string> notes)
        where T : struct, Enum
    {
        if (Find(parent, field) is { } key && !IsReadable<T>(parent[key]))
        {
            notes.Add(Text($"{title} {Describe(parent[key])} заменён значением по умолчанию"));
            parent.Remove(key);
        }
    }

    /// <summary>
    /// Значение разбирается конвертером перечислений: известное имя или число. Неопределённое число здесь
    /// допускается — его заменяет <see cref="SettingsValidator.RepairOnLoad"/> или отклоняет проверка при сохранении.
    /// </summary>
    private static bool IsReadable<T>(JsonNode? node)
        where T : struct, Enum
    {
        if (node is null)
        {
            return false;
        }

        try
        {
            node.Deserialize<T>(JsonDefaults.Options);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>Для полей подключения неопределённое число тоже неизвестно: с ним подключение не поднять.</summary>
    private static bool IsKnownValue<T>(JsonNode? node)
        where T : struct, Enum
    {
        if (!IsReadable<T>(node))
        {
            return false;
        }

        return Enum.IsDefined(node!.Deserialize<T>(JsonDefaults.Options));
    }

    /// <summary>Имя поля как оно записано в файле: разбор настроек не различает регистр имён.</summary>
    private static string? Find(JsonObject parent, string field) =>
        parent.ContainsKey(field) ? field
            : parent.Select(p => p.Key).FirstOrDefault(k => string.Equals(k, field, StringComparison.OrdinalIgnoreCase));

    private static JsonNode? Get(JsonObject parent, string field) => Find(parent, field) is { } key ? parent[key] : null;

    private static IEnumerable<JsonObject> Objects(JsonObject parent, string field) =>
        (Get(parent, field) as JsonArray ?? []).OfType<JsonObject>();

    private static string Name(JsonObject item, string field) =>
        Get(item, field) is JsonValue value && value.TryGetValue<string>(out var text) ? Shorten(text) : "без названия";

    /// <summary>Значение для текста предупреждения: «WireGuard», число как есть, пустое — «пусто».</summary>
    private static string Describe(JsonNode? node)
    {
        if (node is null)
        {
            return "«пусто»";
        }

        return "«" + Shorten(node is JsonValue value && value.TryGetValue<string>(out var text) ? text : node.ToJsonString()) + "»";
    }

    private static string Shorten(string text) => text.Length > 40 ? text[..40] + "…" : text;

    private static string Text(FormattableString text) => text.ToString(CultureInfo.InvariantCulture);
}
