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
/// Исходные цели и группы запоминаются в разделе <see cref="BlockedTargetsKey"/> настроек и при записи файла
/// возвращаются туда, где пользователь их не менял (см. <see cref="Restore"/>). Всё изменённое перечисляется
/// в предупреждении загрузки.
/// <para>
/// Служебным разделам служба доверяет, только если они пришли из её собственного файла настроек
/// (<see cref="KeepOnlyTrusted"/>): иначе клиент канала управления или чужой файл импорта записали бы в файл
/// непроверенные роль, протокол или способ входа.
/// </para>
/// </summary>
public static class UnknownSettingValues
{
    /// <summary>Раздел подключения с исходными значениями полей, которых эта версия не знает.</summary>
    public const string PreservedKey = "preservedUnknownValues";

    /// <summary>
    /// Раздел настроек с исходными целями и группами, изменёнными обезвреживанием (<see cref="BlockTargetsOfDisabled"/>).
    /// </summary>
    public const string BlockedTargetsKey = "preservedBlockedTargets";

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
    /// Есть служебный раздел (в любом регистре имени) у настроек или подключений: запись файла должна пройти через
    /// <see cref="Restore"/>, который вернёт сохранённое и уберёт сами разделы.
    /// </summary>
    public static bool HasServiceSections(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return HasKey(settings.Extra, BlockedTargetsKey) || settings.Profiles?.Any(p => HasKey(p?.Extra, PreservedKey)) == true;
    }

    /// <summary>
    /// Служебные разделы входящих настроек (запрос клиента канала управления) принимаются, только если они
    /// побайтно (в каноническом JSON) равны разделам, которые служба сама прочитала из своего файла настроек:
    /// раздел подключения — разделу подключения с тем же идентификатором в <paramref name="current"/>, раздел
    /// настроек — разделу настроек. Иначе раздел снимается: подключение без него проходит полную проверку, а при
    /// записи файла ничего не возвращается. Вызывается службой до проверки настроек.
    /// </summary>
    public static AppSettings KeepOnlyTrusted(AppSettings incoming, AppSettings current)
    {
        ArgumentNullException.ThrowIfNull(incoming);
        ArgumentNullException.ThrowIfNull(current);
        var changed = false;
        var profiles = new List<ConnectionProfile>(incoming.Profiles.Count);
        foreach (var profile in incoming.Profiles)
        {
            var own = current.Profiles.FirstOrDefault(p => p.Id == profile.Id)?.Extra;
            var extra = Trusted(profile.Extra, own, PreservedKey);
            changed |= !ReferenceEquals(extra, profile.Extra);
            profiles.Add(ReferenceEquals(extra, profile.Extra) ? profile : profile with { Extra = extra });
        }

        var settingsExtra = Trusted(incoming.Extra, current.Extra, BlockedTargetsKey);
        return !changed && ReferenceEquals(settingsExtra, incoming.Extra)
            ? incoming
            : incoming with { Profiles = profiles, Extra = settingsExtra };
    }

    /// <summary>
    /// Подключение без служебного раздела — для файла экспорта и импорта: раздел из чужого файла не должен
    /// попасть в настройки, а в файл экспорта он не нужен (подключение экспортируется таким, каким его видит эта версия).
    /// </summary>
    public static ConnectionProfile WithoutPreserved(ConnectionProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var extra = Trusted(profile.Extra, null, PreservedKey);
        return ReferenceEquals(extra, profile.Extra) ? profile : profile with { Extra = extra };
    }

    private static bool HasKey(IDictionary<string, JsonElement>? extra, string key) =>
        extra?.Keys.Any(k => string.Equals(k, key, StringComparison.OrdinalIgnoreCase)) == true;

    /// <summary>
    /// Неизвестные поля без служебного раздела <paramref name="key"/> (в любом регистре имени), кроме раздела,
    /// равного доверенному из <paramref name="own"/>. Ничего не снято — тот же словарь.
    /// </summary>
    private static IDictionary<string, JsonElement>? Trusted(IDictionary<string, JsonElement>? incoming, IDictionary<string, JsonElement>? own, string key)
    {
        if (incoming is null || !HasKey(incoming, key))
        {
            return incoming;
        }

        var result = new Dictionary<string, JsonElement>(incoming, StringComparer.Ordinal);
        foreach (var name in incoming.Keys.Where(k => string.Equals(k, key, StringComparison.OrdinalIgnoreCase)).ToList())
        {
            var trusted = name == key && own is not null && own.TryGetValue(key, out var ownValue)
                && Canonical(ownValue) is { } expected && Canonical(incoming[name]) is { } actual && expected.AsSpan().SequenceEqual(actual);
            if (!trusted)
            {
                result.Remove(name);
            }
        }

        return result.Count == incoming.Count ? incoming : result.Count == 0 ? null : result;
    }

    /// <summary>Канонический JSON значения: без пробелов, строки в одном виде экранирования; null — значения нет.</summary>
    private static byte[]? Canonical(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Undefined)
        {
            return null;
        }

        var buffer = new System.Buffers.ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            element.WriteTo(writer);
        }

        return buffer.WrittenSpan.ToArray();
    }

    /// <summary>
    /// Обезвреживает неизвестные значения в дереве файла настроек (см. описание класса). Возвращает, что изменено, —
    /// по строке на запись; пустой список, если ничего.
    /// </summary>
    public static List<string> Sanitize(JsonObject root)
    {
        ArgumentNullException.ThrowIfNull(root);
        var notes = new List<string>();
        // Раздел исходных целей файл не содержит (его убирает Restore); оказавшийся там вручную не читается:
        // его заново составляет BlockTargetsOfDisabled по тому, что обезврежено сейчас.
        Take(root, BlockedTargetsKey);
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
    /// Исходные цели и группы запоминаются в разделе <see cref="BlockedTargetsKey"/> (см. <see cref="Restore"/>).
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
        var changedGroups = new JsonArray();
        foreach (var group in settings.Groups)
        {
            var members = group.Members.Where(m => !disabled.Contains(m)).ToList();
            if (members.Count == group.Members.Count)
            {
                groups.Add(group);
                continue;
            }

            var entry = new JsonObject { ["group"] = JsonSerializer.SerializeToNode(group, JsonDefaults.Options) };
            if (members.Count == 0)
            {
                emptied.Add(group.Id);
            }
            else
            {
                entry["kept"] = JsonSerializer.SerializeToNode(members, JsonDefaults.Options);
                groups.Add(group with { Members = members });
            }

            changedGroups.Add(entry);
        }

        var blocked = new List<string>();
        var changedTargets = new JsonArray();
        RouteTarget Usable(RouteTarget target, string where, Func<JsonObject> slot)
        {
            if ((target.IsTunnel(out var tunnel) && disabled.Contains(tunnel)) || (target.IsGroup(out var group) && emptied.Contains(group)))
            {
                blocked.Add(where);
                var entry = slot();
                entry["target"] = JsonSerializer.SerializeToNode(target, JsonDefaults.Options);
                changedTargets.Add(entry);
                return RouteTarget.Blocked;
            }

            return target;
        }

        static JsonObject At(string where, object? id = null, int? index = null, string? key = null)
        {
            var slot = new JsonObject { ["where"] = where };
            if (id is not null)
            {
                slot["id"] = id.ToString();
            }

            if (index is { } position)
            {
                slot["index"] = position;
                slot["key"] = key;
            }

            return slot;
        }

        var result = settings with
        {
            Groups = groups,
            DefaultTarget = Usable(settings.DefaultTarget, "«Остальной интернет»", () => At("defaultTarget")),
            GeoTarget = Usable(settings.GeoTarget, "«Россия (RU-база)»", () => At("geoTarget")),
            BypassTarget = settings.BypassTarget is { } bypass ? Usable(bypass, "«Обход блокировок»", () => At("bypassTarget")) : null,
            RoutingFolders = settings.RoutingFolders.Select(f => f with { Target = Usable(f.Target, Text($"папка «{f.Name}»"), () => At("routingFolders", f.Id)) }).ToList(),
            Rules = settings.Rules.Select((r, i) => r with { Target = Usable(r.Target, "подсеть " + r.Cidr, () => At("rules", null, i, r.Cidr)) }).ToList(),
            DomainRules = settings.DomainRules.Select((r, i) => r with { Target = Usable(r.Target, "домен " + r.Suffix, () => At("domainRules", null, i, r.Suffix)) }).ToList(),
            Profiles = settings.Profiles.Select(p => p.AnyConnect.ServerNetworksTarget is { } networks
                ? p with { AnyConnect = p.AnyConnect with { ServerNetworksTarget = Usable(networks, Text($"сети шлюза «{p.Name}»"), () => At("profiles", p.Id)) } }
                : p).ToList(),
        };

        if (changedTargets.Count > 0 || changedGroups.Count > 0)
        {
            var extra = settings.Extra is null ? new Dictionary<string, JsonElement>(StringComparer.Ordinal) : new Dictionary<string, JsonElement>(settings.Extra, StringComparer.Ordinal);
            extra[BlockedTargetsKey] = JsonSerializer.SerializeToElement(new JsonObject { ["targets"] = changedTargets, ["groups"] = changedGroups }, JsonDefaults.Options);
            result = result with { Extra = extra };
        }

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
    /// Возвращает сохранённые значения подключений на их места в дереве записываемого файла и убирает служебные
    /// разделы <see cref="PreservedKey"/> и <see cref="BlockedTargetsKey"/> — всегда, чем бы они ни были.
    /// Возвращаются только поля из списка <see cref="ProfileFields"/> и только простые значения (имя или число):
    /// объект или массив на месте роли или протокола этой версией не прочитался бы вовсе. Затем цели и группы,
    /// изменённые обезвреживанием, возвращаются туда, где значение всё ещё подставленное (блокировка, урезанный
    /// список участников), если подключения, на которые они указывают, по-прежнему несут сохранённые значения.
    /// Служба доверяет разделам только из своего файла (<see cref="KeepOnlyTrusted"/>).
    /// </summary>
    public static void Restore(JsonObject root)
    {
        ArgumentNullException.ThrowIfNull(root);
        var section = Take(root, BlockedTargetsKey) as JsonObject;
        var disabled = new HashSet<Guid>();
        foreach (var profile in Objects(root, "profiles"))
        {
            if (Take(profile, PreservedKey) is not JsonObject preserved)
            {
                continue;
            }

            if (IdOf(profile) is { } id)
            {
                disabled.Add(id);
            }

            foreach (var (key, value) in preserved.ToList())
            {
                if (ProfileFields.FirstOrDefault(f => string.Equals(f.Name, key, StringComparison.OrdinalIgnoreCase)).Name is { } name && IsPlainValue(value))
                {
                    if (Find(profile, name) is { } existing)
                    {
                        profile.Remove(existing);
                    }

                    profile[name] = value!.DeepClone();
                }
            }
        }

        if (section is not null && disabled.Count > 0)
        {
            RestoreTargets(root, section, disabled);
        }
    }

    /// <summary>Имя значения перечисления (буквы, цифры, «_») или число; не объект, не массив, не пусто.</summary>
    private static bool IsPlainValue(JsonNode? node)
    {
        if (node is not JsonValue value)
        {
            return false;
        }

        return value.GetValueKind() switch
        {
            JsonValueKind.Number => true,
            JsonValueKind.String => value.TryGetValue<string>(out var text) && text.Length is > 0 and <= 64
                && text.All(c => char.IsAsciiLetterOrDigit(c) || c == '_'),
            _ => false,
        };
    }

    /// <summary>Возвращает исходные группы и цели из раздела <see cref="BlockedTargetsKey"/> (см. <see cref="Restore"/>).</summary>
    private static void RestoreTargets(JsonObject root, JsonObject section, HashSet<Guid> disabled)
    {
        var restoredGroups = new HashSet<Guid>();
        var groups = Get(root, "groups") as JsonArray;
        foreach (var entry in Objects(section, "groups"))
        {
            if (Get(entry, "group") is not JsonObject original || IdOf(original) is not { } id
                || Ids(Get(original, "members")) is not { } members)
            {
                continue;
            }

            var keptNode = Get(entry, "kept");
            var kept = keptNode is null ? [] : Ids(keptNode);
            // Вернуть можно, только если все убранные участники — по-прежнему подключения с сохранёнными значениями.
            if (kept is null || members.Except(kept).Any(m => !disabled.Contains(m)))
            {
                continue;
            }

            var current = groups?.OfType<JsonObject>().FirstOrDefault(g => IdOf(g) == id);
            if (keptNode is null)
            {
                // Группа была убрана целиком: возвращается, если такой группы с тех пор не появилось.
                if (current is null)
                {
                    if (groups is null)
                    {
                        groups = [];
                        root["groups"] = groups;
                    }

                    groups.Add(original.DeepClone());
                    restoredGroups.Add(id);
                }
            }
            else if (current is not null && Find(current, "members") is { } field && Ids(current[field]) is { } now && now.SequenceEqual(kept))
            {
                current[field] = Get(original, "members")!.DeepClone();
            }
        }

        var used = new HashSet<JsonNode>(ReferenceEqualityComparer.Instance);
        foreach (var entry in Objects(section, "targets"))
        {
            if (Get(entry, "target") is not JsonObject original || ReadTarget(original) is not { } target
                || !((target.IsTunnel(out var tunnel) && disabled.Contains(tunnel)) || (target.IsGroup(out var group) && restoredGroups.Contains(group)))
                || Slot(root, entry, used) is not { } slot)
            {
                continue;
            }

            slot.Parent[slot.Field] = original.DeepClone();
        }
    }

    /// <summary>
    /// Место цели из записи раздела, если там всё ещё подставленная блокировка: объект и имя поля. Правило ищется
    /// по номеру и адресу (или суффиксу), а если на этом месте другое — первое ещё не возвращённое с тем же адресом.
    /// </summary>
    private static (JsonObject Parent, string Field)? Slot(JsonObject root, JsonObject entry, HashSet<JsonNode> used)
    {
        var where = Get(entry, "where") is JsonValue w && w.TryGetValue<string>(out var text) ? text : "";
        (JsonObject, string)? Blocked(JsonObject? parent, string name) =>
            parent is not null && Find(parent, name) is { } field && ReadTarget(parent[field]) == RouteTarget.Blocked ? (parent, field) : null;

        switch (where)
        {
            case "defaultTarget" or "geoTarget" or "bypassTarget":
                return Blocked(root, where);
            case "routingFolders":
                return Blocked(Objects(root, where).FirstOrDefault(f => IdOf(f) is { } id && id == IdOf(entry)), "target");
            case "profiles":
                var profile = Objects(root, where).FirstOrDefault(p => IdOf(p) is { } id && id == IdOf(entry));
                return Blocked(profile is null ? null : Get(profile, "anyConnect") as JsonObject, "serverNetworksTarget");
            case "rules" or "domainRules":
            {
                var keyName = where == "rules" ? "cidr" : "suffix";
                var key = Get(entry, "key") is JsonValue k && k.TryGetValue<string>(out var keyText) ? keyText : null;
                var index = Get(entry, "index") is JsonValue i && i.TryGetValue<int>(out var position) ? position : -1;
                var items = Objects(root, where).ToList();
                bool Matches(JsonObject item) => !used.Contains(item) && key is not null
                    && Get(item, keyName) is JsonValue v && v.TryGetValue<string>(out var itemKey) && itemKey == key
                    && Blocked(item, "target") is not null;
                var item = index >= 0 && index < items.Count && Matches(items[index]) ? items[index] : items.FirstOrDefault(Matches);
                if (item is null)
                {
                    return null;
                }

                used.Add(item);
                return Blocked(item, "target");
            }

            default:
                return null;
        }
    }

    private static RouteTarget? ReadTarget(JsonNode? node)
    {
        if (node is not JsonObject)
        {
            return null;
        }

        try
        {
            return node.Deserialize<RouteTarget>(JsonDefaults.Options);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static Guid? IdOf(JsonObject item) =>
        Get(item, "id") is JsonValue value && value.TryGetValue<string>(out var text) && Guid.TryParse(text, out var id) ? id : null;

    /// <summary>Список идентификаторов; null — не список или в нём не идентификатор.</summary>
    private static List<Guid>? Ids(JsonNode? node)
    {
        if (node is not JsonArray array)
        {
            return null;
        }

        var ids = new List<Guid>();
        foreach (var item in array)
        {
            if (item is not JsonValue value || !value.TryGetValue<string>(out var text) || !Guid.TryParse(text, out var id))
            {
                return null;
            }

            ids.Add(id);
        }

        return ids;
    }

    /// <summary>Убирает поле (в любом регистре имени) и возвращает значение того, что записано точно этим именем.</summary>
    private static JsonNode? Take(JsonObject parent, string field)
    {
        JsonNode? exact = null;
        foreach (var key in parent.Select(p => p.Key).Where(k => string.Equals(k, field, StringComparison.OrdinalIgnoreCase)).ToList())
        {
            if (key == field)
            {
                exact = parent[key];
            }

            parent.Remove(key);
        }

        return exact;
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
