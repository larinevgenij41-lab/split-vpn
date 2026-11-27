using System.Globalization;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;

namespace SplitVpn.Core.Settings;

public static class SettingsValidator
{
    private static readonly int[] AllowedIntervals = [1, 3, 7];

    /// <summary>
    /// Предел длины названий подключений, групп и папок. Название повторяется в статусе несколько раз:
    /// без предела допустимые настройки делали бы ответ на запрос статуса больше кадра канала управления.
    /// </summary>
    public const int MaxNameLength = 200;

    /// <summary>Предел числа подключений: состояние со всеми туннелями должно помещаться в кадр канала управления.</summary>
    public const int MaxProfiles = 64;

    /// <summary>Предел числа групп подключений.</summary>
    public const int MaxGroups = 64;

    /// <summary>Предел числа папок правил.</summary>
    public const int MaxRoutingFolders = 512;

    /// <summary>Предел числа правил сетей: с таким списком настройки ещё помещаются в кадр канала управления.</summary>
    public const int MaxRules = 16384;

    /// <summary>Предел числа правил доменов.</summary>
    public const int MaxDomainRules = 8192;

    /// <summary>Предел числа контрольных целей в каждом списке: пробы целей идут одновременно.</summary>
    public const int MaxCheckTargets = 8;

    /// <summary>
    /// Проверяет настройки. Модель приходит из файла или по каналу управления и может быть неполной
    /// («null» вместо списка, строки или раздела), поэтому проверяется её нормализованная копия:
    /// валидатор обязан сообщить об ошибках, а не упасть на неполных данных.
    /// </summary>
    /// <param name="settings">Проверяемые настройки.</param>
    /// <param name="previous">
    /// Уже действующие настройки службы. Проверки, добавленные позже (пределы количества, контрольные цели, правила
    /// на публичных зонах), запрещают только новые и изменённые значения: то же значение, уже сохранённое прежней
    /// версией, — предупреждение, иначе из-за него не сохранялись бы никакие другие изменения. null — всё новое.
    /// </param>
    public static ValidationResult Validate(AppSettings settings, AppSettings? previous = null)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var model = SettingsSerializer.Normalize(settings);
        var before = previous is null ? null : SettingsSerializer.Normalize(previous);
        var errors = new List<string>();
        var warnings = new List<string>();

        if (model.SchemaVersion != AppSettings.CurrentSchemaVersion)
        {
            errors.Add("Версия настроек несовместима: обновите приложение и службу вместе.");
        }

        // JSON принимает число вместо имени значения: неизвестный режим молча работал бы как один из известных,
        // а интерфейс не показывал бы ни одного выбранного.
        if (!Enum.IsDefined(model.OutageMode))
        {
            errors.Add("Неизвестный режим защиты при обрыве VPN.");
        }

        // Слишком длинное название повторилось бы в каждом сообщении ниже: остальные проверки ждут исправления.
        if (!ValidateNameLengths(model, errors))
        {
            return new ValidationResult(errors, warnings);
        }

        ValidateProfiles(model, before, errors, warnings);
        ValidateGroups(model, errors);
        ValidateRoutingFolders(model, errors);
        if (model.RoutingFolders.Any(f => f.Priority == RoutePriority.Inherit || !Enum.IsDefined(f.Priority))
            || model.Rules.Any(r => !Enum.IsDefined(r.Priority)) || model.DomainRules.Any(r => !Enum.IsDefined(r.Priority)))
        {
            errors.Add("Недопустимый приоритет правила или папки.");
        }
        ValidateTargets(model, errors, warnings);
        ValidateAnyConnect(model, errors);
        ValidateSshVpn(model, errors, warnings);
        ValidateDomainRules(model, before, errors, warnings);
        ValidateLocalSuffixes(model, errors, warnings);
        ValidateCounts(model, before, errors, warnings);
        ValidateCheckTargets(model, before, errors, warnings);

        var (rules, ruleErrors) = SettingsSerializer.ParseRules(model.Rules, model.RoutingFolders);
        errors.AddRange(ruleErrors);
        var policy = PolicyValidator.ValidateRules(rules, []);
        errors.AddRange(policy.Errors);
        warnings.AddRange(policy.Warnings);

        if (!AllowedIntervals.Contains(model.GeoUpdate.IntervalDays))
        {
            errors.Add("Интервал обновления базы: допустимо 1, 3 или 7 дней.");
        }

        if (!AllowedIntervals.Contains(model.BypassUpdate.IntervalDays))
        {
            errors.Add("Интервал обновления списка обхода блокировок: допустимо 1, 3 или 7 дней.");
        }

        if (model.BypassAggregatePrefix is < BypassAggregation.MinPrefix or > BypassAggregation.Off)
        {
            errors.Add(Text($"Свёртка списка обхода: длина префикса от {BypassAggregation.MinPrefix} до {BypassAggregation.Off} (32 — без свёртки)."));
        }

        if (!AllowedIntervals.Contains(model.AppUpdate.IntervalDays))
        {
            errors.Add("Интервал проверки обновлений программы: допустимо 1, 3 или 7 дней.");
        }

        foreach (var url in model.AppUpdate.ManifestMirrors.Concat(model.AppUpdate.PackageMirrors).Where(u => !IsHttpsUrl(u)))
        {
            errors.Add(Text($"Адрес источника обновлений программы должен быть HTTPS-ссылкой: «{url}»."));
        }

        ValidateGeoSource(model.GeoUpdate, errors);
        ValidateGeoSource(model.BypassUpdate, errors);
        ValidateAddresses(model, errors);
        return new ValidationResult(errors, warnings);
    }

    /// <summary>
    /// Исправляет при загрузке значения, которые проверка допустила бы только при сохранении, а служба без
    /// исправления не пережила бы: длину свёртки списка обхода (иначе не собирается политика), неверные адреса
    /// зеркал и собственного источника списков (иначе падает плановое обновление), интервалы и режим защиты.
    /// Такие значения приходят из ручной правки файла или от другой версии программы. Каждое заменяется значением
    /// по умолчанию, остальные настройки остаются как есть. Без исправлений возвращается тот же экземпляр.
    /// </summary>
    /// <param name="repairs">Что исправлено - для предупреждения пользователю; пустой, если ничего.</param>
    public static AppSettings RepairOnLoad(AppSettings settings, out IReadOnlyList<string> repairs)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var model = SettingsSerializer.Normalize(settings);
        var found = new List<string>();
        var defaults = new AppSettings();

        var outageMode = model.OutageMode;
        if (!Enum.IsDefined(outageMode))
        {
            outageMode = defaults.OutageMode;
            found.Add("неизвестный режим защиты при обрыве VPN заменён режимом по умолчанию.");
        }

        var prefix = model.BypassAggregatePrefix;
        if (prefix is < BypassAggregation.MinPrefix or > BypassAggregation.Off)
        {
            prefix = BypassAggregation.DefaultPrefix;
            found.Add(Text($"длина префикса свёртки списка обхода {model.BypassAggregatePrefix} вне допустимых {BypassAggregation.MinPrefix}-{BypassAggregation.Off}, задана {BypassAggregation.DefaultPrefix}."));
        }

        var geo = RepairGeoSource(model.GeoUpdate, new GeoUpdateSettings(), "RU-база", found);
        var bypass = RepairGeoSource(model.BypassUpdate, new GeoUpdateSettings { Source = GeoSourceKind.ReFilter }, "список обхода блокировок", found);

        var appUpdate = model.AppUpdate;
        if (!AllowedIntervals.Contains(appUpdate.IntervalDays))
        {
            found.Add(Text($"интервал проверки обновлений программы {appUpdate.IntervalDays} дн. заменён на {defaults.AppUpdate.IntervalDays}."));
            appUpdate = appUpdate with { IntervalDays = defaults.AppUpdate.IntervalDays };
        }

        var manifestMirrors = HttpsOnly(appUpdate.ManifestMirrors, "адрес манифеста обновлений программы", found);
        var packageMirrors = HttpsOnly(appUpdate.PackageMirrors, "адрес установщика обновлений программы", found);
        if (manifestMirrors.Count != appUpdate.ManifestMirrors.Count || packageMirrors.Count != appUpdate.PackageMirrors.Count)
        {
            appUpdate = appUpdate with { ManifestMirrors = manifestMirrors, PackageMirrors = packageMirrors };
        }

        // Неизвестный вид цели (число вместо имени) компилятор политики блокирует, а сохранение отклоняет:
        // цель заменяется блокировкой сразу, чтобы настройки снова сохранялись и ничего не ушло мимо VPN.
        var defaultTarget = KnownTarget(model.DefaultTarget, "«Остальной интернет»", found);
        var geoTarget = KnownTarget(model.GeoTarget, "«Россия (RU-база)»", found);
        RouteTarget? bypassTarget = model.BypassTarget is { } bypassValue ? KnownTarget(bypassValue, "«Обход блокировок»", found) : null;
        var folders = model.RoutingFolders.Select(f => Enum.IsDefined(f.Target.Kind) ? f
            : f with { Target = KnownTarget(f.Target, Text($"папки «{f.Name}»"), found) }).ToList();
        var rules = model.Rules.Select(r => Enum.IsDefined(r.Target.Kind) ? r
            : r with { Target = KnownTarget(r.Target, "подсеть " + r.Cidr, found) }).ToList();
        var domainRules = model.DomainRules.Select(r => Enum.IsDefined(r.Target.Kind) ? r
            : r with { Target = KnownTarget(r.Target, "домен " + r.Suffix, found) }).ToList();
        var profiles = model.Profiles.Select(p => p.AnyConnect.ServerNetworksTarget is not { } networks || Enum.IsDefined(networks.Kind) ? p
            : p with { AnyConnect = p.AnyConnect with { ServerNetworksTarget = KnownTarget(networks, Text($"сети шлюза «{p.Name}»"), found) } }).ToList();

        repairs = found;
        return found.Count == 0 ? settings : model with
        {
            OutageMode = outageMode,
            BypassAggregatePrefix = prefix,
            GeoUpdate = geo,
            BypassUpdate = bypass,
            AppUpdate = appUpdate,
            DefaultTarget = defaultTarget,
            GeoTarget = geoTarget,
            BypassTarget = bypassTarget,
            RoutingFolders = folders,
            Rules = rules,
            DomainRules = domainRules,
            Profiles = profiles,
        };
    }

    /// <summary>Цель известного вида остаётся; неизвестная становится блокировкой, о чём пишется строка в <paramref name="found"/>.</summary>
    private static RouteTarget KnownTarget(RouteTarget target, string where, List<string> found)
    {
        if (Enum.IsDefined(target.Kind))
        {
            return target;
        }

        found.Add(Text($"для {where} задана неизвестная цель, трафик блокируется."));
        return RouteTarget.Blocked;
    }

    private static GeoUpdateSettings RepairGeoSource(GeoUpdateSettings geo, GeoUpdateSettings defaults, string title, List<string> found)
    {
        var model = geo;
        if (!AllowedIntervals.Contains(model.IntervalDays))
        {
            found.Add(Text($"{title}: интервал обновления {model.IntervalDays} дн. заменён на {defaults.IntervalDays}."));
            model = model with { IntervalDays = defaults.IntervalDays };
        }

        if (!Enum.IsDefined(model.Source))
        {
            found.Add(Text($"{title}: неизвестный источник заменён источником по умолчанию."));
            model = model with { Source = defaults.Source };
        }

        var mirrors = HttpsOnly(model.Mirrors, Text($"{title}: адрес зеркала"), found);
        if (mirrors.Count != model.Mirrors.Count)
        {
            model = model with { Mirrors = mirrors };
        }

        if (model.Source == GeoSourceKind.CustomUrl && !IsHttpsUrl(model.CustomUrl ?? ""))
        {
            found.Add(Text($"{title}: адрес собственного источника «{model.CustomUrl}» не HTTPS-ссылка, выбран источник по умолчанию."));
            model = model with { Source = defaults.Source };
        }

        return model;
    }

    /// <summary>Только HTTPS-ссылки; об отброшенных адресах - строка в <paramref name="found"/>.</summary>
    private static List<string> HttpsOnly(IReadOnlyList<string> urls, string what, List<string> found)
    {
        var valid = new List<string>();
        foreach (var url in urls)
        {
            if (IsHttpsUrl(url))
            {
                valid.Add(url);
            }
            else
            {
                found.Add(Text($"{what} «{url}» не HTTPS-ссылка и отброшен."));
            }
        }

        return valid;
    }

    private static bool ValidateNameLengths(AppSettings settings, List<string> errors)
    {
        var count = errors.Count;
        var names = settings.Profiles.Select(p => ("подключения", p.Name))
            .Concat(settings.Groups.Select(g => ("группы", g.Name)))
            .Concat(settings.RoutingFolders.Select(f => ("папки правил", f.Name)));
        foreach (var (kind, name) in names.Where(n => n.Name.Length > MaxNameLength))
        {
            errors.Add(Text($"Название {kind} «{name[..40]}…» длиннее {MaxNameLength} символов: сократите его."));
        }

        return errors.Count == count;
    }

    private static void ValidateProfiles(AppSettings settings, AppSettings? previous, List<string> errors, List<string> warnings)
    {
        foreach (var profile in settings.Profiles)
        {
            // Адрес, уже сохранённый у этого подключения: строже проверенный теперь, он - предупреждение, а не ошибка.
            var serverSaved = previous?.Profiles.Any(p => p.Id == profile.Id && p.Protocol == profile.Protocol
                && string.Equals(p.Server, profile.Server, StringComparison.Ordinal)) == true;
            var looseServer = serverSaved ? warnings : errors;

            if (UnknownSettingValues.HasPreservedValues(profile))
            {
                // Подключение записано более новой версией программы: его протокол, роль или способ входа здесь
                // подставлены вместо неизвестных, проверять подставленное бессмысленно, а поднимать такое подключение
                // нельзя. Остальные поля, которые эта версия понимает, проверяются (название, сервер, имя пользователя,
                // разделы EAP, AnyConnect и SSH там, где их смысл не зависит от подставленного). Раздел, пришедший от
                // клиента канала управления или из файла импорта, служба снимает до проверки
                // (UnknownSettingValues.KeepOnlyTrusted, ConnectionEdits.PrepareImport), и такое подключение
                // проверяется полностью.
                if (profile.Role != ProfileRole.Off)
                {
                    errors.Add(Text($"Подключение «{profile.Name}» записано более новой версией программы, и часть его параметров этой версии неизвестна: включить его можно только в той версии."));
                }

                ValidateProfile(profile, errors, looseServer, UnknownSettingValues.SubstitutedFields(profile));
                continue;
            }

            ValidateProfile(profile, errors, looseServer);
        }

        foreach (var duplicate in settings.Profiles.GroupBy(p => p.Name.Trim(), StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1))
        {
            errors.Add(Text($"Названия подключений должны различаться: «{duplicate.Key}»."));
        }

        // Идентификатор — ключ подключения для целей маршрутизации, групп, паролей и политики: повтор
        // сделал бы часть настроек недоступной, а компилятор политики уронил бы службу.
        foreach (var duplicate in settings.Profiles.GroupBy(p => p.Id).Where(g => g.Count() > 1))
        {
            errors.Add(Text($"Внутренний номер подключения повторяется у «{Names(duplicate.Select(p => p.Name))}»: оставьте одно, остальные создайте заново."));
        }

        // Имя записи телефонной книги и интерфейса AnyConnect берётся из первых 8 знаков номера: при совпадении
        // два подключения делили бы одну запись, и пароль одного ушёл бы на сервер другого.
        foreach (var clash in settings.Profiles.GroupBy(p => p.Id.ToString("N")[..8]).Where(g => g.Select(p => p.Id).Distinct().Count() > 1))
        {
            errors.Add(Text($"Внутренние номера подключений «{Names(clash.Select(p => p.Name))}» совпадают в первых знаках: создайте одно из них заново."));
        }

        if (settings.Profiles.Count(p => p.Role == ProfileRole.Primary) > 1)
        {
            errors.Add("Опорное подключение может быть только одно: остальным задайте роль «Дополнительное».");
        }
    }

    private static void ValidateGroups(AppSettings settings, List<string> errors)
    {
        foreach (var group in settings.Groups)
        {
            if (string.IsNullOrWhiteSpace(group.Name))
            {
                errors.Add("У группы подключений не задано название.");
            }

            if (!Enum.IsDefined(group.Mode))
            {
                errors.Add(Text($"Группа «{group.Name}»: неизвестный способ распределения нагрузки."));
            }

            if (group.Members.Count == 0)
            {
                errors.Add(Text($"В группе «{group.Name}» нет ни одного подключения."));
            }

            if (group.Members.Distinct().Count() != group.Members.Count)
            {
                errors.Add(Text($"В группе «{group.Name}» одно подключение указано дважды."));
            }

            foreach (var member in group.Members.Distinct())
            {
                var profile = settings.Profile(member);
                if (profile is null)
                {
                    errors.Add(Text($"В группе «{group.Name}» указано подключение, которого нет в списке."));
                }
                else if (profile.Role == ProfileRole.Off)
                {
                    errors.Add(Text($"В группе «{group.Name}» участвует выключенное подключение «{profile.Name}»."));
                }
            }
        }

        foreach (var duplicate in settings.Groups.GroupBy(g => g.Name.Trim(), StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1))
        {
            errors.Add(Text($"Названия групп должны различаться: «{duplicate.Key}»."));
        }

        foreach (var duplicate in settings.Groups.GroupBy(g => g.Id).Where(g => g.Count() > 1))
        {
            errors.Add(Text($"Внутренний номер группы повторяется у «{Names(duplicate.Select(g => g.Name))}»: оставьте одну, остальные создайте заново."));
        }

        foreach (var group in settings.Groups.Where(g => settings.Profiles.Any(p => p.Id == g.Id)))
        {
            errors.Add(Text($"Внутренний номер группы \"{group.Name}\" совпадает с номером подключения: создайте группу заново."));
        }
    }

    private static void ValidateRoutingFolders(AppSettings settings, List<string> errors)
    {
        foreach (var folder in settings.RoutingFolders)
        {
            if (string.IsNullOrWhiteSpace(folder.Name))
            {
                errors.Add("У папки правил не задано название.");
            }

            if (!Enum.IsDefined(folder.Target.Kind))
            {
                errors.Add(Text($"Для папки «{folder.Name}» задана неизвестная цель."));
            }
            else if (folder.Target.IsTunnel(out var tunnel) && settings.Profile(tunnel) is not { Role: not ProfileRole.Off })
            {
                errors.Add(Text($"Для папки «{folder.Name}» выбрано подключение, которого нет или оно выключено."));
            }
            else if (folder.Target.IsGroup(out var group) && settings.Group(group) is null)
            {
                errors.Add(Text($"Для папки «{folder.Name}» выбрана группа, которой нет в списке."));
            }
        }

        foreach (var duplicate in settings.RoutingFolders.GroupBy(f => f.Name.Trim(), StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1))
        {
            errors.Add(Text($"Названия папок правил должны различаться: «{duplicate.Key}»."));
        }

        foreach (var duplicate in settings.RoutingFolders.GroupBy(f => f.Id).Where(g => g.Count() > 1))
        {
            errors.Add(Text($"Внутренний номер папки повторяется у «{Names(duplicate.Select(f => f.Name))}»: оставьте одну, остальные создайте заново."));
        }

        var folderIds = settings.RoutingFolders.Select(f => f.Id).ToHashSet();
        foreach (var rule in settings.Rules.Where(r => r.FolderId is { } id && !folderIds.Contains(id)))
        {
            errors.Add(Text($"Подсеть {rule.Cidr} ссылается на папку, которой нет в списке."));
        }

        foreach (var rule in settings.DomainRules.Where(r => r.FolderId is { } id && !folderIds.Contains(id)))
        {
            errors.Add(Text($"Домен «{rule.Suffix}» ссылается на папку, которой нет в списке."));
        }
    }

    /// <summary>Названия для сообщения об ошибке; безымянная запись называется прямо.</summary>
    private static string Names(IEnumerable<string> names) =>
        string.Join("», «", names.Select(n => string.IsNullOrWhiteSpace(n) ? "без названия" : n.Trim()));

    /// <summary>
    /// Цель может указывать только на поднимаемый туннель или существующую группу. Иначе служба
    /// применила бы политику, для которой некуда направить трафик, и осталась бы с включённой
    /// защитой без выхода.
    /// </summary>
    private static void ValidateTargets(AppSettings settings, List<string> errors, List<string> warnings)
    {
        foreach (var (where, target) in settings.AllTargets)
        {
            if (!Enum.IsDefined(target.Kind))
            {
                errors.Add(Text($"Для {where} задана неизвестная цель."));
            }
            else if (target.Kind == TargetKind.Tunnel)
            {
                var profile = settings.Profile(target.Id);
                if (profile is null)
                {
                    errors.Add(Text($"Для {where} выбрано подключение, которого нет в списке."));
                }
                else if (profile.Role == ProfileRole.Off)
                {
                    errors.Add(Text($"Для {where} выбрано подключение «{profile.Name}», которое выключено."));
                }
            }
            else if (target.Kind == TargetKind.Group && settings.Group(target.Id) is null)
            {
                errors.Add(Text($"Для {where} выбрана группа, которой нет в списке."));
            }
        }

        var used = new HashSet<Guid>();
        foreach (var target in settings.AllTargets.Select(t => t.Target))
        {
            if (target.IsTunnel(out var tunnel))
            {
                used.Add(tunnel);
            }
            else if (target.IsGroup(out var group))
            {
                used.UnionWith(settings.Group(group)?.Members ?? []);
            }
        }

        foreach (var idle in settings.ActiveProfiles.Where(p => !used.Contains(p.Id)))
        {
            warnings.Add(Text($"Подключение «{idle.Name}» поднимается, но на него ничего не направлено."));
        }
    }

    /// <summary>
    /// AnyConnect в первой версии — только дополнительное подключение для сетей шлюза: без опорной роли,
    /// групп, «остального интернета» и RU-базы. Сеанс требует входа пользователя, поэтому на нём не должны
    /// держаться защита при обрыве и DNS по умолчанию.
    /// </summary>
    private static void ValidateAnyConnect(AppSettings settings, List<string> errors)
    {
        foreach (var profile in settings.Profiles.Where(p => p.Protocol == VpnProtocol.AnyConnect))
        {
            if (profile.Role == ProfileRole.Primary)
            {
                errors.Add(Text($"Подключение AnyConnect «{profile.Name}» не может быть опорным: задайте роль «Дополнительное»."));
            }

            if (settings.Groups.Any(g => g.Members.Contains(profile.Id)))
            {
                errors.Add(Text($"Подключение AnyConnect «{profile.Name}» не может входить в группу подключений."));
            }

            if (settings.DefaultTarget.IsTunnel(out var defaultTunnel) && defaultTunnel == profile.Id)
            {
                errors.Add(Text($"«Остальной интернет» нельзя направить в подключение AnyConnect «{profile.Name}»."));
            }

            if (settings.GeoTarget.IsTunnel(out var geoTunnel) && geoTunnel == profile.Id)
            {
                errors.Add(Text($"«Россия (RU-база)» нельзя направить в подключение AnyConnect «{profile.Name}»."));
            }

            if (settings.BypassTarget is { } bypass && bypass.IsTunnel(out var bypassTunnel) && bypassTunnel == profile.Id)
            {
                errors.Add(Text($"«Обход блокировок» нельзя направить в подключение AnyConnect «{profile.Name}»."));
            }

            if (profile.AnyConnect.ServerNetworksTarget is { Kind: TargetKind.Group })
            {
                errors.Add(Text($"Сети шлюза «{profile.Name}» нельзя направить в группу подключений."));
            }
        }
    }

    /// <summary>
    /// «VPN поверх SSH» в первой версии: одновременно поднимается одно такое подключение (у движка один адаптер
    /// с постоянным адресом) и оно не входит в группы - распределение по блокам адресов рассчитано на туннели с UDP.
    /// </summary>
    private static void ValidateSshVpn(AppSettings settings, List<string> errors, List<string> warnings)
    {
        if (settings.DefaultTarget.IsTunnel(out var carrier) && settings.Profile(carrier) is { Protocol: VpnProtocol.SshVpn, Role: not ProfileRole.Off } rest)
        {
            warnings.Add(Text($"«Остальной интернет» идёт через «{rest.Name}» (VPN поверх SSH): через него работает только TCP. Звонки, игры и другие программы на UDP работать не будут, пока им не назначен другой путь."));
        }

        var profiles = settings.Profiles.Where(p => p.Protocol == VpnProtocol.SshVpn).ToList();
        if (profiles.Any(p => p.Role != ProfileRole.Off) && settings.UpstreamDns.Count > SshTunnel.SshTunnelDefaults.MaxDnsServers)
        {
            warnings.Add("VPN поверх SSH использует первые четыре DNS-сервера. Остальные адреса для SSH применяться не будут.");
        }

        if (profiles.Count(p => p.Role != ProfileRole.Off) > 1)
        {
            errors.Add("Одновременно можно включить только одно подключение «VPN поверх SSH»: остальные выключите.");
        }

        foreach (var profile in profiles.Where(p => settings.Groups.Any(g => g.Members.Contains(p.Id))))
        {
            errors.Add(Text($"Подключение «VPN поверх SSH» «{profile.Name}» не может входить в группу подключений."));
        }
    }

    private static void ValidateDomainRules(AppSettings settings, AppSettings? previous, List<string> errors, List<string> warnings)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var saved = previous?.DomainRules.Select(r => SettingsSerializer.NormalizeSuffix(r.Suffix)).ToHashSet(StringComparer.Ordinal);
        foreach (var rule in settings.DomainRules)
        {
            var suffix = SettingsSerializer.NormalizeSuffix(rule.Suffix);
            if (!SettingsSerializer.IsValidSuffix(suffix))
            {
                errors.Add(Text($"«{rule.Suffix}»: неверный домен. Укажите имя вида example.org."));
            }
            else if (!SettingsSerializer.IsValidDomainSuffix(suffix))
            {
                errors.Add(Text($"«{rule.Suffix}»: правило нельзя задать для домена верхнего уровня целиком — под него попадёт вся зона «{suffix}». Укажите имя вида example.{suffix}."));
            }
            else if (!seen.Add(suffix))
            {
                errors.Add(Text($"Домен «{suffix}» указан дважды."));
            }
            else if (Dns.PublicSuffixes.IsOpenRegistrationZone(suffix))
            {
                // Под правило попала бы чужая публичная зона целиком, и каждое имя в ней стало бы закреплением адресов.
                // Правило, сохранённое прежней версией, только предупреждает: оно работало и раньше.
                (saved?.Contains(suffix) == true ? warnings : errors).Add(Text(
                    $"«{rule.Suffix}»: «{suffix}» — общедоступная зона, в ней регистрируют чужие домены, и под правило попадут все они. Укажите имя вида example.{suffix}."));
            }
            else if (Dns.PublicSuffixes.IsInstitutionalZone(suffix) && saved?.Contains(suffix) != true)
            {
                // Ведомственная зона («gov.ru», «ac.uk»): сторонние домены в ней не регистрируют, и правило на неё целиком
                // осмысленно («gov.ru → напрямую»). Предупреждение о широте - только для нового правила.
                warnings.Add(Text(
                    $"«{rule.Suffix}»: правило охватывает всю ведомственную зону «{suffix}» — все сайты в ней пойдут по нему."));
            }
        }
    }

    /// <summary>
    /// Локальные DNS-суффиксы — имена вида «lan» или «home.arpa», без адресов и лишних символов. Суффикс, совпадающий
    /// с доменом верхнего уровня («com», «ru») или публичной зоной («com.ru»), допустим, но отправил бы на локальный DNS
    /// мимо VPN всю зону — об этом предупреждение.
    /// </summary>
    private static void ValidateLocalSuffixes(AppSettings settings, List<string> errors, List<string> warnings)
    {
        foreach (var suffix in settings.LocalDnsSuffixes)
        {
            var normalized = SettingsSerializer.NormalizeSuffix(suffix);
            if (!SettingsSerializer.IsValidSuffix(normalized))
            {
                errors.Add(Text($"«{suffix}»: неверный локальный DNS-суффикс. Укажите имя вида lan или home.arpa."));
            }
            else if (Dns.PublicSuffixes.IsTopLevelDomain(normalized) || Dns.PublicSuffixes.IsPublicZone(normalized))
            {
                warnings.Add(Text($"Локальный DNS-суффикс «{suffix}» — публичная зона интернета: все имена в ней пойдут на локальный DNS мимо VPN. Укажите суффикс своей сети, например lan или office.example.org."));
            }
        }
    }

    /// <summary>
    /// Пределы количества: при сотнях подключений состояние не помещается в кадр канала управления, и интерфейс
    /// остаётся без связи со службой. Превышение, уже сохранённое прежней версией, — предупреждение, пока число
    /// не растёт: иначе нельзя было бы сохранить ни одного изменения, в том числе удаление лишнего.
    /// </summary>
    private static void ValidateCounts(AppSettings settings, AppSettings? previous, List<string> errors, List<string> warnings)
    {
        void Check(int count, int? before, int limit, string what)
        {
            if (count > limit)
            {
                (before is { } saved && count <= saved ? warnings : errors).Add(Text($"{what}: {count}, допустимо не больше {limit}. Удалите лишние."));
            }
        }

        Check(settings.Profiles.Count, previous?.Profiles.Count, MaxProfiles, "Подключений");
        Check(settings.Groups.Count, previous?.Groups.Count, MaxGroups, "Групп подключений");
        Check(settings.RoutingFolders.Count, previous?.RoutingFolders.Count, MaxRoutingFolders, "Папок правил");
        Check(settings.Rules.Count, previous?.Rules.Count, MaxRules, "Правил сетей");
        Check(settings.DomainRules.Count, previous?.DomainRules.Count, MaxDomainRules, "Правил доменов");
    }

    /// <summary>
    /// Контрольные цели «IPv4:порт» через запятую: неразобранная цель молча выпадала из проверки, а при опечатке во
    /// всех туннель считался проверенным без пробы. Пустой список допустим — так проверку выключают осознанно.
    /// Цель, сохранённая прежней версией, — предупреждение: при применении она пропускается, как и раньше.
    /// </summary>
    private static void ValidateCheckTargets(AppSettings settings, AppSettings? previous, List<string> errors, List<string> warnings)
    {
        void Check(string value, string? before, string what)
        {
            var items = CheckTargetList.Split(value);
            var saved = before is null ? null : CheckTargetList.Split(before);
            foreach (var item in items.Where(i => !CheckTargetList.TryParse(i, out _, out _)))
            {
                (saved?.Contains(item, StringComparer.Ordinal) == true ? warnings : errors).Add(Text(
                    $"{what}: «{item}» — не цель вида 1.1.1.1:443 (IPv4-адрес и порт от 1 до 65535). Неразобранная цель в проверку не попадает."));
            }

            // Предел - по различным разобранным целям, как при применении (Coordinator.ParseTargets): повтор одной цели
            // ничего не добавляет к пробам, а неразобранная выше уже названа.
            var count = DistinctTargets(items);
            if (count > MaxCheckTargets)
            {
                (saved is not null && count <= DistinctTargets(saved) ? warnings : errors).Add(Text(
                    $"{what}: целей {count}, допустимо не больше {MaxCheckTargets} — проверяются только первые {MaxCheckTargets}."));
            }
        }

        static int DistinctTargets(List<string> items) => items
            .Select(i => CheckTargetList.TryParse(i, out var address, out var port) ? (address, port) : ((uint, ushort)?)null)
            .OfType<(uint, ushort)>()
            .Distinct()
            .Count();

        Check(settings.CheckTargets.Foreign, previous?.CheckTargets.Foreign, "Иностранная контрольная цель");
        Check(settings.CheckTargets.Russian, previous?.CheckTargets.Russian, "Российская контрольная цель");
    }

    /// <param name="substituted">
    /// JSON-имена полей, значения которых подставлены вместо неизвестных этой версии (подключение из файла более новой
    /// версии, см. <see cref="UnknownSettingValues.SubstitutedFields"/>): они и проверки, смысл которых от них зависит,
    /// пропускаются. Протокол подставлен - формат адреса сервера неизвестен, и проверяется только, что адрес задан и
    /// без управляющих символов; способ входа и разделы EAP, AnyConnect и SSH тогда тоже не проверяются.
    /// </param>
    /// <param name="looseServer">
    /// Куда идёт сообщение о нестрогой записи IPv4 в адресе шлюза AnyConnect: ошибки для нового значения,
    /// предупреждения для уже сохранённого (см. <see cref="Validate"/>, параметр previous).
    /// </param>
    private static void ValidateProfile(ConnectionProfile profile, List<string> errors, List<string> looseServer, IReadOnlySet<string>? substituted = null)
    {
        bool Known(string field) => substituted?.Contains(field) != true;
        var protocolKnown = Known("protocol");
        var authKnown = protocolKnown && Known("authMethod");

        if (string.IsNullOrWhiteSpace(profile.Name))
        {
            errors.Add("У подключения не задано название.");
        }

        if (!protocolKnown)
        {
            if (string.IsNullOrWhiteSpace(profile.Server) || profile.Server.Length > MaxForeignServerLength || profile.Server.Any(char.IsControl))
            {
                errors.Add(Text($"Подключение «{profile.Name}»: неверный адрес сервера."));
            }
        }
        else if (profile.Protocol == VpnProtocol.AnyConnect && AnyConnectGateway.IsLooseIpv4(profile.Server))
        {
            // Прежние версии принимали «10.1» или «010.0.0.1» и молча подключались к 10.0.0.1 или 8.0.0.1. Уже
            // сохранённый такой адрес не мешает сохранять остальное, но подключение по нему служба не поднимает.
            looseServer.Add(Text($"Подключение «{profile.Name}»: адрес шлюза «{profile.Server}» содержит IPv4 в нестрогой записи (сокращённой, с ведущими нулями, шестнадцатеричной или одним числом) — исправьте адрес на вид 10.0.0.1. Пока он не исправлен, подключение не поднимается."));
        }
        else if (!VpnProtocols.TryParseServer(profile.Server, profile.Protocol, out var server))
        {
            errors.Add(Text($"Подключение «{profile.Name}»: неверный адрес сервера."));
        }
        else if (Ipv4.TryParse(server.Host, out var serverAddress) && IsUnusableAddress(serverAddress))
        {
            errors.Add(Text($"Подключение «{profile.Name}»: {server.Host} не может быть адресом VPN-сервера."));
        }

        if ((authKnown && !VpnProtocols.Supports(profile.Protocol, profile.AuthMethod))
            || (Known("ipsecAuthentication") && !Enum.IsDefined(profile.IpsecAuthentication)) || !Enum.IsDefined(profile.Role))
        {
            errors.Add(Text($"Подключение «{profile.Name}»: неподдерживаемый протокол, способ входа или роль."));
        }

        if (Known("primaryAdapter"))
        {
            // Число вместо имени значения JSON принимает любое: неизвестный выбор адаптера работал бы как «Автоматически».
            if (!Enum.IsDefined(profile.PrimaryAdapter))
            {
                errors.Add(Text($"Подключение «{profile.Name}»: неизвестный способ выбора адаптера."));
            }

            if (profile.PrimaryAdapter == AdapterSelection.Pinned && profile.PinnedInterfaceGuid is null)
            {
                errors.Add(Text($"Подключение «{profile.Name}»: не выбран адаптер для закрепления."));
            }
        }

        // Выключенный профиль без клиентского сертификата EAP-TLS (импорт) допустим: включить его без сертификата нельзя.
        errors.AddRange(VpnProtocols.ValidateAuthentication(profile, protocolKnown, authKnown, requireClientCertificate: profile.Role != ProfileRole.Off));

        if (authKnown && VpnProtocols.NeedsPassword(profile.AuthMethod) && string.IsNullOrWhiteSpace(profile.UserName))
        {
            errors.Add(Text($"Подключение «{profile.Name}»: не задано имя пользователя."));
        }
    }

    /// <summary>Предел длины адреса сервера подключения с неизвестным этой версии протоколом.</summary>
    private const int MaxForeignServerLength = 512;

    private static void ValidateGeoSource(GeoUpdateSettings geo, List<string> errors)
    {
        // Неизвестный источник молча заменялся бы источником по умолчанию.
        if (!Enum.IsDefined(geo.Source))
        {
            errors.Add("Неизвестный источник базы адресов.");
        }

        var urls = geo.Mirrors.AsEnumerable();
        if (geo.Source == GeoSourceKind.CustomUrl)
        {
            urls = urls.Append(geo.CustomUrl ?? "");
        }

        foreach (var url in urls.Where(u => !IsHttpsUrl(u)))
        {
            errors.Add(Text($"Адрес источника базы должен быть HTTPS-ссылкой: «{url}»."));
        }
    }

    private static void ValidateAddresses(AppSettings settings, List<string> errors)
    {
        var addresses = settings.UpstreamDns.AsEnumerable();
        if (settings.LocalDnsServer is not null)
        {
            addresses = addresses.Append(settings.LocalDnsServer);
        }

        foreach (var address in addresses)
        {
            if (!Ipv4.TryParse(address, out var value))
            {
                errors.Add(Text($"Неверный IPv4-адрес DNS: «{address}»."));
            }
            else if (SpecialRanges.Loopback.Contains(value))
            {
                // 127.0.0.1 занят самим посредником: адаптеры указывают на него, а он — на этот список.
                errors.Add(Text($"DNS-сервер не может быть loopback-адресом: «{address}»."));
            }
            else if (IsUnusableAddress(value))
            {
                errors.Add(Text($"DNS-сервер не может быть служебным адресом: «{address}»."));
            }
        }
    }

    /// <summary>
    /// Адреса, которые не могут быть ни VPN-сервером, ни DNS-сервером: «любой адрес» 0.0.0.0,
    /// широковещательный 255.255.255.255 и весь loopback 127.0.0.0/8 (там слушает наш DNS-посредник).
    /// </summary>
    private static bool IsUnusableAddress(uint address) =>
        address is 0 or uint.MaxValue || SpecialRanges.Loopback.Contains(address);

    private static bool IsHttpsUrl(string url) => Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps;

    private static string Text(FormattableString text) => text.ToString(CultureInfo.InvariantCulture);
}
