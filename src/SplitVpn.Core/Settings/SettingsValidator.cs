using System.Globalization;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;

namespace SplitVpn.Core.Settings;

public static class SettingsValidator
{
    private static readonly int[] AllowedIntervals = [1, 3, 7];

    /// <summary>
    /// Проверяет настройки. Модель приходит из файла или по каналу управления и может быть неполной
    /// («null» вместо списка, строки или раздела), поэтому проверяется её нормализованная копия:
    /// валидатор обязан сообщить об ошибках, а не упасть на неполных данных.
    /// </summary>
    public static ValidationResult Validate(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var model = SettingsSerializer.Normalize(settings);
        var errors = new List<string>();
        var warnings = new List<string>();

        if (model.SchemaVersion != AppSettings.CurrentSchemaVersion)
        {
            errors.Add("Версия настроек несовместима: обновите приложение и службу вместе.");
        }

        ValidateProfiles(model, errors);
        ValidateGroups(model, errors);
        ValidateTargets(model, errors, warnings);
        ValidateAnyConnect(model, errors);
        ValidateDomainRules(model, errors);
        ValidateLocalSuffixes(model, errors);

        var (rules, ruleErrors) = SettingsSerializer.ParseRules(model.Rules);
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

        ValidateGeoSource(model.GeoUpdate, errors);
        ValidateGeoSource(model.BypassUpdate, errors);
        ValidateAddresses(model, errors);
        return new ValidationResult(errors, warnings);
    }

    private static void ValidateProfiles(AppSettings settings, List<string> errors)
    {
        foreach (var profile in settings.Profiles)
        {
            ValidateProfile(profile, errors);
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

    private static void ValidateDomainRules(AppSettings settings, List<string> errors)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
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
        }
    }

    /// <summary>Локальные DNS-суффиксы — имена вида «lan» или «home.arpa», без адресов и лишних символов.</summary>
    private static void ValidateLocalSuffixes(AppSettings settings, List<string> errors)
    {
        foreach (var suffix in settings.LocalDnsSuffixes.Where(s => !SettingsSerializer.IsValidSuffix(SettingsSerializer.NormalizeSuffix(s))))
        {
            errors.Add(Text($"«{suffix}»: неверный локальный DNS-суффикс. Укажите имя вида lan или home.arpa."));
        }
    }

    private static void ValidateProfile(ConnectionProfile profile, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(profile.Name))
        {
            errors.Add("У подключения не задано название.");
        }

        if (!VpnProtocols.TryParseServer(profile.Server, profile.Protocol, out var server))
        {
            errors.Add(Text($"Подключение «{profile.Name}»: неверный адрес сервера."));
        }
        else if (Ipv4.TryParse(server.Host, out var serverAddress) && IsUnusableAddress(serverAddress))
        {
            errors.Add(Text($"Подключение «{profile.Name}»: {server.Host} не может быть адресом VPN-сервера."));
        }

        if (!VpnProtocols.Supports(profile.Protocol, profile.AuthMethod) || !Enum.IsDefined(profile.IpsecAuthentication) || !Enum.IsDefined(profile.Role))
        {
            errors.Add(Text($"Подключение «{profile.Name}»: неподдерживаемый протокол, способ входа или роль."));
        }

        errors.AddRange(VpnProtocols.ValidateAuthentication(profile));

        if (VpnProtocols.NeedsPassword(profile.AuthMethod) && string.IsNullOrWhiteSpace(profile.UserName))
        {
            errors.Add(Text($"Подключение «{profile.Name}»: не задано имя пользователя."));
        }

        if (profile.PrimaryAdapter == AdapterSelection.Pinned && profile.PinnedInterfaceGuid is null)
        {
            errors.Add(Text($"Подключение «{profile.Name}»: не выбран адаптер для закрепления."));
        }
    }

    private static void ValidateGeoSource(GeoUpdateSettings geo, List<string> errors)
    {
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
