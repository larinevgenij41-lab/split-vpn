using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;

namespace SplitVpn.Core.Settings;

public sealed record SettingsLoadResult(AppSettings? Settings, string? Error, bool Migrated = false)
{
    public bool IsSuccess => Settings is not null;
}

public static class SettingsSerializer
{
    public static string Serialize(AppSettings settings) => JsonSerializer.Serialize(settings, JsonDefaults.Options);

    public static SettingsLoadResult Deserialize(string json)
    {
        try
        {
            var root = JsonNode.Parse(json) as JsonObject;
            if (root is null)
            {
                return new SettingsLoadResult(null, "Файл настроек пуст.");
            }

            var version = root["schemaVersion"]?.GetValue<int>() ?? 0;
            var migrated = false;
            if (version is 1 or 2 && version != AppSettings.CurrentSchemaVersion)
            {
                MigrateToCurrent(root, version);
                version = AppSettings.CurrentSchemaVersion;
                migrated = true;
            }

            if (version != AppSettings.CurrentSchemaVersion)
            {
                return new SettingsLoadResult(null, string.Create(
                    CultureInfo.InvariantCulture,
                    $"Неподдерживаемая версия схемы настроек: {version}. Ожидается {AppSettings.CurrentSchemaVersion}."));
            }

            var settings = root.Deserialize<AppSettings>(JsonDefaults.Options);
            return settings is null
                ? new SettingsLoadResult(null, "Файл настроек пуст.")
                : new SettingsLoadResult(DropDuplicateIds(Normalize(settings)), null, migrated);
        }
        catch (JsonException ex)
        {
            return new SettingsLoadResult(null, "Файл настроек повреждён: " + ex.Message);
        }
        catch (InvalidOperationException ex)
        {
            return new SettingsLoadResult(null, "Файл настроек повреждён: " + ex.Message);
        }
    }

    /// <summary>
    /// Приводит модель к безопасному виду: «null» вместо списка, строки или вложенного раздела
    /// (чужая версия программы, ручная правка файла) заменяется значением этого поля по умолчанию —
    /// пустым списком, пустой строкой или готовым разделом; элементы-null из списков убираются.
    /// Корректные настройки нормализация не меняет: круговая сериализация даёт тот же файл.
    /// </summary>
    public static AppSettings Normalize(AppSettings? settings)
    {
        var model = settings ?? new AppSettings();
        return model with
        {
            Profiles = Items(model.Profiles, NormalizeProfile),
            Groups = Items(model.Groups, NormalizeGroup),
            LocalDnsSuffixes = Texts(model.LocalDnsSuffixes),
            UpstreamDns = Texts(model.UpstreamDns),
            Rules = Items(model.Rules, r => r with { Cidr = Text(r.Cidr) }),
            DomainRules = Items(model.DomainRules, r => r with { Suffix = Text(r.Suffix) }),
            GeoUpdate = NormalizeGeo(model.GeoUpdate),
            BypassUpdate = NormalizeBypass(model.BypassUpdate),
            CheckTargets = NormalizeCheckTargets(model.CheckTargets),
        };
    }

    /// <summary>
    /// Повторяющиеся идентификаторы подключений и групп: остаётся первая запись. С дубликатами падает
    /// компилятор политики и путается служебный код, который ищет запись по идентификатору; валидатор
    /// сообщает о них отдельно, чтобы потеря записи не прошла молча.
    /// </summary>
    public static AppSettings DropDuplicateIds(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var profiles = settings.Profiles.DistinctBy(p => p.Id).ToList();
        var groups = settings.Groups.DistinctBy(g => g.Id).ToList();
        return profiles.Count == settings.Profiles.Count && groups.Count == settings.Groups.Count
            ? settings
            : settings with { Profiles = profiles, Groups = groups };
    }

    /// <summary>Один профиль без «null» в строках и разделах; см. <see cref="Normalize"/>.</summary>
    public static ConnectionProfile NormalizeProfile(ConnectionProfile profile) => profile with
    {
        Name = Text(profile.Name),
        Server = Text(profile.Server),
        UserName = Text(profile.UserName),
        Eap = NormalizeEap(profile.Eap),
        AnyConnect = NormalizeAnyConnect(profile.AnyConnect),
        Retry = profile.Retry ?? new RetrySettings(),
    };

    private static TunnelGroupSetting NormalizeGroup(TunnelGroupSetting group) => group with
    {
        Name = Text(group.Name),
        Members = group.Members ?? [],
    };

    private static EapSettings NormalizeEap(EapSettings? eap)
    {
        var model = eap ?? new EapSettings();
        return model with
        {
            ServerNames = Text(model.ServerNames),
            TrustedRootThumbprints = Texts(model.TrustedRootThumbprints),
            ClientCertificateThumbprint = Text(model.ClientCertificateThumbprint),
        };
    }

    private static AnyConnectSettings NormalizeAnyConnect(AnyConnectSettings? anyConnect)
    {
        var model = anyConnect ?? new AnyConnectSettings();
        return model with
        {
            Group = Text(model.Group),
            ClientCertificateThumbprint = Text(model.ClientCertificateThumbprint),
            UserAgent = model.UserAgent ?? AnyConnectSettings.DefaultUserAgent,
        };
    }

    private static GeoUpdateSettings NormalizeGeo(GeoUpdateSettings? geo)
    {
        var model = geo ?? new GeoUpdateSettings();
        return model with { Mirrors = Texts(model.Mirrors) };
    }

    /// <summary>
    /// Список обхода блокировок качается из своего источника: RU-базу сюда подставить нельзя, иначе
    /// российские сети попали бы в слой, который перекрывает RU-базу. Свой адрес по-прежнему разрешён.
    /// </summary>
    private static GeoUpdateSettings NormalizeBypass(GeoUpdateSettings? bypass)
    {
        var model = NormalizeGeo(bypass ?? new GeoUpdateSettings { Source = GeoSourceKind.ReFilter });
        return model.Source == GeoSourceKind.CustomUrl ? model : model with { Source = GeoSourceKind.ReFilter };
    }

    private static CheckTargets NormalizeCheckTargets(CheckTargets? targets)
    {
        var model = targets ?? new CheckTargets();
        var defaults = new CheckTargets();
        return model with { Foreign = model.Foreign ?? defaults.Foreign, Russian = model.Russian ?? defaults.Russian };
    }

    private static string Text(string? value) => value ?? "";

    private static List<string> Texts(IReadOnlyList<string?>? source) =>
        source is null ? [] : source.OfType<string>().ToList();

    private static List<T> Items<T>(IReadOnlyList<T?>? source, Func<T, T> normalize)
        where T : class => source is null ? [] : source.OfType<T>().Select(normalize).ToList();

    /// <summary>
    /// Перевод старых схем на текущую.
    /// Схема 1 не знала ни протоколов, ни целей маршрутизации: её профили приводятся к SSTP с MS-CHAP v2,
    /// а активное подключение становится опорным туннелем. Схема 2 существовала в двух видах — с протоколами
    /// и с целями; распознаётся по наличию полей «activeProfileId» и «routingMode».
    /// </summary>
    internal static void MigrateToCurrent(JsonObject root, int version)
    {
        ArgumentNullException.ThrowIfNull(root);
        if (version <= 1)
        {
            ResetProtocols(root);
        }

        if (root["activeProfileId"] is not null || root["routingMode"] is not null)
        {
            MigrateTargets(root);
        }

        root["schemaVersion"] = AppSettings.CurrentSchemaVersion;
    }

    /// <summary>Профили схемы 1: протоколов и EAP она не знала, поля из файла новой конфигурацией не считаем.</summary>
    private static void ResetProtocols(JsonObject root)
    {
        foreach (var profile in (root["profiles"] as JsonArray ?? []).OfType<JsonObject>())
        {
            profile["protocol"] = nameof(VpnProtocol.Sstp);
            profile["authMethod"] = nameof(AuthMethod.MsChapV2);
            profile["ipsecAuthentication"] = nameof(IpsecAuthentication.PreSharedKey);
            profile.Remove("eap");
        }
    }

    /// <summary>Активное подключение становится опорным туннелем, режим и действия правил — целями.</summary>
    private static void MigrateTargets(JsonObject root)
    {
        var active = root["activeProfileId"]?.GetValue<string>();
        var hasActive = Guid.TryParse(active, out var activeId);
        if (root["profiles"] is JsonArray profiles)
        {
            foreach (var profile in profiles.OfType<JsonObject>())
            {
                var isActive = hasActive && Guid.TryParse(profile["id"]?.GetValue<string>(), out var id) && id == activeId;
                profile["role"] = isActive ? nameof(ProfileRole.Primary) : nameof(ProfileRole.Off);
            }
        }

        var tunnel = hasActive ? Target(TargetKind.Tunnel, activeId) : Target(TargetKind.Direct, null);
        var allViaVpn = string.Equals(root["routingMode"]?.GetValue<string>(), "AllViaVpn", StringComparison.OrdinalIgnoreCase);
        root["defaultTarget"] = tunnel.DeepClone();
        root["geoTarget"] = allViaVpn ? tunnel.DeepClone() : Target(TargetKind.Direct, null);
        root.Remove("activeProfileId");
        root.Remove("routingMode");

        foreach (var rule in (root["rules"] as JsonArray ?? []).OfType<JsonObject>())
        {
            var action = rule["action"]?.GetValue<string>();
            rule["target"] = action switch
            {
                "Block" => Target(TargetKind.Block, null),
                "Direct" => Target(TargetKind.Direct, null),
                _ => tunnel.DeepClone(),
            };
            rule.Remove("action");
        }
    }

    private static JsonObject Target(TargetKind kind, Guid? tunnelId)
    {
        var node = new JsonObject { ["kind"] = kind.ToString() };
        if (tunnelId is { } id)
        {
            node["id"] = id.ToString();
        }

        return node;
    }

    /// <summary>Разбор пользовательских правил в модель компилятора; IPv6 в v1 не поддерживается.</summary>
    public static (IReadOnlyList<UserRule> Rules, IReadOnlyList<string> Errors) ParseRules(IEnumerable<UserRuleSetting> settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var rules = new List<UserRule>();
        var errors = new List<string>();
        foreach (var setting in settings)
        {
            if (Ipv4Cidr.TryParse(setting.Cidr, out var cidr))
            {
                rules.Add(new UserRule(cidr, setting.Target, setting.Comment));
            }
            else
            {
                errors.Add(DescribeInvalidRule(setting.Cidr));
            }
        }

        return (rules, errors);
    }

    /// <summary>Суффикс домена в каноническом виде: без точек по краям, в нижнем регистре.</summary>
    public static string NormalizeSuffix(string? suffix) => (suffix ?? "").Trim().Trim('.').ToLowerInvariant();

    /// <summary>Имя, годное как DNS-суффикс: сюда же попадают однословные локальные суффиксы «lan», «local».</summary>
    public static bool IsValidSuffix(string normalized) =>
        normalized.Length is > 0 and <= 253 && Uri.CheckHostName(normalized) == UriHostNameType.Dns;

    /// <summary>
    /// Суффикс правила для домена: не меньше двух меток. Домен верхнего уровня целиком («com», «ru»)
    /// правилом не задаётся — под него попала бы вся зона, а каждое новое имя в ней стало бы отдельным
    /// закреплением адресов в очереди службы. Локальные DNS-суффиксы проверяются <see cref="IsValidSuffix"/>.
    /// </summary>
    public static bool IsValidDomainSuffix(string normalized) =>
        IsValidSuffix(normalized) && normalized.Contains('.', StringComparison.Ordinal);

    private static string DescribeInvalidRule(string text)
    {
        if (text.Contains(':', StringComparison.Ordinal))
        {
            return $"«{text}»: IPv6 ограничен в этой версии — правила IPv6 не поддерживаются.";
        }

        return Ipv4Cidr.HasHostBits(text)
            ? $"«{text}»: у подсети установлены биты хоста."
            : $"«{text}»: неверная IPv4-подсеть.";
    }
}
