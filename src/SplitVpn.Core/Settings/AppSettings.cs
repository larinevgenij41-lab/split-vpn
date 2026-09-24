using System.Text.Json;
using System.Text.Json.Serialization;
using SplitVpn.Core.Policy;

namespace SplitVpn.Core.Settings;

public enum AuthMethod
{
    MsChapV2,
    EapMsChapV2,
    PeapMsChapV2,
    EapTls,
    TtlsMsChapV2,
    TtlsPap,
    Pap,
    Chap,
    MachineCertificate,

    /// <summary>Вход по формам шлюза AnyConnect: SSO во встроенном браузере, пароль или сертификат — как решит сервер.</summary>
    GatewayForm,
}

public enum IpsecAuthentication
{
    PreSharedKey,
    MachineCertificate,
}

public sealed record EapSettings
{
    public string ServerNames { get; init; } = "";
    public IReadOnlyList<string> TrustedRootThumbprints { get; init; } = [];
    public string ClientCertificateThumbprint { get; init; } = "";
}

/// <summary>Параметры подключения Cisco AnyConnect (libopenconnect в процессе-помощнике).</summary>
public sealed record AnyConnectSettings
{
    public const string DefaultUserAgent = "AnyConnect Windows 4.10.06090";

    /// <summary>Группа подключения шлюза (group_list); пусто — первая предложенная.</summary>
    public string Group { get; init; } = "";

    /// <summary>SHA-1 отпечаток клиентского сертификата в хранилище компьютера; пусто — без сертификата.</summary>
    public string ClientCertificateThumbprint { get; init; } = "";

    /// <summary>Канал DTLS (UDP) поверх TLS; без него — только TLS.</summary>
    public bool UseDtls { get; init; } = true;

    /// <summary>Применять прокси (PAC) из сеанса шлюза для пользователя; по умолчанию выключено.</summary>
    public bool ApplyServerProxy { get; init; }

    public string UserAgent { get; init; } = DefaultUserAgent;

    /// <summary>Куда направлены сети, присланные шлюзом; null — в этот же туннель.</summary>
    public RouteTarget? ServerNetworksTarget { get; init; }
}

public enum AdapterSelection
{
    Auto,
    Pinned,
}

/// <summary>Роль подключения среди одновременно поднятых туннелей.</summary>
public enum ProfileRole
{
    /// <summary>Не поднимается.</summary>
    Off,

    /// <summary>Опорный: даёт DNS по умолчанию, его обрыв включает защиту при обрыве.</summary>
    Primary,

    /// <summary>Дополнительный: поднимается и получает только назначенное ему.</summary>
    Secondary,
}

/// <summary>Как группа туннелей распределяет назначенный ей трафик.</summary>
public enum BalanceMode
{
    /// <summary>Между всеми поднятыми участниками, по блокам адресов.</summary>
    Distribute,

    /// <summary>Всё уходит первому поднятому участнику; остальные — резерв.</summary>
    Failover,
}

/// <summary>Поведение при обрыве VPN (PLAN §5 «Защита при обрыве»).</summary>
public enum OutageMode
{
    /// <summary>Блокировать только трафик, назначенный VPN.</summary>
    BlockVpnTraffic,

    /// <summary>Блокировать весь публичный интернет.</summary>
    BlockAllPublic,

    /// <summary>Разрешить весь трафик напрямую.</summary>
    AllowAll,
}

public enum GeoSourceKind
{
    Loyalsoldier,
    Ipverse,
    CustomUrl,

    /// <summary>Список обхода блокировок (Re-filter): им обновляется не RU-база, а отдельный список.</summary>
    ReFilter,
}

public sealed record RetrySettings
{
    public bool Enabled { get; init; } = true;

    public int MaxDelaySeconds { get; init; } = 60;
}

public sealed record ConnectionProfile
{
    public Guid Id { get; init; } = Guid.NewGuid();

    public string Name { get; init; } = "";

    public string Server { get; init; } = "";

    public VpnProtocol Protocol { get; init; } = VpnProtocol.Sstp;

    /// <summary>Роль туннеля: опорный, дополнительный или выключен.</summary>
    public ProfileRole Role { get; init; } = ProfileRole.Off;

    public string UserName { get; init; } = "";

    public string? Domain { get; init; }

    public AuthMethod AuthMethod { get; init; } = AuthMethod.MsChapV2;

    public IpsecAuthentication IpsecAuthentication { get; init; } = IpsecAuthentication.PreSharedKey;

    public EapSettings Eap { get; init; } = new();

    public AnyConnectSettings AnyConnect { get; init; } = new();

    public bool SavePassword { get; init; } = true;

    public AdapterSelection PrimaryAdapter { get; init; } = AdapterSelection.Auto;

    public Guid? PinnedInterfaceGuid { get; init; }

    public bool AllowFallbackWhenPinnedMissing { get; init; }

    public RetrySettings Retry { get; init; } = new();

    /// <summary>
    /// Поля профиля, которых эта версия не знает. Сохраняются как есть, чтобы правка подключения
    /// не стирала настройки, записанные другой версией программы. В сравнении профилей не
    /// участвует: служба сверяет поля поимённо.
    /// </summary>
    [JsonExtensionData]
    public IDictionary<string, JsonElement>? Extra { get; init; }
}

/// <summary>Группа туннелей: цель маршрутизации, за которой стоит несколько подключений.</summary>
public sealed record TunnelGroupSetting
{
    public Guid Id { get; init; } = Guid.NewGuid();

    public string Name { get; init; } = "";

    /// <summary>Участники в порядке предпочтения: при резервировании первый поднятый забирает всё.</summary>
    public IReadOnlyList<Guid> Members { get; init; } = [];

    public BalanceMode Mode { get; init; } = BalanceMode.Distribute;
}

public sealed record UserRuleSetting
{
    public string Cidr { get; init; } = "";

    public RouteTarget Target { get; init; } = RouteTarget.Direct;

    public string? Comment { get; init; }
}

/// <summary>
/// Правило по доменному имени: суффикс и цель. DNS-посредник разрешает имя по выбранному пути
/// и закрепляет полученные адреса за целью на время TTL ответа.
/// </summary>
public sealed record DomainRuleSetting
{
    public string Suffix { get; init; } = "";

    public RouteTarget Target { get; init; } = RouteTarget.Direct;

    public string? Comment { get; init; }
}

public sealed record GeoUpdateSettings
{
    public bool AutoUpdate { get; init; } = true;

    public int IntervalDays { get; init; } = 1;

    public GeoSourceKind Source { get; init; } = GeoSourceKind.Loyalsoldier;

    public string? CustomUrl { get; init; }

    /// <summary>Дополнительные адреса той же базы того же поставщика.</summary>
    public IReadOnlyList<string> Mirrors { get; init; } = [];

    public bool DeferOnMetered { get; init; } = true;
}

/// <summary>
/// Обновление самой программы через GitHub Releases. Проверка и загрузка идут в фоне у службы,
/// установка — только по команде пользователя: она закрывает интерфейс и перезапускает службу.
/// </summary>
public sealed record AppUpdateSettings
{
    public bool AutoCheck { get; init; } = true;

    /// <summary>Скачивать найденное обновление заранее, чтобы установка занимала секунды, а не минуты.</summary>
    public bool AutoDownload { get; init; } = true;

    public int IntervalDays { get; init; } = 1;

    /// <summary>Дополнительные адреса манифеста (HTTPS) на случай недоступности GitHub.</summary>
    public IReadOnlyList<string> ManifestMirrors { get; init; } = [];

    /// <summary>Дополнительные адреса установщика; к адресу-каталогу дописывается имя файла из манифеста.</summary>
    public IReadOnlyList<string> PackageMirrors { get; init; } = [];

    public bool DeferOnMetered { get; init; } = true;
}

public sealed record CheckTargets
{
    /// <summary>Иностранная цель проверки выхода через туннель (IP:порт).</summary>
    public string Foreign { get; init; } = "1.1.1.1:443";

    /// <summary>Российская цель проверки прямого выхода (IP:порт).</summary>
    public string Russian { get; init; } = "77.88.55.242:443";
}

public sealed record AppSettings
{
    public const int CurrentSchemaVersion = 3;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public IReadOnlyList<ConnectionProfile> Profiles { get; init; } = [];

    public IReadOnlyList<TunnelGroupSetting> Groups { get; init; } = [];

    /// <summary>Куда идёт «остальной интернет».</summary>
    public RouteTarget DefaultTarget { get; init; } = RouteTarget.Direct;

    /// <summary>Куда идут адреса из RU-базы.</summary>
    public RouteTarget GeoTarget { get; init; } = RouteTarget.Direct;

    /// <summary>
    /// Куда идут адреса из списка обхода блокировок; null — туда же, куда «остальной интернет»
    /// (список ничего не меняет). Слой ложится поверх RU-базы и ниже правил пользователя.
    /// </summary>
    public RouteTarget? BypassTarget { get; init; }

    public OutageMode OutageMode { get; init; } = OutageMode.BlockVpnTraffic;

    public bool DnsDirectOnOutage { get; init; }

    /// <summary>
    /// Поднимать подключения по очереди в порядке списка, а не все сразу. По умолчанию выключено:
    /// одновременный подъём быстрее, очередь нужна тем, кому важно, какое подключение встанет первым.
    /// </summary>
    public bool SequentialDial { get; init; }

    public bool LocalAccess { get; init; } = true;

    public IReadOnlyList<string> LocalDnsSuffixes { get; init; } = [];

    public string? LocalDnsServer { get; init; }

    /// <summary>Upstream DNS через туннель; пусто — DNS, выданный VPN-сервером.</summary>
    public IReadOnlyList<string> UpstreamDns { get; init; } = [];

    public bool AutoConnect { get; init; }

    public IReadOnlyList<UserRuleSetting> Rules { get; init; } = [];

    public IReadOnlyList<DomainRuleSetting> DomainRules { get; init; } = [];

    public GeoUpdateSettings GeoUpdate { get; init; } = new();

    /// <summary>Обновление списка обхода блокировок: отдельный источник и свой срок проверки.</summary>
    public GeoUpdateSettings BypassUpdate { get; init; } = new() { Source = GeoSourceKind.ReFilter };

    /// <summary>Обновление самой программы: проверка по расписанию, загрузка заранее, установка по команде.</summary>
    public AppUpdateSettings AppUpdate { get; init; } = new();

    public CheckTargets CheckTargets { get; init; } = new();

    /// <summary>
    /// Разделы файла настроек, которых эта версия не знает.
    /// Сохраняются как есть: файл настроек не должен терять чужие разделы при записи.
    /// </summary>
    [JsonExtensionData]
    public IDictionary<string, JsonElement>? Extra { get; init; }

    /// <summary>Опорное подключение; его может не быть, если «остальной интернет» идёт напрямую.</summary>
    [JsonIgnore]
    public ConnectionProfile? PrimaryProfile => Profiles.FirstOrDefault(p => p.Role == ProfileRole.Primary);

    /// <summary>
    /// Все подключения, которые служба поднимает, в порядке списка. Этот порядок пользователь задаёт сам:
    /// он же виден на экране, он же задаёт очерёдность подъёма при <see cref="SequentialDial"/>.
    /// Опорное подключение ищется по роли (<see cref="PrimaryProfile"/>), а не по месту в списке.
    /// </summary>
    [JsonIgnore]
    public IReadOnlyList<ConnectionProfile> ActiveProfiles =>
        Profiles.Where(p => p.Role != ProfileRole.Off).ToList();

    /// <summary>Все цели, которым назначен трафик, с описанием места назначения.</summary>
    [JsonIgnore]
    public IReadOnlyList<(string Where, RouteTarget Target)> AllTargets
    {
        get
        {
            var targets = new List<(string, RouteTarget)>
            {
                ("«Остальной интернет»", DefaultTarget),
                ("«Россия (RU-база)»", GeoTarget),
            };
            if (BypassTarget is { } bypass)
            {
                targets.Add(("«Обход блокировок»", bypass));
            }

            targets.AddRange(Rules.Select(r => ("подсеть " + r.Cidr, r.Target)));
            targets.AddRange(DomainRules.Select(r => ("домен " + r.Suffix, r.Target)));
            targets.AddRange(Profiles.Where(p => p.Protocol == VpnProtocol.AnyConnect && p.Role != ProfileRole.Off)
                .Select(p => ($"сети шлюза «{p.Name}»", ServerNetworksTarget(p))));
            return targets;
        }
    }

    /// <summary>Куда идут сети, присланные шлюзом AnyConnect: по умолчанию — в сам этот туннель.</summary>
    public static RouteTarget ServerNetworksTarget(ConnectionProfile profile) => profile.AnyConnect.ServerNetworksTarget ?? RouteTarget.Tunnel(profile.Id);

    public ConnectionProfile? Profile(Guid? id) => id is { } value ? Profiles.FirstOrDefault(p => p.Id == value) : null;

    public TunnelGroupSetting? Group(Guid? id) => id is { } value ? Groups.FirstOrDefault(g => g.Id == value) : null;

    /// <summary>Название цели для интерфейса и отчётов.</summary>
    public string TargetName(RouteTarget target) => target.Kind switch
    {
        TargetKind.Tunnel => "через «" + (Profile(target.Id)?.Name ?? "неизвестное подключение") + "»",
        TargetKind.Group => "через группу «" + (Group(target.Id)?.Name ?? "неизвестная группа") + "»",
        _ => PolicyValidator.TargetName(target),
    };
}
