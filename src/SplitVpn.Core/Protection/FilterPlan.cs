using System.Globalization;
using System.Net;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;

namespace SplitVpn.Core.Protection;

public enum FilterFamily
{
    V4,
    V6,
    Both,
}

public enum FilterAction
{
    Permit,
    Block,
}

/// <summary>Изменившиеся группы применяются одной транзакцией WFP; большая адресная группа — по разнице.</summary>
public enum FilterGroup
{
    /// <summary>Зависит только от настроек; persistent — переживает перезагрузку.</summary>
    Base,

    /// <summary>Большие адресные наборы: прямой выход и ограничения маршрутов живых туннелей; static.</summary>
    Direct,

    /// <summary>Служебные разрешения, локальная сеть и недоступные туннели; static.</summary>
    Runtime,

    /// <summary>Адреса, полученные по правилам для доменов; static, меняется часто и остаётся маленькой.</summary>
    Dynamic,
}

public abstract record FilterCondition;

public sealed record LoopbackCondition : FilterCondition;

public sealed record RemoteRangeV4(uint Start, uint End) : FilterCondition;

/// <summary>
/// Удалённый адрес в любом из диапазонов. В WFP это подряд идущие условия одного поля: с Windows 7 они
/// объединяются через «или». Тысячи диапазонов ложатся в несколько фильтров вместо тысяч отдельных.
/// </summary>
public sealed record RemoteRangesV4 : FilterCondition
{
    private readonly Ipv4Range[] _ranges;

    /// <param name="ranges">Упорядоченные непересекающиеся диапазоны.</param>
    public RemoteRangesV4(IEnumerable<Ipv4Range> ranges)
    {
        ArgumentNullException.ThrowIfNull(ranges);
        _ranges = ranges.ToArray();
        // Фильтр без условий на адрес совпал бы с любым адресом.
        if (_ranges.Length == 0)
        {
            throw new ArgumentException("Нужен хотя бы один диапазон.", nameof(ranges));
        }
    }

    public IReadOnlyList<Ipv4Range> Ranges => _ranges;

    public bool Contains(uint address)
    {
        int low = 0, high = _ranges.Length - 1;
        while (low <= high)
        {
            var middle = low + ((high - low) / 2);
            if (address < _ranges[middle].Start)
            {
                high = middle - 1;
            }
            else if (address > _ranges[middle].End)
            {
                low = middle + 1;
            }
            else
            {
                return true;
            }
        }

        return false;
    }

    public bool Equals(RemoteRangesV4? other) => other is not null && _ranges.AsSpan().SequenceEqual(other._ranges);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        foreach (var range in _ranges)
        {
            hash.Add(range);
        }

        return hash.ToHashCode();
    }
}

/// <summary>
/// Удалённый адрес IPv4 не равен заданному. Только один адрес на фильтр: условия одного поля WFP объединяет
/// через «или», и «не равно A или не равно B» совпало бы с любым адресом.
/// </summary>
public sealed record RemoteAddressNotV4(uint Address) : FilterCondition;

public sealed record RemotePrefixV6(IPNetwork Network) : FilterCondition;

public sealed record RemotePortCondition(ushort Port, bool NotEqual = false) : FilterCondition;

/// <summary>Локальный порт; для ICMP на слоях ALE здесь хранится тип сообщения.</summary>
public sealed record LocalPortRange(ushort Low, ushort High) : FilterCondition;

public sealed record ProtocolCondition(byte Protocol, bool NotEqual = false) : FilterCondition;

public sealed record LocalInterfaceCondition(ulong Luid, bool NotEqual) : FilterCondition;

public sealed record AppIdCondition(string ExecutablePath) : FilterCondition;

public sealed record LocalSystemUserCondition : FilterCondition;

public sealed record FilterSpec(
    string Name,
    FilterGroup Group,
    FilterFamily Family,
    byte Weight,
    FilterAction Action,
    IReadOnlyList<FilterCondition> Conditions);

/// <summary>Один туннель: его сервер и, если он поднят, интерфейс.</summary>
public sealed record TunnelInput
{
    public required Guid Id { get; init; }

    public string Name { get; init; } = "";

    /// <summary>LUID интерфейса туннеля; null — туннель не поднят.</summary>
    public ulong? Luid { get; init; }

    public IReadOnlyList<uint> ServerAddresses { get; init; } = [];

    public ushort ServerPort { get; init; } = 443;

    /// <summary>AnyConnect: порты TLS узлов шлюза помимо <see cref="ServerPort"/> (перенаправление на другой порт).</summary>
    public IReadOnlyList<ushort> GatewayTcpPorts { get; init; } = [];

    /// <summary>AnyConnect: порты UDP помимо <see cref="ServerPort"/> (порт DTLS, назначенный шлюзом).</summary>
    public IReadOnlyList<ushort> GatewayUdpPorts { get; init; } = [];

    public VpnProtocol Protocol { get; init; } = VpnProtocol.Sstp;

    /// <summary>Туннель несёт «остальной интернет»: если все такие туннели легли — это обрыв.</summary>
    public bool ServesDefault { get; init; }

    /// <summary>
    /// Туннель положен пользователем: его недоступность - решение человека, а не обрыв, и режим «Разрешить всё»
    /// к ней не относится. У группы-заполнителя - положены все её участники.
    /// </summary>
    public bool Paused { get; init; }

    /// <summary>DNS этого туннеля: посреднику нужен доступ даже вне его адресных назначений.</summary>
    public IReadOnlyList<uint> DnsAddresses { get; init; } = [];

    /// <summary>
    /// «VPN поверх SSH»: единственный адрес сервера, на который настроен процесс движка в этом сеансе;
    /// null - сеанса нет, движку закрыто всё.
    /// </summary>
    public uint? EngineServerAddress { get; init; }
}

/// <summary>Адрес и порт TCP узла проверки отзыва сертификата сервера (ссылка http из CRL или AIA).</summary>
public readonly record struct RevocationEndpoint(uint Address, ushort Port);

/// <summary>
/// Адаптер, трафик которого защита пропускает (например, Radmin VPN): к его собственным сетям и к локальным диапазонам.
/// Prefixes - текущие или запомненные сети, которые локальны по уровню доверия (on-link-сети и собственные маршруты
/// адаптера не короче /8, см. <see cref="PolicyCompiler.TrustedNetworks"/>); PrefixesV6 - сети IPv6 адаптера из списка
/// «Доверенные адаптеры». Публичный интернет через него не выпускается.
/// </summary>
public sealed record TrustedAdapterInput(ulong Luid, string Name)
{
    public IReadOnlyList<Ipv4Cidr> Prefixes { get; init; } = [];

    public IReadOnlyList<IPNetwork> PrefixesV6 { get; init; } = [];
}

/// <summary>Факты и настройки, от которых зависит набор фильтров.</summary>
public sealed record ProtectionInputs
{
    public required CompiledPolicy Policy { get; init; }

    public bool LocalAccess { get; init; } = true;

    public OutageMode OutageMode { get; init; } = OutageMode.BlockVpnTraffic;

    public Intent Intent { get; init; } = Intent.Connected;

    public ulong? PrimaryLuid { get; init; }

    /// <summary>Все туннели, которые служба поднимает, и группы-заполнители балансировки.</summary>
    public IReadOnlyList<TunnelInput> Tunnels { get; init; } = [];

    public IReadOnlyList<uint> ServiceDnsAddresses { get; init; } = [];

    public string ServiceExecutablePath { get; init; } = "";

    /// <summary>
    /// Путь к программе движка «VPN поверх SSH»; пусто - файла нет (тогда фильтры по приложению не строятся:
    /// WFP не выдаёт идентификатор отсутствующего файла, а служба движок не запускает).
    /// </summary>
    public string SshEngineExecutablePath { get; init; } = "";

    public IReadOnlyList<Ipv4Cidr> OnLinkPrefixes { get; init; } = [];

    public IReadOnlyList<TrustedAdapterInput> TrustedAdapters { get; init; } = [];

    /// <summary>
    /// Публичные маршрутизаторы недоверенных адаптеров (<see cref="PolicyCompiler.SelectOnLinkPrefixes"/>): пока политика
    /// считает адрес локальным (правило или закрепление его не забрало), защита пропускает его только через свой адаптер.
    /// </summary>
    public IReadOnlyList<AdapterGateway> AdapterGateways { get; init; } = [];

    /// <summary>
    /// Узлы проверки отзыва, пока она нужна туннелю, который не поднят: открываются только TCP на порт ссылки
    /// и только через основной адаптер. Остальной трафик к этим адресам идёт по общей политике.
    /// </summary>
    public IReadOnlyList<RevocationEndpoint> RevocationEndpoints { get; init; } = [];

    /// <summary>
    /// Узлы проверки интернета Windows (NCSI, www.msftconnecttest.com): открываются только TCP на порт 80 и только
    /// через основной адаптер. Без этого сразу после подключения Wi-Fi, пока VPN ещё не поднят, Windows считает сеть
    /// «без интернета» и сама сбрасывает адаптер Wi-Fi, обрывая только что поднятый туннель.
    /// </summary>
    public IReadOnlyList<RevocationEndpoint> ConnectivityCheckEndpoints { get; init; } = [];

    /// <summary>
    /// Узлы издателя, с которых служба сама скачивает недостающий промежуточный сертификат: открываются только
    /// процессу службы, только TCP на порт ссылки и только через основной адаптер, на время загрузки.
    /// </summary>
    public IReadOnlyList<RevocationEndpoint> ServiceFetchEndpoints { get; init; } = [];
}

/// <summary>Схема весов WFP из плана реализации (раздел «Схема WFP»).</summary>
public static class FilterPlanBuilder
{
    public const byte WeightLoopback = 15;

    /// <summary>
    /// Ограничения движка «VPN поверх SSH» и запрет UDP в его туннеле: высший вес, выше разрешений для доменов
    /// и служебных узлов. Вес общий с петлевым разрешением, порядок между ними не определён: движок настроен
    /// без локальных слушателей и петлевой интерфейс не использует.
    /// </summary>
    public const byte WeightEngineGuard = 15;
    public const byte WeightDomain = 14;
    public const byte WeightUserBlock = 13;
    public const byte WeightInfrastructure = 12;
    public const byte WeightRouteGuard = 11;
    public const byte WeightTunnel = 10;
    public const byte WeightDnsGuard = 9;
    public const byte WeightAllowAllOnOutage = 8;
    public const byte WeightLocal = 7;
    public const byte WeightForeignInterface = 6;
    public const byte WeightBlockPublicOnOutage = 5;
    public const byte WeightDirect = 4;
    public const byte WeightBlockAll = 0;

    /// <summary>
    /// Разрешение проверки интернета Windows - вес правил для доменов, выше блока «Туннель недоступен» (13): адрес
    /// www.msftconnecttest.com из общей сети доставки может попасть в диапазон лежащего дополнительного туннеля, и
    /// при весе ниже 13 проба блокировалась бы, Windows помечала бы сеть «без интернета» и сбрасывала Wi-Fi.
    /// Разрешение узкое: только svchost.exe (NCSI), только TCP на порт пробы и только через основной адаптер, -
    /// поэтому чужая программа к тому же адресу и порту им не проходит, а попадает под обычные запреты.
    /// </summary>
    public const byte WeightConnectivityCheck = WeightDomain;

    /// <summary>
    /// Разрешение DNS службы (порт 53 к DNS сети только процессу службы от LocalSystem и только через основной адаптер)
    /// весит больше запрета пользователя и блока «Туннель недоступен» (13): адрес DNS сохраняет решение правил
    /// пользователя для программ (в туннель или «Блокировать»), но служба должна разрешать имена серверов VPN и при
    /// таком правиле, и пока туннель этого правила лежит. Закрепления по домену такой адрес не получают.
    /// </summary>
    public const byte WeightServiceDns = WeightDomain;

    /// <summary>
    /// %SystemRoot%\System32\svchost.exe: в нём живут клиент DHCP и проверка интернета Windows (NCSI), их разрешения
    /// действуют только для этого приложения.
    /// </summary>
    public static string SvchostExecutablePath { get; } = Path.Combine(Environment.SystemDirectory, "svchost.exe");

    public const byte ProtocolTcp = 6;
    public const byte ProtocolUdp = 17;
    public const byte ProtocolIcmpV6 = 58;
    public const byte ProtocolEsp = 50;

    /// <summary>IP-in-IP: так Windows помечает пакеты туннеля IPsec IKEv2 на уровне ALE.</summary>
    public const byte ProtocolIpInIp = 4;
    public const byte ProtocolGre = 47;

    private static readonly IPNetwork[] LocalV6 =
    [
        IPNetwork.Parse("fc00::/7"),
        IPNetwork.Parse("fe80::/10"),
        IPNetwork.Parse("ff00::/8"),
    ];

    public static IReadOnlyList<FilterSpec> BuildBase(ProtectionInputs inputs)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        var filters = new List<FilterSpec>
        {
            Spec("Loopback", FilterGroup.Base, FilterFamily.Both, WeightLoopback, FilterAction.Permit, new LoopbackCondition()),
            // Клиент DHCP — служба Dhcp в svchost.exe; разрешение только ей, как в стандартных правилах брандмауэра
            // Windows «Основы сетей — DHCP». Иначе любая программа ходила бы с порта 68 на 67 мимо защиты.
            Spec("DHCPv4", FilterGroup.Base, FilterFamily.V4, WeightInfrastructure, FilterAction.Permit,
                new AppIdCondition(SvchostExecutablePath), new ProtocolCondition(ProtocolUdp), new LocalPortRange(68, 68), new RemotePortCondition(67)),
            Spec("DHCPv6", FilterGroup.Base, FilterFamily.V6, WeightInfrastructure, FilterAction.Permit,
                new AppIdCondition(SvchostExecutablePath), new ProtocolCondition(ProtocolUdp), new LocalPortRange(546, 546), new RemotePortCondition(547)),
            Spec("IPv6 ND", FilterGroup.Base, FilterFamily.V6, WeightInfrastructure, FilterAction.Permit,
                new ProtocolCondition(ProtocolIcmpV6), new LocalPortRange(133, 137)),
            Spec("DNS-страж UDP", FilterGroup.Base, FilterFamily.Both, WeightDnsGuard, FilterAction.Block,
                new ProtocolCondition(ProtocolUdp), new RemotePortCondition(53)),
            Spec("DNS-страж TCP", FilterGroup.Base, FilterFamily.Both, WeightDnsGuard, FilterAction.Block,
                new ProtocolCondition(ProtocolTcp), new RemotePortCondition(53)),
            Spec("Блокировать всё", FilterGroup.Base, FilterFamily.Both, WeightBlockAll, FilterAction.Block),
        };

        filters.AddRange(inputs.Policy.BlockRanges.Select(r =>
            Spec("Правило: блокировать " + r, FilterGroup.Base, FilterFamily.V4, WeightUserBlock, FilterAction.Block, new RemoteRangeV4(r.Start, r.End))));

        if (inputs.LocalAccess)
        {
            filters.AddRange(SpecialRanges.Local.Select(r =>
                Spec("Локальная сеть " + r, FilterGroup.Base, FilterFamily.V4, WeightLocal, FilterAction.Permit, new RemoteRangeV4(r.Start, r.End))));
            filters.AddRange(LocalV6.Select(n =>
                Spec("Локальная сеть " + n, FilterGroup.Base, FilterFamily.V6, WeightLocal, FilterAction.Permit, new RemotePrefixV6(n))));
        }

        return filters;
    }

    public static IReadOnlyList<FilterSpec> BuildDirect(ProtectionInputs inputs)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        var filters = new List<FilterSpec>();
        foreach (var (label, chunk) in Chunks(inputs.Policy.DirectRanges))
        {
            filters.Add(Spec("Напрямую " + label, FilterGroup.Direct, FilterFamily.V4, WeightDirect, FilterAction.Permit, chunk));
            filters.Add(RouteGuard("Прямой путь " + label, FilterGroup.Direct, chunk, inputs.PrimaryLuid));
        }

        // Без явного правила к серверу пропускается только транспорт туннеля (Runtime).
        foreach (var server in inputs.Policy.DirectServerAddresses)
        {
            var name = Ipv4.Format(server);
            var address = new RemoteRangeV4(server, server);
            filters.Add(Spec("Напрямую к серверу " + name, FilterGroup.Direct, FilterFamily.V4, WeightDirect, FilterAction.Permit, address));
            filters.Add(RouteGuard("Прямой путь к серверу " + name, FilterGroup.Direct, address, inputs.PrimaryLuid));
        }

        // Диапазонов туннеля может быть много: они обновляются по разнице, без полного
        // пересоздания и тысяч точечных проверок WFP при каждой сверке Runtime.
        foreach (var tunnel in inputs.Tunnels.Where(t => t.Luid is not null))
        {
            filters.AddRange(Chunks(inputs.Policy.RangesFor(tunnel.Id)).Select(c => RouteGuard(
                "Назначение " + Describe(tunnel) + ": " + c.Label, FilterGroup.Direct, c.Condition, tunnel.Luid)));
        }

        return filters;
    }

    /// <summary>Сколько диапазонов умещается в один фильтр группы Direct.</summary>
    public const int MaxRangesPerFilter = 512;

    /// <summary>Ширина корзины адресов: диапазоны одной подсети /6 попадают в одни фильтры.</summary>
    private const int ChunkBucketBits = 6;

    /// <summary>
    /// Пакеты диапазонов для фильтров с условием «любой из». Пакеты привязаны к подсетям /6, поэтому изменение
    /// диапазонов в одной части адресного пространства пересоздаёт только её фильтры. Имя пакета несёт контрольную
    /// сумму состава: разностная замена группы Direct сравнивает фильтры по имени.
    /// </summary>
    internal static IEnumerable<(string Label, RemoteRangesV4 Condition)> Chunks(RangeSet ranges)
    {
        foreach (var bucket in ranges.GroupBy(r => r.Start >> (32 - ChunkBucketBits)))
        {
            var items = bucket.ToArray();
            for (var offset = 0; offset < items.Length; offset += MaxRangesPerFilter)
            {
                var part = items.AsSpan(offset, Math.Min(MaxRangesPerFilter, items.Length - offset)).ToArray();
                var label = string.Create(CultureInfo.InvariantCulture,
                    $"{Ipv4.Format(bucket.Key << (32 - ChunkBucketBits))}/{ChunkBucketBits} #{(offset / MaxRangesPerFilter) + 1}: {part.Length} диап. {Checksum(part):x8}");
                yield return (label, new RemoteRangesV4(part));
            }
        }
    }

    /// <summary>FNV-1a по границам диапазонов: одинаковая во всех процессах, в отличие от HashCode.</summary>
    private static uint Checksum(Ipv4Range[] ranges)
    {
        var hash = 2166136261u;
        foreach (var range in ranges)
        {
            foreach (var value in (ReadOnlySpan<uint>)[range.Start, range.End])
            {
                for (var shift = 0; shift < 32; shift += 8)
                {
                    hash = (hash ^ ((value >> shift) & 0xFF)) * 16777619u;
                }
            }
        }

        return hash;
    }

    /// <summary>
    /// Разрешения и блокировки по адресам, полученным из правил для доменов. Адрес, назначенный в туннель,
    /// выпускается только через его интерфейс: маршрут /32 мог не примениться, и тогда адрес ушёл бы
    /// напрямую или в чужой туннель — не туда, куда его назначил пользователь. Пока туннель не поднят,
    /// адрес не выпускается вовсе.
    /// </summary>
    public static IReadOnlyList<FilterSpec> BuildDynamic(ProtectionInputs inputs) => BuildDynamic(inputs, null);

    internal static IReadOnlyList<FilterSpec> BuildDynamic(ProtectionInputs inputs, DomainFilterCache? cache)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        var filters = new List<FilterSpec>(inputs.Policy.Pins.Count);
        var interfaces = new Dictionary<Guid, ulong?>();
        foreach (var tunnel in inputs.Tunnels) { interfaces.TryAdd(tunnel.Id, tunnel.Luid); }
        var blockPublic = inputs.OutageMode == OutageMode.BlockAllPublic && DefaultDown(inputs);
        foreach (var host in inputs.Policy.Pins)
        {
            var kind = host.Target.Kind;
            ulong? luid = kind == TargetKind.Direct
                ? (blockPublic && !SpecialRanges.Local.Contains(host.Address) ? null : inputs.PrimaryLuid)
                : (host.Target.Id is { } id ? interfaces.GetValueOrDefault(id) : null);
            var key = (host.Address, kind, luid);
            if (cache is null || !cache.Reuse(key, filters))
            {
                var start = filters.Count;
                AddHostFilters(filters, host.Address, kind, luid);
                cache?.Remember(key, filters, start);
            }
        }
        cache?.Complete();
        AddRevocationEndpoints(inputs, filters);
        AddServiceFetchEndpoints(inputs, filters);
        return filters;
    }

    private static void AddHostFilters(List<FilterSpec> filters, uint ip, TargetKind kind, ulong? luid)
    {
        var name = Ipv4.Format(ip);
        var address = new RemoteRangeV4(ip, ip);
        if (kind == TargetKind.Block)
        {
            filters.Add(Spec("Домен заблокирован " + name, FilterGroup.Dynamic, FilterFamily.V4, WeightDomain, FilterAction.Block, address));
            return;
        }

        var direct = kind == TargetKind.Direct;
        AddDomainPath(filters, (direct ? "Домен напрямую " : "Домен через VPN ") + name, address, luid, direct);
    }

    /// <summary>
    /// Загрузка промежуточного сертификата самой службой: адрес взят из ещё не проверенного сертификата, поэтому
    /// разрешение действует только для процесса службы от LocalSystem - другие программы к этому адресу не пропускаются.
    /// </summary>
    private static void AddServiceFetchEndpoints(ProtectionInputs inputs, List<FilterSpec> filters)
    {
        if (inputs.PrimaryLuid is not { } primary || string.IsNullOrEmpty(inputs.ServiceExecutablePath))
        {
            return;
        }

        foreach (var endpoint in inputs.ServiceFetchEndpoints.Distinct())
        {
            filters.Add(Spec(
                string.Create(CultureInfo.InvariantCulture, $"Издатель сертификата для службы {Ipv4.Format(endpoint.Address)}:{endpoint.Port}"),
                FilterGroup.Dynamic,
                FilterFamily.V4,
                WeightDomain,
                FilterAction.Permit,
                new AppIdCondition(inputs.ServiceExecutablePath),
                new LocalSystemUserCondition(),
                new RemoteRangeV4(endpoint.Address, endpoint.Address),
                new ProtocolCondition(ProtocolTcp),
                new RemotePortCondition(endpoint.Port),
                new LocalInterfaceCondition(primary, NotEqual: false)));
        }
    }

    /// <summary>
    /// Проверка отзыва сертификата сервера, пока она нужна неподнятому туннелю: Windows скачивает список отзыва
    /// по http до подъёма туннеля. Открывается только TCP на порт ссылки через основной адаптер - не любой
    /// трафик к адресу, который часто принадлежит общей сети доставки. Вес домена: разрешение действует и при
    /// обрыве с блокировкой публичного трафика, иначе за защитой туннель не поднять.
    /// </summary>
    private static void AddRevocationEndpoints(ProtectionInputs inputs, List<FilterSpec> filters)
    {
        AddPrimaryTcpEndpoints(inputs.PrimaryLuid, inputs.RevocationEndpoints, "Проверка отзыва", WeightDomain, null, filters);
        // Адреса узла проверки служба узнаёт через DNS основной (возможно, чужой) сети, поэтому разрешение получает
        // только NCSI в svchost.exe (вес - WeightConnectivityCheck, выше блока «Туннель недоступен»).
        AddPrimaryTcpEndpoints(inputs.PrimaryLuid, inputs.ConnectivityCheckEndpoints, "Проверка интернета Windows",
            WeightConnectivityCheck, new AppIdCondition(SvchostExecutablePath), filters);
    }

    private static void AddPrimaryTcpEndpoints(
        ulong? primaryLuid,
        IReadOnlyList<RevocationEndpoint> endpoints,
        string label,
        byte weight,
        AppIdCondition? app,
        List<FilterSpec> filters)
    {
        if (primaryLuid is not { } primary)
        {
            return;
        }

        foreach (var endpoint in endpoints.Distinct())
        {
            filters.Add(Spec(
                string.Create(CultureInfo.InvariantCulture, $"{label} {Ipv4.Format(endpoint.Address)}:{endpoint.Port}"),
                FilterGroup.Dynamic,
                FilterFamily.V4,
                weight,
                FilterAction.Permit,
                [
                    .. app is null ? Array.Empty<FilterCondition>() : [app],
                    new RemoteRangeV4(endpoint.Address, endpoint.Address),
                    new ProtocolCondition(ProtocolTcp),
                    new RemotePortCondition(endpoint.Port),
                    new LocalInterfaceCondition(primary, NotEqual: false),
                ]));
        }
    }

    /// <summary>Домен важнее адресных слоёв, но прямой DNS по-прежнему проходит только через посредник.</summary>
    private static void AddDomainPath(List<FilterSpec> filters, string name, RemoteRangeV4 address, ulong? luid, bool direct)
    {
        if (luid is not { } active)
        {
            filters.Add(Spec(name, FilterGroup.Dynamic, FilterFamily.V4, WeightDomain, FilterAction.Block, address));
            return;
        }

        filters.Add(Spec(name + ": чужой интерфейс", FilterGroup.Dynamic, FilterFamily.V4, WeightDomain, FilterAction.Block,
            address, new LocalInterfaceCondition(active, NotEqual: true)));
        var conditions = new List<FilterCondition> { address, new LocalInterfaceCondition(active, NotEqual: false) };
        if (direct)
        {
            conditions.Add(new RemotePortCondition(53, NotEqual: true));
        }

        filters.Add(new FilterSpec(name, FilterGroup.Dynamic, FilterFamily.V4, WeightDomain, FilterAction.Permit, conditions));
    }

    private static FilterSpec RouteGuard(string name, FilterGroup group, FilterCondition address, ulong? luid) =>
        luid is { } active
            ? Spec(name, group, FilterFamily.V4, WeightRouteGuard, FilterAction.Block, address, new LocalInterfaceCondition(active, NotEqual: true))
            : Spec(name, group, FilterFamily.V4, WeightRouteGuard, FilterAction.Block, address);

    public static IReadOnlyList<FilterSpec> BuildRuntime(ProtectionInputs inputs)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        var filters = new List<FilterSpec>();
        AddServerTransport(inputs, filters);
        AddServiceDns(inputs, filters);
        AddTunnelsAndOutage(inputs, filters);
        AddSshEngineGuard(inputs, filters);

        if (inputs.LocalAccess)
        {
            // Сети доверенных адаптеров (кроме основного) открывает только их разрешение, привязанное к интерфейсу (ниже):
            // без условия на интерфейс адреса выключенного Radmin (26.0.0.0/8) или ZeroTier при лежащем VPN ушли бы через
            // основной адаптер мимо защиты - сети адаптера служба помнит, пока он есть в системе. Частные диапазоны не
            // вычитаются: их и так пропускает «Локальная сеть», а сеть основного адаптера может совпасть с сетью доверенного.
            // Не вычитаются и зарезервированные диапазоны, частные в сети любого адаптера (192.0.0.0/29 DS-Lite, 198.18.0.0/15
            // fake-IP TUN; PolicyCompiler.IsPrivateOnLink): та же сеть бывает и у недоверенного адаптера, а в интернете этих
            // адресов нет - разрешение без привязки к интерфейсу публичных адресов не открывает.
            var foreignTrusted = PolicyCompiler.OnLinkSet(inputs.TrustedAdapters.Where(a => a.Luid != inputs.PrimaryLuid).SelectMany(a => a.Prefixes));
            var notSubtracted = SpecialRanges.Local.Union(PolicyCompiler.PrivateOnLinkReserved);
            filters.AddRange(PolicyCompiler.OnLinkSet(inputs.OnLinkPrefixes).Subtract(foreignTrusted.Subtract(notSubtracted)).Select(r =>
                Spec("Сеть интерфейса " + r, FilterGroup.Runtime, FilterFamily.V4, WeightLocal, FilterAction.Permit, new RemoteRangeV4(r.Start, r.End))));

            // Публичный маршрутизатор недоверенного адаптера - только через этот адаптер и только пока политика считает его
            // локальным: правило или закрепление в туннель важнее (точка доступа, назвавшая маршрутизатором адрес
            // Telegram, не выведет его из VPN). Транспорт VPN, DHCP и DNS службы доступа к самому маршрутизатору не требуют.
            foreach (var gateway in inputs.AdapterGateways.Distinct()
                .Where(g => inputs.Policy.Classify(g.Address) is { Decision: Decision.Local, Source: DecisionSource.LocalNetwork }))
            {
                filters.Add(Spec("Маршрутизатор " + Ipv4.Format(gateway.Address), FilterGroup.Runtime, FilterFamily.V4, WeightLocal, FilterAction.Permit,
                    new RemoteRangeV4(gateway.Address, gateway.Address), new LocalInterfaceCondition(gateway.Luid, NotEqual: false)));
            }
        }

        // Разрешение по интерфейсу: не зависит от «Локального доступа» и не мигает, пока адрес адаптера меняется
        // (сети запоминаются). Назначения - только сети самого адаптера (on-link и его маршруты не короче /8) и локальные
        // диапазоны: при обрыве в режиме «Блокировать весь публичный» (вес 5) разрешение весом 7 без адресов выпустило бы
        // через такой адаптер (выход Tailscale, ZeroTier) весь интернет. DNS-страж и блокировки пользователя весят больше.
        foreach (var adapter in inputs.TrustedAdapters.Where(a => a.Luid != inputs.PrimaryLuid))
        {
            var name = "Доверенный адаптер «" + adapter.Name + "»";
            var own = SpecialRanges.Local.Union(PolicyCompiler.OnLinkSet(adapter.Prefixes));
            filters.Add(Spec(name, FilterGroup.Runtime, FilterFamily.V4, WeightLocal, FilterAction.Permit,
                new RemoteRangesV4(own), new LocalInterfaceCondition(adapter.Luid, NotEqual: false)));
            filters.AddRange(LocalV6.Concat(adapter.PrefixesV6.Where(n => n.PrefixLength is >= 8 and <= 128)).Distinct().Select(n => Spec(
                name + ": " + n, FilterGroup.Runtime, FilterFamily.V6, WeightLocal, FilterAction.Permit,
                new RemotePrefixV6(n), new LocalInterfaceCondition(adapter.Luid, NotEqual: false))));
        }

        var foreignInterface = inputs.PrimaryLuid is { } primary
            ? Spec("Не основной адаптер", FilterGroup.Runtime, FilterFamily.Both, WeightForeignInterface, FilterAction.Block, new LocalInterfaceCondition(primary, NotEqual: true))
            : Spec("Нет основного адаптера", FilterGroup.Runtime, FilterFamily.Both, WeightForeignInterface, FilterAction.Block);
        filters.Add(foreignInterface);
        return filters;
    }

    /// <summary>
    /// Обрыв: намерение «подключено», а «остальной интернет» нести некому. Ручное отключение с защитой - не обрыв
    /// для режима «разрешить всё», как и носители, положенные пользователем: их трафик остаётся заблокированным.
    /// </summary>
    public static bool IsOutage(ProtectionInputs inputs)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        return DefaultDown(inputs) && inputs.Intent == Intent.Connected && !DefaultPaused(inputs);
    }

    /// <summary>Все туннели, которым назначен «остальной интернет», лежат.</summary>
    private static bool DefaultDown(ProtectionInputs inputs)
    {
        var carriers = inputs.Tunnels.Where(t => t.ServesDefault).ToList();
        return carriers.Count > 0 && carriers.TrueForAll(t => t.Luid is null);
    }

    /// <summary>Все носители «остального интернета» положены пользователем.</summary>
    private static bool DefaultPaused(ProtectionInputs inputs)
    {
        var carriers = inputs.Tunnels.Where(t => t.ServesDefault).ToList();
        return carriers.Count > 0 && carriers.TrueForAll(t => t.Paused);
    }

    private static void AddServerTransport(ProtectionInputs inputs, List<FilterSpec> filters)
    {
        if (inputs.PrimaryLuid is not { } primary)
        {
            return;
        }

        foreach (var tunnel in inputs.Tunnels)
        {
            foreach (var address in tunnel.ServerAddresses.Distinct())
            {
                foreach (var (protocol, port) in Transports(tunnel))
                {
                    var conditions = new List<FilterCondition>
                    {
                        new ProtocolCondition(protocol),
                        new RemoteRangeV4(address, address),
                        new LocalInterfaceCondition(primary, NotEqual: false),
                    };
                    if (port is { } value)
                    {
                        conditions.Add(new RemotePortCondition(value));
                    }

                    filters.Add(new FilterSpec(
                        string.Create(CultureInfo.InvariantCulture, $"{tunnel.Protocol}-сервер {Ipv4.Format(address)} ({protocol}/{port})"),
                        FilterGroup.Runtime,
                        FilterFamily.V4,
                        WeightInfrastructure,
                        FilterAction.Permit,
                        conditions));
                }
            }
        }
    }

    /// <summary>
    /// «VPN поверх SSH». Процессу движка разрешён один путь: TCP на адрес и порт своего сервера через основной
    /// адаптер. Всё остальное блокируется с высшим весом - даже то, что другим программам открывают правила
    /// «напрямую», домены и служебные узлы: ошибка в настройках движка или в маршрутах не станет выходом мимо
    /// туннеля и не замкнёт движок на собственный адаптер. Каждый фильтр несёт одно условие «не равно»; пакет
    /// проходит, только если не совпал ни с одним. В самом туннеле блокируется UDP: SSH его не переносит, и
    /// программа получает отказ сразу, а не ждёт ответа (браузер переходит с QUIC на TCP).
    /// </summary>
    private static void AddSshEngineGuard(ProtectionInputs inputs, List<FilterSpec> filters)
    {
        foreach (var tunnel in inputs.Tunnels.Where(t => t.Protocol == VpnProtocol.SshVpn))
        {
            if (tunnel.Luid is { } luid)
            {
                filters.Add(Spec("Туннель " + Describe(tunnel) + ": без UDP", FilterGroup.Runtime, FilterFamily.Both, WeightEngineGuard,
                    FilterAction.Block, new ProtocolCondition(ProtocolUdp), new LocalInterfaceCondition(luid, NotEqual: false)));
            }

            if (string.IsNullOrEmpty(inputs.SshEngineExecutablePath))
            {
                continue;
            }

            var app = new AppIdCondition(inputs.SshEngineExecutablePath);
            var name = "Движок SSH " + Describe(tunnel) + ": ";
            if (inputs.PrimaryLuid is not { } primary || tunnel.EngineServerAddress is not { } server)
            {
                filters.Add(Spec(name + "нет сеанса", FilterGroup.Runtime, FilterFamily.Both, WeightEngineGuard, FilterAction.Block, app));
                continue;
            }

            filters.Add(Spec(name + "только сервер", FilterGroup.Runtime, FilterFamily.V4, WeightEngineGuard, FilterAction.Block,
                app, new RemoteAddressNotV4(server)));
            filters.Add(Spec(name + "только порт сервера", FilterGroup.Runtime, FilterFamily.V4, WeightEngineGuard, FilterAction.Block,
                app, new RemotePortCondition(tunnel.ServerPort, NotEqual: true)));
            filters.Add(Spec(name + "только TCP", FilterGroup.Runtime, FilterFamily.V4, WeightEngineGuard, FilterAction.Block,
                app, new ProtocolCondition(ProtocolTcp, NotEqual: true)));
            filters.Add(Spec(name + "только основной адаптер", FilterGroup.Runtime, FilterFamily.V4, WeightEngineGuard, FilterAction.Block,
                app, new LocalInterfaceCondition(primary, NotEqual: true)));
            filters.Add(Spec(name + "без IPv6", FilterGroup.Runtime, FilterFamily.V6, WeightEngineGuard, FilterAction.Block, app));
        }
    }

    /// <summary>Какие пакеты пропустить к серверу: у каждого протокола свой транспорт.</summary>
    private static (byte Protocol, ushort? Port)[] Transports(TunnelInput tunnel) => tunnel.Protocol switch
    {
        VpnProtocol.Sstp => [(ProtocolTcp, tunnel.ServerPort)],
        VpnProtocol.L2tpIpsec => [(ProtocolUdp, (ushort?)500), (ProtocolUdp, 4500), (ProtocolUdp, 1701), (ProtocolEsp, null)],
        VpnProtocol.Ikev2 => [(ProtocolUdp, (ushort?)500), (ProtocolUdp, 4500), (ProtocolEsp, null), (ProtocolIpInIp, null)],
        VpnProtocol.Pptp => [(ProtocolTcp, (ushort?)1723), (ProtocolGre, null)],
        // CSTP по TLS и DTLS по UDP — на порт шлюза, плюс порты, о которых сеанс узнал от шлюза: узел после
        // перенаправления и назначенный порт DTLS.
        VpnProtocol.AnyConnect => [
            .. tunnel.GatewayTcpPorts.Prepend(tunnel.ServerPort).Distinct().Select(p => (ProtocolTcp, (ushort?)p)),
            .. tunnel.GatewayUdpPorts.Prepend(tunnel.ServerPort).Distinct().Select(p => (ProtocolUdp, (ushort?)p))],
        VpnProtocol.SshVpn => [(ProtocolTcp, tunnel.ServerPort)],
        _ => throw new InvalidOperationException("Неподдерживаемый протокол VPN."),
    };

    private static void AddServiceDns(ProtectionInputs inputs, List<FilterSpec> filters)
    {
        if (string.IsNullOrEmpty(inputs.ServiceExecutablePath))
        {
            return;
        }

        // Служба спрашивает эти серверы только через основной адаптер (IP_UNICAST_IF): разрешение привязано к нему,
        // чтобы запрос не прошёл мимо через другой интерфейс с более узким маршрутом. Основной неизвестен — без привязки.
        filters.AddRange(inputs.ServiceDnsAddresses.Distinct().Select(address => Spec(
            "DNS службы " + Ipv4.Format(address),
            FilterGroup.Runtime,
            FilterFamily.V4,
            WeightServiceDns,
            FilterAction.Permit,
            [
                new AppIdCondition(inputs.ServiceExecutablePath),
                new LocalSystemUserCondition(),
                .. PrimaryInterface(inputs),
                new RemoteRangeV4(address, address),
                new RemotePortCondition(53),
            ])));

        foreach (var tunnel in inputs.Tunnels.Where(t => t.Luid is not null))
        {
            filters.AddRange(tunnel.DnsAddresses.Distinct().Select(address => Spec(
                "DNS туннеля " + Describe(tunnel) + ": " + Ipv4.Format(address), FilterGroup.Runtime, FilterFamily.V4,
                WeightInfrastructure, FilterAction.Permit, new AppIdCondition(inputs.ServiceExecutablePath),
                new LocalSystemUserCondition(), new LocalInterfaceCondition(tunnel.Luid!.Value, NotEqual: false),
                new RemoteRangeV4(address, address), new RemotePortCondition(53))));
        }
    }

    private static void AddTunnelsAndOutage(ProtectionInputs inputs, List<FilterSpec> filters)
    {
        foreach (var tunnel in inputs.Tunnels.Where(t => t.Luid is not null))
        {
            // Туннель AnyConnect - только IPv4 (помощник отключает IPv6 в сеансе, маршруты и ограничения назначений
            // защиты - только IPv4). Если отключить IPv6 не удалось и шлюз назначил адрес IPv6 с ::/0, разрешение для
            // обоих семейств увело бы в корпоративный туннель весь IPv6 компьютера: IPv6 через него блокируется.
            filters.Add(Spec(
                "Туннель " + Describe(tunnel),
                FilterGroup.Runtime,
                tunnel.Protocol == VpnProtocol.AnyConnect ? FilterFamily.V4 : FilterFamily.Both,
                WeightTunnel,
                FilterAction.Permit,
                new LocalInterfaceCondition(tunnel.Luid!.Value, NotEqual: false)));
            if (tunnel.Protocol == VpnProtocol.AnyConnect)
            {
                // И локальные IPv6 (разрешение «Локальная сеть» не привязано к интерфейсу) через этот туннель не идут.
                filters.Add(Spec("Туннель " + Describe(tunnel) + ": без IPv6", FilterGroup.Runtime, FilterFamily.V6, WeightTunnel,
                    FilterAction.Block, new LocalInterfaceCondition(tunnel.Luid!.Value, NotEqual: false)));
            }
        }

        // Туннель не поднят: назначения неопорного блокируются, иначе они ушли бы по маршруту /1 в чужой
        // туннель или напрямую - не туда, куда их назначил пользователь. У носителя «остального интернета»
        // публичные адреса держит обрыв (блокировка всего), а частные и сети адаптеров, назначенные ему правилом,
        // пропустило бы разрешение «Локальная сеть» - через Wi-Fi или LAN, мимо лежащего, положенного или снятого
        // туннеля. Для него блокируются только они, и снимает это лишь настоящий обрыв в режиме «Разрешить всё».
        // Обрыва нет, пока жив другой участник группы «остального интернета»: тогда у лежащего остаются только
        // назначенные ему правилами адреса, и они блокируются целиком, иначе ушли бы в туннель другого участника.
        var allowAllOutage = inputs.OutageMode == OutageMode.AllowAll && IsOutage(inputs);
        var defaultDown = DefaultDown(inputs);
        var local = SpecialRanges.Local.Union(PolicyCompiler.OnLinkSet(inputs.OnLinkPrefixes));
        foreach (var tunnel in inputs.Tunnels.Where(t => t.Luid is null && !(t.ServesDefault && allowAllOutage)))
        {
            var ranges = inputs.Policy.RangesFor(tunnel.Id);
            if (tunnel.ServesDefault && defaultDown)
            {
                ranges = ranges.Intersect(local);
            }

            // Пакетами, как группа Direct: группа Runtime пересоздаётся целиком при каждом подъёме и обрыве
            // туннеля, и фильтр на каждый диапазон списка обхода давал бы десятки тысяч фильтров за раз.
            filters.AddRange(Chunks(ranges).Select(c => Spec(
                "Туннель недоступен " + Describe(tunnel) + ": " + c.Label,
                FilterGroup.Runtime,
                FilterFamily.V4,
                WeightUserBlock,
                FilterAction.Block,
                c.Condition)));
        }

        if (!DefaultDown(inputs))
        {
            return;
        }

        if (inputs.OutageMode == OutageMode.BlockAllPublic)
        {
            filters.Add(Spec("Обрыв: блокировать весь публичный", FilterGroup.Runtime, FilterFamily.Both, WeightBlockPublicOnOutage, FilterAction.Block));
        }
        else if (allowAllOutage)
        {
            filters.Add(Spec("Обрыв: разрешить всё", FilterGroup.Runtime, FilterFamily.Both, WeightAllowAllOnOutage, FilterAction.Permit));
        }
    }

    private static string Describe(TunnelInput tunnel) => string.IsNullOrEmpty(tunnel.Name) ? tunnel.Id.ToString() : "«" + tunnel.Name + "»";

    /// <summary>Условие «через основной адаптер»; пусто, если основной адаптер неизвестен.</summary>
    private static FilterCondition[] PrimaryInterface(ProtectionInputs inputs) =>
        inputs.PrimaryLuid is { } primary ? [new LocalInterfaceCondition(primary, NotEqual: false)] : [];

    private static FilterSpec Spec(string name, FilterGroup group, FilterFamily family, byte weight, FilterAction action, params FilterCondition[] conditions) =>
        new(name, group, family, weight, action, conditions);
}
