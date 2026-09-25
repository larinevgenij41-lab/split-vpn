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

public sealed record RemotePrefixV6(IPNetwork Network) : FilterCondition;

public sealed record RemotePortCondition(ushort Port, bool NotEqual = false) : FilterCondition;

/// <summary>Локальный порт; для ICMP на слоях ALE здесь хранится тип сообщения.</summary>
public sealed record LocalPortRange(ushort Low, ushort High) : FilterCondition;

public sealed record ProtocolCondition(byte Protocol) : FilterCondition;

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

    public VpnProtocol Protocol { get; init; } = VpnProtocol.Sstp;

    /// <summary>Туннель несёт «остальной интернет»: если все такие туннели легли — это обрыв.</summary>
    public bool ServesDefault { get; init; }

    /// <summary>DNS этого туннеля: посреднику нужен доступ даже вне его адресных назначений.</summary>
    public IReadOnlyList<uint> DnsAddresses { get; init; } = [];
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

    public IReadOnlyList<Ipv4Cidr> OnLinkPrefixes { get; init; } = [];
}

/// <summary>Схема весов WFP из плана реализации (раздел «Схема WFP»).</summary>
public static class FilterPlanBuilder
{
    public const byte WeightLoopback = 15;
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

    public const byte ProtocolTcp = 6;
    public const byte ProtocolUdp = 17;
    public const byte ProtocolIcmpV6 = 58;
    public const byte ProtocolEsp = 50;
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
            Spec("DHCPv4", FilterGroup.Base, FilterFamily.V4, WeightInfrastructure, FilterAction.Permit,
                new ProtocolCondition(ProtocolUdp), new LocalPortRange(68, 68), new RemotePortCondition(67)),
            Spec("DHCPv6", FilterGroup.Base, FilterFamily.V6, WeightInfrastructure, FilterAction.Permit,
                new ProtocolCondition(ProtocolUdp), new LocalPortRange(546, 546), new RemotePortCondition(547)),
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
        foreach (var range in inputs.Policy.DirectRanges)
        {
            var address = new RemoteRangeV4(range.Start, range.End);
            filters.Add(Spec("Напрямую " + range, FilterGroup.Direct, FilterFamily.V4, WeightDirect, FilterAction.Permit, address));
            filters.Add(RouteGuard("Прямой путь " + range, FilterGroup.Direct, address, inputs.PrimaryLuid));
        }

        // Диапазонов туннеля может быть много: они обновляются по разнице, без полного
        // пересоздания и тысяч точечных проверок WFP при каждой сверке Runtime.
        foreach (var tunnel in inputs.Tunnels.Where(t => t.Luid is not null))
        {
            filters.AddRange(inputs.Policy.RangesFor(tunnel.Id).Select(r => RouteGuard(
                "Назначение " + Describe(tunnel) + ": " + r, FilterGroup.Direct,
                new RemoteRangeV4(r.Start, r.End), tunnel.Luid)));
        }

        return filters;
    }

    /// <summary>
    /// Разрешения и блокировки по адресам, полученным из правил для доменов. Адрес, назначенный в туннель,
    /// выпускается только через его интерфейс: маршрут /32 мог не примениться, и тогда адрес ушёл бы
    /// напрямую или в чужой туннель — не туда, куда его назначил пользователь. Пока туннель не поднят,
    /// адрес не выпускается вовсе.
    /// </summary>
    public static IReadOnlyList<FilterSpec> BuildDynamic(ProtectionInputs inputs)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        var filters = new List<FilterSpec>();
        foreach (var host in inputs.Policy.Pins)
        {
            var name = Ipv4.Format(host.Address);
            var address = new RemoteRangeV4(host.Address, host.Address);
            if (host.Target.Kind == TargetKind.Direct)
            {
                var blockOutage = DefaultDown(inputs) && inputs.OutageMode == OutageMode.BlockAllPublic
                    && !SpecialRanges.Local.Contains(host.Address);
                AddDomainPath(filters, "Домен напрямую " + name, address, blockOutage ? null : inputs.PrimaryLuid, direct: true);
                continue;
            }

            if (host.Target.Kind == TargetKind.Block)
            {
                filters.Add(Spec("Домен заблокирован " + name, FilterGroup.Dynamic, FilterFamily.V4, WeightDomain, FilterAction.Block, address));
                continue;
            }

            var tunnel = inputs.Tunnels.FirstOrDefault(t => host.Target.Id is { } id && t.Id == id);
            AddDomainPath(filters, "Домен через VPN " + name, address, tunnel?.Luid, direct: false);
        }

        return filters;
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

    private static FilterSpec RouteGuard(string name, FilterGroup group, RemoteRangeV4 address, ulong? luid) =>
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

        if (inputs.LocalAccess)
        {
            filters.AddRange(PolicyCompiler.OnLinkSet(inputs.OnLinkPrefixes).Select(r =>
                Spec("Сеть интерфейса " + r, FilterGroup.Runtime, FilterFamily.V4, WeightLocal, FilterAction.Permit, new RemoteRangeV4(r.Start, r.End))));
        }

        var foreignInterface = inputs.PrimaryLuid is { } primary
            ? Spec("Не основной адаптер", FilterGroup.Runtime, FilterFamily.Both, WeightForeignInterface, FilterAction.Block, new LocalInterfaceCondition(primary, NotEqual: true))
            : Spec("Нет основного адаптера", FilterGroup.Runtime, FilterFamily.Both, WeightForeignInterface, FilterAction.Block);
        filters.Add(foreignInterface);
        return filters;
    }

    /// <summary>Обрыв: намерение «подключено», а «остальной интернет» нести некому. Ручное отключение с защитой — не обрыв для режима «разрешить всё».</summary>
    public static bool IsOutage(ProtectionInputs inputs)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        return DefaultDown(inputs) && inputs.Intent == Intent.Connected;
    }

    /// <summary>Все туннели, которым назначен «остальной интернет», лежат.</summary>
    private static bool DefaultDown(ProtectionInputs inputs)
    {
        var carriers = inputs.Tunnels.Where(t => t.ServesDefault).ToList();
        return carriers.Count > 0 && carriers.TrueForAll(t => t.Luid is null);
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

    /// <summary>Какие пакеты пропустить к серверу: у каждого протокола свой транспорт.</summary>
    private static (byte Protocol, ushort? Port)[] Transports(TunnelInput tunnel) => tunnel.Protocol switch
    {
        VpnProtocol.Sstp => [(ProtocolTcp, tunnel.ServerPort)],
        VpnProtocol.L2tpIpsec => [(ProtocolUdp, (ushort?)500), (ProtocolUdp, 4500), (ProtocolUdp, 1701), (ProtocolEsp, null)],
        VpnProtocol.Ikev2 => [(ProtocolUdp, (ushort?)500), (ProtocolUdp, 4500), (ProtocolEsp, null)],
        VpnProtocol.Pptp => [(ProtocolTcp, (ushort?)1723), (ProtocolGre, null)],
        // CSTP по TLS и DTLS по UDP — на один и тот же порт шлюза.
        VpnProtocol.AnyConnect => [(ProtocolTcp, tunnel.ServerPort), (ProtocolUdp, tunnel.ServerPort)],
        _ => throw new InvalidOperationException("Неподдерживаемый протокол VPN."),
    };

    private static void AddServiceDns(ProtectionInputs inputs, List<FilterSpec> filters)
    {
        if (string.IsNullOrEmpty(inputs.ServiceExecutablePath))
        {
            return;
        }

        filters.AddRange(inputs.ServiceDnsAddresses.Distinct().Select(address => Spec(
            "DNS службы " + Ipv4.Format(address),
            FilterGroup.Runtime,
            FilterFamily.V4,
            WeightInfrastructure,
            FilterAction.Permit,
            new AppIdCondition(inputs.ServiceExecutablePath),
            new LocalSystemUserCondition(),
            new RemoteRangeV4(address, address),
            new RemotePortCondition(53))));

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
            filters.Add(Spec(
                "Туннель " + Describe(tunnel),
                FilterGroup.Runtime,
                FilterFamily.Both,
                WeightTunnel,
                FilterAction.Permit,
                new LocalInterfaceCondition(tunnel.Luid!.Value, NotEqual: false)));
        }

        // Неопорный туннель не поднят: его назначения блокируются, иначе они ушли бы по маршруту /1
        // в чужой туннель или напрямую — не туда, куда их назначил пользователь.
        foreach (var tunnel in inputs.Tunnels.Where(t => t is { Luid: null, ServesDefault: false }))
        {
            filters.AddRange(inputs.Policy.RangesFor(tunnel.Id).Select(r => Spec(
                "Туннель недоступен " + Describe(tunnel) + ": " + r,
                FilterGroup.Runtime,
                FilterFamily.V4,
                WeightUserBlock,
                FilterAction.Block,
                new RemoteRangeV4(r.Start, r.End))));
        }

        if (!DefaultDown(inputs))
        {
            return;
        }

        if (inputs.OutageMode == OutageMode.BlockAllPublic)
        {
            filters.Add(Spec("Обрыв: блокировать весь публичный", FilterGroup.Runtime, FilterFamily.Both, WeightBlockPublicOnOutage, FilterAction.Block));
        }
        else if (inputs.OutageMode == OutageMode.AllowAll && IsOutage(inputs))
        {
            filters.Add(Spec("Обрыв: разрешить всё", FilterGroup.Runtime, FilterFamily.Both, WeightAllowAllOnOutage, FilterAction.Permit));
        }
    }

    private static string Describe(TunnelInput tunnel) => string.IsNullOrEmpty(tunnel.Name) ? tunnel.Id.ToString() : "«" + tunnel.Name + "»";

    private static FilterSpec Spec(string name, FilterGroup group, FilterFamily family, byte weight, FilterAction action, params FilterCondition[] conditions) =>
        new(name, group, family, weight, action, conditions);
}
