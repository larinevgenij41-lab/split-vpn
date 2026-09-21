using SplitVpn.Core.Net;

namespace SplitVpn.Core.Policy;

/// <summary>Куда направляется трафик: напрямую, в туннель, в группу туннелей или в блок.</summary>
public enum TargetKind
{
    Direct,
    Tunnel,
    Block,

    /// <summary>Группа туннелей: нагрузка распределяется между её участниками.</summary>
    Group,
}

/// <summary>
/// Цель маршрутизации. Заменяет пару «режим маршрутизации + действие правила» из v1:
/// одна и та же цель назначается RU-базе, остальному интернету, подсети и домену.
/// Id — идентификатор подключения для Tunnel и идентификатор группы для Group.
/// </summary>
public readonly record struct RouteTarget(TargetKind Kind, Guid? Id = null)
{
    public static RouteTarget Direct { get; } = new(TargetKind.Direct);

    public static RouteTarget Blocked { get; } = new(TargetKind.Block);

    public static RouteTarget Tunnel(Guid id) => new(TargetKind.Tunnel, id);

    public static RouteTarget Group(Guid id) => new(TargetKind.Group, id);

    public bool IsTunnel(out Guid id)
    {
        id = Id ?? Guid.Empty;
        return Kind == TargetKind.Tunnel && Id is not null;
    }

    public bool IsGroup(out Guid id)
    {
        id = Id ?? Guid.Empty;
        return Kind == TargetKind.Group && Id is not null;
    }

    /// <summary>Цель отправляет трафик в туннель — сам по себе или через группу.</summary>
    public bool IsVpn => Kind is TargetKind.Tunnel or TargetKind.Group && Id is not null;

    public override string ToString() => Kind switch
    {
        TargetKind.Direct => "напрямую",
        TargetKind.Block => "блокировать",
        TargetKind.Group => Id is { } group ? "группа " + group : "группа не указана",
        _ => Id is { } id ? "туннель " + id : "туннель не указан",
    };
}

/// <summary>Итоговое решение для адреса назначения.</summary>
public enum Decision
{
    Vpn,
    Direct,
    Block,
    Local,
    Server,
}

public enum DecisionSource
{
    Default,
    Geo,

    /// <summary>Список обхода блокировок: перекрывает RU-базу, но не правила пользователя.</summary>
    Bypass,

    UserRule,
    LocalNetwork,
    OnLink,
    Loopback,
    Reserved,
    Server,
    ServiceDns,

    /// <summary>Сеть, присланная шлюзом AnyConnect (split include).</summary>
    ServerNetwork,

    /// <summary>Служебный адрес туннеля (его DNS): всегда через свой туннель, что бы ни прислал шлюз.</summary>
    TunnelInfrastructure,
}

/// <summary>Сети шлюза и цель, в которую их направил пользователь.</summary>
public sealed record ServerNetworks(RouteTarget Target, IReadOnlyList<Ipv4Cidr> Cidrs);

/// <summary>Служебный адрес туннеля, который должен идти через этот туннель.</summary>
public readonly record struct TunnelHost(Guid Tunnel, uint Address);

public sealed record UserRule(Ipv4Cidr Cidr, RouteTarget Target, string? Comment = null);

/// <summary>
/// Группа туннелей с уже отобранными участниками: служба передаёт только те, что сейчас годны
/// (при распределении — все поднятые, при резервировании — первый поднятый). Пустой список
/// означает, что группа целиком недоступна.
/// </summary>
public sealed record TunnelGroup(Guid Id, IReadOnlyList<Guid> Members);

/// <summary>Решение и его происхождение; Tunnel заполнен только при Decision.Vpn.</summary>
public readonly record struct Classification(Decision Decision, DecisionSource Source, UserRule? Rule, Guid Tunnel = default);

/// <summary>Входные данные компилятора политики.</summary>
public sealed record PolicyInput
{
    /// <summary>Куда идёт «остальной интернет» — всё, что не попало ни в одно правило.</summary>
    public RouteTarget DefaultTarget { get; init; } = RouteTarget.Direct;

    /// <summary>Куда идут адреса из RU-базы.</summary>
    public RouteTarget GeoTarget { get; init; } = RouteTarget.Direct;

    public RangeSet Geo { get; init; } = RangeSet.Empty;

    /// <summary>
    /// Куда идут адреса из списка обхода блокировок. Слой ложится поверх RU-базы: заблокированный
    /// ресурс на российском хостинге должен идти через VPN, иначе он так и останется недоступен.
    /// </summary>
    public RouteTarget BypassTarget { get; init; } = RouteTarget.Direct;

    public RangeSet Bypass { get; init; } = RangeSet.Empty;

    public IReadOnlyList<UserRule> Rules { get; init; } = [];

    /// <summary>Группы туннелей с годными участниками на момент сборки политики.</summary>
    public IReadOnlyList<TunnelGroup> Groups { get; init; } = [];

    /// <summary>On-link-префиксы интерфейсов (кроме туннелей), считаются локальными сетями.</summary>
    public IReadOnlyList<Ipv4Cidr> OnLinePrefixes { get; init; } = [];

    /// <summary>IPv4-адреса серверов всех активных туннелей: транспорт идёт через основной адаптер.</summary>
    public IReadOnlyList<uint> ServerAddresses { get; init; } = [];

    /// <summary>Адреса DNS, к которым обращается служба до туннеля (начальное разрешение, DNS LAN).</summary>
    public IReadOnlyList<uint> ServiceDnsAddresses { get; init; } = [];

    /// <summary>
    /// Сети поднятых шлюзов AnyConnect. Перекрывают пользовательские правила и частные диапазоны
    /// (шлюз присылает 10.0.0.0/8), но не реальные сети адаптеров и не служебные адреса.
    /// </summary>
    public IReadOnlyList<ServerNetworks> ServerNetworks { get; init; } = [];

    /// <summary>DNS-серверы туннелей: частная сеть шлюза не должна перехватить DNS другого туннеля.</summary>
    public IReadOnlyList<TunnelHost> TunnelHosts { get; init; } = [];
}
