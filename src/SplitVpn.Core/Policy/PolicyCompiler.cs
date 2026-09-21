using SplitVpn.Core.Net;

namespace SplitVpn.Core.Policy;

/// <summary>Согласованная адресная политика для маршрутов, фильтров и диагностики.</summary>
public sealed class CompiledPolicy
{
    private readonly IntervalPainter _painter;
    private readonly Dictionary<Guid, RangeSet> _tunnelRanges;
    private readonly Dictionary<Guid, IReadOnlyList<Ipv4Cidr>> _tunnelCidrs = [];

    internal CompiledPolicy(PolicyInput input, IntervalPainter painter)
    {
        _painter = painter;
        DefaultTarget = input.DefaultTarget;
        GeoTarget = input.GeoTarget;
        BypassTarget = input.BypassTarget;
        ServerAddresses = input.ServerAddresses.Distinct().Order().ToArray();
        DirectRanges = painter.Collect(Decision.Direct);
        LocalRanges = painter.Collect(Decision.Local);
        BlockRanges = painter.Collect(Decision.Block);
        DirectRouteCidrs = DirectRanges.ToCidrs();
        _tunnelRanges = painter.CollectTunnels();
        Tunnels = _tunnelRanges.Keys.Order().ToArray();
    }

    public RouteTarget DefaultTarget { get; }

    public RouteTarget GeoTarget { get; }

    /// <summary>Куда идут адреса из списка обхода блокировок.</summary>
    public RouteTarget BypassTarget { get; }

    /// <summary>Назначения, разрешённые напрямую через основной адаптер (WFP).</summary>
    public RangeSet DirectRanges { get; }

    /// <summary>Точное CIDR-покрытие DirectRanges для таблицы маршрутов.</summary>
    public IReadOnlyList<Ipv4Cidr> DirectRouteCidrs { get; }

    public IReadOnlyList<uint> ServerAddresses { get; }

    public RangeSet LocalRanges { get; }

    public RangeSet BlockRanges { get; }

    /// <summary>Туннели (и недоступные группы), на которые что-то назначено.</summary>
    public IReadOnlyList<Guid> Tunnels { get; }

    public int SegmentCount => _painter.Segments.Count;

    public Classification Classify(uint address) => _painter.Classify(address);

    /// <summary>Назначения, отправленные в указанный туннель.</summary>
    public RangeSet RangesFor(Guid tunnel) => _tunnelRanges.GetValueOrDefault(tunnel, RangeSet.Empty);

    /// <summary>
    /// Точное CIDR-покрытие назначений туннеля для таблицы маршрутов. Считается по требованию:
    /// туннелю «остального интернета» оно не нужно — он забирает трафик парой маршрутов /1.
    /// </summary>
    public IReadOnlyList<Ipv4Cidr> RouteCidrsFor(Guid tunnel)
    {
        if (!_tunnelCidrs.TryGetValue(tunnel, out var cidrs))
        {
            cidrs = RangesFor(tunnel).ToCidrs();
            _tunnelCidrs[tunnel] = cidrs;
        }

        return cidrs;
    }
}

public static class PolicyCompiler
{
    /// <summary>Минимальная длина префикса on-link-сети, которую считаем локальной.</summary>
    public const int MinOnLinkPrefix = 8;

    /// <summary>
    /// Минимальная длина префикса сети, присланной шлюзом. Сеть шире /8 забрала бы заметную часть
    /// интернета в чужой туннель, поэтому такие маршруты отбрасываются (см. LIMITATIONS.md).
    /// </summary>
    public const int MinServerNetworkPrefix = 8;

    public static CompiledPolicy Compile(PolicyInput input)
    {
        ArgumentNullException.ThrowIfNull(input);

        // Слои от низшего приоритета к высшему (PLAN §4 «Порядок применения политики»).
        var background = Label(input.DefaultTarget, DecisionSource.Default);
        var painter = input.Geo.Count > 0 && input.GeoTarget != input.DefaultTarget
            ? new IntervalPainter(background, input.Geo, Label(input.GeoTarget, DecisionSource.Geo))
            : new IntervalPainter(background);

        // Список обхода блокировок ложится поверх RU-базы и ниже правил пользователя: адрес из обоих
        // списков идёт по обходу, но ручное правило на ту же подсеть по-прежнему важнее. Слой красится
        // и тогда, когда цель совпадает с «остальным интернетом»: смысл как раз в том, чтобы перекрыть
        // RU-базу — заблокированный ресурс на российском адресе иначе остался бы недоступен.
        if (input.Bypass.Count > 0)
        {
            painter.Paint(input.Bypass, Label(input.BypassTarget, DecisionSource.Bypass));
        }

        foreach (var rule in input.Rules.OrderBy(r => r.Cidr.PrefixLength))
        {
            painter.Paint(rule.Cidr.ToRange(), Label(rule.Target, DecisionSource.UserRule, rule));
        }

        painter.Paint(SpecialRanges.Reserved, Reserved(input.DefaultTarget));
        painter.Paint(SpecialRanges.Local, new Classification(Decision.Local, DecisionSource.LocalNetwork, null));
        foreach (var (target, cidr) in input.ServerNetworks
            .SelectMany(n => n.Cidrs.Where(c => c.PrefixLength >= MinServerNetworkPrefix).Select(c => (n.Target, c)))
            .OrderBy(n => n.c.PrefixLength))
        {
            // Сети шлюза перекрывают правила пользователя, но не его запрет: адрес, который он запретил,
            // не должен уйти в корпоративный туннель только потому, что шлюз прислал охватывающую сеть.
            painter.PaintKeeping(cidr.ToRange(), Label(target, DecisionSource.ServerNetwork), IsUserBlock);
        }

        painter.Paint(OnLinkSet(input.OnLinePrefixes), new Classification(Decision.Local, DecisionSource.OnLink, null));
        painter.Paint(SpecialRanges.Loopback, new Classification(Decision.Local, DecisionSource.Loopback, null));
        foreach (var host in input.TunnelHosts)
        {
            painter.Paint(RangeSet.From([Ipv4Range.Host(host.Address)]), new Classification(Decision.Vpn, DecisionSource.TunnelInfrastructure, null, host.Tunnel));
        }

        painter.Paint(HostSet(input.ServiceDnsAddresses), new Classification(Decision.Server, DecisionSource.ServiceDns, null));
        painter.Paint(HostSet(input.ServerAddresses), new Classification(Decision.Server, DecisionSource.Server, null));

        // Группы раскрываются последним проходом: до него они помечены собственным идентификатором.
        painter.ExpandGroups(GroupMembers(input.Groups));
        return new CompiledPolicy(input, painter);
    }

    /// <summary>Решение принято правилом пользователя «Блокировать»: его не перекрывает никакой следующий слой.</summary>
    private static bool IsUserBlock(Classification label) =>
        label is { Decision: Decision.Block, Source: DecisionSource.UserRule };

    /// <summary>
    /// Участники групп по идентификатору. Повтор идентификатора не роняет компиляцию: остаётся первая
    /// группа, как и при загрузке настроек (валидатор сообщает о дубликате отдельно).
    /// </summary>
    private static Dictionary<Guid, IReadOnlyList<Guid>> GroupMembers(IEnumerable<TunnelGroup> groups)
    {
        var result = new Dictionary<Guid, IReadOnlyList<Guid>>();
        foreach (var group in groups)
        {
            result.TryAdd(group.Id, group.Members);
        }

        return result;
    }

    /// <summary>Решение для цели маршрутизации.</summary>
    public static Classification Label(RouteTarget target, DecisionSource source, UserRule? rule = null) => target.Kind switch
    {
        TargetKind.Tunnel or TargetKind.Group when target.Id is { } id => new Classification(Decision.Vpn, source, rule, id),
        TargetKind.Block => new Classification(Decision.Block, source, rule),
        // Цель без указанного туннеля или группы до службы не доходит (валидатор настроек), но безопаснее блокировать.
        TargetKind.Tunnel or TargetKind.Group => new Classification(Decision.Block, source, rule),
        _ => new Classification(Decision.Direct, source, rule),
    };

    internal static RangeSet OnLinkSet(IEnumerable<Ipv4Cidr> prefixes)
    {
        return RangeSet.From(prefixes.Where(p => p.PrefixLength >= MinOnLinkPrefix));
    }

    /// <summary>
    /// Зарезервированные диапазоны наружу не выпускаем: они идут туда же, куда «остальной интернет»,
    /// а если тот идёт напрямую — блокируются (такие адреса не отправляем в сеть провайдера).
    /// </summary>
    private static Classification Reserved(RouteTarget defaultTarget) => defaultTarget.IsVpn
        ? Label(defaultTarget, DecisionSource.Reserved)
        : new Classification(Decision.Block, DecisionSource.Reserved, null);

    private static RangeSet HostSet(IEnumerable<uint> addresses) => RangeSet.From(addresses.Select(Ipv4Range.Host));
}
