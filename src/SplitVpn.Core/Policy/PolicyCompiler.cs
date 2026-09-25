using SplitVpn.Core.Net;

namespace SplitVpn.Core.Policy;

/// <summary>Согласованная адресная политика для маршрутов, фильтров и диагностики.</summary>
public sealed class CompiledPolicy
{
    private readonly IntervalPainter _painter;
    private readonly Dictionary<Guid, RangeSet> _tunnelRanges;
    private readonly Dictionary<Guid, IReadOnlyList<Ipv4Cidr>> _tunnelCidrs = [];
    private readonly Dictionary<uint, RouteTarget> _pins;

    internal CompiledPolicy(PolicyInput input, IntervalPainter painter, IReadOnlyList<PinnedHost> pins)
    {
        _painter = painter;
        Pins = pins;
        _pins = pins.ToDictionary(p => p.Address, p => p.Target);
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

    /// <summary>
    /// Адреса правил для доменов с раскрытой целью. Отдельно от диапазонов намеренно: они меняются
    /// с каждым ответом DNS, а перестройка больших групп фильтров на каждый адрес обошлась бы дорого.
    /// </summary>
    public IReadOnlyList<PinnedHost> Pins { get; }

    public int SegmentCount => _painter.Segments.Count;

    /// <summary>
    /// Решение для адреса. Закрепление по правилу для домена важнее адресных слоёв: маршруты, фильтры
    /// и диагностика обязаны видеть одно и то же решение.
    /// </summary>
    public Classification Classify(uint address) => _pins.TryGetValue(address, out var target)
        ? PolicyCompiler.Label(target, DecisionSource.DomainRule)
        : _painter.Classify(address);

    /// <summary>Адреса правил для доменов, закреплённые за указанной целью.</summary>
    public IEnumerable<PinnedHost> PinsFor(RouteTarget target) => Pins.Where(p => p.Target == target);

    /// <summary>Базовый /32 уступает доменному маршруту: два /32 разных целей выбирались бы по метрике.</summary>
    public bool IsPinned(uint address) => _pins.ContainsKey(address);

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
        Verify(painter, "RU-база", input);

        // Список обхода блокировок ложится поверх RU-базы и ниже правил пользователя: адрес из обоих
        // списков идёт по обходу, но ручное правило на ту же подсеть по-прежнему важнее. Слой красится
        // и тогда, когда цель совпадает с «остальным интернетом»: смысл как раз в том, чтобы перекрыть
        // RU-базу — заблокированный ресурс на российском адресе иначе остался бы недоступен.
        if (input.Bypass.Count > 0)
        {
            painter.Paint(input.Bypass, Label(input.BypassTarget, DecisionSource.Bypass));
            Verify(painter, "список обхода", input);
        }

        // Частные сети ложатся ниже правил пользователя: без правила они локальны, а правило направляет
        // удалённую частную сеть в свой туннель. Сеть адаптера защищает слой on-link выше.
        var local = new Classification(Decision.Local, DecisionSource.LocalNetwork, null);
        painter.Paint(SpecialRanges.Private, local);
        Verify(painter, "частные сети", input);
        foreach (var rule in input.Rules.OrderBy(r => r.Cidr.PrefixLength))
        {
            painter.Paint(rule.Cidr.ToRange(), Label(rule.Target, DecisionSource.UserRule, rule));
        }

        Verify(painter, "правила", input);
        painter.Paint(SpecialRanges.Reserved, Reserved(input.DefaultTarget));
        painter.Paint(SpecialRanges.LinkScope, local);
        Verify(painter, "зарезервированные и link-scope", input);
        foreach (var (target, cidr) in input.ServerNetworks
            .SelectMany(n => n.Cidrs.Where(c => c.PrefixLength >= MinServerNetworkPrefix).Select(c => (n.Target, c)))
            .OrderBy(n => n.c.PrefixLength))
        {
            // Сети шлюза перекрывают правила пользователя, но не его запрет: адрес, который он запретил,
            // не должен уйти в корпоративный туннель только потому, что шлюз прислал охватывающую сеть.
            painter.PaintKeeping(cidr.ToRange(), Label(target, DecisionSource.ServerNetwork), IsUserBlock);
        }

        Verify(painter, "сети шлюза", input);
        painter.Paint(OnLinkSet(input.OnLinePrefixes), new Classification(Decision.Local, DecisionSource.OnLink, null));
        painter.Paint(SpecialRanges.Loopback, new Classification(Decision.Local, DecisionSource.Loopback, null));
        Verify(painter, "сеть адаптера и loopback", input);
        foreach (var host in input.TunnelHosts)
        {
            painter.Paint(RangeSet.From([Ipv4Range.Host(host.Address)]), new Classification(Decision.Vpn, DecisionSource.TunnelInfrastructure, null, host.Tunnel));
        }

        painter.Paint(HostSet(input.ServiceDnsAddresses), new Classification(Decision.Server, DecisionSource.ServiceDns, null));
        painter.Paint(HostSet(input.ServerAddresses), new Classification(Decision.Server, DecisionSource.Server, null));
        Verify(painter, "адреса туннелей, DNS и серверы", input);

        // Группы раскрываются последним проходом: до него они помечены собственным идентификатором.
        var groups = GroupMembers(input.Groups);
        painter.ExpandGroups(groups);
        Verify(painter, "раскрытие групп", input);
        return new CompiledPolicy(input, painter, ResolvePins(input, painter, groups));
    }

    /// <summary>
    /// Раскрывает цели закреплений: группа заменяется своим участником по тому же правилу блоков, что и
    /// в разметке, а группа без годных участников остаётся собой — служба считает её недоступным туннелем.
    /// Адреса, которые адресные слои держат за собой (сервер VPN, DNS службы, loopback, сеть адаптера,
    /// служебный адрес туннеля), закреплению не подлежат: суффикс правила накрыл бы и их.
    /// </summary>
    private static List<PinnedHost> ResolvePins(
        PolicyInput input,
        IntervalPainter painter,
        IReadOnlyDictionary<Guid, IReadOnlyList<Guid>> groups)
    {
        if (input.PinnedHosts.Count == 0)
        {
            return [];
        }

        var result = new List<PinnedHost>(input.PinnedHosts.Count);
        var seen = new HashSet<uint>(input.PinnedHosts.Count);
        foreach (var pin in input.PinnedHosts)
        {
            if (!seen.Add(pin.Address) || !CanPin(painter.Classify(pin.Address)))
            {
                continue;
            }

            result.Add(pin with { Target = ResolvePinTarget(pin.Address, pin.Target, groups) });
        }

        return result;
    }

    private static bool CanPin(Classification label) => label.Source is not (DecisionSource.Server
        or DecisionSource.ServiceDns
        or DecisionSource.Loopback
        or DecisionSource.OnLink
        or DecisionSource.TunnelInfrastructure);

    private static RouteTarget ResolvePinTarget(uint address, RouteTarget target, IReadOnlyDictionary<Guid, IReadOnlyList<Guid>> groups)
    {
        if (!target.IsGroup(out var group))
        {
            return target;
        }

        var members = groups.GetValueOrDefault(group, []);
        return members.Count == 0
            ? target
            : RouteTarget.Tunnel(members[(int)((address >> IntervalPainter.BalanceBlockBits) % (uint)members.Count)]);
    }

    /// <summary>
    /// Проверка разметки после слоя. Нарушение не воспроизводится на тестах и изредка случается в работе:
    /// исключение называет слой и несёт входы сборки, чтобы по журналу было видно, на каких данных.
    /// </summary>
    private static void Verify(IntervalPainter painter, string layer, PolicyInput input)
    {
        if (painter.FindViolation() is { } violation)
        {
            throw new PolicyIntegrityException(layer, violation, DescribeInput(input));
        }
    }

    internal static string DescribeInput(PolicyInput input)
    {
        static string Join<T>(IEnumerable<T> items) => string.Join(", ", items);
        return string.Join(Environment.NewLine,
            $"  цели: остальное {input.DefaultTarget}, RU {input.GeoTarget}, обход {input.BypassTarget}",
            $"  RU-база: {input.Geo.Count} диапазонов, {input.Geo.TotalAddresses} адресов; обход: {input.Bypass.Count} диапазонов, {input.Bypass.TotalAddresses} адресов",
            $"  правила: {Join(input.Rules.Select(r => $"{r.Cidr}->{r.Target}"))}",
            $"  группы: {Join(input.Groups.Select(g => $"{g.Id}[{Join(g.Members)}]"))}",
            $"  сеть адаптера: {Join(input.OnLinePrefixes)}",
            $"  серверы: {Join(input.ServerAddresses.Select(Ipv4.Format))}",
            $"  DNS службы: {Join(input.ServiceDnsAddresses.Select(Ipv4.Format))}",
            $"  сети шлюза: {Join(input.ServerNetworks.Select(n => $"{n.Target}: {Join(n.Cidrs)}"))}",
            $"  адреса туннелей: {Join(input.TunnelHosts.Select(h => $"{h.Tunnel}:{Ipv4.Format(h.Address)}"))}",
            $"  закрепления: {input.PinnedHosts.Count}");
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
