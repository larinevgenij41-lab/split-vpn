using SplitVpn.Core.Net;

namespace SplitVpn.Core.Policy;

/// <summary>Согласованная адресная политика для маршрутов, фильтров и диагностики.</summary>
public sealed class CompiledPolicy
{
    private readonly IntervalPainter _painter;
    private readonly Dictionary<Guid, RangeSet> _tunnelRanges;
    private readonly Dictionary<Guid, IReadOnlyList<Ipv4Cidr>> _tunnelCidrs = [];
    private readonly Dictionary<uint, RouteTarget> _pins;

    internal CompiledPolicy(
        PolicyInput input,
        IntervalPainter painter,
        PinResolution pins,
        IReadOnlyList<uint> directServerAddresses,
        IReadOnlyDictionary<Guid, IReadOnlyList<Guid>> groups,
        IReadOnlyList<string>? warnings = null)
    {
        Warnings = warnings ?? [];
        _painter = painter;
        _groups = groups;
        RejectedPins = pins.Rejected;
        IgnoredPins = pins.Ignored;
        Pins = pins.Accepted;
        _pins = Pins.ToDictionary(p => p.Address, p => p.Target);
        DefaultTarget = input.DefaultTarget;
        GeoTarget = input.GeoTarget;
        BypassTarget = input.BypassTarget;
        ServerAddresses = input.ServerAddresses.Distinct().Order().ToArray();
        DirectServerAddresses = directServerAddresses;
        DirectRanges = painter.Collect(Decision.Direct);
        LocalRanges = painter.Collect(Decision.Local);
        BlockRanges = painter.Collect(Decision.Block);
        DirectRouteCidrs = DirectRanges.ToCidrs();
        _tunnelRanges = painter.CollectTunnels();
        Tunnels = _tunnelRanges.Keys.Order().ToArray();
    }

    private CompiledPolicy(CompiledPolicy source, PinResolution pins)
    {
        _painter = source._painter;
        _groups = source._groups;
        Warnings = source.Warnings;
        _tunnelRanges = source._tunnelRanges;
        _tunnelCidrs = source._tunnelCidrs;
        DefaultTarget = source.DefaultTarget;
        GeoTarget = source.GeoTarget;
        BypassTarget = source.BypassTarget;
        ServerAddresses = source.ServerAddresses;
        DirectServerAddresses = source.DirectServerAddresses;
        DirectRanges = source.DirectRanges;
        LocalRanges = source.LocalRanges;
        BlockRanges = source.BlockRanges;
        DirectRouteCidrs = source.DirectRouteCidrs;
        Tunnels = source.Tunnels;
        Pins = pins.Accepted;
        RejectedPins = pins.Rejected;
        IgnoredPins = pins.Ignored;
        _pins = Pins.ToDictionary(p => p.Address, p => p.Target);
    }

    private readonly IReadOnlyDictionary<Guid, IReadOnlyList<Guid>> _groups;

    internal bool SharesAddressPolicy(CompiledPolicy other) => ReferenceEquals(_painter, other._painter);

    internal CompiledPolicy WithPins(PolicyInput input) => new(this,
        PolicyCompiler.ResolvePins(input, _painter, PolicyCompiler.GroupMembers(input.Groups)));

    /// <summary>
    /// Принял бы адресный слой этой политики закрепление (без учёта DNS службы): служба перепроверяет им отказы,
    /// запомненные при прежней сборке, - правило могло измениться. Reason - причина отказа, null - отказа нет или он
    /// молчаливый (<see cref="IgnoredPins"/>).
    /// </summary>
    public (bool Allowed, string? Reason) EvaluatePin(PinnedHost pin)
    {
        ArgumentNullException.ThrowIfNull(pin);
        return PolicyCompiler.PinRejection(pin, PolicyCompiler.ResolvePinTarget(pin.Address, pin.Target, _groups), _painter.Classify(pin.Address));
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

    /// <summary>
    /// Адреса серверов VPN, которые правило пользователя явно направило напрямую. Слой серверов перекрывает
    /// правило, поэтому в DirectRanges их нет; защита выпускает к ним весь трафик, а не только транспорт туннеля.
    /// </summary>
    public IReadOnlyList<uint> DirectServerAddresses { get; }

    public RangeSet LocalRanges { get; }

    public RangeSet BlockRanges { get; }

    /// <summary>Туннели (и недоступные группы), на которые что-то назначено.</summary>
    public IReadOnlyList<Guid> Tunnels { get; }

    /// <summary>
    /// Адреса правил для доменов с раскрытой целью. Отдельно от диапазонов намеренно: они меняются
    /// с каждым ответом DNS, а перестройка больших групп фильтров на каждый адрес обошлась бы дорого.
    /// </summary>
    public IReadOnlyList<PinnedHost> Pins { get; }

    /// <summary>
    /// Закрепления, которые не приняты, потому что адресное решение сильнее правила для домена (см.
    /// <see cref="PolicyCompiler.PinRejection"/>): служба отвечает на такой запрос SERVFAIL и показывает предупреждение.
    /// Молчаливые отказы (<see cref="IgnoredPins"/>) сюда не попадают.
    /// </summary>
    public IReadOnlyList<RejectedPin> RejectedPins { get; }

    /// <summary>
    /// Адреса, которые не закреплены молча: служебные (сервер VPN, DNS, loopback, сеть адаптера, 0.0.0.0/8) и цель
    /// «напрямую» на адресе локальной сети. Адрес идёт по своему адресному решению, которое из VPN его не выводит, ответ
    /// DNS отдаётся как обычно, а конфликтов с другими доменами на том же адресе такое закрепление не создаёт.
    /// </summary>
    public IReadOnlyList<uint> IgnoredPins { get; }

    public int SegmentCount => _painter.Segments.Count;

    /// <summary>
    /// Предупреждения сборки: например, сети шлюза, отброшенные целиком за превышение пределов. Второй рубеж: служба
    /// отбрасывает такой слой раньше (SessionInfo.IncludeCidrs) и сама сообщает об этом в журнал и статус, поэтому
    /// список сейчас не читается - он для проверок и на случай нового источника сетей шлюза мимо этой проверки.
    /// </summary>
    public IReadOnlyList<string> Warnings { get; }

    /// <summary>
    /// Решение для адреса. Принятое закрепление по правилу для домена важнее адресных слоёв (какие закрепления
    /// не принимаются - <see cref="PolicyCompiler.PinRejection"/>): маршруты, фильтры и диагностика обязаны видеть
    /// одно и то же решение.
    /// </summary>
    public Classification Classify(uint address) => _pins.TryGetValue(address, out var target)
        ? PolicyCompiler.Label(target, DecisionSource.DomainRule)
        : _painter.Classify(address);

    /// <summary>Адреса правил для доменов, закреплённые за указанной целью.</summary>
    public IEnumerable<PinnedHost> PinsFor(RouteTarget target) => Pins.Where(p => p.Target == target);

    /// <summary>Базовый /32 уступает доменному маршруту: два /32 разных целей выбирались бы по метрике.</summary>
    public bool IsPinned(uint address) => _pins.ContainsKey(address);

    /// <summary>Цель закрепления адреса правилом для домена или null, если адрес не закреплён.</summary>
    public RouteTarget? PinTarget(uint address) => _pins.TryGetValue(address, out var target) ? target : null;

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

    /// <summary>
    /// Адреса, которые не закрепляются по домену: «этот хост» 0.0.0.0/8 (так отвечает блокирующий DNS),
    /// 240.0.0.0/4 с широковещанием и link-scope. Отказ по ним молчаливый; документационные диапазоны и 192.0.0.0/24 тоже
    /// не закрепляются, но с отказом (<see cref="PinRejection"/>). 198.18.0.0/15 закрепляется (<see cref="FakeIpPool"/>).
    /// </summary>
    private static readonly RangeSet Unpinnable = RangeSet.From([Ipv4Cidr.Parse("0.0.0.0/8"), Ipv4Cidr.Parse("240.0.0.0/4")])
        .Union(SpecialRanges.LinkScope);

    /// <summary>
    /// 198.18.0.0/15: пул подменных адресов (fake-IP) резолверов Clash, sing-box и подобных. Закреплению по домену он
    /// доступен с любой целью, как до итерации 12: маршрут на такой адрес безвреден, а иначе правило для домена при таком
    /// резолвере не работало бы вовсе.
    /// </summary>
    public static RangeSet FakeIpPool { get; } = RangeSet.From([Ipv4Cidr.Parse("198.18.0.0/15")]);

    /// <summary>
    /// Зарезервированные диапазоны, которые в сети адаптера считаются частными: 192.0.0.0/29 (адрес B4 у DS-Lite) и
    /// 198.18.0.0/15 (адаптеры TUN с пулом fake-IP). Сеть из них локальна у любого адаптера и предупреждения не даёт.
    /// </summary>
    private static readonly RangeSet PrivateOnLinkReserved = RangeSet.From([Ipv4Cidr.Parse("192.0.0.0/29"), Ipv4Cidr.Parse("198.18.0.0/15")]);

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
        // Публичный маршрутизатор недоверенного адаптера локален, но ниже правил и закреплений (SelectOnLinkPrefixes).
        painter.Paint(HostSet(input.AdapterGateways), local);
        Verify(painter, "частные сети", input);
        foreach (var rule in input.Rules.OrderBy(r => r.Priority).ThenBy(r => r.Cidr.PrefixLength))
        {
            painter.Paint(rule.Cidr.ToRange(), Label(rule.Target, DecisionSource.UserRule, rule));
        }

        Verify(painter, "правила", input);
        painter.Paint(SpecialRanges.Reserved, Reserved(input.DefaultTarget));
        painter.Paint(SpecialRanges.LinkScope, local);
        Verify(painter, "зарезервированные и link-scope", input);
        var warnings = new List<string>();
        PaintServerNetworks(painter, input.ServerNetworks, warnings);

        Verify(painter, "сети шлюза", input);
        // Link-local, multicast и широковещание остаются локальными и тогда, когда шлюз прислал охватывающую их сеть.
        painter.Paint(SpecialRanges.LinkScope, local);
        painter.Paint(OnLinkSet(input.OnLinePrefixes), new Classification(Decision.Local, DecisionSource.OnLink, null));
        painter.Paint(SpecialRanges.Loopback, new Classification(Decision.Local, DecisionSource.Loopback, null));
        Verify(painter, "сеть адаптера и loopback", input);
        foreach (var host in input.TunnelHosts)
        {
            // DNS туннеля сильнее сетей шлюза и обычных правил, но не запрета пользователя: запрещённый им адрес
            // не открывается ради DNS. Loopback и сеть своего адаптера в туннель не уводятся никогда: шлюз,
            // назвавший своим DNS адрес из домашней сети (X-CSTP-DNS: 192.168.1.10), иначе забрал бы в туннель
            // узел локальной сети. Такой адрес служба и сама убирает из DNS туннеля с предупреждением.
            // С «Ручные правила важнее сетей шлюза» адрес DNS шлюза не перекрывает и правило ровно на этот адрес (/32). Широкое
            // правило (10.0.0.0/8 → «Напрямую») его не забирает: иначе split DNS шлюза пропал бы, а имена ушли бы к чужому DNS.
            painter.PaintKeeping(Ipv4Range.Host(host.Address), new Classification(Decision.Vpn, DecisionSource.TunnelInfrastructure, null, host.Tunnel),
                label => IsUserBlock(label) || (host.UserRulesWin && IsUserHostRule(label))
                    || label.Source is DecisionSource.Loopback or DecisionSource.OnLink);
        }

        // Решение правила для адреса сервера запоминается до слоя серверов, который его перекроет.
        var directServers = input.ServerAddresses.Distinct()
            .Where(a => painter.Classify(a) is { Decision: Decision.Direct, Source: DecisionSource.UserRule })
            .Order().ToArray();
        // DNS адаптера, которому и так положено «напрямую» (публичный 8.8.8.8 при прямом остальном интернете или
        // по правилу), остаётся прямым: иначе слой серверов отнял бы адрес у всех программ на всех портах (ping,
        // DoH). Обычный DNS к нему держит DNS-страж, а службе её разрешение на порт 53 даётся отдельно.
        // Адрес DNS выбирает сеть (DHCP), поэтому он не перекрывает решений пользователя и служебных слоёв: правило
        // пользователя (в туннель или «Блокировать»), сеть шлюза и DNS туннеля сохраняются. Самой службе это не мешает:
        // её разрешение DNS (вес выше запрета пользователя и блока лежащего туннеля) привязано к основному адаптеру,
        // и запрос уходит через него (IP_UNICAST_IF), какой бы маршрут ни был у адреса для программ.
        painter.PaintKeeping(HostSet(input.ServiceDnsAddresses.Where(a => painter.Classify(a) is not { Decision: Decision.Direct })),
            new Classification(Decision.Server, DecisionSource.ServiceDns, null),
            label => label.Source is DecisionSource.UserRule or DecisionSource.ServerNetwork or DecisionSource.TunnelInfrastructure);
        painter.Paint(HostSet(input.ServerAddresses), new Classification(Decision.Server, DecisionSource.Server, null));
        Verify(painter, "адреса туннелей, DNS и серверы", input);

        // Группы раскрываются последним проходом: до него они помечены собственным идентификатором.
        var groups = GroupMembers(input.Groups);
        painter.ExpandGroups(groups);
        Verify(painter, "раскрытие групп", input);
        return new CompiledPolicy(input, painter, ResolvePins(input, painter, groups), directServers, groups, warnings);
    }

    /// <summary>
    /// Сеть адаптера целиком из частных, CGNAT 100.64.0.0/10 и link-local диапазонов, из 192.0.0.0/29 (DS-Lite) или
    /// 198.18.0.0/15 (адаптеры TUN с fake-IP).
    /// </summary>
    public static bool IsPrivateOnLink(Ipv4Cidr prefix) =>
        SpecialRanges.Local.Covers(prefix.ToRange()) || PrivateOnLinkReserved.Covers(prefix.ToRange());

    /// <summary>
    /// Публичная сеть адаптера, о которой стоит предупредить: не частная (<see cref="IsPrivateOnLink"/>) и не из
    /// зарезервированных диапазонов (документационные сети в интернете не встречаются, о них предупреждать незачем).
    /// </summary>
    public static bool IsPublicOnLink(Ipv4Cidr prefix) =>
        prefix.PrefixLength >= MinOnLinkPrefix && !IsPrivateOnLink(prefix) && !SpecialRanges.Reserved.Covers(prefix.ToRange());

    /// <summary>
    /// Какие сети адаптеров считаются локальными (идут напрямую поверх правил).
    /// <list type="bullet">
    /// <item>Частные (RFC 1918), CGNAT, link-local сети, 192.0.0.0/29 и 198.18.0.0/15 - у любого адаптера.</item>
    /// <item>Адаптер из списка «Доверенные адаптеры» (<see cref="AdapterTrust.Explicit"/>): любая его сеть и его
    /// собственные маршруты не короче /8 (подсети за Tailscale, управляемые маршруты ZeroTier).</item>
    /// <item>Распознанная виртуальная сеть (<see cref="AdapterTrust.Overlay"/>): публичная сеть и маршруты - только из
    /// известных диапазонов поставщика (<see cref="OverlayAdapters.VendorRanges"/>). Контроллер ZeroTier, назначивший
    /// 149.154.160.0/20, иначе открыл бы этот кусок интернета мимо VPN.</item>
    /// <item>Остальные публичные сети - не локальны (Untrusted): чужая точка доступа с такой сетью иначе вывела бы её из
    /// VPN. Маршрутизатор такой сети с частным адресом локален как прежде, с публичным - уходит в Gateways: он локален
    /// слоем ниже правил пользователя и закреплений, а защита пропускает его только через свой адаптер.</item>
    /// </list>
    /// </summary>
    public static OnLinkSelection SelectOnLinkPrefixes(
        IEnumerable<AdapterCandidate> adapters,
        Func<AdapterCandidate, AdapterTrust> trust,
        Func<AdapterCandidate, IEnumerable<Ipv4Cidr>>? routes = null)
    {
        ArgumentNullException.ThrowIfNull(adapters);
        ArgumentNullException.ThrowIfNull(trust);
        var local = new List<Ipv4Cidr>();
        var untrusted = new List<(AdapterCandidate, Ipv4Cidr)>();
        var gateways = new List<AdapterGateway>();
        foreach (var adapter in adapters)
        {
            var level = trust(adapter);
            // Маршруты нужны только доверенному адаптеру: таблица маршрутов велика, а таких адаптеров единицы.
            local.AddRange(TrustedNetworks(adapter, level, level == AdapterTrust.None ? [] : routes?.Invoke(adapter) ?? []));
            foreach (var prefix in adapter.OnLinkPrefixes.Where(p => p.PrefixLength >= MinOnLinkPrefix && !IsLocalFor(p, adapter, level)))
            {
                untrusted.Add((adapter, prefix));
                if (adapter.DefaultGateway is not { } gateway || !prefix.Contains(gateway))
                {
                    continue;
                }

                if (SpecialRanges.Local.Contains(gateway))
                {
                    local.Add(new Ipv4Cidr(gateway, 32));
                }
                else
                {
                    gateways.Add(new AdapterGateway(gateway, adapter.Luid));
                }
            }
        }

        return new OnLinkSelection([.. local.Distinct()], [.. untrusted.Distinct()], [.. gateways.Distinct()]);
    }

    /// <summary>
    /// Сети адаптера, которые локальны по его уровню доверия: on-link-сети и (для доверенного) его маршруты. Служба
    /// запоминает их, пока адаптер на время теряет адрес, и строит по ним разрешение защиты для адаптера.
    /// </summary>
    public static List<Ipv4Cidr> TrustedNetworks(AdapterCandidate adapter, AdapterTrust level, IEnumerable<Ipv4Cidr> routes)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        ArgumentNullException.ThrowIfNull(routes);
        var result = adapter.OnLinkPrefixes.Where(p => p.PrefixLength >= MinOnLinkPrefix && IsLocalFor(p, adapter, level)).ToList();
        if (level != AdapterTrust.None)
        {
            // Маршрут по умолчанию и пара /1 (выход Tailscale, полный туннель ZeroTier) сюда не попадают: не короче /8.
            result.AddRange(routes.Where(r => r.PrefixLength >= MinOnLinkPrefix
                && (level == AdapterTrust.Explicit || SpecialRanges.Local.Covers(r.ToRange()) || OverlayAdapters.VendorRanges(adapter.Description).Covers(r.ToRange()))));
        }

        return [.. result.Distinct()];
    }

    private static bool IsLocalFor(Ipv4Cidr prefix, AdapterCandidate adapter, AdapterTrust level) =>
        IsPrivateOnLink(prefix)
        || level == AdapterTrust.Explicit
        || (level == AdapterTrust.Overlay && OverlayAdapters.VendorRanges(adapter.Description).Covers(prefix.ToRange()));

    /// <summary>
    /// Слой сетей шлюзов. Слой шлюза, вышедший за <see cref="GatewayNetworkLimits"/>, отбрасывается целиком
    /// с предупреждением. Остальные красятся множествами: по одному проходу на пару «длина префикса, шлюз»
    /// от широких к узким — тот же порядок, что при покраске по одной сети, но без O(n·m) вставок.
    /// </summary>
    private static void PaintServerNetworks(IntervalPainter painter, IReadOnlyList<ServerNetworks> networks, List<string> warnings)
    {
        var accepted = new List<ServerNetworks>(networks.Count);
        foreach (var layer in networks)
        {
            if (GatewayNetworkLimits.Violation(GatewayNetworkLimits.Union(layer.Cidrs)) is { } violation)
            {
                warnings.Add($"Сети шлюза ({layer.Target}) отброшены целиком: {violation}.");
                continue;
            }

            accepted.Add(layer);
        }

        for (var prefix = MinServerNetworkPrefix; prefix <= 32; prefix++)
        {
            foreach (var layer in accepted)
            {
                var length = prefix;
                var ranges = RangeSet.From(layer.Cidrs.Where(c => c.PrefixLength == length));
                // Запрет пользователя сохраняется всегда: адрес, который он запретил, не должен уйти в корпоративный
                // туннель только потому, что шлюз прислал охватывающую сеть. С флагом UserRulesWin так же сохраняются
                // все ручные правила, какой бы ни была длина их префикса.
                painter.PaintKeeping(ranges, Label(layer.Target, DecisionSource.ServerNetwork), layer.UserRulesWin ? IsUserRule : IsUserBlock);
            }
        }
    }

    /// <summary>
    /// Раскрывает цели закреплений: группа заменяется своим участником по тому же правилу блоков, что и
    /// в разметке, а группа без годных участников остаётся собой — служба считает её недоступным туннелем.
    /// Адреса, которые адресные слои держат за собой (см. <see cref="PinRejection"/>), закреплению не подлежат:
    /// суффикс правила накрыл бы и их, а ответ чужого DNS мог бы назвать любой адрес.
    /// </summary>
    internal static PinResolution ResolvePins(
        PolicyInput input,
        IntervalPainter painter,
        IReadOnlyDictionary<Guid, IReadOnlyList<Guid>> groups)
    {
        if (input.PinnedHosts.Count == 0)
        {
            return new([], [], []);
        }

        var result = new List<PinnedHost>(input.PinnedHosts.Count);
        var rejected = new List<RejectedPin>();
        var ignored = new List<uint>();
        var seen = new HashSet<uint>(input.PinnedHosts.Count);
        // DNS службы может сохранить адресное решение пользователя (а не метку ServiceDns), но закреплению он
        // не подлежит: блок «чужой интерфейс» закрепления весит не меньше разрешения DNS службы.
        var serviceDns = input.ServiceDnsAddresses.ToHashSet();
        foreach (var pin in input.PinnedHosts)
        {
            if (!seen.Add(pin.Address))
            {
                continue;
            }

            if (serviceDns.Contains(pin.Address))
            {
                ignored.Add(pin.Address);
                continue;
            }

            var resolved = ResolvePinTarget(pin.Address, pin.Target, groups);
            var (allowed, reason) = PinRejection(pin, resolved, painter.Classify(pin.Address));
            if (allowed)
            {
                result.Add(pin with { Target = resolved });
            }
            else if (reason is null)
            {
                ignored.Add(pin.Address);
            }
            else
            {
                rejected.Add(new RejectedPin(pin.Address, pin.Target, reason));
            }
        }

        return new(result, rejected, ignored);
    }

    /// <summary>
    /// Можно ли закрепить адрес по правилу для домена поверх его адресного решения. Закрепление - ответ DNS, а его
    /// содержимое выбирает сервер имён (возможно, чужой). Принцип: закрепление может увести трафик В туннель, но не
    /// вывести его из туннеля и не открыть то, что пользователь закрыл.
    /// <list type="bullet">
    /// <item>Молчаливый отказ (Reason = null, адрес идёт по своему решению, ответ DNS отдаётся): служебные адреса
    /// (сервер VPN, DNS службы, служебный адрес туннеля, loopback, сеть адаптера), <see cref="Unpinnable"/> (блокирующий
    /// DNS отвечает 0.0.0.0) и цель «напрямую» на адресе локальной сети без ручного правила - он и так не уходит в VPN, а
    /// прямой маршрут через маршрутизатор открыл бы его в обход «Локального доступа» по выбору чужого DNS.</item>
    /// <item>Закрепление, которое ничего не меняет (та же цель, что у адресного решения), принимается.</item>
    /// <item>Локальная сеть без ручного правила (10.x, публичный маршрутизатор недоверенного адаптера): туннель и группа
    /// принимаются - трафик уходит только в VPN, а при лежащем туннеле адрес блокируется.</item>
    /// <item>198.18.0.0/15 (<see cref="FakeIpPool"/>) принимается с любой целью; остальные зарезервированные диапазоны
    /// (документационные, 192.0.0.0/24) - отказ.</item>
    /// <item>Запрет пользователя по адресу и сеть шлюза AnyConnect с другой целью - отказ.</item>
    /// <item>Цель «напрямую» поверх ручного правила в туннель: для публичного адреса решает приоритет - правило для
    /// домена с приоритетом не ниже CIDR-правила (равный - домен важнее, как в 0.18.0) принимается, иначе отказ; для
    /// частного и зарезервированного адреса - всегда отказ (чужой DNS мог бы вывести адрес сети за VPN наружу).</item>
    /// </list>
    /// Отказ с причиной служба не отдаёт программе (SERVFAIL) и показывает предупреждение с правилом и причиной.
    /// </summary>
    internal static (bool Allowed, string? Reason) PinRejection(PinnedHost pin, RouteTarget resolvedTarget, Classification label)
    {
        if (Unpinnable.Contains(pin.Address)
            || label.Source is DecisionSource.Server or DecisionSource.ServiceDns or DecisionSource.Loopback
                or DecisionSource.OnLink or DecisionSource.TunnelInfrastructure)
        {
            return (false, null);
        }

        var pinned = Label(resolvedTarget, DecisionSource.DomainRule);
        if (pinned.Decision == label.Decision && pinned.Tunnel == label.Tunnel)
        {
            return (true, null);
        }

        var direct = pin.Target.Kind == TargetKind.Direct;
        return label switch
        {
            { Source: DecisionSource.LocalNetwork } => direct ? (false, null) : (true, null),
            { Source: DecisionSource.Reserved } when FakeIpPool.Contains(pin.Address) => (true, null),
            { Source: DecisionSource.Reserved } => (false, "адрес из зарезервированного диапазона"),
            { Source: DecisionSource.ServerNetwork } => (false, "адрес из сети шлюза AnyConnect"),
            { Source: DecisionSource.UserRule, Decision: Decision.Block } => (false, "адрес запрещён правилом пользователя"),
            { Source: DecisionSource.UserRule, Decision: Decision.Vpn } when direct && SpecialRanges.AllNonPublic.Contains(pin.Address) =>
                (false, $"правило {label.Rule?.Cidr} направляет частный адрес в VPN, а правило для домена - напрямую"),
            { Source: DecisionSource.UserRule, Decision: Decision.Vpn } when direct && pin.Priority < (label.Rule?.Priority ?? RoutePriority.Normal) =>
                (false, $"правило {label.Rule?.Cidr} с более высоким приоритетом направляет адрес в VPN"),
            _ => (true, null),
        };
    }

    internal static RouteTarget ResolvePinTarget(uint address, RouteTarget target, IReadOnlyDictionary<Guid, IReadOnlyList<Guid>> groups)
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

    /// <summary>Решение принято любым правилом пользователя.</summary>
    private static bool IsUserRule(Classification label) => label.Source == DecisionSource.UserRule;

    /// <summary>Решение принято правилом пользователя ровно на один адрес (/32).</summary>
    private static bool IsUserHostRule(Classification label) =>
        label is { Source: DecisionSource.UserRule, Rule.Cidr.PrefixLength: 32 };

    /// <summary>Решение принято правилом пользователя «Блокировать»: его не перекрывает никакой следующий слой.</summary>
    private static bool IsUserBlock(Classification label) =>
        label is { Decision: Decision.Block, Source: DecisionSource.UserRule };

    /// <summary>
    /// Участники групп по идентификатору. Повтор идентификатора не роняет компиляцию: остаётся первая
    /// группа, как и при загрузке настроек (валидатор сообщает о дубликате отдельно).
    /// </summary>
    internal static Dictionary<Guid, IReadOnlyList<Guid>> GroupMembers(IEnumerable<TunnelGroup> groups)
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
        TargetKind.Direct => new Classification(Decision.Direct, source, rule),
        // Неизвестный вид цели (число вместо имени в файле или запросе) не должен молча уходить мимо VPN.
        _ => new Classification(Decision.Block, source, rule),
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
