using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using SplitVpn.Core.Diagnostics;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Policy;

namespace SplitVpn.Windows.Dns;

public enum DnsProxyMode
{
    /// <summary>Upstream через туннель.</summary>
    Online,

    /// <summary>Туннеля нет: только кеш и закреплённые записи.</summary>
    Offline,

    /// <summary>Туннеля нет, пользователь разрешил DNS напрямую: исходный DNS через основной адаптер.</summary>
    DirectAllowed,
}

/// <summary>Маршрут пересылки: список серверов и интерфейс, через который им отправлять запросы.</summary>
public sealed record DnsRoute(IReadOnlyList<IPEndPoint> Servers, uint? InterfaceIndex);

/// <summary>
/// Правило для домена: имена под этим суффиксом разрешаются по своему пути, а полученные адреса
/// закрепляются за целью на время TTL ответа. Без закрепления (суффиксы шлюза AnyConnect) правило только
/// выбирает DNS-сервер, а трафик идёт по политике. Unavailable — цель правила существует, но сейчас
/// недоступна: такое имя не разрешается вовсе, чтобы не уйти к чужому DNS. ExactName — правило только для
/// самого имени (узел проверки отзыва), его поддомены под правило не попадают.
/// </summary>
public sealed record DomainRoute(string Suffix, RouteTarget Target, DnsRoute? Route, bool PinAddresses = true, bool Unavailable = false, bool ExactName = false);

/// <summary>Куда отправлять запрос; Unavailable — отвечать отказом, не обращаясь к общему upstream.</summary>
internal sealed record DnsRouteChoice(DnsRoute? Route, bool Unavailable);

/// <summary>Имя разрешено по правилу для домена: адреса нужно закрепить за целью.</summary>
public sealed record PinnedRouteNotice(string Name, string Suffix, RouteTarget Target, IReadOnlyList<uint> Addresses, TimeSpan Ttl);

/// <summary>Приёмник закреплений: служба ставит маршруты и фильтры на полученные адреса.</summary>
public interface IPinnedRouteSink
{
    /// <summary>
    /// Ответ DNS ждёт применения маршрута: иначе первое соединение уйдёт не туда. false — применение не
    /// подтверждено, и посредник обязан ответить отказом, а не адресом без защиты.
    /// </summary>
    ValueTask<bool> ObserveAsync(PinnedRouteNotice notice, CancellationToken cancellationToken);
}

public sealed record DnsProxyConfiguration
{
    public DnsProxyMode Mode { get; init; } = DnsProxyMode.Offline;

    public DnsRoute? Tunnel { get; init; }

    public DnsRoute? Direct { get; init; }

    public IReadOnlyList<string> LocalSuffixes { get; init; } = [];

    public DnsRoute? Local { get; init; }

    /// <summary>Правила для доменов; при совпадении нескольких выигрывает самый длинный суффикс.</summary>
    public IReadOnlyList<DomainRoute> DomainRoutes { get; init; } = [];
}

public sealed record DnsProxyStats(long Queries, long CacheHits, long Pinned, long Forwarded, long Failures);

/// <summary>
/// Локальный DNS-посредник для системного резолвера. Имена в журнал не пишутся.
/// </summary>
public sealed class DnsProxyServer : IAsyncDisposable
{
    private const int MaxUdpMessage = 4096;
    private static readonly TimeSpan PinnedTtl = TimeSpan.FromMinutes(5);

    /// <summary>Границы срока жизни закрепления по правилу для домена.</summary>
    public static readonly TimeSpan MinRouteTtl = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan MaxRouteTtl = TimeSpan.FromHours(1);

    /// <summary>
    /// Сколько запросов посредник обрабатывает одновременно. Локальная программа может слать их без
    /// ограничения: без предела растут память, сокеты upstream и очередь службы.
    /// </summary>
    public const int MaxConcurrentQueries = 256;

    /// <summary>Сколько соединений TCP обслуживается одновременно.</summary>
    public const int MaxTcpClients = 64;

    /// <summary>Предел на всё обслуживание TCP-клиента: заголовок, тело, ответ.</summary>
    public static readonly TimeSpan TcpRequestTimeout = TimeSpan.FromSeconds(10);

    /// <summary>Размер ответа, который любой UDP-клиент принимает без EDNS (RFC 1035).</summary>
    private const int MinUdpPayload = 512;

    /// <summary>Больше в одну UDP-датаграмму не помещается.</summary>
    private const int MaxUdpPayload = 65507;

    /// <summary>После устойчивой ошибки приёма цикл ждёт, а не крутится вхолостую.</summary>
    private static readonly TimeSpan ReceiveErrorPause = TimeSpan.FromMilliseconds(100);

    private readonly DnsCache _cache;
    private readonly IPAddress _listenAddress;
    private readonly IPAddress? _optionalAddress;
    private readonly CancellationTokenSource _stop = new();
    private readonly List<Task> _loops = [];
    private readonly Lock _workGate = new();
    private readonly HashSet<Task> _workers = [];
    private Task? _disposeTask;
    private readonly SemaphoreSlim _concurrency = new(MaxConcurrentQueries);
    private readonly SemaphoreSlim _tcpClients = new(MaxTcpClients);

    /// <summary>Одинаковые запросы в полёте объединяются: очередь у upstream не растёт от повторов.</summary>
    private readonly ConcurrentDictionary<string, Task<byte[]?>> _inFlight = new(StringComparer.Ordinal);

    private DnsProxyConfiguration _configuration = new();
    private readonly List<Listener> _listeners = [];
    private long _queries;
    private long _cacheHits;
    private long _pinned;
    private long _forwarded;
    private long _failures;

    /// <summary>
    /// optionalAddress — второй адрес (::1): занимается, если свободен. Не удалось — посредник работает
    /// только на основном адресе и повторяет попытку в фоне, а адаптерам этот адрес как DNS назначается лишь
    /// после того, как он занят (<see cref="OptionalListening"/>).
    /// </summary>
    public DnsProxyServer(IPAddress listenAddress, DnsCache cache, IPAddress? optionalAddress = null)
    {
        _listenAddress = listenAddress;
        _cache = cache;
        _optionalAddress = optionalAddress;
    }

    public DnsProxyConfiguration Configuration
    {
        get => Volatile.Read(ref _configuration);
        set => Volatile.Write(ref _configuration, value ?? throw new ArgumentNullException(nameof(value)));
    }

    public DnsProxyStats Stats => new(
        Interlocked.Read(ref _queries),
        Interlocked.Read(ref _cacheHits),
        Interlocked.Read(ref _pinned),
        Interlocked.Read(ref _forwarded),
        Interlocked.Read(ref _failures));

    /// <summary>Кому сообщать об адресах, полученных по правилам для доменов.</summary>
    public IPinnedRouteSink? RouteSink { get; set; }

    /// <summary>Куда, кроме Trace, сообщать о неполном прослушивании (служба пишет в свой журнал).</summary>
    public Action<string>? Warning { get; set; }

    /// <summary>Пауза между попытками занять TCP основного адреса и дополнительный адрес; в тестах короче.</summary>
    internal TimeSpan RetryInterval { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Занят ли TCP на основном адресе. Пока нет — ответы, не помещающиеся в UDP, заменяются отказом.</summary>
    public bool TcpListening
    {
        get
        {
            lock (_workGate)
            {
                return _listeners.Count > 0 && _listeners[0].Tcp is not null;
            }
        }
    }

    /// <summary>Занят ли дополнительный адрес (::1): только тогда его можно ставить адаптерам как DNS.</summary>
    public bool OptionalListening
    {
        get
        {
            lock (_workGate)
            {
                return _listeners.Count > 1;
            }
        }
    }

    /// <summary>
    /// Занимает порт 53 эксклюзивно: UDP обязательно, TCP — если свободен, иначе повторяет в фоне. Пока TCP
    /// чужой, ответ, не помещающийся в UDP, заменяется отказом, а не усечённым ответом с TC: иначе резолвер
    /// повторил бы запрос по TCP и получил ответ от чужого процесса. Отказ всего DNS из-за занятого TCP хуже.
    /// </summary>
    public void Start() => Start(53);

    /// <summary>Случайный локальный порт в тестах позволяет не затрагивать системный DNS.</summary>
    internal IPEndPoint? ListenEndPoint => EndPointOf(0);

    /// <summary>Адрес дополнительного слушателя (для тестов).</summary>
    internal IPEndPoint? OptionalEndPoint => EndPointOf(1);

    private IPEndPoint? EndPointOf(int index)
    {
        lock (_workGate)
        {
            return _listeners.Count > index ? _listeners[index].EndPoint : null;
        }
    }

    internal void Start(int port)
    {
        lock (_workGate)
        {
            ObjectDisposedException.ThrowIf(_disposeTask is not null, this);
            if (_listeners.Count > 0)
            {
                throw new InvalidOperationException("DNS-посредник уже запущен.");
            }

            var primary = BindPrimary(port);
            _listeners.Add(primary);
            _loops.Add(Task.Run(() => UdpLoopAsync(primary, _stop.Token)));
            if (primary.Tcp is { } tcp)
            {
                _loops.Add(Task.Run(() => TcpAcceptLoopAsync(tcp, _stop.Token)));
            }
            else
            {
                Warn($"DNS-посредник: TCP {primary.EndPoint} занят другим процессом, работа только по UDP " +
                    "(ответы больше UDP-буфера — отказ); попытки занять TCP продолжаются");
                _loops.Add(Task.Run(() => TcpRetryLoopAsync(primary, _stop.Token)));
            }

            if (_optionalAddress is not null)
            {
                var endpoint = new IPEndPoint(_optionalAddress, primary.EndPoint.Port);
                try
                {
                    var optional = Bind(endpoint);
                    _listeners.Add(optional);
                    _loops.Add(Task.Run(() => UdpLoopAsync(optional, _stop.Token)));
                    _loops.Add(Task.Run(() => TcpAcceptLoopAsync(optional.Tcp!, _stop.Token)));
                }
                catch (SocketException ex)
                {
                    // Адрес занят другим процессом или стек IPv6 выключен: пока он не занят, адаптерам не назначается.
                    Warn($"DNS-посредник не занял {endpoint}: {ex.SocketErrorCode}; попытки продолжаются");
                    _loops.Add(Task.Run(() => OptionalRetryLoopAsync(endpoint, _stop.Token)));
                }
            }
        }
    }

    private void Warn(string message)
    {
        Warning?.Invoke(message);
    }

    /// <summary>TCP основного адреса занят чужим: повторять, пока не освободится, затем обслуживать.</summary>
    private async Task TcpRetryLoopAsync(Listener listener, CancellationToken token)
    {
        while (await PauseAsync(token))
        {
            var tcp = new TcpListener(listener.EndPoint) { ExclusiveAddressUse = true };
            try
            {
                tcp.Start();
            }
            catch (SocketException)
            {
                tcp.Stop();
                continue;
            }

            lock (_workGate)
            {
                if (_disposeTask is not null)
                {
                    tcp.Stop();
                    return;
                }

                listener.Tcp = tcp;
            }

            Warn($"DNS-посредник занял TCP {listener.EndPoint}");
            await TcpAcceptLoopAsync(tcp, token);
            return;
        }
    }

    /// <summary>Дополнительный адрес (::1) не занят при старте: повторять, пока не освободится или не появится стек IPv6.</summary>
    private async Task OptionalRetryLoopAsync(IPEndPoint endpoint, CancellationToken token)
    {
        while (await PauseAsync(token))
        {
            Listener optional;
            try
            {
                optional = Bind(endpoint);
            }
            catch (SocketException)
            {
                continue;
            }

            Task[] loops;
            lock (_workGate)
            {
                if (_disposeTask is not null)
                {
                    optional.Close();
                    return;
                }

                _listeners.Add(optional);
                loops = [Task.Run(() => UdpLoopAsync(optional, token), CancellationToken.None), Task.Run(() => TcpAcceptLoopAsync(optional.Tcp!, token), CancellationToken.None)];
            }

            Warn($"DNS-посредник занял {endpoint}");
            await Task.WhenAll(loops);
            return;
        }
    }

    /// <summary>Пауза перед повторной попыткой; false — посредник останавливается.</summary>
    private async Task<bool> PauseAsync(CancellationToken token)
    {
        await Task.Delay(RetryInterval, token).ContinueWith(_ => { }, TaskScheduler.Default);
        return !token.IsCancellationRequested;
    }

    /// <summary>
    /// Основной слушатель. Порт 0 (тесты) означает «любой свободный на UDP и TCP сразу». Система выдаёт
    /// номера подряд, и они надолго застревают в блоке, исключённом для другого протокола (Hyper-V
    /// резервирует блоки по 100 портов), поэтому номер берётся случайный из динамического диапазона.
    /// Заданный порт: TCP чужой — занимается только UDP (TCP — в фоне); UDP чужой — исключение.
    /// </summary>
    private Listener BindPrimary(int port)
    {
        if (port != 0)
        {
            var endpoint = new IPEndPoint(_listenAddress, port);
            try
            {
                return Bind(endpoint);
            }
            catch (SocketException)
            {
                return new Listener(BindUdp(endpoint), null);
            }
        }

        const int attempts = 50;
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return Bind(new IPEndPoint(_listenAddress, Random.Shared.Next(49152, 65536)));
            }
            catch (SocketException) when (attempt < attempts)
            {
            }
        }
    }

    /// <summary>Эксклюзивно занимает UDP и TCP на одном адресе и порту; при неудаче не держит ни того, ни другого.</summary>
    private static Listener Bind(IPEndPoint endpoint)
    {
        // TCP первым: при порте 0 система выбирает его с учётом исключённых диапазонов TCP (Hyper-V и т.п.),
        // а номер, выбранный для UDP, в такой диапазон попадает часто.
        var tcp = new TcpListener(endpoint) { ExclusiveAddressUse = true };
        try
        {
            tcp.Start();
            return new Listener(BindUdp((IPEndPoint)tcp.LocalEndpoint), tcp);
        }
        catch
        {
            tcp.Stop();
            throw;
        }
    }

    private static Socket BindUdp(IPEndPoint endpoint)
    {
        var udp = new Socket(endpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp) { ExclusiveAddressUse = true };
        try
        {
            udp.Bind(endpoint);
            return udp;
        }
        catch
        {
            udp.Dispose();
            throw;
        }
    }

    /// <summary>UDP-сокет и TCP-слушатель одного адреса; TCP основного адреса может появиться позже.</summary>
    private sealed class Listener(Socket udp, TcpListener? tcp)
    {
        private volatile TcpListener? _tcp = tcp;

        public Socket Udp { get; } = udp;

        public IPEndPoint EndPoint { get; } = (IPEndPoint)udp.LocalEndPoint!;

        public TcpListener? Tcp
        {
            get => _tcp;
            set => _tcp = value;
        }

        public void Close()
        {
            Udp.Dispose();
            _tcp?.Stop();
        }
    }

    public ValueTask DisposeAsync()
    {
        lock (_workGate)
        {
            return new ValueTask(_disposeTask ??= DisposeCoreAsync());
        }
    }

    private async Task DisposeCoreAsync()
    {
        await _stop.CancelAsync();
        Listener[] listeners;
        lock (_workGate)
        {
            listeners = _listeners.ToArray();
        }

        foreach (var listener in listeners)
        {
            listener.Close();
        }

        await Task.WhenAll(_loops.Select(t => t.ContinueWith(_ => { }, TaskScheduler.Default)));
        // Приём уже завершён: новых обработчиков не будет. Сначала они вернут разрешения
        // семафоров и закроют клиентские сокеты, затем можно освобождать общие ресурсы.
        Task[] workers;
        lock (_workGate)
        {
            workers = _workers.ToArray();
        }

        await Task.WhenAll(workers);
        await Task.WhenAll(_inFlight.Values);
        _concurrency.Dispose();
        _tcpClients.Dispose();
        _stop.Dispose();
    }

    private void RunWorker(Func<Task> action)
    {
        var worker = Task.Run(async () =>
        {
            try
            {
                await action();
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref _failures);
                System.Diagnostics.Trace.TraceError("Ошибка обработчика DNS: {0}", ex.GetType().Name);
            }
        });
        lock (_workGate)
        {
            _workers.Add(worker);
        }

        _ = RemoveCompletedWorkerAsync(worker);
    }

    private async Task RemoveCompletedWorkerAsync(Task worker)
    {
        await worker;
        lock (_workGate)
        {
            _workers.Remove(worker);
        }
    }

    /// <summary>Обработка одного запроса; открыто для тестов.</summary>
    public async Task<byte[]?> HandleAsync(byte[] query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        if (!Verbose.IsOn)
        {
            return await HandleCoreAsync(query, null, cancellationToken);
        }

        // Подробный журнал: одна строка на запрос — имя, правило, путь, итог и время.
        var trace = new DnsTrace();
        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        var response = await HandleCoreAsync(query, trace, cancellationToken);
        Verbose.Write(DnsTrace.Category, trace.Describe(response, System.Diagnostics.Stopwatch.GetElapsedTime(started)));
        return response;
    }

    private async Task<byte[]?> HandleCoreAsync(byte[] query, DnsTrace? trace, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _queries);
        if (!DnsMessage.TryReadQuestion(query, out var question))
        {
            trace?.Outcome = "неразборчивый запрос";
            return null;
        }

        trace?.Question = question;
        var pinned = TryAnswerPinned(query, question);
        if (pinned is not null)
        {
            Interlocked.Increment(ref _pinned);
            trace?.Outcome = "закреплённый адрес";
            return pinned;
        }

        var configuration = Configuration;
        var domain = MatchDomain(configuration, question.Name);
        trace?.Rule = domain;
        if (domain?.Target.Kind == TargetKind.Block)
        {
            // Имя заблокировано правилом: отвечаем «такого имени нет», upstream не трогаем.
            trace?.Outcome = "блокировка";
            return DnsMessage.BuildEmptyResponse(query, rcode: 3);
        }

        var choice = SelectRoute(configuration, question.Name, domain);
        trace?.Route = choice.Route;
        if (choice.Unavailable)
        {
            // Правило есть, но его туннель не поднят. Общий DNS дал бы ответ чужого вида и увёл бы частное
            // имя к провайдеру или в другой VPN; кеш прежнего пути здесь тоже не годится.
            Interlocked.Increment(ref _failures);
            trace?.Outcome = "путь правила недоступен";
            return DnsMessage.BuildServerFailure(query);
        }

        var offline = configuration.Mode == DnsProxyMode.Offline;
        var context = Context(choice.Route);
        var id = DnsMessage.GetId(query);

        // Ответ с RRSIG или без проверки DNSSEC годится только клиенту с теми же CD, DO и EDNS.
        var flags = DnsMessage.ReadQueryFlags(query);

        // Пути нет вовсе (аварийный режим): выбирать контекст не из чего — годится любой известный ответ.
        var cached = _cache.TryGet(question, context, id, offline, flags)
            ?? (choice.Route is null ? _cache.TryGetAnyPath(question, id, flags) : null);
        if (cached is not null && (offline || !IsStale(cached)))
        {
            Interlocked.Increment(ref _cacheHits);
            trace?.Outcome = offline ? "кеш (аварийный режим)" : "кеш";
            return await AnnounceAsync(configuration, domain, question, cached, query, trace, cancellationToken);
        }

        if (choice.Route is null)
        {
            Interlocked.Increment(ref _failures);
            trace?.Outcome = "нет пути (" + configuration.Mode + ")";
            return DnsMessage.BuildServerFailure(query);
        }

        var response = await ForwardAsync(query, question, flags, context, choice.Route);
        if (response is null)
        {
            Interlocked.Increment(ref _failures);
            // Путь не ответил: просроченный ответ того же пути лучше отказа, но не старше предельного
            // возраста. Ответ чужого пути здесь не годится — он может быть про другую сеть.
            var stale = _cache.TryGet(question, context, id, offline: true, flags);
            trace?.Outcome = stale is null ? "серверы не ответили" : "серверы не ответили, просроченный кеш";
            return stale is null ? DnsMessage.BuildServerFailure(query)
                : await AnnounceAsync(configuration, domain, question, stale, query, trace, cancellationToken);
        }

        Interlocked.Increment(ref _forwarded);
        trace?.Outcome = "переслан";
        if (ReferenceEquals(Configuration, configuration))
        {
            // Пока шёл запрос, настройки могли смениться: ответ прежнего пути в новый кеш не кладётся.
            _cache.Put(question, context, response, flags);
        }

        return await AnnounceAsync(configuration, domain, question, response, query, trace, cancellationToken);
    }

    /// <summary>
    /// Сообщает службе адреса имени, подпадающего под правило для домена, и возвращает ответ только после
    /// подтверждённого применения. Не подтверждено — отказ: адрес без маршрута ушёл бы мимо назначенного пути.
    /// </summary>
    private async Task<byte[]> AnnounceAsync(
        DnsProxyConfiguration configuration,
        DomainRoute? domain,
        DnsQuestion question,
        byte[] response,
        byte[] query,
        DnsTrace? trace,
        CancellationToken cancellationToken)
    {
        if (domain is not { PinAddresses: true } || RouteSink is null || question.Type != DnsMessage.TypeA || DnsMessage.GetRcode(response) != 0)
        {
            return response;
        }

        var addresses = DnsMessage.ReadAddresses(response, question.Name);
        if (addresses.Count == 0)
        {
            return response;
        }

        if (ReferenceEquals(Configuration, configuration))
        {
            try
            {
                var ttl = RouteTtl(response);
                var started = System.Diagnostics.Stopwatch.GetTimestamp();
                if (await RouteSink.ObserveAsync(new PinnedRouteNotice(question.Name, domain.Suffix, domain.Target, addresses, ttl), cancellationToken))
                {
                    // Маршрут уже стареет, пока ответ ждёт очередь. Клиентский кеш не должен пережить
                    // закрепление, даже если upstream прислал суточный TTL или разные TTL записей.
                    var remaining = ttl - System.Diagnostics.Stopwatch.GetElapsedTime(started);
                    if (DnsMessage.CapTtls(response, (uint)Math.Max(0, remaining.TotalSeconds)))
                    {
                        trace?.Pin = "маршрут закреплён за " + (int)System.Diagnostics.Stopwatch.GetElapsedTime(started).TotalMilliseconds + " мс";
                        return response;
                    }
                }
            }
            catch (Exception ex) when (ex is InvalidOperationException or ObjectDisposedException)
            {
                // Служба останавливается: закрепление не применить.
            }
        }

        Interlocked.Increment(ref _failures);
        trace?.Pin = "маршрут не закреплён — отказ клиенту";
        return DnsMessage.BuildServerFailure(query);
    }

    private static TimeSpan RouteTtl(byte[] response)
    {
        var seconds = DnsMessage.GetMinTtl(response) ?? 0;
        return TimeSpan.FromSeconds(Math.Clamp(seconds, MinRouteTtl.TotalSeconds, MaxRouteTtl.TotalSeconds));
    }

    /// <summary>
    /// Пересылка с объединением одинаковых запросов в полёте. Ответ у каждого клиента свой: идентификатор
    /// принадлежит его запросу.
    /// </summary>
    private async Task<byte[]?> ForwardAsync(byte[] query, DnsQuestion question, DnsQueryFlags flags, string context, DnsRoute route)
    {
        var shared = await ShareAsync(InFlightKey(flags, question, context), query, route);
        if (shared is null)
        {
            return null;
        }

        var copy = shared.ToArray();
        DnsMessage.SetId(copy, DnsMessage.GetId(query));
        return copy;
    }

    /// <summary>
    /// Ключ объединения. Биты CD, DO и наличие OPT меняют ответ upstream (проверка DNSSEC, записи RRSIG, EDNS):
    /// запросы, различающиеся ими, объединять нельзя.
    /// </summary>
    internal static string InFlightKey(DnsQueryFlags flags, DnsQuestion question, string context) =>
        string.Join('|', question.Name, question.Type, question.Class, context,
            flags.CheckingDisabled ? "cd" : "", flags.Edns ? "opt" : "", flags.DnssecOk ? "do" : "");

    /// <summary>
    /// Ответ для UDP-клиента. Добранный по TCP ответ бывает больше, чем клиент принимает по UDP: тогда
    /// отдаётся усечённый ответ с TC (заголовок и вопрос), и резолвер повторяет запрос по TCP. TCP-порт не
    /// наш (tcpOurs = false) — отказ SERVFAIL: повтор по TCP ушёл бы чужому процессу. Клиенту с EDNS в таком
    /// ответе нужна своя запись OPT (RFC 6891 §7): без неё он решит, что сервер EDNS не понимает.
    /// </summary>
    internal static byte[] FitUdp(byte[] query, byte[] response, bool tcpOurs = true)
    {
        var edns = DnsMessage.ReadEdns(query);
        var limit = Math.Min(MaxUdpPayload, Math.Max(MinUdpPayload, edns.Present ? (int)edns.UdpSize : 0));
        if (response.Length <= limit)
        {
            return response;
        }

        var reply = tcpOurs ? DnsMessage.BuildEmptyResponse(query, DnsMessage.GetRcode(response)) : DnsMessage.BuildServerFailure(query);
        if (tcpOurs)
        {
            reply[2] |= 0x02;
        }

        return edns.Present ? DnsMessage.AppendOpt(reply, MaxUdpMessage, edns.DnssecOk) : reply;
    }

    private Task<byte[]?> ShareAsync(string key, byte[] query, DnsRoute route)
    {
        if (_inFlight.TryGetValue(key, out var running))
        {
            return running;
        }

        var completion = new TaskCompletionSource<byte[]?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var work = _inFlight.GetOrAdd(key, completion.Task);
        if (!ReferenceEquals(work, completion.Task))
        {
            return work;
        }

        _ = Task.Run(async () =>
        {
            byte[]? result = null;
            try
            {
                result = await DnsForwarder.ForwardAsync(query, route.Servers, route.InterfaceIndex, DnsForwarder.DefaultTimeout, _stop.Token);
            }
            catch (Exception ex) when (ex is OperationCanceledException or SocketException or IOException or ObjectDisposedException)
            {
                // Остановка службы или обрыв пути: ожидающие получат отказ, а не зависнут.
            }
            finally
            {
                _inFlight.TryRemove(key, out _);
                completion.TrySetResult(result);
            }
        });
        return completion.Task;
    }

    /// <summary>Путь разрешения: ответы разных серверов и интерфейсов нельзя смешивать в одном кеше.</summary>
    private static string Context(DnsRoute? route) =>
        route is null ? "" : route.InterfaceIndex + ":" + string.Join(",", route.Servers);

    /// <summary>Правило для домена с самым длинным подходящим суффиксом.</summary>
    internal static DomainRoute? MatchDomain(DnsProxyConfiguration configuration, string name)
    {
        DomainRoute? best = null;
        foreach (var domain in configuration.DomainRoutes)
        {
            if ((best is null || domain.Suffix.Length > best.Suffix.Length) && Matches(name, domain))
            {
                best = domain;
            }
        }

        return best;
    }

    private static bool Matches(string name, DomainRoute domain) =>
        domain.ExactName ? IsSameName(name, domain.Suffix) : IsUnderSuffix(name, domain.Suffix);

    private static bool IsSameName(string name, string exact)
    {
        var trimmed = exact.AsSpan().Trim('.');
        return trimmed.Length > 0 && name.AsSpan().TrimEnd('.').Equals(trimmed, StringComparison.OrdinalIgnoreCase);
    }

    internal static DnsRouteChoice SelectRoute(DnsProxyConfiguration configuration, string name) =>
        SelectRoute(configuration, name, MatchDomain(configuration, name));

    private static DnsRouteChoice SelectRoute(DnsProxyConfiguration configuration, string name, DomainRoute? domain)
    {
        string? local = null;
        if (configuration.Local is not null)
        {
            foreach (var suffix in configuration.LocalSuffixes)
            {
                if ((local is null || suffix.Length > local.Length) && IsUnderSuffix(name, suffix))
                {
                    local = suffix;
                }
            }
        }

        // Из двух совпавших суффиксов выигрывает более длинный; при равенстве — правило для домена.
        if (local is not null && (domain is null || local.Length > domain.Suffix.Length))
        {
            return new DnsRouteChoice(configuration.Local, false);
        }

        if (domain is not null)
        {
            if (domain.Route is { } route)
            {
                return new DnsRouteChoice(route, false);
            }

            if (domain.Unavailable)
            {
                return new DnsRouteChoice(null, true);
            }
        }

        return new DnsRouteChoice(configuration.Mode switch
        {
            DnsProxyMode.Online => configuration.Tunnel,
            DnsProxyMode.DirectAllowed => configuration.Direct,
            _ => null,
        }, false);
    }

    private static bool IsUnderSuffix(string name, string suffix)
    {
        var trimmed = suffix.AsSpan().Trim('.');
        return trimmed.Length > 0
            && name.AsSpan().EndsWith(trimmed, StringComparison.OrdinalIgnoreCase)
            && (name.Length == trimmed.Length || name[name.Length - trimmed.Length - 1] == '.');
    }

    private static bool IsStale(byte[] response) => DnsMessage.GetMinTtl(response) is null or 0;

    private byte[]? TryAnswerPinned(byte[] query, DnsQuestion question)
    {
        if (!_cache.TryGetPinned(question.Name, out var addresses))
        {
            return null;
        }

        return question.Type == DnsMessage.TypeA
            ? DnsMessage.BuildAddressResponse(query, addresses, (uint)PinnedTtl.TotalSeconds)
            : DnsMessage.BuildEmptyResponse(query);
    }

    private async Task UdpLoopAsync(Listener listener, CancellationToken token)
    {
        var socket = listener.Udp;
        var buffer = new byte[MaxUdpMessage];
        while (!token.IsCancellationRequested)
        {
            SocketReceiveFromResult received;
            try
            {
                received = await socket.ReceiveFromAsync(buffer, new IPEndPoint(socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0), token);
            }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.MessageSize)
            {
                // ICMP port unreachable от клиента или слишком длинная датаграмма — ошибка одного пакета.
                continue;
            }
            catch (SocketException)
            {
                // Устойчивая ошибка сокета повторялась бы без паузы и заняла бы ядро процессора целиком.
                Interlocked.Increment(ref _failures);
                await Task.Delay(ReceiveErrorPause, token).ContinueWith(_ => { }, TaskScheduler.Default);
                continue;
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
            {
                return;
            }

            if (!_concurrency.Wait(0, CancellationToken.None))
            {
                // Предел одновременных запросов: пакет отбрасывается, клиент повторит. Копить работу нельзя.
                Interlocked.Increment(ref _failures);
                continue;
            }

            var query = buffer.AsSpan(0, received.ReceivedBytes).ToArray();
            RunWorker(() => ReplyUdpAsync(listener, query, received.RemoteEndPoint, token));
        }
    }

    private async Task ReplyUdpAsync(Listener listener, byte[] query, EndPoint client, CancellationToken token)
    {
        try
        {
            var response = await HandleAsync(query, token);
            if (response is not null)
            {
                // Пока TCP чужой, усечённый ответ отправил бы повтор запроса к чужому процессу: вместо него отказ.
                await listener.Udp.SendToAsync(FitUdp(query, response, tcpOurs: listener.Tcp is not null), client, token);
            }
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException)
        {
            Interlocked.Increment(ref _failures);
        }
        finally
        {
            _concurrency.Release();
        }
    }

    private async Task TcpAcceptLoopAsync(TcpListener listener, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(token);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }

            if (!_tcpClients.Wait(0, CancellationToken.None))
            {
                // Предел соединений: лишние закрываются сразу, иначе программа удержит их все.
                Interlocked.Increment(ref _failures);
                client.Dispose();
                continue;
            }

            RunWorker(() => ServeTcpAsync(client, token));
        }
    }

    /// <summary>
    /// Обслуживание одного TCP-клиента под общим дедлайном: местная программа может открыть соединение
    /// и не прислать заголовок — без предела такие соединения копились бы до остановки службы.
    /// </summary>
    private async Task ServeTcpAsync(TcpClient client, CancellationToken token)
    {
        using (client)
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            deadline.CancelAfter(TcpRequestTimeout);
            try
            {
                var stream = client.GetStream();
                var header = new byte[2];
                await stream.ReadExactlyAsync(header, deadline.Token);
                var length = BinaryPrimitives.ReadUInt16BigEndian(header);
                if (length is 0 or > MaxUdpMessage)
                {
                    Interlocked.Increment(ref _failures);
                    return;
                }

                var query = new byte[length];
                await stream.ReadExactlyAsync(query, deadline.Token);
                var response = await HandleAsync(query, deadline.Token) ?? DnsMessage.BuildServerFailure(query);
                var framed = new byte[response.Length + 2];
                BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)response.Length);
                response.CopyTo(framed, 2);
                await stream.WriteAsync(framed, deadline.Token);
            }
            catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or FormatException)
            {
                Interlocked.Increment(ref _failures);
            }
            finally
            {
                _tcpClients.Release();
            }
        }
    }
}
