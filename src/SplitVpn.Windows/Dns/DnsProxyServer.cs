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
/// <param name="TcpOnly">Путь не переносит UDP («VPN поверх SSH»): запросы идут сразу по TCP.</param>
public sealed record DnsRoute(IReadOnlyList<IPEndPoint> Servers, uint? InterfaceIndex, bool TcpOnly = false);

/// <summary>
/// Правило для домена: имена под этим суффиксом разрешаются по своему пути, а полученные адреса
/// закрепляются за целью на время TTL ответа. Без закрепления (суффиксы шлюза AnyConnect) правило только
/// выбирает DNS-сервер, а трафик идёт по политике. Unavailable — цель правила существует, но сейчас
/// недоступна: такое имя не разрешается вовсе, чтобы не уйти к чужому DNS. ExactName — правило только для
/// самого имени (узел проверки отзыва), его поддомены под правило не попадают.
/// PinContext связывает служебное закрепление с поколением сетевого пути; приёмник отклоняет устаревший контекст.
/// </summary>
public sealed record DomainRoute(string Suffix, RouteTarget Target, DnsRoute? Route, bool PinAddresses = true, bool Unavailable = false, bool ExactName = false, string? PinContext = null, RoutePriority? Priority = null)
{
    public IReadOnlyList<string>? Origins { get; init; }
}

/// <summary>Куда отправлять запрос; Unavailable — отвечать отказом, не обращаясь к общему upstream.</summary>
/// <param name="Local">Выбран путь локального суффикса: он длиннее правила для домена, и правило к имени не относится.</param>
internal sealed record DnsRouteChoice(DnsRoute? Route, bool Unavailable, bool Local = false);

/// <summary>Имя разрешено по правилу для домена: адреса нужно закрепить за целью в исходном PinContext.</summary>
public sealed record PinnedRouteNotice(string Name, string Suffix, RouteTarget Target, IReadOnlyList<uint> Addresses, TimeSpan Ttl, string? PinContext = null)
{
    /// <summary>Временный владелец адресов до решения о выдаче ответа клиенту.</summary>
    public IReadOnlyList<string>? Origins { get; init; }

    public Guid? LeaseId { get; init; }

    /// <summary>Конфигурация, породившая ответ, ещё действует.</summary>
    public Func<bool>? IsCurrent { get; init; }
}

/// <summary>Приёмник закреплений: служба ставит маршруты и фильтры на полученные адреса.</summary>
public interface IPinnedRouteSink
{
    /// <summary>
    /// Ответ DNS ждёт применения маршрута: иначе первое соединение уйдёт не туда. false — применение не
    /// подтверждено, и посредник обязан ответить отказом, а не адресом без защиты.
    /// </summary>
    ValueTask<bool> ObserveAsync(PinnedRouteNotice notice, CancellationToken cancellationToken);

    /// <summary>
    /// Как <see cref="ObserveAsync"/>, но адрес, который закрепить нельзя (конфликт с другой целью, отказ политики, предел
    /// закреплений), не отклоняет ответ целиком: возвращаются принятые и применённые адреса, и посредник отдаёт клиенту
    /// только их, вырезая остальные записи A. null или пусто - не принят ни один, ответ уходит отказом. По умолчанию -
    /// всё или ничего через <see cref="ObserveAsync"/>.
    /// </summary>
    async ValueTask<IReadOnlyList<uint>?> ObservePartialAsync(PinnedRouteNotice notice, CancellationToken cancellationToken) =>
        await ObserveAsync(notice, cancellationToken) ? notice.Addresses : null;

    /// <summary>Подтверждает выдачу ответа или снимает только его временные закрепления.</summary>
    ValueTask<bool> CompleteAsync(PinnedRouteNotice notice, bool accepted) => ValueTask.FromResult(accepted);

    /// <summary>
    /// Адреса того же имени, уже открытые применённым набором, - ими посредник отвечает, если адреса самого ответа
    /// открыть не удалось. Пусто - ответ уходит отказом. Служба отдаёт их только для проверки интернета Windows.
    /// </summary>
    IReadOnlyList<uint> OpenAddresses(PinnedRouteNotice notice) => [];
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
    private const int MaxUdpMessage = ushort.MaxValue;
    private static readonly TimeSpan PinnedTtl = TimeSpan.FromMinutes(5);

    /// <summary>Границы срока жизни закрепления по правилу для домена.</summary>
    public static readonly TimeSpan MinRouteTtl = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan MaxRouteTtl = TimeSpan.FromHours(1);

    /// <summary>
    /// Сколько адресов одного ответа закрепляется. Ответ по TCP вмещает тысячи записей A: без предела одно имя (или поток
    /// случайных поддоменов) за минуты занимал бы весь предел закреплений службы. Лишние записи вырезаются из ответа.
    /// </summary>
    public const int MaxPinnedAddressesPerAnswer = 16;

    /// <summary>
    /// Сколько запросов посредник обрабатывает одновременно. Локальная программа может слать их без
    /// ограничения: без предела растут память, сокеты upstream и очередь службы.
    /// </summary>
    public const int MaxConcurrentQueries = 256;

    /// <summary>
    /// Сколько запросов одновременно ждут один путь DNS (серверы одного туннеля или провайдера). Зависший путь
    /// держит каждый запрос до тайм-аута; без своей доли он занимал все <see cref="MaxConcurrentQueries"/>,
    /// и посредник переставал отвечать на имена, которые к этому пути не относятся. Так 18.11.2026 зависший
    /// туннель «VPN поверх SSH» с правилами на домены Google оставил компьютер без DNS на три минуты.
    /// </summary>
    public const int MaxQueriesPerRoute = MaxConcurrentQueries / 4;

    /// <summary>Сколько соединений TCP обслуживается одновременно.</summary>
    public const int MaxTcpClients = 64;

    /// <summary>Предел на обслуживание одного запроса TCP-клиента: заголовок, тело, ответ.</summary>
    public static readonly TimeSpan TcpRequestTimeout = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Сколько соединение TCP может ждать следующего запроса после ответа (RFC 7766 §6.2.3: несколько секунд).
    /// Сколько всего живёт одно соединение и сколько запросов оно может прислать. Без этих пределов срок
    /// соединения начинался заново с каждым запросом: любая местная программа, присылая запрос раз в несколько
    /// секунд, занимала все <see cref="MaxTcpClients"/> мест навсегда, и большие ответы (повтор по TCP после TC)
    /// переставали разрешаться. Запрос, уже начатый к сроку, дообслуживается; следующий не принимается.
    /// </summary>
    public static readonly TimeSpan DefaultTcpIdleTimeout = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan DefaultTcpConnectionLifetime = TimeSpan.FromSeconds(30);
    public const int MaxTcpQueriesPerConnection = 100;

    /// <summary>Ожидание следующего запроса в соединении TCP; в тестах короче.</summary>
    internal TimeSpan TcpIdleTimeout { get; init; } = DefaultTcpIdleTimeout;

    /// <summary>Наибольший срок одного соединения TCP; в тестах короче.</summary>
    internal TimeSpan TcpConnectionLifetime { get; init; } = DefaultTcpConnectionLifetime;

    /// <summary>Код ответа REFUSED (RFC 1035): имя заблокировано правилом.</summary>
    internal const int RcodeRefused = 5;

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
    private readonly Dictionary<DnsQuestion, int> _udpWaiters = [];
    private readonly Lock _udpWaitersLock = new();
    private readonly SemaphoreSlim _concurrency = new(MaxConcurrentQueries);
    private readonly Dictionary<string, int> _routeLoad = new(StringComparer.Ordinal);
    private readonly Lock _routeLoadLock = new();
    private readonly SemaphoreSlim _tcpClients = new(MaxTcpClients);

    /// <summary>Одинаковые запросы в полёте объединяются: очередь у upstream не растёт от повторов.</summary>
    private readonly ConcurrentDictionary<RequestKey, Task<byte[]?>> _inFlight = new();

    // Конфигурация сравнивается по экземпляру: тот же адрес DNS в другой сети - другое поколение.
    private readonly record struct RequestKey(DnsProxyConfiguration Configuration, string Query)
    {
        public bool Equals(RequestKey other) => ReferenceEquals(Configuration, other.Configuration) && Query == other.Query;

        public override int GetHashCode() => HashCode.Combine(System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(Configuration), Query);
    }

    private DnsProxyConfiguration _configuration = new();
    private readonly List<Listener> _listeners = [];
    private long _queries;
    private long _cacheHits;
    private long _pinned;
    private long _forwarded;
    private long _failures;

    /// <summary>Есть ли правило блокировки пользователя в текущей конфигурации (см. <see cref="HasUserBlockRule"/>).</summary>
    private UserBlockRules? _userBlockRules;

    private sealed record UserBlockRules(DnsProxyConfiguration Configuration, bool Present);

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
        set
        {
            Volatile.Write(ref _configuration, value ?? throw new ArgumentNullException(nameof(value)));
            // Запросы, ждущие пути (PatientNames), перечитывают настройки.
            Interlocked.Exchange(ref _configurationChanged, new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)).TrySetResult();
        }
    }

    private TaskCompletionSource _configurationChanged = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>
    /// Имена, запрос к которым не получает мгновенный отказ, пока пути нет: посредник ждёт новых настроек не дольше
    /// <see cref="PatientWait"/> и отвечает по ним. Это имена проверки интернета Windows. Запись загрузки 21.11.2026:
    /// Windows спрашивает www.msftconnecttest.com через 10 мс после появления шлюза Wi-Fi, а служба выбирает
    /// основной адаптер и открывает путь ещё 0,4 с. Мгновенный отказ Windows не повторяет: через 5 с объявляет
    /// сеть «только локальной», и служба автонастройки WLAN запускает восстановление - перепроверку на 16-й секунде,
    /// перезапуск адаптера на 32-й и отключение Wi-Fi на 65-й.
    /// </summary>
    public IReadOnlyCollection<string> PatientNames { get; init; } = [];

    /// <summary>Сколько запрос из <see cref="PatientNames"/> ждёт новых настроек; Windows ждёт ответа около 5 с.</summary>
    internal TimeSpan PatientWait { get; init; } = TimeSpan.FromSeconds(4);

    /// <summary>Настройки сменились, пока запрос к терпеливому имени ждал пути: его нужно разобрать заново.</summary>
    private async Task<bool> WaitForNewPathAsync(DnsProxyConfiguration seen, string name, long deadline, CancellationToken cancellationToken)
    {
        if (PatientNames.Count == 0 || !PatientNames.Contains(name.TrimEnd('.'), StringComparer.OrdinalIgnoreCase))
        {
            return false;
        }

        var signal = Volatile.Read(ref _configurationChanged);
        if (!ReferenceEquals(Configuration, seen))
        {
            return true;
        }

        var left = deadline - Environment.TickCount64;
        if (left <= 0)
        {
            return false;
        }

        try
        {
            await signal.Task.WaitAsync(TimeSpan.FromMilliseconds(left), cancellationToken);
            return true;
        }
        catch (TimeoutException)
        {
            return false;
        }
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

    /// <summary>Приём TCP-соединения; тесты подменяют его, чтобы воспроизвести ошибку приёма.</summary>
    internal Func<TcpListener, CancellationToken, ValueTask<TcpClient>> AcceptTcp { get; init; } =
        static (listener, token) => listener.AcceptTcpClientAsync(token);

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
    /// Слушать ещё и все адреса IPv4 (0.0.0.0), чтобы отвечать на запросы к адресу самого адаптера. Запрос,
    /// привязанный к адаптеру (так Windows проверяет интернет на каждом интерфейсе), до 127.0.0.1 не доходит:
    /// стек отвечает ошибкой 10049. Слушатель не эксклюзивный: чужая программа по-прежнему может занять порт
    /// на своём адресе (DNS WSL, Hyper-V, общий доступ к интернету), и её запросы достаются ей, а запросы
    /// к 127.0.0.1 - основному слушателю. Адрес слушателя виден из сети, поэтому он отвечает только на запросы
    /// с адресов этого компьютера (<see cref="IsLocalSource"/>). Адрес, который служба объявляет DNS-сервером
    /// адаптера, посредник сверх того занимает эксклюзивно (<see cref="ClaimAdapterAddresses"/>).
    /// </summary>
    public bool ServeAdapterAddresses { get; init; }

    /// <summary>Занят ли слушатель всех адресов (для тестов и диагностики).</summary>
    public bool AdapterListening
    {
        get
        {
            lock (_workGate)
            {
                return _wildcard is not null;
            }
        }
    }

    private Listener? _wildcard;

    /// <summary>Эксклюзивно занятые адреса адаптеров (<see cref="ClaimAdapterAddresses"/>).</summary>
    private readonly Dictionary<IPAddress, Listener> _claimed = [];

    /// <summary>Адреса, занять которые не удалось: предупреждение пишется один раз, а не на каждой сверке.</summary>
    private readonly HashSet<IPAddress> _claimFailures = [];

    /// <summary>
    /// Циклы приёма занятых адресов, в том числе уже освобождённых и ещё не вышедших: остановка посредника ждёт их
    /// до освобождения семафоров, иначе запоздалый цикл запустил бы обработчик на освобождённых ресурсах.
    /// </summary>
    private readonly List<Task> _claimLoops = [];

    /// <summary>
    /// Эксклюзивно (SO_EXCLUSIVEADDRUSE, UDP и TCP) занимает порт посредника на адресах адаптеров и обслуживает их
    /// тем же обработчиком, что и слушатель всех адресов, - только для отправителей с этого компьютера. Аудит
    /// 24.11.2026: при не эксклюзивном слушателе всех адресов процесс без прав администратора занимал
    /// &lt;адрес адаптера&gt;:53 - более точная привязка выигрывает - и получал запросы всей системы первым, ведь
    /// адрес адаптера стоит первым DNS-сервером. Эксклюзивно занятый адрес чужой процесс занять уже не может, а
    /// остальные адреса (ICS 192.168.137.1, Default Switch Hyper-V, WSL) остаются свободны для своих резолверов.
    /// Возвращает адреса набора, которые сейчас заняты эксклюзивно (в том числе занятые раньше); только их служба
    /// вправе объявлять DNS-серверами адаптеров. Адрес, уже занятый другим процессом, в ответ не входит: попытка
    /// повторяется при следующем вызове (служба вызывает его на каждой сверке). Ранее занятые адреса вне набора
    /// не освобождаются: служба сначала убирает адрес из DNS адаптера, потом зовёт <see cref="ReleaseAdapterAddresses"/>.
    /// </summary>
    public IReadOnlyList<IPAddress> ClaimAdapterAddresses(IEnumerable<IPAddress> addresses)
    {
        ArgumentNullException.ThrowIfNull(addresses);
        var held = new List<IPAddress>();
        var messages = new List<string>();
        lock (_workGate)
        {
            if (_disposeTask is not null || _listeners.Count == 0)
            {
                return held;
            }

            var port = _listeners[0].EndPoint.Port;
            foreach (var address in addresses.Distinct())
            {
                if (address.AddressFamily != AddressFamily.InterNetwork || IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any))
                {
                    continue;
                }

                if (_claimed.ContainsKey(address))
                {
                    held.Add(address);
                    continue;
                }

                var endpoint = new IPEndPoint(address, port);
                Listener claimed;
                try
                {
                    // Bind при неудаче не держит ни UDP, ни TCP: частичного захвата не остаётся.
                    claimed = Bind(endpoint);
                }
                catch (SocketException ex)
                {
                    if (_claimFailures.Add(address))
                    {
                        messages.Add($"DNS-посредник не занял {endpoint} эксклюзивно ({ex.SocketErrorCode}): порт держит другая " +
                            "программа. Адрес адаптера DNS-сервером не ставится - только 127.0.0.1, проверка интернета Windows " +
                            "на адаптере может не пройти; попытки продолжаются");
                    }

                    continue;
                }

                _claimed.Add(address, claimed);
                _claimLoops.RemoveAll(t => t.IsCompleted);
                _claimLoops.Add(Task.Run(() => UdpLoopAsync(claimed, _stop.Token, localOnly: true), CancellationToken.None));
                _claimLoops.Add(Task.Run(() => TcpAcceptLoopAsync(claimed, claimed.Tcp!, _stop.Token, localOnly: true), CancellationToken.None));
                if (_claimFailures.Remove(address))
                {
                    messages.Add($"DNS-посредник занял {endpoint} эксклюзивно");
                }

                held.Add(address);
            }
        }

        foreach (var message in messages)
        {
            Warn(message);
        }

        return held;
    }

    /// <summary>
    /// Освобождает эксклюзивно занятые адреса адаптеров, кроме <paramref name="keep"/>. Вызывается после того, как
    /// адрес убран из DNS адаптеров: иначе на мгновение адрес стоял бы DNS-сервером, не будучи занят.
    /// </summary>
    public void ReleaseAdapterAddresses(IEnumerable<IPAddress> keep)
    {
        ArgumentNullException.ThrowIfNull(keep);
        var kept = keep.ToHashSet();
        var released = new List<Listener>();
        lock (_workGate)
        {
            if (_disposeTask is not null)
            {
                return;
            }

            foreach (var address in _claimed.Keys.Where(a => !kept.Contains(a)).ToList())
            {
                released.Add(_claimed[address]);
                _claimed.Remove(address);
            }

            _claimFailures.RemoveWhere(a => !kept.Contains(a));
        }

        // Циклы приёма выходят сами по закрытому сокету и остаются в _claimLoops до остановки посредника.
        foreach (var listener in released)
        {
            listener.Close();
        }
    }

    /// <summary>Эксклюзивно занятые адреса адаптеров (для тестов).</summary>
    internal IReadOnlyList<IPAddress> ClaimedAdapterAddresses
    {
        get
        {
            lock (_workGate)
            {
                return [.. _claimed.Keys];
            }
        }
    }

    /// <summary>Задачи циклов приёма (для тестов): цикл не должен завершаться ошибкой.</summary>
    internal IReadOnlyList<Task> ReceiveLoops
    {
        get
        {
            lock (_workGate)
            {
                return [.. _loops, .. _claimLoops];
            }
        }
    }

    /// <summary>Адрес слушателя всех адресов (для тестов).</summary>
    internal IPEndPoint? AdapterEndPoint
    {
        get
        {
            lock (_workGate)
            {
                return _wildcard?.EndPoint;
            }
        }
    }

    /// <summary>Как часто перечитываются адреса компьютера: при незнакомом отправителе и для знакомого.</summary>
    private static readonly TimeSpan LocalAddressMissRefresh = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan LocalAddressHitRefresh = TimeSpan.FromSeconds(30);

    private readonly Lock _localAddressesLock = new();
    private IPAddress[] _localAddresses = [];
    private long _localAddressesRead;

    /// <summary>Адреса IPv4 этого компьютера; тесты подменяют список.</summary>
    internal Func<IPAddress[]> ReadLocalAddresses { get; init; } = static () =>
        [.. System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up)
            .SelectMany(n => n.GetIPProperties().UnicastAddresses)
            .Select(u => u.Address)
            .Where(a => a.AddressFamily == AddressFamily.InterNetwork)];

    /// <summary>
    /// Отправитель - этот же компьютер: запрос к адресу адаптера приходит с адреса самого компьютера. Запрос из
    /// сети (слушатель всех адресов доступен и с неё) отбрасывается без ответа. Список адресов перечитывается
    /// не чаще раза в секунду при незнакомом отправителе (адрес мог только что появиться) и раз в полминуты
    /// при знакомом (адрес мог уйти другому устройству).
    /// </summary>
    internal bool IsLocalSource(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        lock (_localAddressesLock)
        {
            var known = Array.IndexOf(_localAddresses, address) >= 0;
            var age = _localAddressesRead == 0 ? TimeSpan.MaxValue : System.Diagnostics.Stopwatch.GetElapsedTime(_localAddressesRead);
            if (age < (known ? LocalAddressHitRefresh : LocalAddressMissRefresh))
            {
                return known;
            }

            _localAddressesRead = System.Diagnostics.Stopwatch.GetTimestamp();
            try
            {
                _localAddresses = ReadLocalAddresses();
            }
            catch (System.Net.NetworkInformation.NetworkInformationException)
            {
                // Список не прочитался: остаётся прежний.
            }

            return Array.IndexOf(_localAddresses, address) >= 0;
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

            var bound = BindAll(port);
            var primary = bound.Primary;
            _listeners.Add(primary);
            _loops.Add(Task.Run(() => UdpLoopAsync(primary, _stop.Token)));
            if (primary.Tcp is { } tcp)
            {
                _loops.Add(Task.Run(() => TcpAcceptLoopAsync(primary, tcp, _stop.Token)));
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
                if (bound.Optional is { } optional)
                {
                    _listeners.Add(optional);
                    _loops.Add(Task.Run(() => UdpLoopAsync(optional, _stop.Token)));
                    _loops.Add(Task.Run(() => TcpAcceptLoopAsync(optional, optional.Tcp!, _stop.Token)));
                }
                else
                {
                    // Адрес занят другим процессом или стек IPv6 выключен: пока он не занят, адаптерам не назначается.
                    Warn($"DNS-посредник не занял {endpoint}: {bound.OptionalError}; попытки продолжаются");
                    _loops.Add(Task.Run(() => OptionalRetryLoopAsync(endpoint, _stop.Token)));
                }
            }

            if (ServeAdapterAddresses)
            {
                // Первая попытка - сразу: служба ставит адаптеру DNS в той же сверке, и список не меняется дважды.
                var endpoint = new IPEndPoint(IPAddress.Any, primary.EndPoint.Port);
                if (bound.Wildcard is { } wildcard)
                {
                    StartWildcard(wildcard);
                }
                else
                {
                    Warn($"DNS-посредник не занял {endpoint}: {bound.WildcardError}; проверка интернета Windows на адаптере " +
                        "не пройдёт, попытки продолжаются");
                    _loops.Add(Task.Run(() => WildcardRetryLoopAsync(endpoint, _stop.Token)));
                }
            }
        }
    }

    /// <summary>Слушатели, занятые при старте; не занятый дополнительный или общий слушатель - с кодом ошибки.</summary>
    private readonly record struct BoundListeners(
        Listener Primary, Listener? Optional, SocketError OptionalError, Listener? Wildcard, SocketError WildcardError);

    /// <summary>
    /// Занимает основной, дополнительный (::1) и общий (0.0.0.0) слушатели одного порта. Заданный порт (53) - как
    /// прежде: основной обязательно, остальные - если свободны (иначе повтор в фоне). Порт 0 (тесты): номер
    /// случайный, и если он свободен на 127.0.0.1, но занят на ::1 или 0.0.0.0 другим процессом, все слушатели
    /// освобождаются и берётся другой номер - иначе посредник стартовал бы без них и ждал повтора 5 с. Ошибку,
    /// которую смена номера не исправит (стек IPv6 выключен), принимаем сразу, как при заданном порте.
    /// </summary>
    private BoundListeners BindAll(int port)
    {
        if (port != 0)
        {
            return BindSecondary(BindPrimary(port));
        }

        const int attempts = 50;
        for (var attempt = 1; ; attempt++)
        {
            var bound = BindSecondary(BindPrimary(0));
            var collided = IsCollision(bound.Optional, bound.OptionalError) || IsCollision(bound.Wildcard, bound.WildcardError);
            if (!collided || attempt >= attempts)
            {
                return bound;
            }

            bound.Wildcard?.Close();
            bound.Optional?.Close();
            bound.Primary.Close();
        }

        static bool IsCollision(Listener? listener, SocketError error) =>
            listener is null && error is SocketError.AddressAlreadyInUse or SocketError.AccessDenied;
    }

    private BoundListeners BindSecondary(Listener primary)
    {
        var port = primary.EndPoint.Port;
        Listener? optional = null;
        var optionalError = SocketError.Success;
        if (_optionalAddress is not null)
        {
            try
            {
                optional = Bind(new IPEndPoint(_optionalAddress, port));
            }
            catch (SocketException ex)
            {
                optionalError = ex.SocketErrorCode;
            }
        }

        Listener? wildcard = null;
        var wildcardError = SocketError.Success;
        if (ServeAdapterAddresses)
        {
            try
            {
                wildcard = BindShared(new IPEndPoint(IPAddress.Any, port));
            }
            catch (SocketException ex)
            {
                wildcardError = ex.SocketErrorCode;
            }
        }

        return new BoundListeners(primary, optional, optionalError, wildcard, wildcardError);
    }

    /// <summary>Запускает приём на слушателе всех адресов; вызывается под <see cref="_workGate"/>.</summary>
    private void StartWildcard(Listener wildcard)
    {
        _wildcard = wildcard;
        _loops.Add(Task.Run(() => UdpLoopAsync(wildcard, _stop.Token, localOnly: true)));
        _loops.Add(Task.Run(() => TcpAcceptLoopAsync(wildcard, wildcard.Tcp!, _stop.Token, localOnly: true)));
    }

    /// <summary>Слушатель всех адресов не занят при старте: повторять, пока порт не освободится.</summary>
    private async Task WildcardRetryLoopAsync(IPEndPoint endpoint, CancellationToken token)
    {
        while (await PauseAsync(token))
        {
            Listener wildcard;
            try
            {
                wildcard = BindShared(endpoint);
            }
            catch (SocketException)
            {
                continue;
            }

            lock (_workGate)
            {
                if (_disposeTask is not null)
                {
                    wildcard.Close();
                    return;
                }

                StartWildcard(wildcard);
            }

            Warn($"DNS-посредник занял {endpoint}");
            return;
        }
    }

    /// <summary>Не эксклюзивно занимает UDP и TCP на всех адресах: чужие слушатели на своих адресах остаются.</summary>
    private static Listener BindShared(IPEndPoint endpoint)
    {
        var tcp = new TcpListener(endpoint);
        Socket? udp = null;
        try
        {
            tcp.Start();
            udp = new Socket(endpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            udp.Bind(endpoint);
            return new Listener(udp, tcp);
        }
        catch
        {
            udp?.Dispose();
            tcp.Stop();
            throw;
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
            await TcpAcceptLoopAsync(listener, tcp, token);
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
                loops = [Task.Run(() => UdpLoopAsync(optional, token), CancellationToken.None), Task.Run(() => TcpAcceptLoopAsync(optional, optional.Tcp!, token), CancellationToken.None)];
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

        /// <summary>Сокеты закрыты: ошибки приёма после этого - штатный выход цикла, а не отказ.</summary>
        public bool Closed => _closed;

        private volatile bool _closed;

        public void Close()
        {
            _closed = true;
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
        Task[] claimLoops;
        lock (_workGate)
        {
            // После установки _disposeTask (под этой же блокировкой) новые адреса не занимаются: снимок полный.
            listeners = [.. _listeners, .. _wildcard is { } wildcard ? [wildcard] : Array.Empty<Listener>(), .. _claimed.Values];
            _claimed.Clear();
            claimLoops = [.. _claimLoops];
        }

        foreach (var listener in listeners)
        {
            listener.Close();
        }

        await Task.WhenAll(_loops.Concat(claimLoops).Select(t => t.ContinueWith(_ => { }, TaskScheduler.Default)));
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
            return EchoQuestionCase(query, await HandleCoreAsync(query, null, cancellationToken));
        }

        // Подробный журнал: одна строка на запрос — имя, правило, путь, итог и время.
        var trace = new DnsTrace();
        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        var response = await HandleCoreAsync(query, trace, cancellationToken);
        Verbose.Write(DnsTrace.Category, trace.Describe(response, System.Diagnostics.Stopwatch.GetElapsedTime(started)));
        return EchoQuestionCase(query, response);
    }

    private static byte[]? EchoQuestionCase(byte[] query, byte[]? response)
    {
        // Кеш отдаёт каждому клиенту собственную копию. Меняем только буквы несжатых меток той же длины.
        for (var i = DnsMessage.HeaderLength; response is not null && i < Math.Min(query.Length, response.Length);)
        {
            var length = query[i];
            if (length is 0 or > 63 || length != response[i++] || length > Math.Min(query.Length, response.Length) - i)
            {
                break;
            }

            query.AsSpan(i, length).CopyTo(response.AsSpan(i, length));
            i += length;
        }

        return response;
    }

    private async Task<byte[]?> HandleCoreAsync(byte[] query, DnsTrace? trace, CancellationToken cancellationToken, long patientDeadline = 0)
    {
        if (patientDeadline == 0)
        {
            Interlocked.Increment(ref _queries);
            patientDeadline = Environment.TickCount64 + (long)PatientWait.TotalMilliseconds;
        }

        if (!DnsMessage.TryReadQuestion(query, out var question))
        {
            trace?.Outcome = "неразборчивый запрос";
            return null;
        }

        if ((query[2] & 0x78) != 0)
        {
            var unsupported = DnsMessage.BuildEmptyResponse(query, 4);
            unsupported[2] = (byte)((unsupported[2] & ~0x78) | (query[2] & 0x78));
            return unsupported;
        }

        trace?.Question = question;
        var pinned = TryAnswerPinned(query, question);
        if (pinned is not null)
        {
            Interlocked.Increment(ref _pinned);
            trace?.Outcome = "закреплённый адрес";
            return pinned;
        }

        // Поколение кеша берётся до конфигурации: служба сначала меняет конфигурацию, затем очищает кеш, и ответ,
        // полученный до очистки, но записываемый после неё, в кеш новой сети не попадёт.
        var generation = _cache.Generation;
        var configuration = Configuration;
        var domain = MatchDomain(configuration, question.Name) ?? InheritedDomain(configuration, question.Name);
        trace?.Rule = domain;
        var choice = SelectRoute(configuration, question.Name, domain);
        if (choice.Local) { domain = null; }
        if (domain?.Target.Kind == TargetKind.Block)
        {
            // Имя заблокировано правилом: REFUSED, upstream не трогаем. Не NXDOMAIN — имя существует,
            // и ложный отрицательный ответ закешировали бы надолго (DOMAIN-ROUTING-PLAN).
            trace?.Outcome = "блокировка";
            return DnsMessage.BuildEmptyResponse(query, rcode: RcodeRefused);
        }

        trace?.Route = choice.Route;
        if (choice.Local)
        {
            // Локальный суффикс точнее правила: имя разрешает локальный DNS, и его адрес (например, принтер
            // в соседнем VLAN офиса) не закрепляется за целью правила и не получает пустой AAAA.
            domain = null;
        }

        if (choice.Unavailable)
        {
            // Правило есть, но его туннель не поднят. Общий DNS дал бы ответ чужого вида и увёл бы частное
            // имя к провайдеру или в другой VPN; кеш прежнего пути здесь тоже не годится.
            if (await WaitForNewPathAsync(configuration, question.Name, patientDeadline, cancellationToken))
            {
                return await HandleCoreAsync(query, trace, cancellationToken, patientDeadline);
            }

            Interlocked.Increment(ref _failures);
            trace?.Outcome = "путь правила недоступен";
            return DnsMessage.BuildServerFailure(query);
        }

        // ANY может нести A/AAAA и HTTPS-подсказки сразу: без закрепления всех адресов ответ небезопасен.
        if (domain is { PinAddresses: true } && question.Type == 255)
        {
            return DnsMessage.BuildEmptyResponse(query, rcode: RcodeRefused);
        }

        if (domain is { PinAddresses: true } && question.Type is DnsMessage.TypeAaaa or DnsMessage.TypeSvcb or DnsMessage.TypeHttps)
        {
            // Правило закрепляет только IPv4, а публичный IPv6 под защитой заблокирован: настоящий AAAA увёл бы
            // приложение на адрес без маршрута. Пустой успешный ответ — и оно берёт закреплённый IPv4.
            // HTTPS и SVCB несут подсказки адресов (ipv4hint): браузер может подключиться к ним без запроса A,
            // и адрес ушёл бы мимо закрепления. Такие записи под правилом не отдаются.
            trace?.Outcome = question.Type == DnsMessage.TypeAaaa ? "AAAA под правилом — пустой ответ" : "HTTPS/SVCB под правилом — пустой ответ";
            return DnsMessage.BuildEmptyResponse(query);
        }

        // Просроченный ответ годится только там, где пути нет. В аварийном режиме у имени может быть свой
        // рабочий путь (правило «напрямую», split DNS, локальный суффикс): тогда ответ обновляется как обычно.
        var offline = choice.Route is null;
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
            return await AnswerAsync(configuration, domain, choice.Local, context, question, cached, query, trace, cancellationToken);
        }

        if (choice.Route is null)
        {
            if (await WaitForNewPathAsync(configuration, question.Name, patientDeadline, cancellationToken))
            {
                return await HandleCoreAsync(query, trace, cancellationToken, patientDeadline);
            }

            Interlocked.Increment(ref _failures);
            trace?.Outcome = "нет пути (" + configuration.Mode + ")";
            return DnsMessage.BuildServerFailure(query);
        }

        var response = await ForwardAsync(configuration, query, question, flags, context, choice.Route, cancellationToken);
        if (response is null)
        {
            Interlocked.Increment(ref _failures);
            // Путь не ответил (молчание, SERVFAIL): просроченный ответ того же пути лучше отказа, но не старше
            // предельного возраста. Ответ чужого пути здесь не годится — он может быть про другую сеть. REFUSED
            // от всех серверов пути сюда не попадает: это окончательный ответ (DnsForwarder.ForwardAsync), и
            // просроченный адрес не обходит свежую блокировку корпоративного DNS или фильтра.
            var stale = _cache.TryGet(question, context, id, offline: true, flags);
            trace?.Outcome = stale is null ? "серверы не ответили" : "серверы не ответили, просроченный кеш";
            return stale is null ? DnsMessage.BuildServerFailure(query)
                : await AnswerAsync(configuration, domain, choice.Local, context, question, stale, query, trace, cancellationToken);
        }

        Interlocked.Increment(ref _forwarded);
        trace?.Outcome = "переслан";
        if (ReferenceEquals(Configuration, configuration))
        {
            // Пока шёл запрос, настройки могли смениться: ответ прежнего пути в новый кеш не кладётся.
            // Смена могла случиться и сразу после этой проверки - тогда запись отбросит поколение кеша.
            _cache.Put(question, context, response, flags, generation);
        }

        return await AnswerAsync(configuration, domain, choice.Local, context, question, response, query, trace, cancellationToken);
    }

    /// <summary>
    /// Итоговый ответ клиенту. Имя без своего правила, чья CNAME-цепочка ведёт в домен, заблокированный правилом
    /// пользователя, получает отказ, как и само заблокированное имя: иначе любое имя с CNAME в такой домен обходило бы
    /// блокировку. Проверка идёт и для ответа из кеша: ответ без правила кешируется, и повторный запрос её не минует.
    /// Другие правила (закрепление, недоступный путь, служебные имена) на цепочку не распространяются: ответ пришёл
    /// путём самого имени, и его адреса нельзя закреплять за целью правила - чужой DNS направил бы так в туннель
    /// любой адрес.
    /// </summary>
    private async Task<byte[]> AnswerAsync(
        DnsProxyConfiguration configuration,
        DomainRoute? domain,
        bool local,
        string context,
        DnsQuestion question,
        byte[] response,
        byte[] query,
        DnsTrace? trace,
        CancellationToken cancellationToken)
    {
        if (domain is null && !local)
        {
            // Пока шёл запрос, пользователь мог добавить правило блокировки: ответ сверяется и с текущими настройками,
            // иначе он ушёл бы клиенту по старым и попал бы в кеш Windows уже после сброса, последовавшего за сменой.
            var current = Configuration;
            var block = ChainBlockRule(configuration, question.Name, response)
                ?? (ReferenceEquals(current, configuration) ? null : ChainBlockRule(current, question.Name, response));
            if (block is not null)
            {
                trace?.Rule = block;
                trace?.Outcome = "блокировка по CNAME";
                return DnsMessage.BuildEmptyResponse(query, rcode: RcodeRefused);
            }
        }

        return await AnnounceAsync(configuration, domain, context, question, response, query, trace, cancellationToken);
    }

    /// <summary>
    /// Правило блокировки пользователя, в домен которого ведёт CNAME-цепочка ответа, или null. Без таких правил
    /// в конфигурации цепочка не разбирается.
    /// </summary>
    private DomainRoute? ChainBlockRule(DnsProxyConfiguration configuration, string question, byte[] response)
    {
        if (!HasUserBlockRule(configuration))
        {
            return null;
        }

        foreach (var name in DnsMessage.ReadCanonicalNames(response, question))
        {
            // Как и для имени вопроса: действует самое длинное подходящее правило, а более длинный локальный
            // суффикс его отменяет.
            var rule = MatchDomain(configuration, name);
            if (rule is not null && IsUserBlockRule(rule) && !SelectRoute(configuration, name, rule).Local)
            {
                return rule;
            }
        }

        return null;
    }

    /// <summary>
    /// Правило блокировки, заданное пользователем. Правила пользователя служба строит с закреплением и для всего
    /// домена; служебные (проверка интернета Windows, узлы проверки отзыва, имя шлюза) - только для самого имени
    /// (ExactName) и никогда не блокируют; суффиксы split DNS шлюза идут без закрепления.
    /// </summary>
    private static bool IsUserBlockRule(DomainRoute rule) =>
        rule is { Target.Kind: TargetKind.Block, PinAddresses: true, ExactName: false, PinContext: null };

    /// <summary>
    /// Есть ли в конфигурации правило блокировки пользователя. Ответ запоминается только для текущей конфигурации:
    /// запросы, начатые до смены настроек, проверяют и прежнюю, и она не должна вытеснять запомненный ответ текущей.
    /// </summary>
    private bool HasUserBlockRule(DnsProxyConfiguration configuration)
    {
        var known = Volatile.Read(ref _userBlockRules);
        if (known is not null && ReferenceEquals(known.Configuration, configuration))
        {
            return known.Present;
        }

        var present = false;
        foreach (var rule in configuration.DomainRoutes)
        {
            if (IsUserBlockRule(rule))
            {
                present = true;
                break;
            }
        }

        if (ReferenceEquals(configuration, Configuration))
        {
            Volatile.Write(ref _userBlockRules, new UserBlockRules(configuration, present));
        }

        return present;
    }

    /// <summary>
    /// Сообщает службе адреса имени, подпадающего под правило для домена, и возвращает ответ только после
    /// подтверждённого применения. Не подтверждено — отказ: адрес без маршрута ушёл бы мимо назначенного пути.
    /// </summary>
    private async Task<byte[]> AnnounceAsync(
        DnsProxyConfiguration configuration,
        DomainRoute? domain,
        string context,
        DnsQuestion question,
        byte[] response,
        byte[] query,
        DnsTrace? trace,
        CancellationToken cancellationToken)
    {
        if (!IsAnswerCurrent(configuration, domain, question.Name, context))
        {
            return DnsMessage.BuildServerFailure(query);
        }

        if (domain is not { PinAddresses: true } || DnsMessage.GetRcode(response) != 0)
        {
            return response;
        }

        if (DnsMessage.IsTruncated(response))
        {
            // Усечённый ответ (TCP добрать не удалось) клиент отбросит и переспросит по TCP: его адреса не
            // закрепляются и связи не подтверждаются. Клиенту уходит TC без записей - резолвер, не умеющий TCP,
            // не возьмёт из неполного ответа адрес без маршрута.
            var truncated = DnsMessage.BuildEmptyResponse(query);
            truncated[2] |= 0x02;
            return truncated;
        }

        var ttl = RouteTtl(response);
        var leaseId = Guid.NewGuid();
        // CNAME-связь создаёт только ответ из одних CNAME: клиенту предстоит отдельный запрос канонического имени, и
        // связь передаёт ему правило исходного. Ответ с адресами несёт цепочку целиком - его адреса закрепляются ниже,
        // а связь лишь позволила бы чужому DNS (x.evil.ru CNAME mail.google.com + A) увести постороннее имя под
        // правило. Цель «напрямую» не наследуется вовсе (см. InheritedDomain), поэтому и связь для неё не нужна.
        // Срок связи короткий: его хватает, чтобы клиент прошёл по цепочке.
        var links = DnsMessage.IsCnameOnly(response) && domain.Target.Kind != TargetKind.Direct
            ? DnsMessage.ReadCanonicalNames(response, question.Name)
            : [];
        var linkLifetime = CanonicalLinkLifetime(response);
        if (links.Count > 0)
        {
            // Клиент с собственным кешем (systemd-resolved в WSL, браузер) спросит каноническое имя, пока помнит CNAME:
            // CNAME не должен пережить связь, иначе каноническое имя пойдёт общим путём мимо правила. Повторный
            // запрос исходного имени отвечается из кеша посредника и продлевает связь - шквала к upstream нет.
            // Секунда запаса: отсчёт TTL у клиента начинается позже, чем срок связи.
            var cap = linkLifetime - TimeSpan.FromSeconds(1);
            ttl = cap < ttl ? cap : ttl;
        }

        if (!_cache.TryReserveCanonicalLinks(links, domain.Suffix, linkLifetime, leaseId,
            suffix => configuration.DomainRoutes.FirstOrDefault(d => d.PinAddresses && d.Suffix == suffix) is not { } existing
                || existing.Target == domain.Target, domain.Origins ?? [question.Name]))
        {
            return DnsMessage.BuildServerFailure(query);
        }

        var accepted = false;
        try
        {
            var result = await AnnounceAddressesAsync(configuration, domain, context, question, response, query, trace, ttl, leaseId, cancellationToken);
            accepted = DnsMessage.GetRcode(result) == 0;
            return result;
        }
        finally
        {
            _cache.CompleteCanonicalLinks(leaseId, accepted);
        }
    }

    private async Task<byte[]> AnnounceAddressesAsync(DnsProxyConfiguration configuration, DomainRoute domain, string context,
        DnsQuestion question, byte[] response, byte[] query, DnsTrace? trace, TimeSpan ttl, Guid leaseId, CancellationToken cancellationToken)
    {
        // Дополнительная секция под правилом с закреплением не отдаётся (кроме OPT): адреса целей SRV, MX и NS из неё
        // ушли бы клиенту незакреплёнными, и программа, взявшая адрес оттуда, подключилась бы мимо правила.
        if (DnsMessage.RemoveAdditionalRecords(response) is not { } stripped)
        {
            Interlocked.Increment(ref _failures);
            trace?.Pin = "ответ не разобран — отказ клиенту";
            return DnsMessage.BuildServerFailure(query);
        }

        response = stripped;
        var all = DnsMessage.ReadAddresses(response, question.Name);
        if (all.Count == 0)
        {
            return IsAnswerCurrent(configuration, domain, question.Name, context) && DnsMessage.CapTtls(response, (uint)ttl.TotalSeconds)
                ? response : DnsMessage.BuildServerFailure(query);
        }

        // Закрепляется не больше MaxPinnedAddressesPerAnswer адресов ответа: ответ по TCP вмещает тысячи записей A, и
        // одно имя заполнило бы предел закреплений службы. Лишние записи вырезаются из ответа, а не закрепляются.
        var addresses = all.Distinct().Take(MaxPinnedAddressesPerAnswer).ToList();
        if (IsAnswerCurrent(configuration, domain, question.Name, context) && RouteSink is { } sink)
        {
            var notice = new PinnedRouteNotice(question.Name, domain.Suffix, domain.Target, addresses, ttl, domain.PinContext)
            {
                Origins = domain.Origins,
                LeaseId = leaseId,
                IsCurrent = () => IsAnswerCurrent(configuration, domain, question.Name, context),
            };
            var completed = false;
            var stopping = false;
            try
            {
                var started = System.Diagnostics.Stopwatch.GetTimestamp();

                // Пока ответ ждал применения, политика могла смениться (правило снято или ведёт в другую
                // цель): подтверждение относится к прежней конфигурации, и адрес клиенту уже не отдаётся.
                // Адрес, который закрепить нельзя (конфликт, отказ политики, предел), ответ целиком не отклоняет:
                // клиенту уходят только принятые адреса.
                if (await sink.ObservePartialAsync(notice, cancellationToken) is { Count: > 0 } accepted
                    && IsAnswerCurrent(configuration, domain, question.Name, context)
                    && KeepAddresses(query, response, accepted) is { } reply)
                {
                    // Маршрут уже стареет, пока ответ ждёт очередь. Клиентский кеш не должен пережить
                    // закрепление, даже если upstream прислал суточный TTL или разные TTL записей.
                    var remaining = ttl - System.Diagnostics.Stopwatch.GetElapsedTime(started);
                    if (DnsMessage.CapTtls(reply, (uint)Math.Max(0, remaining.TotalSeconds)))
                    {
                        var granted = accepted.Count == addresses.Count ? notice : notice with { Addresses = accepted };
                        completed = await sink.CompleteAsync(granted, accepted: true);
                        if (completed)
                        {
                            trace?.Pin = "маршрут закреплён за " + (int)System.Diagnostics.Stopwatch.GetElapsedTime(started).TotalMilliseconds + " мс"
                                + (reply.Length != response.Length ? ", лишние адреса вырезаны" : "");
                            if (!ReferenceEquals(granted, notice))
                            {
                                // Временных владельцев невыданных адресов служба и не записывала; снятие - на всякий случай.
                                await sink.CompleteAsync(notice with { Addresses = addresses.Except(accepted).ToList() }, accepted: false);
                            }

                            return reply;
                        }
                    }
                }
            }
            catch (Exception ex) when (ex is InvalidOperationException or ObjectDisposedException)
            {
                // Служба останавливается: закрепление не применить.
                stopping = true;
            }
            finally
            {
                if (!completed)
                {
                    await sink.CompleteAsync(notice, accepted: false);
                }
            }

            // Адреса этого ответа открыть не удалось (очередь службы занята, предел адресов), но служба уже открыла
            // другие адреса того же имени: ответ ими лучше отказа. Отказ на проверку интернета Windows - это сброс Wi-Fi.
            if (!stopping && question.Type == DnsMessage.TypeA && IsAnswerCurrent(configuration, domain, question.Name, context)
                && sink.OpenAddresses(notice) is { Count: > 0 } open)
            {
                trace?.Pin = "адреса ответа не открыты - отданы уже открытые";
                return DnsMessage.BuildAddressResponse(query, open, (uint)MinRouteTtl.TotalSeconds);
            }
        }

        Interlocked.Increment(ref _failures);
        trace?.Pin = "маршрут не закреплён — отказ клиенту";
        return DnsMessage.BuildServerFailure(query);
    }

    /// <summary>
    /// Ответ клиенту только с принятыми службой адресами: остальные записи A секции ответа вырезаются, счётчики секций
    /// пересчитываются. Если вырезать нельзя (сжатое имя ссылается внутрь вырезанной записи), на запрос A строится ответ из
    /// одних принятых адресов, на другой - null (отказ).
    /// </summary>
    private static byte[]? KeepAddresses(byte[] query, byte[] response, IReadOnlyList<uint> accepted)
    {
        var keep = accepted.ToHashSet();
        if (DnsMessage.KeepAnswerAddresses(response, keep) is { } trimmed)
        {
            return trimmed;
        }

        return DnsMessage.TryReadQuestion(query, out var question) && question.Type == DnsMessage.TypeA
            ? DnsMessage.BuildAddressResponse(query, [.. accepted.Distinct()], DnsMessage.GetMinTtl(response) ?? (uint)MinRouteTtl.TotalSeconds)
            : null;
    }

    /// <summary>
    /// Ответ ещё годится для действующей конфигурации. Сама замена конфигурации ответ не отменяет: подъём туннеля
    /// пересобирает её целиком, и ответы в полёте (в том числе на проверку интернета Windows) становились отказом
    /// ровно во время подключения VPN. Отказ нужен, только если сменилось то, от чего ответ зависит: правило имени
    /// или путь DNS - иначе клиент получил бы адрес, разрешённый не тем путём.
    /// </summary>
    private bool IsAnswerCurrent(DnsProxyConfiguration configuration, DomainRoute? domain, string name, string context)
    {
        var current = Configuration;
        if (ReferenceEquals(current, configuration))
        {
            return true;
        }

        var currentDomain = MatchDomain(current, name) ?? InheritedDomain(current, name);
        var choice = SelectRoute(current, name, currentDomain);
        if (choice.Local)
        {
            currentDomain = null;
        }

        return !choice.Unavailable && Context(choice.Route) == context && SameRule(domain, currentDomain);
    }

    /// <summary>Правило то же: суффикс, цель, закрепление, контекст и путь DNS. Путь сравнивается по серверам, а не по экземпляру.</summary>
    private static bool SameRule(DomainRoute? previous, DomainRoute? current) =>
        previous is null
            ? current is null
            : current is not null && previous with { Route = null, Origins = null } == current with { Route = null, Origins = null }
                && (previous.Origins ?? []).SequenceEqual(current.Origins ?? [], StringComparer.OrdinalIgnoreCase)
                && Context(previous.Route) == Context(current.Route);

    /// <summary>Наибольший срок CNAME-связи: клиенту он нужен лишь на то, чтобы сразу спросить каноническое имя.</summary>
    internal static readonly TimeSpan MaxCanonicalLinkLifetime = TimeSpan.FromSeconds(30);

    /// <summary>Наименьший срок CNAME-связи: ответ с TTL 0 тоже даёт клиенту время на следующий запрос цепочки.</summary>
    internal static readonly TimeSpan MinCanonicalLinkLifetime = TimeSpan.FromSeconds(5);

    /// <summary>Срок CNAME-связи: TTL ответа, но в пределах 5-30 с (а не срок закрепления адресов до часа).</summary>
    internal static TimeSpan CanonicalLinkLifetime(byte[] response)
    {
        var seconds = DnsMessage.GetMinTtl(response) ?? 0;
        return TimeSpan.FromSeconds(Math.Clamp(seconds, MinCanonicalLinkLifetime.TotalSeconds, MaxCanonicalLinkLifetime.TotalSeconds));
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
    private async Task<byte[]?> ForwardAsync(DnsProxyConfiguration configuration, byte[] query, DnsQuestion question, DnsQueryFlags flags, string context, DnsRoute route, CancellationToken cancellationToken)
    {
        if (!TryEnterRoute(context))
        {
            // Путь не отвечает и уже держит свою долю запросов: новый запрос к нему получает отказ сразу
            // (или просроченный ответ из кеша), не занимая место, которое нужно именам на других путях.
            return null;
        }

        try
        {
            var shared = await ShareAsync(new RequestKey(configuration, InFlightKey(flags, question, context)), query, route).WaitAsync(cancellationToken);
            if (shared is null)
            {
                return null;
            }

            var copy = shared.ToArray();
            DnsMessage.SetId(copy, DnsMessage.GetId(query));
            return copy;
        }
        finally
        {
            LeaveRoute(context);
        }
    }

    private bool TryEnterRoute(string context)
    {
        lock (_routeLoadLock)
        {
            var count = _routeLoad.GetValueOrDefault(context);
            if (count >= MaxQueriesPerRoute)
            {
                return false;
            }

            _routeLoad[context] = count + 1;
            return true;
        }
    }

    private void LeaveRoute(string context)
    {
        lock (_routeLoadLock)
        {
            if (--_routeLoad[context] == 0)
            {
                _routeLoad.Remove(context);
            }
        }
    }

    /// <summary>
    /// Ключ объединения. Биты CD, DO, RD, наличие OPT и опции EDNS меняют ответ upstream (проверка DNSSEC,
    /// записи RRSIG, рекурсия, Client Subnet и Cookie): запросы, различающиеся ими, объединять нельзя.
    /// </summary>
    internal static string InFlightKey(DnsQueryFlags flags, DnsQuestion question, string context) =>
        string.Join('|', question.Name, question.Type, question.Class, context,
            flags.AuthenticData ? "ad" : "", flags.CheckingDisabled ? "cd" : "", flags.Edns ? "opt" : "", flags.DnssecOk ? "do" : "",
            flags.NoRecursion ? "nord" : "", flags.EdnsOptions ?? "");

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
        if (response.Length <= limit && (tcpOurs || !DnsMessage.IsTruncated(response)))
        {
            return response;
        }

        var reply = tcpOurs ? DnsMessage.BuildEmptyResponse(query, DnsMessage.GetRcode(response)) : DnsMessage.BuildServerFailure(query);
        if (tcpOurs)
        {
            reply[2] |= 0x02;
        }

        // Запись OPT добавил сам конструктор ответа.
        return reply;
    }

    private Task<byte[]?> ShareAsync(RequestKey key, byte[] query, DnsRoute route)
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
                result = await DnsForwarder.ForwardAsync(query, route.Servers, route.InterfaceIndex, DnsForwarder.TimeoutFor(route), route.TcpOnly, _stop.Token);
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
        DomainRoute? manual = null;
        foreach (var domain in configuration.DomainRoutes)
        {
            if (!Matches(name, domain))
            {
                continue;
            }

            if (domain.Priority.HasValue && (manual is null || domain.Priority > manual.Priority
                || domain.Priority == manual.Priority && domain.Suffix.Length > manual.Suffix.Length))
            {
                manual = domain;
            }

            if (best is null || domain.Suffix.Length > best.Suffix.Length)
            {
                best = domain;
            }
        }

        return best?.Priority is null ? best : manual;
    }

    /// <summary>
    /// Правило, унаследованное именем по CNAME-связи (ответ только с CNAME пришёл раньше). Собственное правило
    /// имени и локальный суффикс важнее: связь лишь закрывает имя, которое иначе ушло бы общим путём.
    /// Наследование не может ослабить защиту имени (порядок: блокировать > туннель > напрямую). Наследуются только
    /// «блокировать» и туннель: у имени без своего правила адреса идут по адресным правилам, которые могут вести в
    /// туннель, и унаследованное «напрямую» вывело бы их из VPN по выбору чужого DNS. Поэтому цель «напрямую» не
    /// наследуется: каноническое имя разрешается своим путём, а его адреса - по адресным правилам.
    /// </summary>
    private DomainRoute? InheritedDomain(DnsProxyConfiguration configuration, string name)
    {
        if (configuration.DomainRoutes.Count == 0
            || (configuration.Local is not null && configuration.LocalSuffixes.Any(s => IsUnderSuffix(name, s))))
        {
            return null;
        }

        var owners = _cache.GetCanonicalOwners(name);
        if (owners.Count == 0) { return null; }
        foreach (var route in configuration.DomainRoutes.Where(d => d.PinAddresses && d.Target.Kind != TargetKind.Direct))
        {
            var origins = owners.Where(o => o.Suffix == route.Suffix).Select(o => o.Origin)
                .Order(StringComparer.OrdinalIgnoreCase).ToArray();
            if (origins.Length > 0)
            {
                return route with { Origins = origins };
            }
        }

        return null;
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
            return new DnsRouteChoice(configuration.Local, false, Local: true);
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
        if (question.Class != DnsMessage.ClassIn || !_cache.TryGetPinned(question.Name, out var addresses, out var remaining))
        {
            return null;
        }

        return question.Type == DnsMessage.TypeA
            ? DnsMessage.BuildAddressResponse(query, addresses, (uint)Math.Max(0, Math.Min(PinnedTtl.TotalSeconds, remaining?.TotalSeconds ?? PinnedTtl.TotalSeconds)))
            : DnsMessage.BuildEmptyResponse(query);
    }

    private async Task UdpLoopAsync(Listener listener, CancellationToken token, bool localOnly = false)
    {
        var socket = listener.Udp;
        var buffer = new byte[MaxUdpMessage];
        while (!token.IsCancellationRequested && !listener.Closed)
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
            catch (SocketException) when (listener.Closed)
            {
                // Сокет освобождённого адреса закрыт, пока приём ждал (OperationAborted): штатный выход, не отказ.
                return;
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

            if (localOnly && (received.RemoteEndPoint is not IPEndPoint sender || !IsLocalSource(sender.Address)))
            {
                // Слушатель всех адресов доступен из сети: чужим не отвечаем.
                continue;
            }

            if (!DnsMessage.TryReadQuestion(buffer.AsSpan(0, received.ReceivedBytes), out var question))
            {
                continue;
            }

            if (!TryAcceptUdp(question))
            {
                // Предел одновременных запросов: пакет отбрасывается, клиент повторит. Копить работу нельзя.
                Interlocked.Increment(ref _failures);
                continue;
            }

            var query = buffer.AsSpan(0, received.ReceivedBytes).ToArray();
            RunWorker(() => ReplyUdpAsync(listener, query, question, received.RemoteEndPoint, token));
        }
    }

    private bool TryAcceptUdp(DnsQuestion question)
    {
        lock (_udpWaitersLock)
        {
            var count = _udpWaiters.GetValueOrDefault(question);
            if (count >= MaxConcurrentQueries / 8 || !_concurrency.Wait(0)) { return false; }
            _udpWaiters[question] = count + 1;
            return true;
        }
    }

    private async Task ReplyUdpAsync(Listener listener, byte[] query, DnsQuestion question, EndPoint client, CancellationToken token)
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
            lock (_udpWaitersLock)
            {
                if (--_udpWaiters[question] == 0) { _udpWaiters.Remove(question); }
                _concurrency.Release();
            }
        }
    }

    /// <summary>
    /// Приём соединений TCP. Слушатель освобождённого адреса (<see cref="ReleaseAdapterAddresses"/>) останавливается,
    /// пока приём ещё ждёт: тот завершается ошибкой OperationAborted, а следующий приём на остановленном слушателе -
    /// InvalidOperationException. Оба случая - штатный выход, а не отказ: раньше второй ронял задачу цикла.
    /// </summary>
    private async Task TcpAcceptLoopAsync(Listener owner, TcpListener listener, CancellationToken token, bool localOnly = false)
    {
        while (!token.IsCancellationRequested && !owner.Closed)
        {
            TcpClient client;
            try
            {
                client = await AcceptTcp(listener, token);
            }
            catch (SocketException ex) when (!token.IsCancellationRequested && !owner.Closed)
            {
                // Ошибка одного соединения (клиент сбросил его до приёма) не должна навсегда остановить TCP:
                // UDP продолжает отправлять клиентов сюда по флагу TC. Пауза — чтобы устойчивая ошибка не заняла ядро.
                // Прерванный приём (OperationAborted) - признак остановки слушателя, а не отказ: он не считается.
                if (ex.SocketErrorCode != SocketError.OperationAborted)
                {
                    Interlocked.Increment(ref _failures);
                }

                await Task.Delay(ReceiveErrorPause, token).ContinueWith(_ => { }, TaskScheduler.Default);
                continue;
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException or InvalidOperationException)
            {
                // InvalidOperationException - слушатель уже остановлен (адрес освобождён или посредник останавливается).
                return;
            }

            if (localOnly && (client.Client.RemoteEndPoint is not IPEndPoint peer || !IsLocalSource(peer.Address)))
            {
                client.Dispose();
                continue;
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
            try
            {
                var stream = client.GetStream();
                var header = new byte[2];
                var opened = Environment.TickCount64;
                for (var served = 0; served < MaxTcpQueriesPerConnection && !token.IsCancellationRequested; served++)
                {
                    using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
                    if (served == 0)
                    {
                        // Первый запрос: соединение без заголовка закрывается по общему сроку запроса как отказ.
                        deadline.CancelAfter(TcpRequestTimeout);
                        if (await stream.ReadAsync(header.AsMemory(0, 1), deadline.Token) == 0)
                        {
                            return;
                        }
                    }
                    else
                    {
                        // Следующий запрос ждётся не дольше простоя и не позже абсолютного срока соединения;
                        // не дождались — штатное закрытие (RFC 7766), а не отказ.
                        var left = TcpConnectionLifetime - TimeSpan.FromMilliseconds(Environment.TickCount64 - opened);
                        var wait = left < TcpIdleTimeout ? left : TcpIdleTimeout;
                        if (wait <= TimeSpan.Zero)
                        {
                            return;
                        }

                        deadline.CancelAfter(wait);
                        try
                        {
                            if (await stream.ReadAsync(header.AsMemory(0, 1), deadline.Token) == 0)
                            {
                                return;
                            }
                        }
                        catch (OperationCanceledException) when (!token.IsCancellationRequested)
                        {
                            return;
                        }

                        deadline.CancelAfter(TcpRequestTimeout);
                    }

                    await stream.ReadExactlyAsync(header.AsMemory(1), deadline.Token);
                    var length = BinaryPrimitives.ReadUInt16BigEndian(header);
                    if (length < DnsMessage.HeaderLength)
                    {
                        Interlocked.Increment(ref _failures);
                        return;
                    }

                    var query = new byte[length];
                    await stream.ReadExactlyAsync(query, deadline.Token);
                    var response = await HandleAsync(query, deadline.Token) ?? DnsMessage.BuildServerFailure(query);
                    if (DnsMessage.IsTruncated(response))
                    {
                        // По TCP ответ с битом TC бессмыслен: клиенту повторять запрос уже негде.
                        response = DnsMessage.BuildServerFailure(query);
                    }

                    var framed = new byte[response.Length + 2];
                    BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)response.Length);
                    response.CopyTo(framed, 2);
                    await stream.WriteAsync(framed, deadline.Token);
                }
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
