using Microsoft.Extensions.Logging;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Coordination;

/// <summary>
/// Проверка интернета Windows (NCSI) идёт напрямую через основной адаптер, а не через VPN.
///
/// Разбор 09.11.2026: служба стартует раньше Wi-Fi и до подъёма VPN держит блокировку. Через несколько секунд после
/// подключения Wi-Fi Windows проверяет интернет (DNS dns.msftncsi.com и http://www.msftconnecttest.com/connecttest.txt),
/// проверка упирается в блокировку, и сеть записывается «без интернета». Через ~30 с служба автонастройки WLAN
/// «восстанавливает» такую сеть сбросом драйвера Wi-Fi (System, WLAN-AutoConfig 4003, тип 4): только что поднятый
/// туннель обрывается, а сервер ещё пару минут держит мёртвый сеанс. Ещё через ~65 с без интернета следует второй шаг -
/// «временное отключение» Wi-Fi.
///
/// Поэтому оба имени разрешаются через DNS основного адаптера, а адреса веб-проверки получают служебное закрепление,
/// как узлы проверки отзыва: защита открывает к ним только TCP на порт 80 через основной адаптер, маршрута не ставит
/// (адрес принадлежит общей сети доставки). Провайдер видит эти проверки, как и без VPN. Правило пользователя для
/// того же имени (например, «через VPN» для msftconnecttest.com) важнее служебного.
/// </summary>
public sealed partial class Coordinator
{
    /// <summary>Имя веб-проверки NCSI: к его адресам открывается TCP 80 через основной адаптер.</summary>
    internal const string ConnectivityCheckWebHost = "www.msftconnecttest.com";

    /// <summary>Имя DNS-проверки NCSI: нужно только разрешение имени, трафика к его адресу нет.</summary>
    internal const string ConnectivityCheckDnsHost = "dns.msftncsi.com";

    private const ushort ConnectivityCheckPort = 80;

    private static readonly string[] ConnectivityCheckHosts = [ConnectivityCheckWebHost, ConnectivityCheckDnsHost];

    /// <param name="serviceSuffixes">Служебные имена, адреса которых закрепляются только портом: сюда добавляется имя веб-проверки.</param>
    private void AddConnectivityCheckRoutes(List<DomainRoute> routes, HashSet<string> serviceSuffixes)
    {
        // Без основного адаптера прямого пути нет: имя идёт по общей политике, как и весь остальной трафик.
        if (DomainDnsRoute(RouteTarget.Direct) is not { } direct)
        {
            return;
        }

        foreach (var host in ConnectivityCheckHosts)
        {
            if (MatchingDomainRule(host) is not null || routes.Exists(r => r.Suffix == host))
            {
                continue;
            }

            var pin = host == ConnectivityCheckWebHost;
            // Только само имя: поддомены идут по общей политике.
            routes.Add(new DomainRoute(host, RouteTarget.Direct, direct, PinAddresses: pin, ExactName: true,
                PinContext: pin ? ConnectivityPinContext : null));
            if (pin)
            {
                serviceSuffixes.Add(host);
            }
        }
    }

    /// <summary>
    /// Сколько адресов веб-проверки открывается одновременно. Имя разрешает DNS сети, к которой подключён компьютер,
    /// а в чужой сети он может ответить чем угодно: без предела такой ответ открывал бы TCP 80 напрямую к любому
    /// числу адресов. Настоящий ответ - один-два адреса сети доставки.
    /// </summary>
    internal const int MaxConnectivityCheckAddresses = 4;

    /// <summary>
    /// Адреса веб-проверки NCSI для защиты: TCP 80 через основной адаптер. Только публичные адреса и не больше
    /// <see cref="MaxConnectivityCheckAddresses"/>: частные адреса настоящая проверка не использует.
    /// </summary>
    private List<RevocationEndpoint> ConnectivityCheckEndpoints() =>
        Facts.RevocationPins
            .Where(pin => pin.Value.Contains(ConnectivityCheckWebHost) && !SpecialRanges.AllNonPublic.Contains(pin.Key))
            .OrderBy(pin => pin.Key)
            .Take(MaxConnectivityCheckAddresses)
            .Select(pin => new RevocationEndpoint(pin.Key, ConnectivityCheckPort))
            .ToList();

    /// <summary>
    /// Проверяет весь ответ до записи под _pinGate: уже выданные адреса сохраняются до конца TTL,
    /// а ответ сверх лимита получает отказ DNS, а не подтверждение без разрешающего фильтра.
    /// </summary>
    private bool CanPinConnectivityCheck(IReadOnlyList<uint> addresses, DateTimeOffset now)
    {
        if (addresses.Any(a => SpecialRanges.AllNonPublic.Contains(a)))
        {
            return false;
        }

        return _desiredPins
            .Where(pin => pin.Value.Exists(p => p.Suffix == ConnectivityCheckWebHost && p.Target == RouteTarget.Direct && p.ExpiresUtc > now))
            .Select(pin => pin.Key)
            .Concat(addresses)
            .Distinct()
            .Take(MaxConnectivityCheckAddresses + 1)
            .Count() <= MaxConnectivityCheckAddresses;
    }

    private bool HasConnectivityCheckPin(DateTimeOffset now)
    {
        lock (_pinGate)
        {
            return _desiredPins.Values.Any(owners => owners.Exists(p => p.Suffix == ConnectivityCheckWebHost
                && p.Target == RouteTarget.Direct && p.ExpiresUtc > now));
        }
    }

    /// <summary>Проверяется под _pinGate до записи и подтверждения ответа: прежний путь не заполняет новый набор.</summary>
    private bool PinContextMatches(PinnedRouteNotice notice) =>
        notice.Suffix != ConnectivityCheckWebHost || notice.PinContext == ConnectivityPinContext;

    /// <summary>Путь DNS и поколение: ответ до смены адаптера не подходит даже после возврата на тот же путь.</summary>
    internal string? ConnectivityPinContext { get; private set; }

    private string? _connectivityPinRoute;
    private long _connectivityPinGeneration;
    private string? _connectivityPinnedContext;

    private bool _connectivityPinRunning;

    private DateTimeOffset _connectivityPinAttemptUtc;

    private DateTimeOffset _connectivityPinRefreshUtc;

    /// <summary>Запас до истечения закрепления: остаётся время на повтор при временном сбое DNS.</summary>
    private static readonly TimeSpan ConnectivityPinRefreshMargin = TimeSpan.FromMinutes(5);

    /// <summary>Пауза между попытками заранее разрешить имя веб-проверки, пока оно не разрешилось.</summary>
    private static readonly TimeSpan ConnectivityPinRetry = TimeSpan.FromSeconds(30);

    /// <summary>Вызывается до сборки политики, чтобы разрешения прежнего пути не попали на новый адаптер.</summary>
    private void RefreshConnectivityCheckContext()
    {
        var primary = Facts.Primary;
        var route = primary is null || MatchingDomainRule(ConnectivityCheckWebHost) is not null ? null
            : $"{primary.InterfaceGuid}|{primary.Luid}|{primary.InterfaceIndex}|{primary.DefaultGateway}|{string.Join(',', primary.Addresses)}|{string.Join(',', ServiceDnsAddresses())}";
        if (route == _connectivityPinRoute)
        {
            return;
        }

        lock (_pinGate)
        {
            // Удаляется только владелец служебного закрепления: другие домены на том же IP сохраняются.
            // При возврате от пользовательского правила к служебному его старый неограниченный набор тоже не переносится.
            if (route is not null || _revocationPinSuffixes.Contains(ConnectivityCheckWebHost))
            {
                foreach (var (address, owners) in _desiredPins.ToList())
                {
                    if (owners.RemoveAll(p => p.Suffix == ConnectivityCheckWebHost && p.Target == RouteTarget.Direct) > 0)
                    {
                        _pinVersion++;
                    }

                    if (owners.Count == 0)
                    {
                        _desiredPins.Remove(address);
                    }
                }
            }
            ResetConnectivityCheckContext();
            _connectivityPinRoute = route;
            ConnectivityPinContext = route is null ? null : $"{++_connectivityPinGeneration}|{route}";
        }
    }

    private void ResetConnectivityCheckContext()
    {
        _connectivityPinRoute = null;
        ConnectivityPinContext = null;
        _connectivityPinnedContext = null;
        _connectivityPinRunning = false;
        _connectivityPinAttemptUtc = default;
        _connectivityPinRefreshUtc = default;
    }

    /// <summary>
    /// Открывает адрес веб-проверки заранее, как только появился основной адаптер, не дожидаясь запроса Windows.
    /// Закрепление по запросу ждёт очередь службы не дольше <see cref="PinApplyTimeout"/>, а при запуске Windows она
    /// занята сверкой и дозвоном: отказ в ответе DNS - это та же сеть «без интернета» и тот же сброс Wi-Fi. С готовым
    /// закреплением ответ с тем же адресом уходит сразу. Имя разрешается в фоновой задаче, очередь его не ждёт.
    /// </summary>
    private void EnsureConnectivityCheckPin()
    {
        var now = _deps.Time.GetUtcNow();
        if (_connectivityPinRunning || Facts.Primary is not { } primary || ConnectivityPinContext is not { } context
            || (context == _connectivityPinnedContext && now < _connectivityPinRefreshUtc && HasConnectivityCheckPin(now))
            || now - _connectivityPinAttemptUtc < ConnectivityPinRetry || MatchingDomainRule(ConnectivityCheckWebHost) is not null)
        {
            return;
        }

        var servers = ServiceDnsAddresses();
        if (servers.Count == 0)
        {
            return;
        }

        _connectivityPinRunning = true;
        _connectivityPinAttemptUtc = now;
        var interfaceIndex = primary.InterfaceIndex;
        _ = Task.Run(async () =>
        {
            IReadOnlyList<uint> addresses = [];
            try
            {
                using var limit = new CancellationTokenSource(RevocationResolveLimit);
                addresses = await _deps.Resolver.ResolveAsync(ConnectivityCheckWebHost, servers, interfaceIndex, limit.Token);
            }
            catch (Exception ex)
            {
                // Не разрешилось - не беда: адрес закрепится по запросу самой Windows, а попытка повторится.
                _deps.Logger.LogInformation("Имя проверки интернета Windows заранее не разрешилось: {Error}", ex.Message);
            }

            await EnqueueAsync("ConnectivityCheckResolved", () => OnConnectivityCheckResolvedAsync(context, addresses));
        });
    }

    internal Task OnConnectivityCheckResolvedAsync(string? context, IReadOnlyList<uint> addresses)
    {
        // Старый ответ не должен сбросить признак нового запроса, уже выполняющегося для другого пути.
        if (context is null || context != ConnectivityPinContext)
        {
            return Task.CompletedTask;
        }

        _connectivityPinRunning = false;
        var usable = addresses.Where(a => !SpecialRanges.AllNonPublic.Contains(a)).Distinct().Take(MaxConnectivityCheckAddresses).ToList();

        if (usable.Count == 0 || !ProtectionActive
            || MatchingDomainRule(ConnectivityCheckWebHost) is not null)
        {
            return Task.CompletedTask;
        }

        if (!PinDirect(ConnectivityCheckWebHost, usable, _deps.Time.GetUtcNow() + RevocationPinTtl))
        {
            return Task.CompletedTask;
        }

        _connectivityPinnedContext = context;
        _connectivityPinRefreshUtc = _deps.Time.GetUtcNow() + RevocationPinTtl - ConnectivityPinRefreshMargin;
        try
        {
            EnsureRoutesSafe();
        }
        catch (Exception ex) when (ex is Windows.Native.NativeCallException or InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            _deps.Logger.LogWarning(ex, "Адрес проверки интернета Windows заранее не открыт");
            Facts.ForceProtection = true;
            _connectivityPinnedContext = null;
        }

        return Task.CompletedTask;
    }

    private static bool IsConnectivityCheckHost(string suffix) => ConnectivityCheckHosts.Contains(suffix, StringComparer.Ordinal);
}
