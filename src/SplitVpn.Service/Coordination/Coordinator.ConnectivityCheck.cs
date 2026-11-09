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
            routes.Add(new DomainRoute(host, RouteTarget.Direct, direct, PinAddresses: pin, ExactName: true));
            if (pin)
            {
                serviceSuffixes.Add(host);
            }
        }
    }

    /// <summary>Адреса веб-проверки NCSI для защиты: TCP 80 через основной адаптер.</summary>
    private List<RevocationEndpoint> ConnectivityCheckEndpoints() =>
        Facts.RevocationPins
            .Where(pin => pin.Value.Contains(ConnectivityCheckWebHost))
            .Select(pin => new RevocationEndpoint(pin.Key, ConnectivityCheckPort))
            .ToList();

    private static bool IsConnectivityCheckHost(string suffix) => ConnectivityCheckHosts.Contains(suffix, StringComparer.Ordinal);
}
