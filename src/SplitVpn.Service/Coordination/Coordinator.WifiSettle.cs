using System.Globalization;
using Microsoft.Extensions.Logging;

namespace SplitVpn.Service.Coordination;

/// <summary>
/// Подключение Wi-Fi и его восстановление Windows. После загрузки Windows нередко сама перезапускает адаптер Wi-Fi:
/// через 16 секунд после подключения повторяет проверку безопасности, ещё через 16 перезапускает драйвер (System 4003),
/// а через 65 секунд после возврата отключает Wi-Fi ещё на минуту. Причина не установлена (0.17.9 убрала отказ
/// проверки интернета Windows, перезапуски остались). Служба поэтому делает две вещи: ведёт запись подключения
/// (<see cref="WifiIncidentRecorder"/>) и не поднимает новые туннели, пока Wi-Fi не устоялся, — туннель, поднятый
/// на 9-й секунде, на 32-й всё равно рвётся вместе с адаптером. Защита и DNS включаются сразу, как и раньше.
/// </summary>
public sealed partial class Coordinator
{
    /// <summary>Сколько после подключения Wi-Fi новые туннели не поднимаются: повторная проверка безопасности приходит на 16-й секунде.</summary>
    internal static readonly TimeSpan WifiSettleDelay = TimeSpan.FromSeconds(20);

    /// <summary>
    /// Сколько после подключения повторная проверка безопасности считается признаком восстановления. Позже это
    /// обычная смена ключей, она идёт раз в час и ничего не предвещает.
    /// </summary>
    internal static readonly TimeSpan WifiRecoveryWatch = TimeSpan.FromSeconds(90);

    /// <summary>Сколько туннели ждут после повторной проверки безопасности: перезапуск адаптера приходит через 16 секунд.</summary>
    internal static readonly TimeSpan WifiMarkerHold = TimeSpan.FromSeconds(20);

    /// <summary>Сколько туннели ждут после возврата Wi-Fi из перезапуска: отключение на минуту приходит на 65-й секунде.</summary>
    internal static readonly TimeSpan WifiAfterRecoveryHold = TimeSpan.FromSeconds(70);

    /// <summary>
    /// Предел ожидания от первого подключения цепочки. Восстановление иногда идёт по кругу несколько раз подряд;
    /// держать VPN выключенным всё это время хуже, чем поднять его и потерять при следующем перезапуске.
    /// </summary>
    internal static readonly TimeSpan WifiHoldLimit = TimeSpan.FromMinutes(3);

    private WifiIncidentRecorder? _wifiRecorder;
    private Guid? _wifiInterface;
    private bool _wifiConnected;
    private DateTimeOffset _wifiConnectedAt;
    private DateTimeOffset? _wifiChainStart;
    private bool _wifiRecoverySeen;
    private bool _wifiMarkerReported;
    private bool _wifiHoldActive;
    private DateTimeOffset _wifiHoldUntil;

    /// <summary>Запись подключения Wi-Fi: для испытаний.</summary>
    internal WifiIncidentRecorder? WifiRecorder => _wifiRecorder;

    private IDisposable? SubscribeWifiEvents(CancellationToken cancellationToken)
    {
        try
        {
            return _deps.SubscribeWifiEvents(wifi =>
            {
                // Строка в запись ставится сразу, из потока журнала событий: очередь службы может быть занята сверкой.
                _wifiRecorder?.Note(string.Create(CultureInfo.InvariantCulture,
                    $"Windows: {Describe(wifi.Kind)} (событие от {wifi.Time.ToLocalTime():HH:mm:ss.fff}{(wifi.Detail.Length > 0 ? "; " + wifi.Detail : "")})"));
                if (!cancellationToken.IsCancellationRequested)
                {
                    TryEnqueue("WifiEvent", () =>
                    {
                        OnWifiEvent(wifi);
                        return Task.CompletedTask;
                    });
                }
            });
        }
        catch (Exception ex)
        {
            _deps.Logger.LogWarning(ex, "События Wi-Fi недоступны: запись подключения и ожидание перед подъёмом VPN не работают");
            return null;
        }
    }

    private static string Describe(WifiEventKind kind) => kind switch
    {
        WifiEventKind.Connected => "Wi-Fi подключён (8001)",
        WifiEventKind.Disconnected => "Wi-Fi отключён (8003)",
        WifiEventKind.SecurityStopped => "проверка безопасности Wi-Fi остановлена (11004)",
        WifiEventKind.SecuritySucceeded => "проверка безопасности Wi-Fi выполнена (11005)",
        _ => "восстановление адаптера Wi-Fi (4003)",
    };

    /// <summary>Событие Wi-Fi в очереди службы.</summary>
    internal void OnWifiEvent(WifiEvent wifi)
    {
        switch (wifi.Kind)
        {
            case WifiEventKind.Connected:
                // Новая цепочка, если прежняя давно кончилась: её предел ожидания к этому подключению не относится.
                if (_wifiChainStart is not { } chain || wifi.Time - chain > WifiHoldLimit + WifiAfterRecoveryHold)
                {
                    _wifiChainStart = wifi.Time;
                    _wifiRecoverySeen = false;
                }

                // Событие 8001 опоздало, а сверка уже начала отсчёт для этого же подключения: оставляем её отсчёт.
                if (_wifiConnected && _wifiInterface == wifi.InterfaceGuid && wifi.Time <= _wifiConnectedAt)
                {
                    break;
                }

                _wifiConnected = true;
                _wifiInterface = wifi.InterfaceGuid;
                _wifiConnectedAt = wifi.Time;
                _wifiMarkerReported = false;
                HoldDials(wifi.Time + (_wifiRecoverySeen ? WifiAfterRecoveryHold : WifiSettleDelay));
                break;

            case WifiEventKind.Disconnected:
                if (wifi.InterfaceGuid is null || wifi.InterfaceGuid == _wifiInterface)
                {
                    _wifiConnected = false;
                }

                break;

            case WifiEventKind.SecuritySucceeded:
                // При подключении проверка безопасности идёт до события 8001; после него в первые полторы минуты
                // её повторяет только лестница восстановления Windows.
                if (_wifiConnected && wifi.InterfaceGuid == _wifiInterface && wifi.Time - _wifiConnectedAt <= WifiRecoveryWatch)
                {
                    var after = (int)(wifi.Time - _wifiConnectedAt).TotalSeconds;
                    _wifiRecorder?.Trigger(string.Create(CultureInfo.InvariantCulture, $"повторная проверка безопасности через {after} с после подключения Wi-Fi"));
                    HoldDials(wifi.Time + WifiMarkerHold);
                    if (!_wifiMarkerReported)
                    {
                        _wifiMarkerReported = true;
                        Journal("Предупреждение", "Windows перепроверяет подключение Wi-Fi: возможен перезапуск адаптера. Новые подключения VPN подождут." + RecordHint());
                    }
                }

                break;

            case WifiEventKind.Recovery:
                _wifiChainStart ??= wifi.Time;
                _wifiRecoverySeen = true;
                _wifiRecorder?.Trigger("Windows перезапускает адаптер Wi-Fi (System 4003; " + wifi.Detail + ")");
                Journal("Предупреждение", "Windows сочла подключение Wi-Fi ограниченным и перезапускает адаптер: подключения VPN оборвутся и поднимутся заново, когда Wi-Fi устоится." + RecordHint());
                break;
        }
    }

    private const uint WirelessInterfaceType = 71;

    /// <summary>Сверка уже видела сеть без основного адаптера: его появление после этого - новое подключение.</summary>
    private bool _primaryAbsentSeen;

    /// <summary>
    /// Основной адаптер Wi-Fi появился, пока служба работала. Ожидание ставится здесь же, в сверке, а не только по
    /// событию 8001: событие журнала Windows приходит с опозданием до секунды и ждёт очередь службы, а сверка,
    /// вызванная уведомлением о смене сети, успевала выбрать адаптер и начать подъём туннеля раньше него
    /// (запись 21.11.2026: подключение в 19:50:48.430, подъём туннеля в 19:50:49.024). Адаптер, который уже был
    /// подключён при запуске службы, не ждёт: служба могла быть просто перезапущена.
    /// </summary>
    private void NotePrimaryForWifiSettle(Core.Net.AdapterCandidate? adapter)
    {
        if (adapter is null)
        {
            _primaryAbsentSeen = true;
            return;
        }

        if (!_primaryAbsentSeen)
        {
            return;
        }

        _primaryAbsentSeen = false;
        if (adapter.IfType != WirelessInterfaceType)
        {
            return;
        }

        var now = _deps.Time.GetUtcNow();
        // Событие 8001 могло прийти раньше и дать точное время подключения: тогда отсчёт уже идёт от него.
        if (!(_wifiConnected && _wifiInterface == adapter.InterfaceGuid && now - _wifiConnectedAt < WifiSettleDelay))
        {
            OnWifiEvent(new WifiEvent(WifiEventKind.Connected, adapter.InterfaceGuid, now, "адаптер стал основным"));
        }
    }

    private string RecordHint() => _wifiRecorder?.LastFile is { } file ? " Запись: " + Path.GetFileName(file) + "." : "";

    private void HoldDials(DateTimeOffset until)
    {
        var limit = (_wifiChainStart ?? until) + WifiHoldLimit;
        until = until < limit ? until : limit;
        if (until <= _deps.Time.GetUtcNow())
        {
            return;
        }

        _wifiHoldUntil = _wifiHoldActive && _wifiHoldUntil > until ? _wifiHoldUntil : until;
        _wifiHoldActive = true;
    }

    /// <summary>Wi-Fi только что подключился или восстанавливается: новые туннели пока не поднимаются.</summary>
    private bool WifiDialHeld(DateTimeOffset now) =>
        _wifiHoldActive && now < _wifiHoldUntil && Facts.Primary is { } primary && primary.InterfaceGuid == _wifiInterface;

    /// <summary>Ожидание кончилось: нужна сверка, которая поднимет отложенные туннели (AnyConnect сам её не назначает).</summary>
    private bool WifiHoldExpired(DateTimeOffset now)
    {
        if (!_wifiHoldActive || now < _wifiHoldUntil)
        {
            return false;
        }

        _wifiHoldActive = false;
        return true;
    }
}
