using System.Globalization;
using Microsoft.Extensions.Logging;

namespace SplitVpn.Service.Coordination;

/// <summary>
/// Перевод системных часов назад. Сроки службы (дозвон, повтор после ошибки, периодическая сверка, ожидание Wi-Fi,
/// проверки туннелей) хранятся как моменты настенного времени. Windows нередко поправляет часы уже после загрузки:
/// перевод назад на N часов отодвинул бы все сроки на N часов — дозвоны и повторы стояли бы, а защита держала бы
/// трафик заблокированным. Тик сравнивает настенное время с монотонным счётчиком и при скачке назад сдвигает все
/// хранимые сроки и отметки на величину скачка: промежутки между ними остаются прежними. Скачок вперёд (сон,
/// поправка вперёд) ничего не ломает: сроки просто наступают, и он не трогается.
/// </summary>
public sealed partial class Coordinator
{
    /// <summary>Меньший скачок назад - погрешность синхронизации времени, сроки ради него не сдвигаются.</summary>
    internal static readonly TimeSpan ClockJumpThreshold = TimeSpan.FromSeconds(5);

    /// <summary>Настенное время и монотонный счётчик прошлого тика; null - тика ещё не было.</summary>
    private DateTimeOffset? _lastTickUtc;
    private long _lastTickTimestamp;

    /// <summary>
    /// Сравнивает настенное время тика с ожидаемым по монотонному счётчику. Возвращает величину скачка назад,
    /// если он больше <see cref="ClockJumpThreshold"/>, и уже сдвинутые сроки; иначе TimeSpan.Zero.
    /// </summary>
    private TimeSpan DetectClockJumpBack(DateTimeOffset now)
    {
        var timestamp = _deps.Time.GetTimestamp();
        var previous = _lastTickUtc;
        var previousTimestamp = _lastTickTimestamp;
        _lastTickUtc = now;
        _lastTickTimestamp = timestamp;
        if (previous is not { } last)
        {
            return TimeSpan.Zero;
        }

        // Ожидаемое время - прошлый тик плюс прошедшее по монотонному счётчику. Сон компьютера и поправка вперёд
        // дают время не меньше ожидаемого и сюда не попадают.
        var jump = last + _deps.Time.GetElapsedTime(previousTimestamp, timestamp) - now;
        if (jump <= ClockJumpThreshold)
        {
            return TimeSpan.Zero;
        }

        ShiftDeadlines(jump);
        Journal("Предупреждение", string.Create(CultureInfo.InvariantCulture,
            $"Часы Windows переведены назад примерно на {FormatShift(jump)}: сроки повторов подключения и проверок сдвинуты, ожидание не затянется."));
        return jump;
    }

    private static string FormatShift(TimeSpan shift) =>
        shift >= TimeSpan.FromHours(1)
            ? string.Create(CultureInfo.InvariantCulture, $"{(int)shift.TotalHours} ч {shift.Minutes} мин")
            : shift >= TimeSpan.FromMinutes(1)
                ? string.Create(CultureInfo.InvariantCulture, $"{(int)shift.TotalMinutes} мин {shift.Seconds} с")
                : string.Create(CultureInfo.InvariantCulture, $"{(int)shift.TotalSeconds} с");

    /// <summary>
    /// Сдвигает назад на <paramref name="shift"/> все сроки и отметки, заданные по прежним часам. Не сдвигаются: отметка
    /// своего разрыва RAS (сравнивается со временем события в журнале Windows, записанным по прежним часам), сроки,
    /// которые считает монотонный счётчик (таймеры, нечитаемые пароли), и состояния RU-базы, списка обхода и обновлений
    /// программы - их менеджеры сами распознают срок, оказавшийся в далёком будущем.
    /// </summary>
    private void ShiftDeadlines(TimeSpan shift)
    {
        DateTimeOffset Back(DateTimeOffset value) =>
            value == default || value == DateTimeOffset.MaxValue || value - DateTimeOffset.MinValue <= shift ? value : value - shift;
        DateTimeOffset? BackOptional(DateTimeOffset? value) => value is { } present ? Back(present) : null;

        Facts.PartialErrorRetryAt = Back(Facts.PartialErrorRetryAt);
        Facts.LastFullReconcile = Back(Facts.LastFullReconcile);
        Facts.LastForcedReconcile = Back(Facts.LastForcedReconcile);
        Facts.LastConflictCheck = Back(Facts.LastConflictCheck);
        Facts.ConflictCheckStartedUtc = Back(Facts.ConflictCheckStartedUtc);
        Facts.LastDirectFilterCheck = Back(Facts.LastDirectFilterCheck);
        Facts.PinnedAdapterOfflineSinceUtc = BackOptional(Facts.PinnedAdapterOfflineSinceUtc);

        foreach (var tunnel in Facts.Tunnels.Values)
        {
            tunnel.NextDialAt = Back(tunnel.NextDialAt);
            tunnel.NextVerifyAt = Back(tunnel.NextVerifyAt);
            tunnel.NextLinkWatchAt = Back(tunnel.NextLinkWatchAt);
            tunnel.NextServerResolveAt = Back(tunnel.NextServerResolveAt);
            tunnel.ServerResolvedUtc = Back(tunnel.ServerResolvedUtc);
            tunnel.ServerResolveStartedUtc = BackOptional(tunnel.ServerResolveStartedUtc);
            tunnel.AdapterMissingSinceUtc = BackOptional(tunnel.AdapterMissingSinceUtc);
            tunnel.SessionStartedUtc = BackOptional(tunnel.SessionStartedUtc);
            tunnel.DialStartedUtc = BackOptional(tunnel.DialStartedUtc);
            tunnel.AnyConnectStartedUtc = BackOptional(tunnel.AnyConnectStartedUtc);
            tunnel.UncleanDropUtc = BackOptional(tunnel.UncleanDropUtc);
            tunnel.LastConflictProbeUtc = Back(tunnel.LastConflictProbeUtc);
            tunnel.LastCertificateProbeUtc = Back(tunnel.LastCertificateProbeUtc);
            tunnel.IntermediateFetchUtc = Back(tunnel.IntermediateFetchUtc);
            if (tunnel.SignIn is { } prompt)
            {
                tunnel.SignIn = prompt with { ExpiresUtc = Back(prompt.ExpiresUtc) };
            }

            if (tunnel.AnyConnect is { } link)
            {
                link.ProgressUtc = Back(link.ProgressUtc);
                link.ParametersReceivedUtc = BackOptional(link.ParametersReceivedUtc);
                if (!link.Established)
                {
                    // Таймер срока подъёма считает монотонно; его срок пересчитывается по сдвинутой отметке.
                    ArmEstablishDeadline(tunnel, link);
                }
            }

            if (tunnel.Ssh is { } ssh)
            {
                ssh.NextHealthAt = Back(ssh.NextHealthAt);
            }
        }

        foreach (var exit in _sshExits.Values)
        {
            exit.Deadline = Back(exit.Deadline);
        }

        _tickFailureRetryAt = Back(_tickFailureRetryAt);
        _wifiConnectedAt = Back(_wifiConnectedAt);
        _wifiChainStart = BackOptional(_wifiChainStart);
        _wifiHoldUntil = Back(_wifiHoldUntil);
        _retryPinnedSaveAt = Back(_retryPinnedSaveAt);
        _connectivityRefusalLoggedUtc = Back(_connectivityRefusalLoggedUtc);
        _connectivityPinAttemptUtc = Back(_connectivityPinAttemptUtc);
        _connectivityPinRefreshUtc = Back(_connectivityPinRefreshUtc);
        lock (_pinGate)
        {
            // Закрепления по правилам для доменов живут TTL ответа DNS: без сдвига маршрут к адресу держался бы
            // на N часов дольше, чем его выдал DNS.
            _lastPinFailureUtc = Back(_lastPinFailureUtc);
            _nextPinExpiry = Back(_nextPinExpiry);
            foreach (var owners in _desiredPins.Values)
            {
                for (var i = 0; i < owners.Count; i++)
                {
                    owners[i] = owners[i] with { ExpiresUtc = Back(owners[i].ExpiresUtc) };
                }
            }

            foreach (var address in Facts.Pinned.Keys.ToList())
            {
                var pin = Facts.Pinned[address];
                Facts.Pinned[address] = pin with { ExpiresUtc = Back(pin.ExpiresUtc) };
            }
        }

        _deps.Logger.LogWarning("Часы переведены назад на {Shift}: сроки координатора сдвинуты", shift);
    }
}
