using System.Globalization;
using Microsoft.Extensions.Logging;

namespace SplitVpn.Service.Coordination;

/// <summary>
/// Перевод системных часов назад. Сроки службы (дозвон, повтор после ошибки, периодическая сверка, ожидание Wi-Fi,
/// проверки туннелей) хранятся как моменты настенного времени. Windows нередко поправляет часы уже после загрузки:
/// перевод назад на N часов отодвинул бы все сроки на N часов — дозвоны и повторы стояли бы, а защита держала бы
/// трафик заблокированным. Каждая работа очереди актора (и тик) сравнивает настенное время с монотонным счётчиком и
/// при скачке назад сдвигает все хранимые сроки и отметки на величину скачка: промежутки между ними остаются прежними.
/// Скачок вперёд (сон, поправка вперёд) ничего не ломает: сроки просто наступают, и он не трогается.
///
/// Сдвигать можно только значения, записанные по прежним часам: записанное уже по новым, сдвинутое второй раз, истекло
/// бы на N часов раньше. Поэтому точка отсчёта берётся в конструкторе (перевод часов во время стартовой сверки виден
/// первой же работе очереди), а сроки закреплений, которые пишут потоки DNS-посредника вне актора, проверяются тем же
/// детектором под _pinGate перед каждой записью: закрепления сдвигаются сразу при обнаружении, сроки актора - в
/// начале его ближайшей работы.
/// </summary>
public sealed partial class Coordinator
{
    /// <summary>Меньший скачок назад - погрешность синхронизации времени, сроки ради него не сдвигаются.</summary>
    internal static readonly TimeSpan ClockJumpThreshold = TimeSpan.FromSeconds(5);

    /// <summary>Настенное время и монотонный счётчик последней проверки детектора. Под _pinGate.</summary>
    private DateTimeOffset _clockCheckUtc;
    private long _clockCheckTimestamp;

    /// <summary>
    /// Скачок, уже учтённый в желаемых закреплениях, но ещё не в сроках актора и не в применённом наборе
    /// (<see cref="CoordinatorFacts.Pinned"/> меняется только в очереди актора). Под _pinGate.
    /// </summary>
    private TimeSpan _pendingDeadlineShift;
    private TimeSpan _pendingAppliedPinShift;

    /// <summary>Точка отсчёта детектора - до стартовой сверки: перевод часов во время неё тоже будет замечен.</summary>
    private void StartClockWatch()
    {
        lock (_pinGate)
        {
            _clockCheckUtc = _deps.Time.GetUtcNow();
            _clockCheckTimestamp = _deps.Time.GetTimestamp();
        }
    }

    /// <summary>
    /// Текущее настенное время с проверкой на скачок назад. Вызывается под _pinGate - и из очереди актора, и из потоков
    /// DNS-посредника - перед каждой записью срока закрепления: при скачке закрепления, записанные по прежним часам,
    /// сдвигаются сразу, а значение, которое запишет вызывающий, уже по новым часам, второй раз не сдвинется. Дёшево
    /// (два чтения часов) и идемпотентно: повторный вызов сравнивает с только что взятой точкой отсчёта.
    /// </summary>
    private DateTimeOffset ClockNowLocked()
    {
        var now = _deps.Time.GetUtcNow();
        var timestamp = _deps.Time.GetTimestamp();
        // Ожидаемое время - прошлая проверка плюс прошедшее по монотонному счётчику. Сон компьютера и поправка вперёд
        // дают время не меньше ожидаемого и сюда не попадают.
        var jump = _clockCheckUtc + _deps.Time.GetElapsedTime(_clockCheckTimestamp, timestamp) - now;
        _clockCheckUtc = now;
        _clockCheckTimestamp = timestamp;
        if (jump > ClockJumpThreshold)
        {
            ShiftPinDeadlinesLocked(jump);
            _pendingDeadlineShift += jump;
            _pendingAppliedPinShift += jump;
        }

        return now;
    }

    /// <summary>
    /// Проверка часов в очереди актора: в начале каждой работы и тика. Возвращает величину скачка назад, если он
    /// больше <see cref="ClockJumpThreshold"/> (замеченного здесь или потоком DNS-посредника после прошлой работы),
    /// и уже сдвинутые сроки; иначе TimeSpan.Zero.
    /// </summary>
    private TimeSpan DetectClockJumpBack()
    {
        TimeSpan jump;
        lock (_pinGate)
        {
            ClockNowLocked();
            jump = _pendingDeadlineShift;
            _pendingDeadlineShift = TimeSpan.Zero;
            if (_pendingAppliedPinShift > TimeSpan.Zero)
            {
                // Применённый набор собран из желаемого до скачка: его сроки - по прежним часам.
                foreach (var address in Facts.Pinned.Keys.ToList())
                {
                    var pin = Facts.Pinned[address];
                    Facts.Pinned[address] = pin with { ExpiresUtc = ShiftBack(pin.ExpiresUtc, _pendingAppliedPinShift) };
                }

                _pendingAppliedPinShift = TimeSpan.Zero;
            }
        }

        if (jump <= TimeSpan.Zero)
        {
            return TimeSpan.Zero;
        }

        ShiftDeadlines(jump);
        Journal("Предупреждение", string.Create(CultureInfo.InvariantCulture,
            $"Часы Windows переведены назад примерно на {FormatShift(jump)}: сроки повторов подключения и проверок сдвинуты, ожидание не затянется."));
        return jump;
    }

    private static DateTimeOffset ShiftBack(DateTimeOffset value, TimeSpan shift) =>
        value == default || value == DateTimeOffset.MaxValue || value - DateTimeOffset.MinValue <= shift ? value : value - shift;

    /// <summary>
    /// Сроки, которые пишут и читают потоки DNS-посредника: желаемые закрепления, ближайшее истечение, отметки отказов.
    /// Вызывается под _pinGate в момент обнаружения скачка. Закрепления по правилам для доменов живут TTL ответа DNS:
    /// без сдвига маршрут к адресу держался бы на N часов дольше, чем его выдал DNS.
    /// </summary>
    private void ShiftPinDeadlinesLocked(TimeSpan shift)
    {
        _lastPinFailureUtc = ShiftBack(_lastPinFailureUtc, shift);
        _nextPinExpiry = ShiftBack(_nextPinExpiry, shift);
        _connectivityRefusalLoggedUtc = ShiftBack(_connectivityRefusalLoggedUtc, shift);
        foreach (var owners in _desiredPins.Values)
        {
            for (var i = 0; i < owners.Count; i++)
            {
                owners[i] = owners[i] with { ExpiresUtc = ShiftBack(owners[i].ExpiresUtc, shift) };
            }
        }
    }

    private static string FormatShift(TimeSpan shift) =>
        shift >= TimeSpan.FromHours(1)
            ? string.Create(CultureInfo.InvariantCulture, $"{(int)shift.TotalHours} ч {shift.Minutes} мин")
            : shift >= TimeSpan.FromMinutes(1)
                ? string.Create(CultureInfo.InvariantCulture, $"{(int)shift.TotalMinutes} мин {shift.Seconds} с")
                : string.Create(CultureInfo.InvariantCulture, $"{(int)shift.TotalSeconds} с");

    /// <summary>
    /// Сдвигает назад на <paramref name="shift"/> все сроки и отметки актора, заданные по прежним часам (сроки
    /// закреплений сдвигает <see cref="ShiftPinDeadlinesLocked"/>). Не сдвигаются: отметка своего разрыва RAS
    /// (сравнивается со временем события в журнале Windows, записанным по прежним часам), сроки, которые считает
    /// монотонный счётчик (таймеры, нечитаемые пароли), и состояния RU-базы, списка обхода и обновлений программы -
    /// их менеджеры сами распознают срок, оказавшийся в далёком будущем.
    /// </summary>
    private void ShiftDeadlines(TimeSpan shift)
    {
        DateTimeOffset Back(DateTimeOffset value) => ShiftBack(value, shift);
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
        _connectivityPinAttemptUtc = Back(_connectivityPinAttemptUtc);
        _connectivityPinRefreshUtc = Back(_connectivityPinRefreshUtc);
        _deps.Logger.LogWarning("Часы переведены назад на {Shift}: сроки координатора сдвинуты", shift);
    }
}
