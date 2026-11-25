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
/// детектором под _pinGate перед каждой записью: закрепления сдвигаются сразу при обнаружении.
///
/// Сроки актора: скачок, замеченный самим актором (начало работы, тик, сборка политики, применение и снятие закреплений),
/// сдвигает их сразу. Скачок, замеченный потоком DNS-посредника, откладывается до ближайшей проверки в акторе, и тогда
/// сдвигаются только значения, не менявшиеся с прошлой проверки актора (<see cref="_deadlineCheckpoint"/>): изменённое
/// после неё могло быть записано уже после обнаружения - по новым часам, и второй сдвиг увёл бы его на N часов раньше
/// (повтор дозвона, срок подъёма AnyConnect, повтор после ошибки). Цена - значение, записанное между прошлой проверкой
/// актора и самим переводом, остаётся несдвинутым: это узкое окно внутри одной работы.
/// </summary>
public sealed partial class Coordinator
{
    /// <summary>Меньший скачок назад - погрешность синхронизации времени, сроки ради него не сдвигаются.</summary>
    internal static readonly TimeSpan ClockJumpThreshold = TimeSpan.FromSeconds(5);

    /// <summary>Настенное время и монотонный счётчик последней проверки детектора. Под _pinGate.</summary>
    private DateTimeOffset _clockCheckUtc;
    private long _clockCheckTimestamp;

    /// <summary>
    /// Скачок, замеченный вне актора (потоком DNS-посредника) и уже учтённый в желаемых закреплениях, но ещё не в сроках
    /// актора и не в применённом наборе (<see cref="CoordinatorFacts.Pinned"/> меняется только в очереди актора). Под _pinGate.
    /// </summary>
    private TimeSpan _pendingDeadlineShift;
    private TimeSpan _pendingAppliedPinShift;

    /// <summary>Скачок, замеченный актором в <see cref="ClockNowLocked"/>: сдвигает все сроки актора сразу. Под _pinGate.</summary>
    private TimeSpan _actorDeadlineShift;

    /// <summary>
    /// Значения сроков актора на момент его последней проверки часов. Отложенный сдвиг (скачок замечен потоком
    /// DNS-посредника) применяется только к совпадающим с ними: остальные записаны позже и, возможно, уже по новым часам.
    /// Только в очереди актора.
    /// </summary>
    private readonly Dictionary<(Guid Owner, int Field), DateTimeOffset> _deadlineCheckpoint = [];

    /// <summary>Точка отсчёта детектора - до стартовой сверки: перевод часов во время неё тоже будет замечен.</summary>
    private void StartClockWatch()
    {
        lock (_pinGate)
        {
            _clockCheckUtc = _deps.Time.GetUtcNow();
            _clockCheckTimestamp = _deps.Time.GetTimestamp();
        }

        TakeDeadlineCheckpoint();
    }

    /// <summary>
    /// Текущее настенное время с проверкой на скачок назад. Вызывается под _pinGate - и из очереди актора, и из потоков
    /// DNS-посредника - перед каждой записью срока закрепления: при скачке закрепления, записанные по прежним часам,
    /// сдвигаются сразу, а значение, которое запишет вызывающий, уже по новым часам, второй раз не сдвинется. Дёшево
    /// (два чтения часов) и идемпотентно: повторный вызов сравнивает с только что взятой точкой отсчёта.
    /// </summary>
    private DateTimeOffset ClockNowLocked(bool onActor = false)
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
            _pendingAppliedPinShift += jump;
            if (onActor)
            {
                _actorDeadlineShift += jump;
            }
            else
            {
                _pendingDeadlineShift += jump;
            }
        }

        return now;
    }

    /// <summary>
    /// Проверка часов в очереди актора: в начале каждой работы и тика, перед сборкой политики и перед применением и
    /// снятием закреплений. Скачок, замеченный здесь, сдвигает сроки актора сразу; замеченный потоком DNS-посредника
    /// после прошлой проверки - только не менявшиеся с неё (см. <see cref="_deadlineCheckpoint"/>). Возвращает общий
    /// сдвиг или TimeSpan.Zero. Вызывается только из очереди актора и не под _pinGate.
    /// </summary>
    private TimeSpan DetectClockJumpBack()
    {
        TimeSpan detected;
        TimeSpan deferred;
        lock (_pinGate)
        {
            ClockNowLocked(onActor: true);
            detected = _actorDeadlineShift;
            deferred = _pendingDeadlineShift;
            _actorDeadlineShift = TimeSpan.Zero;
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

        var jump = detected + deferred;
        if (jump > TimeSpan.Zero)
        {
            ShiftDeadlines(detected, deferred);
            Journal("Предупреждение", string.Create(CultureInfo.InvariantCulture,
                $"Часы Windows переведены назад примерно на {FormatShift(jump)}: сроки повторов подключения и проверок сдвинуты, ожидание не затянется."));
        }

        TakeDeadlineCheckpoint();
        return jump;
    }

    /// <summary>Запоминает текущие значения сроков актора: от них отложенный сдвиг отличает записанное позже.</summary>
    private void TakeDeadlineCheckpoint()
    {
        _deadlineCheckpoint.Clear();
        VisitDeadlines((key, value) =>
        {
            _deadlineCheckpoint[key] = value;
            return value;
        });
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
    /// Сдвигает назад сроки и отметки актора, заданные по прежним часам (перечень - <see cref="VisitDeadlines"/>).
    /// </summary>
    /// <param name="detected">Скачок, замеченный актором: сдвигает все сроки.</param>
    /// <param name="deferred">
    /// Скачок, замеченный потоком DNS-посредника: сдвигает только значения, совпадающие с запомненными при прошлой
    /// проверке актора (<see cref="_deadlineCheckpoint"/>); изменённые после неё могли быть записаны уже по новым часам.
    /// </param>
    private void ShiftDeadlines(TimeSpan detected, TimeSpan deferred)
    {
        VisitDeadlines((key, value) =>
        {
            var shift = deferred > TimeSpan.Zero && _deadlineCheckpoint.TryGetValue(key, out var seen) && seen == value
                ? detected + deferred
                : detected;
            return ShiftBack(value, shift);
        });

        foreach (var tunnel in Facts.Tunnels.Values)
        {
            if (tunnel.AnyConnect is { Established: false } link)
            {
                // Таймер срока подъёма считает монотонно; его срок пересчитывается по сдвинутой отметке.
                ArmEstablishDeadline(tunnel, link);
            }
        }

        _deps.Logger.LogWarning("Часы переведены назад на {Shift}: сроки координатора сдвинуты", detected + deferred);
    }

    /// <summary>Номера сроков в <see cref="VisitDeadlines"/>: ключ запомненного значения - владелец и номер.</summary>
    private enum DeadlineField
    {
        PartialErrorRetryAt,
        LastFullReconcile,
        LastForcedReconcile,
        LastConflictCheck,
        ConflictCheckStartedUtc,
        LastDirectFilterCheck,
        PinnedAdapterOfflineSinceUtc,
        TickFailureRetryAt,
        WifiConnectedAt,
        WifiChainStart,
        WifiHoldUntil,
        RetryPinnedSaveAt,
        ConnectivityPinAttemptUtc,
        ConnectivityPinRefreshUtc,
        NextDialAt,
        NextVerifyAt,
        NextLinkWatchAt,
        NextServerResolveAt,
        ServerResolvedUtc,
        ServerResolveStartedUtc,
        AdapterMissingSinceUtc,
        SessionStartedUtc,
        DialStartedUtc,
        AnyConnectStartedUtc,
        UncleanDropUtc,
        LastConflictProbeUtc,
        LastCertificateProbeUtc,
        IntermediateFetchUtc,
        SignInExpiresUtc,
        AnyConnectProgressUtc,
        AnyConnectParametersReceivedUtc,
        SshNextHealthAt,
        SshExitDeadline,
    }

    /// <summary>
    /// Обходит все сроки и отметки актора, заданные по настенным часам, и записывает значение, которое вернёт
    /// <paramref name="visit"/>. Отсутствующие (null) не передаются. Не входят: отметка своего разрыва RAS
    /// (сравнивается со временем события в журнале Windows, записанным по прежним часам), сроки, которые считает
    /// монотонный счётчик (таймеры, нечитаемые пароли), и состояния RU-базы, списка обхода и обновлений программы -
    /// их менеджеры сами распознают срок, оказавшийся в далёком будущем. Сроки закреплений сдвигает
    /// <see cref="ShiftPinDeadlinesLocked"/>.
    /// </summary>
    private void VisitDeadlines(Func<(Guid Owner, int Field), DateTimeOffset, DateTimeOffset> visit)
    {
        DateTimeOffset Visit(Guid owner, DeadlineField field, DateTimeOffset value) => visit((owner, (int)field), value);
        DateTimeOffset? VisitOptional(Guid owner, DeadlineField field, DateTimeOffset? value) =>
            value is { } present ? Visit(owner, field, present) : null;

        var global = Guid.Empty;
        Facts.PartialErrorRetryAt = Visit(global, DeadlineField.PartialErrorRetryAt, Facts.PartialErrorRetryAt);
        Facts.LastFullReconcile = Visit(global, DeadlineField.LastFullReconcile, Facts.LastFullReconcile);
        Facts.LastForcedReconcile = Visit(global, DeadlineField.LastForcedReconcile, Facts.LastForcedReconcile);
        Facts.LastConflictCheck = Visit(global, DeadlineField.LastConflictCheck, Facts.LastConflictCheck);
        Facts.ConflictCheckStartedUtc = Visit(global, DeadlineField.ConflictCheckStartedUtc, Facts.ConflictCheckStartedUtc);
        Facts.LastDirectFilterCheck = Visit(global, DeadlineField.LastDirectFilterCheck, Facts.LastDirectFilterCheck);
        Facts.PinnedAdapterOfflineSinceUtc = VisitOptional(global, DeadlineField.PinnedAdapterOfflineSinceUtc, Facts.PinnedAdapterOfflineSinceUtc);
        _tickFailureRetryAt = Visit(global, DeadlineField.TickFailureRetryAt, _tickFailureRetryAt);
        _wifiConnectedAt = Visit(global, DeadlineField.WifiConnectedAt, _wifiConnectedAt);
        _wifiChainStart = VisitOptional(global, DeadlineField.WifiChainStart, _wifiChainStart);
        _wifiHoldUntil = Visit(global, DeadlineField.WifiHoldUntil, _wifiHoldUntil);
        _retryPinnedSaveAt = Visit(global, DeadlineField.RetryPinnedSaveAt, _retryPinnedSaveAt);
        _connectivityPinAttemptUtc = Visit(global, DeadlineField.ConnectivityPinAttemptUtc, _connectivityPinAttemptUtc);
        _connectivityPinRefreshUtc = Visit(global, DeadlineField.ConnectivityPinRefreshUtc, _connectivityPinRefreshUtc);

        foreach (var tunnel in Facts.Tunnels.Values)
        {
            var id = tunnel.ProfileId;
            tunnel.NextDialAt = Visit(id, DeadlineField.NextDialAt, tunnel.NextDialAt);
            tunnel.NextVerifyAt = Visit(id, DeadlineField.NextVerifyAt, tunnel.NextVerifyAt);
            tunnel.NextLinkWatchAt = Visit(id, DeadlineField.NextLinkWatchAt, tunnel.NextLinkWatchAt);
            tunnel.NextServerResolveAt = Visit(id, DeadlineField.NextServerResolveAt, tunnel.NextServerResolveAt);
            tunnel.ServerResolvedUtc = Visit(id, DeadlineField.ServerResolvedUtc, tunnel.ServerResolvedUtc);
            tunnel.ServerResolveStartedUtc = VisitOptional(id, DeadlineField.ServerResolveStartedUtc, tunnel.ServerResolveStartedUtc);
            tunnel.AdapterMissingSinceUtc = VisitOptional(id, DeadlineField.AdapterMissingSinceUtc, tunnel.AdapterMissingSinceUtc);
            tunnel.SessionStartedUtc = VisitOptional(id, DeadlineField.SessionStartedUtc, tunnel.SessionStartedUtc);
            tunnel.DialStartedUtc = VisitOptional(id, DeadlineField.DialStartedUtc, tunnel.DialStartedUtc);
            tunnel.AnyConnectStartedUtc = VisitOptional(id, DeadlineField.AnyConnectStartedUtc, tunnel.AnyConnectStartedUtc);
            tunnel.UncleanDropUtc = VisitOptional(id, DeadlineField.UncleanDropUtc, tunnel.UncleanDropUtc);
            tunnel.LastConflictProbeUtc = Visit(id, DeadlineField.LastConflictProbeUtc, tunnel.LastConflictProbeUtc);
            tunnel.LastCertificateProbeUtc = Visit(id, DeadlineField.LastCertificateProbeUtc, tunnel.LastCertificateProbeUtc);
            tunnel.IntermediateFetchUtc = Visit(id, DeadlineField.IntermediateFetchUtc, tunnel.IntermediateFetchUtc);
            if (tunnel.SignIn is { } prompt)
            {
                var expires = Visit(id, DeadlineField.SignInExpiresUtc, prompt.ExpiresUtc);
                if (expires != prompt.ExpiresUtc)
                {
                    tunnel.SignIn = prompt with { ExpiresUtc = expires };
                }
            }

            if (tunnel.AnyConnect is { } link)
            {
                link.ProgressUtc = Visit(id, DeadlineField.AnyConnectProgressUtc, link.ProgressUtc);
                link.ParametersReceivedUtc = VisitOptional(id, DeadlineField.AnyConnectParametersReceivedUtc, link.ParametersReceivedUtc);
            }

            if (tunnel.Ssh is { } ssh)
            {
                ssh.NextHealthAt = Visit(id, DeadlineField.SshNextHealthAt, ssh.NextHealthAt);
            }
        }

        foreach (var (id, exit) in _sshExits)
        {
            exit.Deadline = Visit(id, DeadlineField.SshExitDeadline, exit.Deadline);
        }
    }
}
