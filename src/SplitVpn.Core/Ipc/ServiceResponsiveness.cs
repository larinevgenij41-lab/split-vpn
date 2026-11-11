namespace SplitVpn.Core.Ipc;

/// <summary>
/// Когда показывать «Служба не отвечает». Короткая занятость службы (долгая сверка, установка фильтров) даёт
/// одиночный таймаут опроса — баннер от него только мигал бы. Таймаут становится видимым, когда их два подряд
/// и успешного ответа нет не меньше <see cref="SilenceThreshold"/>. Остальные причины (служба остановлена,
/// версии, права, подмена канала) определяются сразу и показываются без задержки.
/// </summary>
public sealed class ServiceResponsiveness
{
    /// <summary>Сколько таймаутов подряд нужно, чтобы показать «Служба не отвечает».</summary>
    public const int TimeoutsToReport = 2;

    /// <summary>Сколько времени без успешного ответа нужно, чтобы показать «Служба не отвечает».</summary>
    public static readonly TimeSpan SilenceThreshold = TimeSpan.FromSeconds(7);

    private DateTimeOffset? _lastSuccess;
    private int _timeouts;

    /// <summary>Служба ответила: счётчик таймаутов сбрасывается.</summary>
    public void OnSuccess(DateTimeOffset now)
    {
        _lastSuccess = now;
        _timeouts = 0;
    }

    /// <summary>Запрос не удался. true — показать недоступность; false — считать службу занятой и повторить опрос.</summary>
    public bool OnFailure(ServiceUnavailableReason reason, DateTimeOffset now)
    {
        if (reason != ServiceUnavailableReason.Timeout)
        {
            _timeouts = 0;
            return true;
        }

        _timeouts++;
        return _timeouts >= TimeoutsToReport && (_lastSuccess is not { } last || now - last >= SilenceThreshold);
    }
}
