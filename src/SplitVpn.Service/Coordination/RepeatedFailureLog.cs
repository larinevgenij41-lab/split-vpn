using System.Globalization;
using Microsoft.Extensions.Logging;

namespace SplitVpn.Service.Coordination;

/// <summary>
/// Подавление повторов устойчивого сбоя в журнале службы. Шаг тика, опрос туннеля или работа очереди, падающие
/// на каждом тике (раз в 2 с), иначе писали бы запись со стеком 43 200 раз в сутки, и ротация журнала вытесняла бы
/// полезную историю за несколько дней. Ключ сбоя - источник, тип исключения и сообщение: первый сбой пишется
/// полностью, со стеком; повторы - на уровне Debug, а не чаще раза в <see cref="SummaryInterval"/> одна строка
/// «повторяется: N раз за M мин» без стека. Когда источник снова отработал, пишется одна запись о восстановлении.
/// Вызывается из очереди актора и из фоновых задач, поэтому под замком.
/// </summary>
internal sealed class RepeatedFailureLog(ILogger logger, TimeProvider time)
{
    /// <summary>Не чаще этого пишется сводка о повторах одного сбоя.</summary>
    internal static readonly TimeSpan SummaryInterval = TimeSpan.FromMinutes(10);

    /// <summary>Сколько разных сбоев помнится одновременно; при переполнении забывается самый давний.</summary>
    internal const int MaxKeys = 64;

    private readonly Lock _lock = new();
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);

    private sealed class Entry(string source, string what, LogLevel level, DateTimeOffset now)
    {
        public string Source { get; } = source;

        public string What { get; } = what;

        public LogLevel Level { get; } = level;

        public DateTimeOffset FirstUtc { get; } = now;

        public DateTimeOffset LastReportUtc { get; set; } = now;

        public DateTimeOffset LastSeenUtc { get; set; } = now;

        /// <summary>Повторы после последней записи (полной или сводки).</summary>
        public int Suppressed { get; set; }

        /// <summary>Все повторы с первого сбоя.</summary>
        public int Total { get; set; } = 1;
    }

    /// <summary>Сколько сбоев сейчас помнится (для проверок).</summary>
    internal int Count
    {
        get
        {
            lock (_lock)
            {
                return _entries.Count;
            }
        }
    }

    /// <summary>
    /// Сбой источника <paramref name="source"/>. <paramref name="what"/> - готовый текст записи («Тик службы: сбой
    /// шага …»); первый сбой с этим типом и сообщением пишется с <paramref name="exception"/> на уровне
    /// <paramref name="level"/>, повторы подавляются. true - сбой записан полностью (первый или новый текст ошибки).
    /// <paramref name="withStack"/> = false - и первая запись без стека, только с текстом ошибки (ожидаемые сбои сети).
    /// <paramref name="summarize"/> = false - без сводок: повторы только в подробный журнал (Debug).
    /// </summary>
    public bool Failure(string source, string what, Exception exception, LogLevel level = LogLevel.Error, bool withStack = true, bool summarize = true)
    {
        var now = time.GetUtcNow();
        var key = source + "\n" + exception.GetType().FullName + "\n" + exception.Message;
        int count;
        TimeSpan span;
        Entry entry;
        lock (_lock)
        {
            if (!_entries.TryGetValue(key, out var known))
            {
                if (_entries.Count >= MaxKeys)
                {
                    // Самый давний сбой забывается: повторись он, будет записан заново, полностью.
                    var oldest = _entries.MinBy(e => e.Value.LastSeenUtc).Key;
                    _entries.Remove(oldest);
                }

                entry = _entries[key] = new Entry(source, what, level, now);
                count = 0;
                span = TimeSpan.Zero;
            }
            else
            {
                entry = known;
                entry.LastSeenUtc = now;
                entry.Suppressed++;
                entry.Total++;
                if (now < entry.LastReportUtc)
                {
                    // Часы перевели назад: отсчёт до сводки начинается заново, а не растягивается на величину перевода.
                    entry.LastReportUtc = now;
                }

                if (!summarize || now - entry.LastReportUtc < SummaryInterval)
                {
                    count = -1;
                    span = TimeSpan.Zero;
                }
                else
                {
                    count = entry.Suppressed;
                    span = now - entry.LastReportUtc;
                    entry.Suppressed = 0;
                    entry.LastReportUtc = now;
                }
            }
        }

        if (count == 0)
        {
            if (withStack)
            {
                logger.Log(level, exception, "{What}", what);
            }
            else
            {
                logger.Log(level, "{What}: {Error}", what, exception.Message);
            }

            return true;
        }

        if (count < 0)
        {
            if (logger.IsEnabled(LogLevel.Debug))
            {
                logger.LogDebug("{What} (повтор: {Error})", what, exception.Message);
            }

            return false;
        }

        // Сводка - без стека: он записан при первом сбое.
        logger.Log(entry.Level is LogLevel.Error or LogLevel.Critical ? LogLevel.Warning : entry.Level,
            "{What} — повторяется: {Count} раз за {Minutes} мин ({Type}: {Error})",
            what, count, Math.Max(1, (int)Math.Round(span.TotalMinutes)).ToString(CultureInfo.InvariantCulture),
            exception.GetType().Name, exception.Message);
        return false;
    }

    /// <summary>
    /// Источник отработал без сбоя: если он сбоил, пишется одна запись о восстановлении, и сбои забываются.
    /// </summary>
    public void Recovered(string source, string text)
    {
        List<Entry>? ended = null;
        lock (_lock)
        {
            if (_entries.Count == 0)
            {
                return;
            }

            foreach (var (key, entry) in _entries.ToList())
            {
                if (string.Equals(entry.Source, source, StringComparison.Ordinal))
                {
                    _entries.Remove(key);
                    (ended ??= []).Add(entry);
                }
            }
        }

        if (ended is null)
        {
            return;
        }

        var now = time.GetUtcNow();
        var first = ended.Min(e => e.FirstUtc);
        var total = ended.Sum(e => e.Total);
        var minutes = Math.Max(0, (int)Math.Round((now - first).TotalMinutes));
        logger.LogInformation("{Text} (сбой повторялся {Count} раз за {Minutes} мин)", text, total, minutes.ToString(CultureInfo.InvariantCulture));
    }
}
