using System.Globalization;
using Serilog.Core;
using Serilog.Events;
using SplitVpn.Core.Diagnostics;

namespace SplitVpn.Service.Diagnostics;

/// <summary>
/// Подробный журнал на срок. Срок хранится в реестре (<see cref="VerboseRegistry"/>) и читается до создания
/// журнала, поэтому режим переживает перезапуск службы и перезагрузку, а по истечении выключается сам —
/// забытый режим не копит сотни мегабайт.
/// </summary>
public sealed class VerboseMode : IDisposable
{
    public static readonly TimeSpan MinDuration = TimeSpan.FromMinutes(1);

    /// <summary>Подробные файлы старше этого удаляются при запуске и при включении: Serilog чистит их только при ротации.</summary>
    public static readonly TimeSpan FileLifetime = TimeSpan.FromDays(7);

    /// <summary>Шаблоны имён подробных файлов в каталоге журналов.</summary>
    public static readonly string[] FilePatterns = ["verbose-*.log", "dns-*.log"];

    private readonly LoggingLevelSwitch _level;
    private readonly TimeProvider _time;
    private readonly Func<string?> _load;
    private readonly Action<DateTimeOffset?> _save;
    private readonly Func<string?>? _loadRemaining;
    private readonly Action<TimeSpan?>? _saveRemaining;
    private readonly string _logsDirectory;
    private readonly Lock _lock = new();
    private ITimer? _timer;
    private ITimer? _checkpoint;

    /// <summary>Срок по часам на момент включения: его хранит реестр (интерфейс читает его же).</summary>
    private DateTimeOffset? _until;

    /// <summary>Монотонная отметка включения и остаток срока на тот момент: истечение считается по ним.</summary>
    private long _appliedAt;
    private TimeSpan _remainingAtApply;

    /// <summary>Номер включения: таймер прежнего включения не гасит продлённый режим.</summary>
    private long _generation;

    /// <summary>
    /// Режим выключен, но срок не удалён из реестра: после перезапуска службы режим включился бы снова.
    /// Повторное выключение повторяет удаление.
    /// </summary>
    private bool _clearPending;

    /// <summary>Как часто остаток срока записывается в реестр, пока режим включён.</summary>
    internal static readonly TimeSpan CheckpointInterval = TimeSpan.FromMinutes(5);

    /// <param name="loadRemaining">Остаток срока из реестра (<see cref="VerboseRegistry.RemainingValueName"/>).</param>
    /// <param name="saveRemaining">Запись остатка; null удаляет.</param>
    public VerboseMode(LoggingLevelSwitch level, TimeProvider time, Func<string?> load, Action<DateTimeOffset?> save, string logsDirectory,
        Func<string?>? loadRemaining = null, Action<TimeSpan?>? saveRemaining = null)
    {
        _level = level;
        _time = time;
        _load = load;
        _save = save;
        _logsDirectory = logsDirectory;
        _loadRemaining = loadRemaining;
        _saveRemaining = saveRemaining;
    }

    /// <summary>Событие для журнала службы: уровень («Сведения», «Предупреждение») и текст. Подключается после создания журнала.</summary>
    public Action<string, string>? Journal { get; set; }

    /// <summary>
    /// До какого момента режим включён: сейчас плюс остаток по монотонному времени. Перевод часов не продлевает и
    /// не обрывает режим, срок лишь пересчитывается к новым часам.
    /// </summary>
    public DateTimeOffset? UntilUtc
    {
        get
        {
            lock (_lock)
            {
                return _until is null ? null : _time.GetUtcNow() + Left();
            }
        }
    }

    /// <summary>
    /// Прочитать срок из реестра и применить. Истёкшее значение удаляется. Срок по часам ограничен записанным остатком:
    /// часы, переведённые назад, пока служба не работала, не продлевают режим сверх запрошенного.
    /// </summary>
    public void Initialize()
    {
        string? stored;
        string? storedRemaining;
        try
        {
            stored = _load();
            storedRemaining = _loadRemaining?.Invoke();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            stored = null;
            storedRemaining = null;
        }

        var now = _time.GetUtcNow();
        var until = VerboseRegistry.Effective(stored, now);
        if (until is { } value && VerboseRegistry.ParseRemaining(storedRemaining) is { } remaining && value - now > remaining)
        {
            until = remaining > TimeSpan.Zero ? now + remaining : null;
        }

        lock (_lock)
        {
            // Истёкшее значение удаляется, слишком дальнее — записывается обрезанным: иначе вписанный вручную
            // срок «навсегда» при ежедневной перезагрузке продлевался бы ещё на сутки каждый раз.
            if (stored is not null && (until is null || stored != VerboseRegistry.Format(until.Value)))
            {
                TrySave(until);
            }

            if (until is null && storedRemaining is not null)
            {
                TrySaveRemaining(null);
            }

            Apply(until, until is { } term ? term - now : TimeSpan.Zero);
        }

        DeleteOldFiles();
    }

    /// <summary>Включить на срок (от минуты до суток); повторное включение продлевает или сокращает срок.</summary>
    public DateTimeOffset Enable(TimeSpan duration)
    {
        duration = duration < MinDuration ? MinDuration : duration > VerboseRegistry.MaxDuration ? VerboseRegistry.MaxDuration : duration;
        var until = _time.GetUtcNow() + duration;
        lock (_lock)
        {
            // Реестр и режим меняются вместе: иначе одновременное выключение оставило бы их разными.
            _save(until);
            TrySaveRemaining(duration);
            _clearPending = false;
            Apply(until, duration);
        }

        DeleteOldFiles();
        Journal?.Invoke("Сведения", "Подробный журнал включён до " + until.ToLocalTime().ToString("dd.MM HH:mm", CultureInfo.GetCultureInfo("ru-RU")) + ".");
        return until;
    }

    /// <summary>
    /// Выключить вручную. Режим гаснет сразу; false — срок не удалён из реестра, и после перезапуска службы
    /// до прежнего срока режим включится снова: вызывающий сообщает об этом пользователю.
    /// </summary>
    public bool Disable(string reason) => Disable(reason, expected: null);

    /// <summary>Выключить; expected — только если действует именно это включение (истечение не гасит продлённый режим).</summary>
    private bool Disable(string reason, long? expected)
    {
        bool saved;
        lock (_lock)
        {
            if ((_until is null && !_clearPending) || (expected is not null && (_until is null || _generation != expected)))
            {
                return true;
            }

            var wasOn = _until is not null;
            Apply(null, TimeSpan.Zero);
            saved = TrySave(null);
            TrySaveRemaining(null);
            _clearPending = !saved;
            if (!wasOn)
            {
                return saved;
            }
        }

        Journal?.Invoke("Сведения", "Подробный журнал выключен: " + reason + ".");
        return saved;
    }

    public void Dispose()
    {
        lock (_lock)
        {
            // Остаток — в реестр: после перезапуска режим продолжится не дольше него, как бы ни перевели часы.
            if (_until is not null)
            {
                TrySaveRemaining(Left());
            }

            _timer?.Dispose();
            _timer = null;
            _checkpoint?.Dispose();
            _checkpoint = null;
        }
    }

    /// <summary>Остаток срока по монотонному времени.</summary>
    private TimeSpan Left()
    {
        var left = _remainingAtApply - _time.GetElapsedTime(_appliedAt);
        return left > TimeSpan.Zero ? left : TimeSpan.Zero;
    }

    private void Apply(DateTimeOffset? until, TimeSpan remaining)
    {
        _until = until;
        _generation++;
        _appliedAt = _time.GetTimestamp();
        _remainingAtApply = remaining;
        _timer?.Dispose();
        _timer = null;
        _checkpoint?.Dispose();
        _checkpoint = null;
        var on = until is not null;
        _level.MinimumLevel = on ? LogEventLevel.Verbose : LogEventLevel.Information;
        Verbose.Set(on);
        if (on)
        {
            var generation = _generation;
            Arm(generation, remaining);
            if (_saveRemaining is not null)
            {
                _checkpoint = _time.CreateTimer(_ => Checkpoint(generation), null, CheckpointInterval, CheckpointInterval);
            }
        }
    }

    private void Arm(long generation, TimeSpan due) =>
        _timer = _time.CreateTimer(_ => Expire(generation), null, due < TimeSpan.Zero ? TimeSpan.Zero : due, Timeout.InfiniteTimeSpan);

    /// <summary>
    /// Срок считается по монотонному времени с включения, как и таймер: перевод часов его не меняет. Таймер, сработавший
    /// на миллисекунды раньше (грубая гранулярность), взводится на остаток, а не теряется.
    /// </summary>
    private void Expire(long generation)
    {
        lock (_lock)
        {
            if (_until is null || _generation != generation)
            {
                return;
            }

            var left = _remainingAtApply - _time.GetElapsedTime(_appliedAt);
            if (left > TimeSpan.Zero)
            {
                _timer?.Dispose();
                Arm(generation, left);
                return;
            }
        }

        Disable("срок истёк", generation);
    }

    private void Checkpoint(long generation)
    {
        lock (_lock)
        {
            if (_until is not null && _generation == generation)
            {
                TrySaveRemaining(Left());
            }
        }
    }

    private void TrySaveRemaining(TimeSpan? remaining)
    {
        try
        {
            _saveRemaining?.Invoke(remaining);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            // Без остатка в реестре после перезапуска действует срок по часам, как прежде.
        }
    }

    private bool TrySave(DateTimeOffset? until)
    {
        try
        {
            _save(until);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            // Истёкший срок при следующем чтении считается выключенным; ручное выключение до срока об этом
            // сообщает вызывающему (см. Disable).
            Journal?.Invoke("Предупреждение", "Срок подробного журнала не удалён из реестра: " + ex.Message);
            return false;
        }
    }

    private void DeleteOldFiles()
    {
        var limit = _time.GetUtcNow().UtcDateTime - FileLifetime;
        try
        {
            foreach (var pattern in FilePatterns)
            {
                foreach (var file in new DirectoryInfo(_logsDirectory).EnumerateFiles(pattern))
                {
                    if (file.LastWriteTimeUtc < limit)
                    {
                        try
                        {
                            file.Delete();
                        }
                        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                        {
                            // Файл ещё открыт журналом — удалится в следующий раз.
                        }
                    }
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Каталога журналов нет: удалять нечего.
        }
    }
}
