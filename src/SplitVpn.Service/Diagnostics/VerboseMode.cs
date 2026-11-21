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
    private readonly string _logsDirectory;
    private readonly Lock _lock = new();
    private ITimer? _timer;
    private DateTimeOffset? _until;

    /// <summary>
    /// Режим выключен, но срок не удалён из реестра: после перезапуска службы режим включился бы снова.
    /// Повторное выключение повторяет удаление.
    /// </summary>
    private bool _clearPending;

    public VerboseMode(LoggingLevelSwitch level, TimeProvider time, Func<string?> load, Action<DateTimeOffset?> save, string logsDirectory)
    {
        _level = level;
        _time = time;
        _load = load;
        _save = save;
        _logsDirectory = logsDirectory;
    }

    /// <summary>Событие для журнала службы: уровень («Сведения», «Предупреждение») и текст. Подключается после создания журнала.</summary>
    public Action<string, string>? Journal { get; set; }

    public DateTimeOffset? UntilUtc
    {
        get
        {
            lock (_lock)
            {
                return _until;
            }
        }
    }

    /// <summary>Прочитать срок из реестра и применить. Истёкшее значение удаляется.</summary>
    public void Initialize()
    {
        string? stored;
        try
        {
            stored = _load();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            stored = null;
        }

        var until = VerboseRegistry.Effective(stored, _time.GetUtcNow());
        lock (_lock)
        {
            // Истёкшее значение удаляется, слишком дальнее — записывается обрезанным: иначе вписанный вручную
            // срок «навсегда» при ежедневной перезагрузке продлевался бы ещё на сутки каждый раз.
            if (stored is not null && (until is null || stored != VerboseRegistry.Format(until.Value)))
            {
                TrySave(until);
            }

            Apply(until);
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
            _clearPending = false;
            Apply(until);
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

    /// <summary>Выключить; expected — только если действует именно этот срок (истечение не гасит продлённый режим).</summary>
    private bool Disable(string reason, DateTimeOffset? expected)
    {
        bool saved;
        lock (_lock)
        {
            if ((_until is null && !_clearPending) || (expected is not null && _until != expected))
            {
                return true;
            }

            var wasOn = _until is not null;
            Apply(null);
            saved = TrySave(null);
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
            _timer?.Dispose();
            _timer = null;
        }
    }

    private void Apply(DateTimeOffset? until)
    {
        _until = until;
        _timer?.Dispose();
        _timer = null;
        var on = until is not null;
        _level.MinimumLevel = on ? LogEventLevel.Verbose : LogEventLevel.Information;
        Verbose.Set(on);
        if (until is { } value)
        {
            Arm(value);
        }
    }

    private void Arm(DateTimeOffset until)
    {
        var due = until - _time.GetUtcNow();
        _timer = _time.CreateTimer(_ => Expire(until), null, due < TimeSpan.Zero ? TimeSpan.Zero : due, Timeout.InfiniteTimeSpan);
    }

    /// <summary>
    /// Таймер идёт по монотонному времени, срок — по часам: он может сработать на миллисекунды раньше
    /// (грубая гранулярность, подстройка часов). Тогда он взводится на остаток, а не теряется.
    /// </summary>
    private void Expire(DateTimeOffset expected)
    {
        lock (_lock)
        {
            if (_until != expected)
            {
                return;
            }

            if (expected > _time.GetUtcNow())
            {
                _timer?.Dispose();
                Arm(expected);
                return;
            }
        }

        Disable("срок истёк", expected);
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
