using System.Collections.Concurrent;
using System.Diagnostics;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Serilog.Filters;
using SplitVpn.Core.Diagnostics;
using ILogger = Serilog.ILogger;

namespace SplitVpn.Service.Diagnostics;

/// <summary>
/// Журналы службы. Основной service-.log — только сведения и выше, как раньше: его читают глазами.
/// В подробном режиме рядом пишутся verbose-.log (всё, кроме потока DNS, чтобы временная линия была
/// полной) и dns-.log (строка на запрос: поток частый и не должен вытеснять события IPC и сеансов).
/// </summary>
public static class ServiceLogging
{
    /// <summary>Источник строк DNS-запросов: они идут только в dns-.log.</summary>
    public const string DnsQuerySource = "SplitVpn.Dns.Query";

    private const string VerboseTemplate = "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}";

    public static Logger Create(string logsDirectory, LoggingLevelSwitch level) => new LoggerConfiguration()
        .MinimumLevel.ControlledBy(level)
        // Журнал: файл на сутки, но при 10 МБ он продолжается следующим файлом, а не обрывается до полуночи.
        // Предел в 30 файлов при пределе возраста в 14 суток означает, что даже «разговорчивые» сутки (до трёх
        // файлов) целиком остаются в истории.
        .WriteTo.File(Path.Combine(logsDirectory, "service-.log"), restrictedToMinimumLevel: LogEventLevel.Information,
            formatProvider: System.Globalization.CultureInfo.InvariantCulture,
            rollingInterval: RollingInterval.Day, retainedFileCountLimit: 30, retainedFileTimeLimit: TimeSpan.FromDays(14),
            fileSizeLimitBytes: 10_000_000, rollOnFileSizeLimit: true)
        .WriteTo.Logger(verbose => verbose
            .Filter.ByIncludingOnly(_ => Verbose.IsOn)
            .Filter.ByExcluding(Matching.FromSource(DnsQuerySource))
            .WriteTo.File(Path.Combine(logsDirectory, "verbose-.log"), outputTemplate: VerboseTemplate,
                formatProvider: System.Globalization.CultureInfo.InvariantCulture,
                rollingInterval: RollingInterval.Day, retainedFileCountLimit: 10, fileSizeLimitBytes: 20_000_000, rollOnFileSizeLimit: true))
        .WriteTo.Logger(dns => dns
            .Filter.ByIncludingOnly(Matching.FromSource(DnsQuerySource))
            .WriteTo.File(Path.Combine(logsDirectory, "dns-.log"), outputTemplate: VerboseTemplate,
                formatProvider: System.Globalization.CultureInfo.InvariantCulture,
                rollingInterval: RollingInterval.Day, retainedFileCountLimit: 5, fileSizeLimitBytes: 20_000_000, rollOnFileSizeLimit: true))
        .CreateLogger();

    /// <summary>Строки <see cref="Verbose"/> из кода без внедрения зависимостей — в Serilog с источником «SplitVpn.&lt;категория&gt;».</summary>
    public static Action<string, string> VerboseSink(ILogger root)
    {
        var loggers = new ConcurrentDictionary<string, ILogger>(StringComparer.Ordinal);
        return (category, text) => loggers
            .GetOrAdd(category, c => root.ForContext(Constants.SourceContextPropertyName, "SplitVpn." + c))
            .Debug("{Text}", text);
    }
}

/// <summary>
/// Trace.TraceWarning/TraceError из SplitVpn.Windows раньше не доходили никуда: у процесса службы нет
/// слушателей, кроме отладочного вывода. Теперь они попадают в журнал службы.
/// </summary>
public sealed class SerilogTraceListener(ILogger logger) : TraceListener
{
    private readonly ILogger _logger = logger.ForContext(Constants.SourceContextPropertyName, "SplitVpn.Trace");

    public override void Write(string? message) => _logger.Debug("{Text}", message);

    public override void WriteLine(string? message) => _logger.Debug("{Text}", message);

    public override void TraceEvent(TraceEventCache? eventCache, string source, TraceEventType eventType, int id, string? message) =>
        _logger.Write(Level(eventType), "{Text}", message);

    public override void TraceEvent(TraceEventCache? eventCache, string source, TraceEventType eventType, int id, string? format, params object?[]? args) =>
        _logger.Write(Level(eventType), "{Text}", args is { Length: > 0 } && format is not null
            ? string.Format(System.Globalization.CultureInfo.InvariantCulture, format, args)
            : format);

    private static LogEventLevel Level(TraceEventType type) => type switch
    {
        TraceEventType.Critical or TraceEventType.Error => LogEventLevel.Error,
        TraceEventType.Warning => LogEventLevel.Warning,
        TraceEventType.Information => LogEventLevel.Information,
        _ => LogEventLevel.Debug,
    };
}
