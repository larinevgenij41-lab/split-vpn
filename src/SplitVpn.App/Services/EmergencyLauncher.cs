using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using SplitVpn.Core.Diagnostics;
using SplitVpn.Core.Recovery;

namespace SplitVpn.App.Services;

/// <summary>Запуск процесса с правами администратора (окно UAC) и ожидание его завершения; в проверках подменяется.</summary>
public interface IElevatedProcessRunner
{
    /// <summary>Запускает процесс и ждёт его не дольше <paramref name="timeout"/>; процесс по сроку не завершается.</summary>
    Task<ElevatedProcessOutcome> RunAsync(ProcessStartInfo startInfo, TimeSpan timeout, CancellationToken cancellationToken);
}

/// <summary>
/// Итог запуска: код завершения, ошибка запуска Win32 (1223 — отказ в окне UAC) или «не завершился в срок».
/// </summary>
public sealed record ElevatedProcessOutcome(int? ExitCode, int? StartError, bool TimedOut)
{
    public static ElevatedProcessOutcome Exited(int code) => new(code, null, false);

    public static ElevatedProcessOutcome NotStarted(int win32Error) => new(null, win32Error, false);

    public static ElevatedProcessOutcome Overdue { get; } = new(null, null, true);
}

/// <summary>ShellExecute с глаголом «runas»: Windows показывает окно контроля учётных записей.</summary>
public sealed class ShellElevatedProcessRunner : IElevatedProcessRunner
{
    public async Task<ElevatedProcessOutcome> RunAsync(ProcessStartInfo startInfo, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(startInfo);
        Process? process;
        try
        {
            process = Process.Start(startInfo);
        }
        catch (Win32Exception ex)
        {
            Verbose.Write("Ui", "команда с правами администратора не запущена: " + ex.NativeErrorCode + " «" + ex.Message + "»");
            return ElevatedProcessOutcome.NotStarted(ex.NativeErrorCode);
        }

        if (process is null)
        {
            return ElevatedProcessOutcome.NotStarted(0);
        }

        using (process)
        {
            // Отмена ожидания не завершает команду: она должна дойти до конца, иначе сеть останется наполовину.
            return await WindowsServiceHost.ExitsWithinAsync(token => process.WaitForExitAsync(token).WaitAsync(cancellationToken), timeout)
                ? ElevatedProcessOutcome.Exited(process.ExitCode)
                : ElevatedProcessOutcome.Overdue;
        }
    }
}

/// <summary>Флаг экстренного выключения из реестра (HKLM\Software\SplitVpn); в проверках подменяется.</summary>
public interface IEmergencyFlagSource
{
    /// <summary>null — программа не выключена или флаг не прочитан.</summary>
    EmergencyFlag? Read();
}

public sealed class RegistryEmergencyFlagSource : IEmergencyFlagSource
{
    public EmergencyFlag? Read() => EmergencyRegistry.Read();
}

/// <summary>Экстренное выключение и включение программы; в проверках подменяется.</summary>
public interface IEmergencyLauncher
{
    Task<EmergencyRunResult> RunAsync(bool on, CancellationToken cancellationToken = default);
}

/// <summary>
/// «Экстренно выключить» и «Включить программу»: «SplitVpn.Service.exe emergency-off|emergency-on» с правами
/// администратора. Канал управления не используется вовсе: команда работает, когда служба зависла, остановлена или
/// канал занят чужим процессом. После завершения читается отчёт команды (<see cref="EmergencyReportFiles.LastPath"/>),
/// но только записанный этим запуском.
/// </summary>
public sealed class EmergencyLauncher : IEmergencyLauncher
{
    /// <summary>
    /// Срок ожидания emergency-off: с запасом больше худшего случая команды — сумма сроков всех шагов в
    /// EmergencyOrchestrator (блокировка 15 с, остановка службы до 2 мин 15 с, фильтры WFP 2 мин, DNS 1,5 мин,
    /// маршруты 1 мин и остальные шаги) — около 11 минут.
    /// </summary>
    internal static readonly TimeSpan OffTimeout = TimeSpan.FromMinutes(12);

    /// <summary>Срок emergency-on: остановка «пустой» службы, флаг, тип запуска и запуск службы — около 6 минут в худшем случае.</summary>
    internal static readonly TimeSpan OnTimeout = TimeSpan.FromMinutes(7);

    /// <summary>ERROR_CANCELLED: пользователь отказался в окне UAC.</summary>
    public const int UacCancelled = 1223;

    /// <summary>Допуск на расхождение часов процессов: отчёт с началом раньше запуска больше этого — прежний.</summary>
    private static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(5);

    private readonly IElevatedProcessRunner _runner;
    private readonly Func<string?> _findExecutable;
    private readonly Func<string, string?> _readFile;
    private readonly string _reportPath;
    private readonly TimeProvider _time;

    public EmergencyLauncher()
        : this(new ShellElevatedProcessRunner(), NetworkRecovery.FindServiceExecutable, ReadReport, EmergencyReportFiles.LastPath, TimeProvider.System)
    {
    }

    internal EmergencyLauncher(IElevatedProcessRunner runner, Func<string?> findExecutable, Func<string, string?> readFile, string reportPath, TimeProvider time)
    {
        _runner = runner;
        _findExecutable = findExecutable;
        _readFile = readFile;
        _reportPath = reportPath;
        _time = time;
    }

    /// <summary>
    /// Запуск команды: ShellExecute с «runas» (окно UAC), скрытое окно консоли, рабочий каталог — System32
    /// (повышенный процесс не ищет библиотеки в каталоге, откуда запущен интерфейс).
    /// </summary>
    public static ProcessStartInfo BuildStartInfo(string executable, bool on) => new(executable, on ? EmergencyCommands.On : EmergencyCommands.Off)
    {
        UseShellExecute = true,
        Verb = "runas",
        WindowStyle = ProcessWindowStyle.Hidden,
        WorkingDirectory = Environment.SystemDirectory,
    };

    public async Task<EmergencyRunResult> RunAsync(bool on, CancellationToken cancellationToken = default)
    {
        var executable = _findExecutable();
        if (executable is null)
        {
            return EmergencyRunResult.NotFound(on);
        }

        var started = _time.GetUtcNow();
        Verbose.Write("Ui", (on ? "включение программы" : "экстренное выключение") + ": запуск «" + executable + "»");
        var outcome = await _runner.RunAsync(BuildStartInfo(executable, on), on ? OnTimeout : OffTimeout, cancellationToken);
        if (outcome.StartError is { } error)
        {
            return error == UacCancelled ? EmergencyRunResult.Cancelled(on) : EmergencyRunResult.StartFailed(on, error);
        }

        var report = FreshReport(on, started);
        Verbose.Write("Ui", (on ? "включение программы" : "экстренное выключение") + ": "
            + (outcome.TimedOut ? "не завершилось в срок" : "код " + outcome.ExitCode?.ToString(CultureInfo.InvariantCulture))
            + (report is null ? ", отчёта этого запуска нет" : ", отчёт прочитан"));
        return outcome.TimedOut
            ? EmergencyRunResult.Overdue(on, on ? OnTimeout : OffTimeout, report, report is null ? null : _reportPath)
            : EmergencyRunResult.FromExitCode(on, outcome.ExitCode ?? EmergencyExitCodes.Unexpected, report, report is null ? null : _reportPath);
    }

    /// <summary>Отчёт этого запуска; прежний (другая команда или начат раньше запуска) не годится.</summary>
    internal EmergencyReport? FreshReport(bool on, DateTimeOffset launchedUtc)
    {
        string? text;
        try
        {
            text = _readFile(_reportPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Verbose.Write("Ui", "отчёт экстренного выключения не прочитан: " + ex.GetType().Name + " «" + ex.Message + "»");
            return null;
        }

        var report = text is null ? null : EmergencyReportFiles.Parse(text);
        return IsFresh(report, on, launchedUtc) ? report : null;
    }

    internal static bool IsFresh(EmergencyReport? report, bool on, DateTimeOffset launchedUtc) =>
        report is not null
        && string.Equals(report.Command, on ? EmergencyCommands.On : EmergencyCommands.Off, StringComparison.Ordinal)
        && report.StartedUtc >= launchedUtc - ClockSkew
        && report.FinishedUtc >= report.StartedUtc;

    private static string? ReadReport(string path)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        // Команда пишет отчёт до своего завершения; чтение не мешает следующей команде его заменить.
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }
}

/// <summary>Чем закончился запуск.</summary>
public enum EmergencyRunKind
{
    /// <summary>Код 0.</summary>
    Succeeded,

    /// <summary>Отказ в окне UAC: ничего не делалось.</summary>
    Cancelled,

    /// <summary>Уже выполняется другая такая команда (код 5).</summary>
    Busy,

    /// <summary>Сделано не всё (коды 1-4), команда не запустилась или файл службы не найден.</summary>
    Failed,

    /// <summary>Команда не завершилась в срок ожидания.</summary>
    Overdue,
}

/// <summary>Насколько важен итог шага для пользователя.</summary>
public enum EmergencyStepSeverity
{
    Ok,

    /// <summary>Необязательный шаг не удался (кеш DNS, возврат автоперезапуска): на итог не влияет.</summary>
    Warning,

    Error,
}

/// <summary>Шаг отчёта для показа: название и итог по-русски.</summary>
public sealed record EmergencyStepRow(string Title, string OutcomeText, string? Detail, EmergencyStepSeverity Severity)
{
    public bool IsProblem => Severity != EmergencyStepSeverity.Ok;

    public bool IsError => Severity == EmergencyStepSeverity.Error;

    public bool IsWarning => Severity == EmergencyStepSeverity.Warning;

    /// <summary>Цвет точки у строки; итог шага всегда есть и словами.</summary>
    public Views.StateTone Tone => Severity switch
    {
        EmergencyStepSeverity.Error => Views.StateTone.Critical,
        EmergencyStepSeverity.Warning => Views.StateTone.Caution,
        _ => Views.StateTone.Success,
    };

    /// <summary>Строка для экранного диктора: название, итог и подробности.</summary>
    public string Spoken => Title + ": " + OutcomeText + (Detail is { Length: > 0 } ? " (" + Detail + ")" : "");

    public static EmergencyStepRow From(EmergencyStepReport step)
    {
        ArgumentNullException.ThrowIfNull(step);
        var severity = step.Succeeded ? EmergencyStepSeverity.Ok : step.Required ? EmergencyStepSeverity.Error : EmergencyStepSeverity.Warning;
        var title = string.IsNullOrWhiteSpace(step.Title) ? EmergencySteps.Title(step.Step) : step.Title;
        return new EmergencyStepRow(title, DescribeOutcome(step.Outcome), step.Detail, severity);
    }

    public static string DescribeOutcome(EmergencyStepOutcome outcome) => outcome switch
    {
        EmergencyStepOutcome.Done => "сделано",
        EmergencyStepOutcome.Already => "уже было так",
        EmergencyStepOutcome.Skipped => "не требовалось",
        EmergencyStepOutcome.Timeout => "не уложился в срок",
        _ => "не удалось",
    };
}

/// <summary>
/// Итог экстренного выключения или включения для пользователя: что получилось одной фразой, что делать дальше,
/// шаги и путь к отчёту. Никогда не просто «код 1».
/// </summary>
public sealed record EmergencyRunResult
{
    public bool On { get; init; }

    public EmergencyRunKind Kind { get; init; }

    /// <summary>Код завершения команды; null — команда не запускалась или не завершилась.</summary>
    public int? ExitCode { get; init; }

    public string Title { get; init; } = "";

    public string Summary { get; init; } = "";

    /// <summary>Что делать дальше; пусто — ничего.</summary>
    public string Advice { get; init; } = "";

    public IReadOnlyList<EmergencyStepRow> Steps { get; init; } = [];

    /// <summary>Файл отчёта этого запуска; null — отчёта нет.</summary>
    public string? ReportPath { get; init; }

    public bool IsError => Kind is not (EmergencyRunKind.Succeeded or EmergencyRunKind.Cancelled);

    public bool HasSteps => Steps.Count > 0;

    public bool HasAdvice => Advice.Length > 0;

    /// <summary>Значок итога: успех, «подождите» (занято, не дождались) или «сделано не всё».</summary>
    public Views.StateTone Tone => Kind switch
    {
        EmergencyRunKind.Succeeded or EmergencyRunKind.Cancelled => Views.StateTone.Success,
        EmergencyRunKind.Busy or EmergencyRunKind.Overdue => Views.StateTone.Caution,
        _ => Views.StateTone.Critical,
    };

    public Wpf.Ui.Controls.SymbolRegular Symbol => Kind switch
    {
        EmergencyRunKind.Succeeded or EmergencyRunKind.Cancelled => Wpf.Ui.Controls.SymbolRegular.CheckmarkCircle24,
        EmergencyRunKind.Busy or EmergencyRunKind.Overdue => Wpf.Ui.Controls.SymbolRegular.Clock24,
        _ => Wpf.Ui.Controls.SymbolRegular.Warning24,
    };

    /// <summary>Для экранного диктора: заголовок и итог одной строкой.</summary>
    public string Spoken => Title + ": " + Summary;

    /// <summary>Есть неудавшиеся шаги или предупреждения: список шагов раскрыт сразу.</summary>
    public bool HasProblems => Steps.Any(s => s.IsProblem);

    public string StepsHeader => $"Шаги ({Steps.Count})";

    /// <summary>Код завершения процесса SplitVpn.exe ‐‐emergency-off: код команды, 1223 — отказ в окне UAC, 1 — не запустилась.</summary>
    public int ProcessExitCode => ExitCode ?? (Kind == EmergencyRunKind.Cancelled ? EmergencyLauncher.UacCancelled : EmergencyExitCodes.Unexpected);

    private static string TitleFor(bool on) => on ? "Включение программы" : "Экстренное выключение";

    public static EmergencyRunResult Cancelled(bool on) => new()
    {
        On = on,
        Kind = EmergencyRunKind.Cancelled,
        Title = TitleFor(on),
        Summary = on ? "Включение программы отменено." : "Экстренное выключение отменено.",
    };

    public static EmergencyRunResult NotFound(bool on) => new()
    {
        On = on,
        Kind = EmergencyRunKind.Failed,
        Title = TitleFor(on),
        Summary = "Файл службы «Раздельного VPN» не найден: программа удалена или установка повреждена.",
        Advice = on
            ? "Переустановите программу."
            : "Если интернет не работает, запустите от имени администратора recover-network.cmd из папки программы (подпапка scripts) или перезагрузите компьютер.",
    };

    public static EmergencyRunResult StartFailed(bool on, int win32Error) => new()
    {
        On = on,
        Kind = EmergencyRunKind.Failed,
        Title = TitleFor(on),
        Summary = string.Create(CultureInfo.InvariantCulture, $"Windows не запустила команду с правами администратора (код {win32Error})."),
        Advice = on
            ? "Повторите «Включить программу». Если не помогает — перезагрузите компьютер и повторите."
            : "Если интернет не работает, запустите от имени администратора recover-network.cmd из папки программы (подпапка scripts) или перезагрузите компьютер.",
    };

    public static EmergencyRunResult Overdue(bool on, TimeSpan waited, EmergencyReport? report, string? reportPath) => new()
    {
        On = on,
        Kind = EmergencyRunKind.Overdue,
        Title = TitleFor(on),
        Summary = string.Create(CultureInfo.InvariantCulture, $"Команда не завершилась за {waited.TotalMinutes:0} мин."),
        Advice = "Она может ещё выполняться. Проверьте состояние через несколько минут; если интернет так и не заработает — перезагрузите компьютер.",
        Steps = Rows(report),
        ReportPath = reportPath,
    };

    public static EmergencyRunResult FromExitCode(bool on, int code, EmergencyReport? report, string? reportPath)
    {
        var steps = Rows(report);
        var summary = report is { Summary.Length: > 0 } ? report.Summary : EmergencyExitCodes.Describe(code, on);
        return new EmergencyRunResult
        {
            On = on,
            Kind = code switch
            {
                EmergencyExitCodes.Success => EmergencyRunKind.Succeeded,
                EmergencyExitCodes.Busy => EmergencyRunKind.Busy,
                _ => EmergencyRunKind.Failed,
            },
            ExitCode = code,
            Title = TitleFor(on),
            Summary = summary,
            Advice = Advise(on, code, report),
            Steps = steps,
            ReportPath = reportPath,
        };
    }

    private static List<EmergencyStepRow> Rows(EmergencyReport? report) =>
        report?.Steps.Select(EmergencyStepRow.From).ToList() ?? [];

    private const string LastResort =
        "Если интернет не работает, запустите от имени администратора recover-network.cmd из папки программы (подпапка scripts) или перезагрузите компьютер.";

    private static string Advise(bool on, int code, EmergencyReport? report) => (on, code) switch
    {
        (false, EmergencyExitCodes.Success) =>
            "VPN отключён, защита снята, служба остановлена и сама не запустится — даже после перезагрузки. Чтобы снова пользоваться программой, нажмите «Включить программу».",
        (true, EmergencyExitCodes.Success) =>
            "VPN сам не подключается: нажмите «Подключить», когда он понадобится.",
        (false, EmergencyExitCodes.ServiceNotConfirmed) =>
            "Интернет уже работает без программы. Проверьте службу «Раздельный VPN» в «Службах» Windows: если она ещё работает, повторите экстренное выключение.",
        (true, EmergencyExitCodes.ServiceNotConfirmed) =>
            "Запустите службу кнопкой в меню слева или перезагрузите компьютер.",
        (false, EmergencyExitCodes.Incomplete) => NotRestored(report)
            + "Перезагрузите компьютер: служба теперь запускается только вручную, поэтому после перезагрузки Windows не применит оставшиеся фильтры программы.",
        (true, EmergencyExitCodes.Incomplete) =>
            "Программа по-прежнему выключена. Повторите «Включить программу».",
        (_, EmergencyExitCodes.NotElevated) =>
            "Повторите и подтвердите запрос Windows на права администратора.",
        (_, EmergencyExitCodes.Busy) =>
            "Уже выполняется другое экстренное выключение или включение. Дождитесь его окончания — это может занять несколько минут — и при необходимости повторите.",
        (true, _) => "Повторите «Включить программу». Если не помогает — перезагрузите компьютер и повторите.",
        _ => LastResort,
    };

    /// <summary>Что не вернулось: неудавшиеся обязательные шаги отчёта.</summary>
    private static string NotRestored(EmergencyReport? report)
    {
        var failed = report?.Steps.Where(s => !s.Succeeded && s.Required)
            .Select(s => string.IsNullOrWhiteSpace(s.Title) ? EmergencySteps.Title(s.Step) : s.Title).ToList() ?? [];
        return failed.Count == 0 ? "" : "Не возвращено: " + string.Join(", ", failed) + ". ";
    }

    /// <summary>Текст для окна сообщения (запуск с ‐‐emergency-off): итог, совет, неудавшиеся шаги, путь к отчёту.</summary>
    public string ToMessageText()
    {
        var text = new StringBuilder(Summary);
        if (Advice.Length > 0)
        {
            text.AppendLine().AppendLine().Append(Advice);
        }

        var problems = Steps.Where(s => s.IsProblem).ToList();
        if (problems.Count > 0)
        {
            text.AppendLine().AppendLine().Append("Не получилось:");
            foreach (var step in problems)
            {
                text.AppendLine().Append("• ").Append(step.Spoken).Append(step.IsWarning ? " — не влияет на итог" : "");
            }
        }

        if (ReportPath is not null)
        {
            text.AppendLine().AppendLine().Append("Отчёт: ").Append(ReportPath);
        }

        return text.ToString();
    }

    /// <summary>Отчёт для буфера обмена: всё, включая успешные шаги и код завершения.</summary>
    public string ToReportText()
    {
        var text = new StringBuilder().Append(Title).Append(": ").Append(Summary);
        if (Advice.Length > 0)
        {
            text.AppendLine().Append(Advice);
        }

        if (ExitCode is { } code)
        {
            text.AppendLine().Append(CultureInfo.InvariantCulture, $"Код завершения: {code}");
        }

        foreach (var step in Steps)
        {
            text.AppendLine().Append("• ").Append(step.Spoken);
        }

        if (ReportPath is not null)
        {
            text.AppendLine().Append("Отчёт: ").Append(ReportPath);
        }

        return text.ToString();
    }
}
