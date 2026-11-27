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
    /// <summary>
    /// Запускает процесс и ждёт его не дольше <paramref name="timeout"/>. Процесс по сроку не завершается: итог
    /// «не завершился в срок» несёт задачу, которая завершится его кодом, когда он всё-таки выйдет.
    /// </summary>
    Task<ElevatedProcessOutcome> RunAsync(ProcessStartInfo startInfo, TimeSpan timeout, CancellationToken cancellationToken);
}

/// <summary>
/// Итог запуска: код завершения, ошибка запуска Win32 (1223 — отказ в окне UAC) или «ещё выполняется» — тогда
/// <paramref name="StillRunning"/> завершится кодом процесса, когда он выйдет (процесс не завершается принудительно).
/// </summary>
public sealed record ElevatedProcessOutcome(int? ExitCode, int? StartError, Task<int>? StillRunning)
{
    public bool TimedOut => StillRunning is not null;

    public static ElevatedProcessOutcome Exited(int code) => new(code, null, null);

    public static ElevatedProcessOutcome NotStarted(int win32Error) => new(null, win32Error, null);

    public static ElevatedProcessOutcome Overdue(Task<int> stillRunning) => new(null, null, stillRunning);
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
            // ShellExecute с «runas» ждёт ответа в окне UAC: не в потоке интерфейса (окно не замирает).
            process = await Task.Run(() => Process.Start(startInfo), CancellationToken.None);
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

        // Отмена и срок ожидания не завершают команду: она должна дойти до конца, иначе сеть останется наполовину.
        if (await WindowsServiceHost.ExitsWithinAsync(token => process.WaitForExitAsync(token).WaitAsync(cancellationToken), timeout))
        {
            using (process)
            {
                return ElevatedProcessOutcome.Exited(process.ExitCode);
            }
        }

        // Не дождались: дескриптор процесса остаётся у нас, и итог придёт, когда команда действительно выйдет.
        return ElevatedProcessOutcome.Overdue(WaitExitAsync(process));
    }

    private static async Task<int> WaitExitAsync(Process process)
    {
        using (process)
        {
            await process.WaitForExitAsync(CancellationToken.None);
            return process.ExitCode;
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
/// «Экстренно выключить» и «Включить программу»: «SplitVpn.Service.exe emergency-off|emergency-on ‐‐report-id &lt;guid&gt;»
/// с правами администратора. Канал управления не используется вовсе: команда работает, когда служба зависла, остановлена
/// или канал занят чужим процессом. После завершения читается отчёт команды (<see cref="EmergencyReportFiles.LastPath"/>),
/// но только этого запуска: с той же меткой, той же командой и тем же кодом завершения.
/// </summary>
public sealed class EmergencyLauncher : IEmergencyLauncher
{
    /// <summary>Запас сверх худшего случая команды: запуск процесса, запись отчёта, медленный диск.</summary>
    internal static readonly TimeSpan WaitMargin = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Срок ожидания emergency-off: худший случай команды из договора (<see cref="EmergencyTimeouts.OffWorstCase"/> —
    /// он же общий срок команды в службе) и запас. Не дождались — команда ещё выполняется, и итог придёт позже.
    /// </summary>
    internal static readonly TimeSpan OffTimeout = EmergencyTimeouts.OffWorstCase + WaitMargin;

    /// <summary>Срок emergency-on: <see cref="EmergencyTimeouts.OnWorstCase"/> и запас.</summary>
    internal static readonly TimeSpan OnTimeout = EmergencyTimeouts.OnWorstCase + WaitMargin;

    /// <summary>ERROR_CANCELLED: пользователь отказался в окне UAC.</summary>
    public const int UacCancelled = 1223;

    /// <summary>Больше этого отчёт не читается: настоящий занимает единицы килобайт.</summary>
    internal const int MaxReportBytes = 1024 * 1024;

    /// <summary>Допуск на расхождение часов процессов при сверке времени отчёта.</summary>
    private static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(5);

    private readonly IElevatedProcessRunner _runner;
    private readonly Func<string?> _findExecutable;
    private readonly Func<string, string?> _readFile;
    private readonly string _reportPath;
    private readonly TimeProvider _time;
    private readonly Func<Guid> _newReportId;

    public EmergencyLauncher()
        : this(new ShellElevatedProcessRunner(), NetworkRecovery.FindServiceExecutable, ReadTrustedReport, EmergencyReportFiles.LastPath, TimeProvider.System)
    {
    }

    internal EmergencyLauncher(IElevatedProcessRunner runner, Func<string?> findExecutable, Func<string, string?> readFile, string reportPath,
        TimeProvider time, Func<Guid>? newReportId = null)
    {
        _runner = runner;
        _findExecutable = findExecutable;
        _readFile = readFile;
        _reportPath = reportPath;
        _time = time;
        _newReportId = newReportId ?? Guid.NewGuid;
    }

    /// <summary>
    /// Запуск команды: ShellExecute с «runas» (окно UAC), скрытое окно консоли, рабочий каталог — System32
    /// (повышенный процесс не ищет библиотеки в каталоге, откуда запущен интерфейс), метка запуска для отчёта.
    /// </summary>
    public static ProcessStartInfo BuildStartInfo(string executable, bool on, Guid reportId) => new(executable,
        (on ? EmergencyCommands.On : EmergencyCommands.Off) + " " + EmergencyCommands.ReportIdOption + " " + reportId.ToString("D"))
    {
        UseShellExecute = true,
        Verb = "runas",
        WindowStyle = ProcessWindowStyle.Hidden,
        WorkingDirectory = Environment.SystemDirectory,
    };

    public async Task<EmergencyRunResult> RunAsync(bool on, CancellationToken cancellationToken = default)
    {
        string? executable;
        try
        {
            // Проверка прав на каталоги до корня диска читает дескрипторы — не в потоке интерфейса.
            executable = await Task.Run(_findExecutable, CancellationToken.None);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Verbose.Write("Ui", "файл службы не найден: " + ex.GetType().Name + " «" + ex.Message + "»");
            executable = null;
        }

        if (executable is null)
        {
            return EmergencyRunResult.NotFound(on);
        }

        var reportId = _newReportId();
        var started = _time.GetUtcNow();
        var timeout = on ? OnTimeout : OffTimeout;
        Verbose.Write("Ui", (on ? "включение программы" : "экстренное выключение") + ": запуск «" + executable + "»");
        var outcome = await _runner.RunAsync(BuildStartInfo(executable, on, reportId), timeout, cancellationToken);
        if (outcome.StartError is { } error)
        {
            return error == UacCancelled ? EmergencyRunResult.Cancelled(on) : EmergencyRunResult.StartFailed(on, error);
        }

        if (outcome.StillRunning is { } stillRunning)
        {
            Verbose.Write("Ui", (on ? "включение программы" : "экстренное выключение") + ": не завершилось за отведённое время, ждём дальше");
            return EmergencyRunResult.Overdue(on, timeout, CompleteAsync(on, reportId, started, stillRunning));
        }

        return await FinishAsync(on, outcome.ExitCode ?? EmergencyExitCodes.Unexpected, reportId, started);
    }

    /// <summary>Итог команды, которая не уложилась в ожидание: когда процесс выйдет. Исключений не бросает.</summary>
    private async Task<EmergencyRunResult> CompleteAsync(bool on, Guid reportId, DateTimeOffset started, Task<int> stillRunning)
    {
        int code;
        try
        {
            code = await stillRunning.ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Verbose.Write("Ui", "окончание команды не дождались: " + ex.GetType().Name + " «" + ex.Message + "»");
            return EmergencyRunResult.FromExitCode(on, EmergencyExitCodes.Unexpected, null, null);
        }

        return await FinishAsync(on, code, reportId, started).ConfigureAwait(false);
    }

    private async Task<EmergencyRunResult> FinishAsync(bool on, int code, Guid reportId, DateTimeOffset started)
    {
        // Отчёт читается и проверяется (владелец каталога и файла, размер, разбор) не в потоке интерфейса.
        var report = await Task.Run(() => FreshReport(on, reportId, code, started), CancellationToken.None).ConfigureAwait(false);
        Verbose.Write("Ui", (on ? "включение программы" : "экстренное выключение") + ": код " + code.ToString(CultureInfo.InvariantCulture)
            + (report is null ? ", отчёта этого запуска нет" : ", отчёт прочитан"));
        return EmergencyRunResult.FromExitCode(on, code, report, report is null ? null : _reportPath);
    }

    /// <summary>
    /// Отчёт этого запуска; любой другой (прежний, другой команды, с другой меткой или кодом, подложенный, повреждённый) —
    /// null. Исключений не бросает: без отчёта итог строится по коду завершения.
    /// </summary>
    internal EmergencyReport? FreshReport(bool on, Guid reportId, int exitCode, DateTimeOffset launchedUtc)
    {
        try
        {
            var text = _readFile(_reportPath);
            var report = text is null ? null : EmergencyReportFiles.Parse(text);
            return IsThisRun(report, on, reportId, exitCode, launchedUtc, _time.GetUtcNow()) ? report : null;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Verbose.Write("Ui", "отчёт экстренного выключения не прочитан: " + ex.GetType().Name + " «" + ex.Message + "»");
            return null;
        }
    }

    /// <summary>
    /// Отчёт — этого запуска: та же метка, та же команда, тот же код завершения, начат не раньше запуска и не позже
    /// «сейчас» (с допуском на часы), закончен не раньше начала, и список шагов цел (нет null).
    /// </summary>
    internal static bool IsThisRun(EmergencyReport? report, bool on, Guid reportId, int exitCode, DateTimeOffset launchedUtc, DateTimeOffset nowUtc) =>
        report is not null
        && report.ReportId == reportId
        && string.Equals(report.Command, on ? EmergencyCommands.On : EmergencyCommands.Off, StringComparison.Ordinal)
        && report.ExitCode == exitCode
        && report.Steps is { } steps && steps.All(s => s is not null && s.Step is not null)
        && report.Summary is not null
        && report.StartedUtc >= launchedUtc - ClockSkew
        && report.StartedUtc <= nowUtc + ClockSkew
        && report.FinishedUtc >= report.StartedUtc;

    /// <summary>
    /// Текст отчёта, если ему можно верить: каталог отчётов и сам файл — не ссылки и принадлежат SYSTEM или
    /// Administrators (записать их могла только команда с правами администратора), файл не больше
    /// <see cref="MaxReportBytes"/>. Иначе null.
    /// </summary>
    internal static string? ReadTrustedReport(string path) => ReadTrustedReport(path, AdminOnlyAccess.OwnedByAdminsProblem);

    /// <summary>Шов для тестов: <paramref name="trust"/> — почему объекту нельзя верить (null — можно).</summary>
    internal static string? ReadTrustedReport(string path, Func<FileSystemInfo, string?> trust)
    {
        ArgumentNullException.ThrowIfNull(trust);
        if (!File.Exists(path) || Path.GetDirectoryName(path) is not { } directory)
        {
            return null;
        }

        if ((trust(new DirectoryInfo(directory)) ?? trust(new FileInfo(path))) is { } problem)
        {
            Verbose.Write("Ui", "отчёт экстренного выключения не прочитан: " + problem);
            return null;
        }

        // Команда пишет отчёт до своего завершения; чтение не мешает следующей команде его заменить.
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var buffer = new byte[MaxReportBytes + 1];
        var total = 0;
        int read;
        while (total < buffer.Length && (read = stream.Read(buffer, total, buffer.Length - total)) > 0)
        {
            total += read;
        }

        if (total > MaxReportBytes)
        {
            Verbose.Write("Ui", "отчёт экстренного выключения не прочитан: больше 1 МБ");
            return null;
        }

        return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: false).GetString(buffer, 0, total).TrimStart('﻿');
    }
}

/// <summary>Чем закончился запуск.</summary>
public enum EmergencyRunKind
{
    /// <summary>Код 0.</summary>
    Succeeded,

    /// <summary>Отказ в окне UAC: ничего не делалось.</summary>
    Cancelled,

    /// <summary>Уже выполняется другая экстренная команда этой программы (код 5): включение ничего не делало.</summary>
    Busy,

    /// <summary>Сделано не всё (коды 1-4), команда не запустилась или файл службы не найден.</summary>
    Failed,

    /// <summary>Команда не завершилась за отведённое время и ещё выполняется: итог придёт в <see cref="EmergencyRunResult.Completion"/>.</summary>
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

    /// <summary>Код завершения команды; null — команда не запускалась или ещё не завершилась.</summary>
    public int? ExitCode { get; init; }

    public string Title { get; init; } = "";

    public string Summary { get; init; } = "";

    /// <summary>Что делать дальше; пусто — ничего.</summary>
    public string Advice { get; init; } = "";

    public IReadOnlyList<EmergencyStepRow> Steps { get; init; } = [];

    /// <summary>Файл отчёта этого запуска; null — отчёта нет.</summary>
    public string? ReportPath { get; init; }

    /// <summary>
    /// Только у <see cref="EmergencyRunKind.Overdue"/>: окончательный итог, когда команда действительно завершится.
    /// Задача не завершается исключением; команда при этом не прерывается.
    /// </summary>
    public Task<EmergencyRunResult>? Completion { get; init; }

    public bool IsError => Kind is not (EmergencyRunKind.Succeeded or EmergencyRunKind.Cancelled or EmergencyRunKind.Overdue);

    public bool HasSteps => Steps.Count > 0;

    public bool HasAdvice => Advice.Length > 0;

    /// <summary>Сделано не всё, и последнее средство может помочь: команда не запустилась, код 1 или 3 и выше (кроме 5).</summary>
    public bool OffersLastResort => !On && Kind == EmergencyRunKind.Failed
        && ExitCode is null or EmergencyExitCodes.Unexpected or >= EmergencyExitCodes.Incomplete and not EmergencyExitCodes.Busy;

    /// <summary>Значок итога: успех, «подождите» (занято, ещё выполняется) или «сделано не всё».</summary>
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

    /// <summary>Есть неудавшиеся шаги или предупреждения.</summary>
    public bool HasProblems => Steps.Any(s => s.IsProblem);

    public string StepsHeader => $"Шаги ({Steps.Count})";

    /// <summary>Код завершения процесса SplitVpn.exe ‐‐emergency-off: код команды, 1223 — отказ в окне UAC, 1 — не запустилась.</summary>
    public int ProcessExitCode => ExitCode ?? (Kind == EmergencyRunKind.Cancelled ? EmergencyLauncher.UacCancelled : EmergencyExitCodes.Unexpected);

    private static string TitleFor(bool on) => on ? "Включение программы" : "Экстренное выключение";

    private const string LastResort =
        "Если интернет не работает, запустите от имени администратора recover-network.cmd из папки программы (подпапка scripts) или перезагрузите компьютер.";

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
        Summary = "Файл службы «Раздельного VPN» не найден в папке установки или лежит там, куда может писать обычный пользователь: "
            + "запускать его с правами администратора небезопасно.",
        Advice = on
            ? "Переустановите программу."
            : "Если интернет не работает, запустите от имени администратора recover-network.cmd из папки программы (подпапка scripts) или переустановите программу.",
    };

    public static EmergencyRunResult StartFailed(bool on, int win32Error) => new()
    {
        On = on,
        Kind = EmergencyRunKind.Failed,
        Title = TitleFor(on),
        Summary = string.Create(CultureInfo.InvariantCulture, $"Windows не запустила команду с правами администратора (код {win32Error})."),
        Advice = on ? "Повторите «Включить программу». Если не помогает — перезагрузите компьютер и повторите." : LastResort,
    };

    /// <summary>Команда идёт дольше отведённого: итог ещё будет (<paramref name="completion"/>), команда не прерывается.</summary>
    public static EmergencyRunResult Overdue(bool on, TimeSpan waited, Task<EmergencyRunResult> completion) => new()
    {
        On = on,
        Kind = EmergencyRunKind.Overdue,
        Title = TitleFor(on),
        Summary = string.Create(CultureInfo.InvariantCulture, $"Команда ещё выполняется: она идёт дольше {waited.TotalMinutes:0} мин."),
        Advice = "Дождитесь её окончания — итог появится сам. Не запускайте команду повторно и не перезагружайте компьютер, пока она идёт.",
        Completion = completion,
    };

    public static EmergencyRunResult FromExitCode(bool on, int code, EmergencyReport? report, string? reportPath)
    {
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
            Advice = string.Join(" ", new[] { Advise(on, code, report), StaticAddressNotes(report) }.Where(s => s.Length > 0)),
            Steps = Rows(report),
            ReportPath = reportPath,
        };
    }

    /// <summary>
    /// Шаги отчёта: сначала не выполненные (сбой, срок), затем предупреждения, затем выполненные, внутри — в порядке
    /// выполнения. Список стоит в шапке окна, ограниченной по высоте, и то, что не получилось, должно быть видно первым.
    /// </summary>
    private static List<EmergencyStepRow> Rows(EmergencyReport? report) =>
        report?.Steps?.Where(s => s is not null).Select(EmergencyStepRow.From)
            .OrderBy(row => row.Severity switch { EmergencyStepSeverity.Error => 0, EmergencyStepSeverity.Warning => 1, _ => 2 })
            .ToList() ?? [];

    /// <summary>Совет по коду и отчёту. Список неудавшихся шагов уже есть в итоге команды и здесь не повторяется.</summary>
    private static string Advise(bool on, int code, EmergencyReport? report) => (on, code) switch
    {
        (false, EmergencyExitCodes.Success) =>
            "VPN отключён, защита снята, служба остановлена и сама не запустится — даже после перезагрузки. Чтобы снова пользоваться программой, нажмите «Включить программу».",
        (true, EmergencyExitCodes.Success) =>
            "VPN сам не подключается: нажмите «Подключить», когда он понадобится.",
        (false, EmergencyExitCodes.ServiceNotConfirmed) =>
            "Интернет уже работает без программы, и служба сейчас не работает, но не подтверждено, что она не запустится снова "
            + "(отметка отключения, ручной запуск или остановка службы). После перезагрузки программа может снова включиться — повторите экстренное выключение.",
        (true, EmergencyExitCodes.ServiceNotConfirmed) =>
            "Запустите службу кнопкой в меню слева или перезагрузите компьютер.",
        (false, EmergencyExitCodes.Incomplete) => IncompleteAdvice(report),
        (true, EmergencyExitCodes.Incomplete) =>
            "Программа по-прежнему выключена. Повторите «Включить программу».",
        (_, EmergencyExitCodes.NotElevated) =>
            "Нужна учётная запись администратора: повторите и в окне Windows подтвердите действие от имени администратора (или попросите администратора компьютера).",
        (true, EmergencyExitCodes.Busy) =>
            "Сейчас выполняется другая экстренная команда этой программы (с ярлыка, из скрипта или из второго окна). Дождитесь её окончания — это может занять несколько минут — и повторите «Включить программу».",
        (false, EmergencyExitCodes.Busy) =>
            "Сейчас выполняется другая экстренная команда этой программы. Дождитесь её окончания и при необходимости повторите.",
        (true, _) => "Повторите «Включить программу». Если не помогает — перезагрузите компьютер и повторите.",
        _ => LastResort,
    };

    /// <summary>
    /// Код 3: сеть возвращена не полностью. Совет перезагрузиться опирается на ручной запуск службы — только если отметка
    /// отключения и ручной запуск подтверждены отчётом; служба всё ещё работает — об этом прямо.
    /// </summary>
    private static string IncompleteAdvice(EmergencyReport? report)
    {
        var steps = report?.Steps?.Where(s => s is not null).ToList() ?? [];
        var stillRunning = steps.Any(s => s.Step == EmergencySteps.ServiceRecheck && !s.Succeeded
            && s.Detail?.StartsWith("служба всё ещё работает", StringComparison.Ordinal) == true);
        var manualConfirmed = steps.Any(s => s.Step == EmergencySteps.Flag && s.Succeeded)
            && steps.Any(s => s.Step == EmergencySteps.StartType && s.Succeeded);
        var text = new StringBuilder();
        if (stillRunning)
        {
            text.Append("Служба программы всё ещё работает и может снова применить фильтры, маршруты и DNS. ");
        }

        if (manualConfirmed)
        {
            text.Append("Перезагрузите компьютер: служба теперь запускается только вручную, поэтому после перезагрузки Windows не применит оставшиеся фильтры программы. ");
        }
        else if (report is null)
        {
            text.Append("Перезагрузите компьютер. ");
        }
        else
        {
            text.Append("Отметка отключения или ручной запуск службы не подтверждены: после перезагрузки программа может снова включиться. Повторите экстренное выключение. ");
        }

        return text.Append("Если интернет так и не заработает, запустите от имени администратора recover-network.cmd из папки программы (подпапка scripts).").ToString();
    }

    /// <summary>
    /// Адаптеры со статическим адресом, чей DNS программы оставлен как есть (без DHCP «автоматически» оставило бы их без
    /// DNS): человеку нужно указать DNS вручную. Берётся из подробностей шагов DNS отчёта.
    /// </summary>
    private static string StaticAddressNotes(EmergencyReport? report)
    {
        var notes = report?.Steps?
            .Where(s => s is { Step: EmergencySteps.Dns or EmergencySteps.DnsAgain, Detail: not null })
            .SelectMany(s => s.Detail!.Split("; ", StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Where(part => part.Contains(EmergencyNotes.StaticAddress, StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .ToList() ?? [];
        return notes.Count == 0 ? "" : "Обратите внимание: " + string.Join("; ", notes) + ".";
    }

    /// <summary>Текст для окна сообщения (запуск с ‐‐emergency-off): итог, совет, подробности неудавшихся шагов, путь к отчёту.</summary>
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
            text.AppendLine().AppendLine().Append("Подробности:");
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
