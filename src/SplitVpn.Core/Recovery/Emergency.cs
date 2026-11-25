using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Recovery;

/// <summary>
/// Экстренное отключение программы («аварийная кнопка»): всё, что программа меняла в Windows, возвращается к обычному
/// поведению, служба останавливается и сама больше не запускается, пока программу не включат снова. Здесь — договор
/// между командой службы (SplitVpn.Service.exe), приложением и скриптами: команды, коды завершения, значения реестра,
/// путь и вид отчёта.
/// </summary>
public static class EmergencyCommands
{
    /// <summary>
    /// «SplitVpn.Service.exe emergency-off [‐‐report-id &lt;guid&gt;]»: выключить всё. Нужны права администратора. Ключ
    /// <see cref="ReportIdOption"/> — метка запуска: она повторяется в отчёте (<see cref="EmergencyReport.ReportId"/>), и
    /// запустивший команду отличает свой отчёт от прежнего или подложенного.
    /// </summary>
    public const string Off = "emergency-off";

    /// <summary>«SplitVpn.Service.exe emergency-on»: снять отключение и запустить службу; защита не применяется до «Подключить».</summary>
    public const string On = "emergency-on";

    /// <summary>Прежнее имя: «recover» без ключей — то же, что <see cref="Off"/>.</summary>
    public const string RecoverAlias = "recover";

    /// <summary>Ключ метки запуска (только для <see cref="Off"/> и <see cref="On"/>): за ним — GUID.</summary>
    public const string ReportIdOption = "--report-id";

    /// <summary>
    /// Метка запуска из аргументов: значение сразу за <see cref="ReportIdOption"/>, строго GUID в виде «D» (36 знаков с
    /// дефисами, без скобок), не нулевой. Нет ключа, нет значения или оно не такое — null (ключ тогда не учитывается).
    /// </summary>
    public static Guid? ParseReportId(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        for (var i = 0; i < args.Count - 1; i++)
        {
            if (string.Equals(args[i], ReportIdOption, StringComparison.OrdinalIgnoreCase))
            {
                return Guid.TryParseExact(args[i + 1], "D", out var id) && id != Guid.Empty ? id : null;
            }
        }

        return null;
    }
}

/// <summary>Коды завершения команд <see cref="EmergencyCommands"/>.</summary>
public static class EmergencyExitCodes
{
    /// <summary>off: сеть возвращена, служба остановлена и в ручном запуске. on: программа включена, служба работает.</summary>
    public const int Success = 0;

    /// <summary>Неожиданная ошибка самой команды (или истёк общий срок).</summary>
    public const int Unexpected = 1;

    /// <summary>off: сеть возвращена, но остановка службы (или её ручной запуск, флаг) не подтверждены. on: программа включена, но запуск службы не подтверждён.</summary>
    public const int ServiceNotConfirmed = 2;

    /// <summary>off: сеть возвращена не полностью (фильтры, соединения, маршруты, DNS или помощники). on: флаг отключения не снят.</summary>
    public const int Incomplete = 3;

    /// <summary>Команда запущена без прав администратора: ничего не делалось.</summary>
    public const int NotElevated = 4;

    /// <summary>
    /// on: уже выполняется другая команда восстановления этой программы (emergency-off, emergency-on или recover из того же
    /// SplitVpn.Service.exe) — включение ничего не делало, его нужно повторить после её окончания. Другая команда
    /// определяется по живым процессам (файл и командная строка), а не по мьютексу: мьютекс в Global\ может заранее занять
    /// и обычный пользователь. off этот код не возвращает: экстренное отключение выполняется и рядом с другой командой
    /// (шаги идемпотентны), а блокировка, занятая дольше срока, только упоминается в итоге.
    /// </summary>
    public const int Busy = 5;

    /// <summary>Короткое описание кода для человека.</summary>
    public static string Describe(int code, bool on = false) => code switch
    {
        Success => on ? "Программа включена, служба запущена." : "Программа экстренно отключена: сеть возвращена, служба остановлена.",
        ServiceNotConfirmed => on ? "Программа включена, но запуск службы не подтверждён." : "Сеть возвращена, но остановка службы не подтверждена.",
        Incomplete => on ? "Программа не включена: флаг отключения не снят." : "Сеть возвращена не полностью.",
        NotElevated => "Нужны права администратора.",
        Busy => on
            ? "Программа не включена: уже выполняется другая экстренная команда этой программы."
            : "Уже выполняется другая экстренная команда этой программы.",
        _ => "Непредвиденная ошибка.",
    };
}

/// <summary>Значения в разделе HKLM\Software\SplitVpn (64-битное представление реестра).</summary>
public static class EmergencyRegistry
{
    /// <summary>Раздел программы (тот же, что у имени канала управления).</summary>
    public const string KeyPath = Ipc.IpcNames.RegistryKey;

    /// <summary>DWORD: 1 — программа экстренно отключена. Пишет только команда emergency-off, снимает только emergency-on.</summary>
    public const string FlagValue = "EmergencyOff";

    /// <summary>Строка: когда отключили (UTC, формат «O»).</summary>
    public const string SinceValue = "EmergencyOffUtc";

    /// <summary>
    /// Строка: тип запуска службы до отключения — <see cref="StartAuto"/>, <see cref="StartDelayedAuto"/>,
    /// <see cref="StartDemand"/> или <see cref="StartDisabled"/>. Нет значения — при включении ставится автозапуск.
    /// </summary>
    public const string PreviousStartValue = "EmergencyOffPreviousStart";

    public const string StartAuto = "auto";
    public const string StartDelayedAuto = "delayed-auto";
    public const string StartDemand = "demand";
    public const string StartDisabled = "disabled";

    /// <summary>
    /// Строка: действия диспетчера служб при сбое службы, снятые командой на время остановки (формат —
    /// <c>v1;reset=&lt;с&gt;;actions=&lt;тип&gt;:&lt;мс&gt;,…</c>). Пишется до снятия, удаляется после возврата. Осталась от
    /// прерванной команды — действия возвращает следующая команда или запуск службы.
    /// </summary>
    public const string SavedFailureActionsValue = "EmergencySavedFailureActions";

    /// <summary>Сколько раз читать флаг при сбое чтения.</summary>
    private const int ReadAttempts = 3;

    /// <summary>
    /// Флаг из реестра; null — программа не отключена (нет ключа или значения). Сбой чтения повторяется; не прошёл и
    /// повтор — ключ есть, но не читается, и это не «не отключена»: ответ — флаг с <see cref="EmergencyFlag.Unreadable"/>,
    /// служба запускается «пустой» (лучше без VPN, чем включить отключённую программу).
    /// </summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static EmergencyFlag? Read() => Read(() =>
    {
        using var root = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64);
        using var key = root.OpenSubKey(KeyPath);
        return key is null ? (null, null, false) : (key.GetValue(FlagValue), key.GetValue(SinceValue), true);
    }, TimeSpan.FromMilliseconds(200));

    /// <summary>Шов для тестов: <paramref name="read"/> — значения флага и есть ли ключ (исключение — сбой чтения).</summary>
    public static EmergencyFlag? Read(Func<(object? Flag, object? Since, bool KeyExists)> read, TimeSpan retryDelay)
    {
        ArgumentNullException.ThrowIfNull(read);
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                var (flag, since, _) = read();
                return Parse(flag, since);
            }
            catch (Exception ex) when (ex is System.Security.SecurityException or IOException or UnauthorizedAccessException)
            {
                if (attempt >= ReadAttempts)
                {
                    // Отсутствующий ключ OpenSubKey отдаёт как null, без исключения: исключение — ключ есть, но не читается.
                    return new EmergencyFlag(null, Unreadable: true);
                }

                Thread.Sleep(retryDelay);
            }
        }
    }

    /// <summary>Разбор значений (для тестов): флаг — DWORD, не равный нулю.</summary>
    public static EmergencyFlag? Parse(object? flag, object? since) =>
        flag is int value && value != 0
            ? new EmergencyFlag(since is string text && DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var when) ? when : null)
            : null;
}

/// <summary>
/// Сроки команд — единственный источник: из них заданы сроки шагов и общий срок команды в службе (EmergencyOptions), и из
/// них же приложение выводит своё ожидание (<see cref="OffWorstCase"/>, <see cref="OnWorstCase"/> плюс запас).
/// </summary>
public static class EmergencyTimeouts
{
    /// <summary>Сколько ждать занятую блокировку команд.</summary>
    public static readonly TimeSpan LockWait = TimeSpan.FromSeconds(15);

    /// <summary>Проверка, не выполняется ли другая команда этой программы (перечисление процессов).</summary>
    public static readonly TimeSpan OtherCommandCheck = TimeSpan.FromSeconds(15);

    /// <summary>
    /// Сколько ждать штатной остановки службы до принудительного завершения: срок остановки хоста службы (28 с) и 2 с на
    /// выход процесса (в службе — ServiceRecovery.StopWaitBeforeKill; тест сверяет их).
    /// </summary>
    public static readonly TimeSpan StopWaitBeforeKill = TimeSpan.FromSeconds(30);

    /// <summary>Сколько ждать выхода завершаемого процесса.</summary>
    public static readonly TimeSpan KillWait = TimeSpan.FromSeconds(10);

    /// <summary>Срок одного вызова диспетчера служб.</summary>
    public static readonly TimeSpan ScmCallTimeout = TimeSpan.FromSeconds(15);

    /// <summary>Сколько ждать запуска службы.</summary>
    public static readonly TimeSpan StartWait = TimeSpan.FromSeconds(45);

    /// <summary>
    /// Перед выходом процесса шагам, не уложившимся в свой срок и ещё работающим в фоне, даётся столько, чтобы начатая
    /// запись (копия DNS, состояние) не оборвалась на середине. Дольше процесс их не ждёт.
    /// </summary>
    public static readonly TimeSpan AbandonedStepGrace = TimeSpan.FromSeconds(10);

    /// <summary>Срок шага, не названного в <see cref="Step"/>.</summary>
    public static readonly TimeSpan DefaultStep = TimeSpan.FromSeconds(30);

    /// <summary>Срок шага.</summary>
    public static TimeSpan Step(string step) => step switch
    {
        EmergencySteps.Service => StopWaitBeforeKill + (3 * (KillWait + ScmCallTimeout)) + TimeSpan.FromSeconds(30),
        EmergencySteps.StartService => StartWait + ScmCallTimeout + TimeSpan.FromSeconds(10),
        EmergencySteps.Wfp or EmergencySteps.WfpAgain => TimeSpan.FromMinutes(2),
        EmergencySteps.Dns or EmergencySteps.DnsAgain => TimeSpan.FromSeconds(90),
        EmergencySteps.Routes or EmergencySteps.RoutesAgain => TimeSpan.FromSeconds(60),
        EmergencySteps.Ras => TimeSpan.FromSeconds(45),
        EmergencySteps.Flag or EmergencySteps.ClearFlag or EmergencySteps.Wcm => TimeSpan.FromSeconds(15),
        EmergencySteps.FlushDns => TimeSpan.FromSeconds(20),
        // Только подсчёт и завершение процессов службы: повторные снятия — отдельные шаги со своими сроками.
        EmergencySteps.ServiceRecheck => (2 * (KillWait + ScmCallTimeout)) + TimeSpan.FromSeconds(10),
        _ => DefaultStep,
    };

    /// <summary>
    /// Все шаги, которые может выполнить emergency-off, — каждый не больше одного раза (повторные снятия — только когда
    /// нужны, возврат автоперезапуска — в одном из двух мест).
    /// </summary>
    public static IReadOnlyList<string> OffSteps { get; } =
    [
        EmergencySteps.Flag, EmergencySteps.StartType, EmergencySteps.FailureActions, EmergencySteps.Service, EmergencySteps.RestoreFailureActions,
        EmergencySteps.Helpers, EmergencySteps.Wfp, EmergencySteps.Ras, EmergencySteps.Routes, EmergencySteps.Dns, EmergencySteps.Wcm,
        EmergencySteps.ServiceRecheck, EmergencySteps.WfpAgain, EmergencySteps.RoutesAgain, EmergencySteps.DnsAgain,
        EmergencySteps.SuspendState, EmergencySteps.FlushDns,
    ];

    /// <summary>Все шаги emergency-on.</summary>
    public static IReadOnlyList<string> OnSteps { get; } =
    [
        EmergencySteps.FailureActions, EmergencySteps.Service, EmergencySteps.RestoreFailureActions, EmergencySteps.SuspendState,
        EmergencySteps.ClearFlag, EmergencySteps.RestoreStartType, EmergencySteps.StartService,
    ];

    /// <summary>
    /// Худший случай emergency-off: ожидание блокировки, проверка другой команды, сумма сроков всех шагов и запас шагам, не
    /// уложившимся в срок. Это же — общий срок команды в службе: дольше она не работает. Сейчас — 17 мин.
    /// </summary>
    public static TimeSpan OffWorstCase { get; } = WorstCase(OffSteps);

    /// <summary>Худший случай emergency-on (так же, как <see cref="OffWorstCase"/>). Сейчас — 6 мин 20 с.</summary>
    public static TimeSpan OnWorstCase { get; } = WorstCase(OnSteps);

    private static TimeSpan WorstCase(IEnumerable<string> steps) =>
        steps.Aggregate(LockWait + OtherCommandCheck + AbandonedStepGrace, (total, step) => total + Step(step));
}

/// <summary>Общие для службы и приложения фрагменты подробностей шагов.</summary>
public static class EmergencyNotes
{
    /// <summary>
    /// В подробностях шага DNS: адаптер со статическим IPv4-адресом оставлен как есть (без DHCP «автоматически» оставило
    /// бы его без DNS) — DNS нужно указать вручную. Приложение показывает такие пояснения отдельно.
    /// </summary>
    public const string StaticAddress = "со статическим адресом";
}

/// <summary>Программа экстренно отключена; <paramref name="SinceUtc"/> — когда (если известно).</summary>
/// <param name="Unreadable">Флаг не прочитан и после повторов, хотя ключ есть: служба на всякий случай «пустая».</param>
public sealed record EmergencyFlag(DateTimeOffset? SinceUtc, bool Unreadable = false);

/// <summary>Взаимное исключение команд: две одновременно не выполняются.</summary>
public static class EmergencyMutex
{
    public const string Name = @"Global\SplitVpn.Recovery";
}

/// <summary>
/// Отчёты команд: новый файл <c>%ProgramData%\SplitVpn.Recovery\emergency-&lt;время UTC&gt;-&lt;guid&gt;.json</c> на каждый
/// запуск и копия последнего — <c>last.json</c>. Каталог: SYSTEM и Administrators — полный доступ, Users — чтение.
/// </summary>
public static class EmergencyReportFiles
{
    public const string DirectoryName = "SplitVpn.Recovery";
    public const string LastFileName = "last.json";

    public static string DefaultDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), DirectoryName);

    public static string LastPath => Path.Combine(DefaultDirectory, LastFileName);

    /// <summary>Отчёт из текста; null — текст не отчёт.</summary>
    public static EmergencyReport? Parse(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<EmergencyReport>(json, JsonDefaults.Options);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

/// <summary>Итог шага.</summary>
public enum EmergencyStepOutcome
{
    /// <summary>Сделано сейчас.</summary>
    [JsonStringEnumMemberName("done")]
    Done,

    /// <summary>Уже было в нужном состоянии.</summary>
    [JsonStringEnumMemberName("already")]
    Already,

    /// <summary>Не нужен или неприменим (например, службы нет).</summary>
    [JsonStringEnumMemberName("skipped")]
    Skipped,

    [JsonStringEnumMemberName("failed")]
    Failed,

    /// <summary>
    /// Не уложился в свой срок (следующие шаги всё равно выполнены) или не запущен, потому что истёк общий срок команды
    /// (подробности — «не запущен: истёк общий срок команды»).
    /// </summary>
    [JsonStringEnumMemberName("timeout")]
    Timeout,
}

/// <summary>Шаги команд в порядке выполнения и их названия для человека.</summary>
public static class EmergencySteps
{
    public const string Flag = "flag";
    public const string StartType = "start-type";
    public const string FailureActions = "failure-actions";
    public const string Service = "service";
    public const string Helpers = "helpers";
    public const string SuspendState = "suspend-state";
    public const string Wfp = "wfp";
    public const string Ras = "ras";
    public const string Routes = "routes";
    public const string Dns = "dns";
    public const string Wcm = "wcm";

    /// <summary>
    /// После сетевых шагов: процессы службы ещё живы (остановка не удалась) — завершаются, и фильтры, маршруты и DNS
    /// снимаются ещё раз отдельными шагами (<see cref="WfpAgain"/>, <see cref="RoutesAgain"/>, <see cref="DnsAgain"/>).
    /// Остались процессы — сеть не считается возвращённой (код 3): живая служба вернёт своё.
    /// </summary>
    public const string ServiceRecheck = "service-recheck";

    /// <summary>Фильтры снимаются повторно: процессы службы были живы после сетевых шагов.</summary>
    public const string WfpAgain = "wfp-again";

    /// <summary>Маршруты снимаются повторно: процессы службы были живы после сетевых шагов.</summary>
    public const string RoutesAgain = "routes-again";

    /// <summary>
    /// DNS возвращается повторно: процессы службы были живы, или шаг DNS шёл по правилам работающей службы, а процессов
    /// службы уже нет (тогда — по правилам остановленной: иначе на адаптерах остался бы loopback без посредника).
    /// </summary>
    public const string DnsAgain = "dns-again";

    public const string FlushDns = "flush-dns";
    public const string RestoreFailureActions = "restore-failure-actions";

    // Шаги emergency-on.
    public const string ClearFlag = "clear-flag";
    public const string RestoreStartType = "restore-start-type";
    public const string StartService = "start-service";

    private static readonly Dictionary<string, string> Titles = new(StringComparer.Ordinal)
    {
        [Flag] = "Отметка отключения",
        [StartType] = "Ручной запуск службы",
        [FailureActions] = "Автоперезапуск службы приостановлен",
        [Service] = "Остановка службы",
        [Helpers] = "Помощники VPN (AnyConnect, SSH)",
        [SuspendState] = "Защита приостановлена",
        [Wfp] = "Фильтры защиты (WFP)",
        [Ras] = "VPN-соединения Windows",
        [Routes] = "Маршруты программы",
        [Dns] = "DNS адаптеров",
        [Wcm] = "Настройка Wi-Fi Windows",
        [ServiceRecheck] = "Повторная проверка службы",
        [WfpAgain] = "Фильтры защиты — повторно",
        [RoutesAgain] = "Маршруты программы — повторно",
        [DnsAgain] = "DNS адаптеров — повторно",
        [FlushDns] = "Кеш DNS",
        [RestoreFailureActions] = "Автоперезапуск службы возвращён",
        [ClearFlag] = "Отметка отключения снята",
        [RestoreStartType] = "Тип запуска службы",
        [StartService] = "Запуск службы",
    };

    /// <summary>Короткое название шага по-русски; неизвестный — сам идентификатор.</summary>
    public static string Title(string step) => Titles.GetValueOrDefault(step, step);
}

/// <summary>Один шаг отчёта.</summary>
/// <param name="Step">Идентификатор (<see cref="EmergencySteps"/>).</param>
/// <param name="Title">Название по-русски.</param>
/// <param name="Outcome">Итог.</param>
/// <param name="Detail">Подробности: что сделано или почему не получилось.</param>
/// <param name="Ms">Длительность в миллисекундах.</param>
/// <param name="Required">Сбой шага влияет на код завершения; иначе это предупреждение (кеш DNS, возврат автоперезапуска).</param>
public sealed record EmergencyStepReport(string Step, string Title, EmergencyStepOutcome Outcome, string? Detail, long Ms, bool Required = true)
{
    [JsonIgnore]
    public bool Succeeded => Outcome is EmergencyStepOutcome.Done or EmergencyStepOutcome.Already or EmergencyStepOutcome.Skipped;
}

/// <summary>Отчёт команды (JSON, UTF-8, camelCase).</summary>
public sealed record EmergencyReport
{
    public int Version { get; init; } = 1;

    /// <summary><see cref="EmergencyCommands.Off"/>, <see cref="EmergencyCommands.On"/> или «uninstall-network».</summary>
    public string Command { get; init; } = "";

    /// <summary>Метка запуска из <see cref="EmergencyCommands.ReportIdOption"/>; null — команду запустили без неё.</summary>
    public Guid? ReportId { get; init; }

    public DateTimeOffset StartedUtc { get; init; }

    public DateTimeOffset FinishedUtc { get; init; }

    /// <summary>Код завершения (<see cref="EmergencyExitCodes"/>).</summary>
    public int ExitCode { get; init; }

    /// <summary>Итог одной фразой по-русски.</summary>
    public string Summary { get; init; } = "";

    /// <summary>
    /// Каждый сетевой шаг (помощники, фильтры, соединения, маршруты, DNS, настройка Wi-Fi, повторная проверка службы) есть
    /// в отчёте и выполнен; шаг, не запущенный из-за общего срока, — не выполнен.
    /// </summary>
    public bool NetworkClean { get; init; }

    /// <summary>off: служба подтверждённо остановлена. on: служба подтверждённо работает.</summary>
    public bool ServiceConfirmed { get; init; }

    public IReadOnlyList<EmergencyStepReport> Steps { get; init; } = [];
}
