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
    /// <summary>«SplitVpn.Service.exe emergency-off»: выключить всё. Нужны права администратора.</summary>
    public const string Off = "emergency-off";

    /// <summary>«SplitVpn.Service.exe emergency-on»: снять отключение и запустить службу; защита не применяется до «Подключить».</summary>
    public const string On = "emergency-on";

    /// <summary>Прежнее имя: «recover» без ключей — то же, что <see cref="Off"/>.</summary>
    public const string RecoverAlias = "recover";
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

    /// <summary>Уже выполняется другая команда экстренного отключения или включения: ничего не делалось.</summary>
    public const int Busy = 5;

    /// <summary>Короткое описание кода для человека.</summary>
    public static string Describe(int code, bool on = false) => code switch
    {
        Success => on ? "Программа включена, служба запущена." : "Программа экстренно отключена: сеть возвращена, служба остановлена.",
        ServiceNotConfirmed => on ? "Программа включена, но запуск службы не подтверждён." : "Сеть возвращена, но остановка службы не подтверждена.",
        Incomplete => on ? "Программа не включена: флаг отключения не снят." : "Сеть возвращена не полностью.",
        NotElevated => "Нужны права администратора.",
        Busy => "Уже выполняется другое экстренное отключение или включение.",
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

    /// <summary>Флаг из реестра; null — программа не отключена (или ключ недоступен).</summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static EmergencyFlag? Read()
    {
        try
        {
            using var root = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64);
            using var key = root.OpenSubKey(KeyPath);
            return Parse(key?.GetValue(FlagValue), key?.GetValue(SinceValue));
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Разбор значений (для тестов): флаг — DWORD, не равный нулю.</summary>
    public static EmergencyFlag? Parse(object? flag, object? since) =>
        flag is int value && value != 0
            ? new EmergencyFlag(since is string text && DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var when) ? when : null)
            : null;
}

/// <summary>Программа экстренно отключена; <paramref name="SinceUtc"/> — когда (если известно).</summary>
public sealed record EmergencyFlag(DateTimeOffset? SinceUtc);

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

    /// <summary>Не уложился в свой срок; следующие шаги всё равно выполнены.</summary>
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

    public DateTimeOffset StartedUtc { get; init; }

    public DateTimeOffset FinishedUtc { get; init; }

    /// <summary>Код завершения (<see cref="EmergencyExitCodes"/>).</summary>
    public int ExitCode { get; init; }

    /// <summary>Итог одной фразой по-русски.</summary>
    public string Summary { get; init; } = "";

    /// <summary>Сетевые шаги (фильтры, соединения, маршруты, DNS, помощники) выполнены.</summary>
    public bool NetworkClean { get; init; }

    /// <summary>off: служба подтверждённо остановлена. on: служба подтверждённо работает.</summary>
    public bool ServiceConfirmed { get; init; }

    public IReadOnlyList<EmergencyStepReport> Steps { get; init; } = [];
}
