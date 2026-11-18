namespace SplitVpn.Core.State;

/// <summary>Состояние службы Windows «SplitVpn» по данным диспетчера служб.</summary>
public enum ServiceHostState
{
    /// <summary>Диспетчер служб не ответил или отказал в чтении.</summary>
    Unknown,
    NotInstalled,
    Stopped,
    StartPending,
    StopPending,
    Running,
}

/// <summary>Действие со службой из интерфейса; выполняется отдельным процессом с правами администратора.</summary>
public enum ServiceHostAction
{
    Start,
    Stop,
    Restart,
}

/// <summary>Тон индикатора службы: интерфейс подбирает по нему цвет темы.</summary>
public enum ServiceHostTone
{
    Neutral,
    Progress,
    Good,
    Warning,
    Bad,
}

/// <summary>
/// Что показать в блоке «Служба» и какие кнопки доступны. Во время действия все кнопки заблокированы:
/// второй запрос прав администратора поверх первого только запутает.
/// </summary>
/// <param name="Text">Короткое состояние: «Работает», «Остановлена», «Не отвечает»…</param>
public sealed record ServiceHostView(string Text, ServiceHostTone Tone, bool CanStart, bool CanStop, bool CanRestart)
{
    /// <param name="state">Состояние по диспетчеру служб.</param>
    /// <param name="notResponding">Служба запущена, но не отвечает на запросы (признак опроса главного окна).</param>
    /// <param name="pending">Действие, которое выполняется сейчас; null — действий нет.</param>
    public static ServiceHostView From(ServiceHostState state, bool notResponding, ServiceHostAction? pending) => pending switch
    {
        ServiceHostAction.Start => new("Запускается…", ServiceHostTone.Progress, false, false, false),
        ServiceHostAction.Stop => new("Останавливается…", ServiceHostTone.Progress, false, false, false),
        ServiceHostAction.Restart => new("Перезапускается…", ServiceHostTone.Progress, false, false, false),
        _ => state switch
        {
            ServiceHostState.Running when notResponding => new("Не отвечает", ServiceHostTone.Warning, false, true, true),
            ServiceHostState.Running => new("Работает", ServiceHostTone.Good, false, true, true),
            ServiceHostState.Stopped => new("Остановлена", ServiceHostTone.Bad, true, false, false),
            ServiceHostState.StartPending => new("Запускается…", ServiceHostTone.Progress, false, false, false),
            ServiceHostState.StopPending => new("Останавливается…", ServiceHostTone.Progress, false, false, false),
            ServiceHostState.NotInstalled => new("Не установлена", ServiceHostTone.Bad, false, false, false),
            _ => new("Неизвестно", ServiceHostTone.Neutral, false, false, false),
        },
    };
}

/// <summary>Команды управления службой для запуска с повышением и разбор их кодов выхода.</summary>
public static class ServiceHostCommands
{
    /// <summary>ERROR_SERVICE_ALREADY_RUNNING: «Запустить» по уже запущенной службе — не ошибка.</summary>
    public const int AlreadyRunning = 1056;

    /// <summary>ERROR_SERVICE_NOT_ACTIVE: «Остановить» по уже остановленной службе — не ошибка.</summary>
    public const int NotActive = 1062;

    /// <summary>Программа и аргументы. Перезапуск — одной командой, чтобы запрос прав администратора был один.</summary>
    public static (string FileName, string Arguments) For(ServiceHostAction action, string serviceName) => action switch
    {
        ServiceHostAction.Start => ("sc.exe", "start " + serviceName),
        ServiceHostAction.Stop => ("sc.exe", "stop " + serviceName),
        _ => ("powershell.exe", $"-NoProfile -NonInteractive -WindowStyle Hidden -Command \"Restart-Service -Name {serviceName} -Force -ErrorAction Stop\""),
    };

    /// <summary>sc.exe возвращает код ошибки Win32, PowerShell при ошибке командлета — 1.</summary>
    public static bool Succeeded(ServiceHostAction action, int exitCode) => exitCode == 0 || action switch
    {
        ServiceHostAction.Start => exitCode == AlreadyRunning,
        ServiceHostAction.Stop => exitCode == NotActive,
        _ => false,
    };

    /// <summary>Состояние, которого нужно дождаться после успешной команды.</summary>
    public static ServiceHostState Target(ServiceHostAction action) =>
        action == ServiceHostAction.Stop ? ServiceHostState.Stopped : ServiceHostState.Running;
}
