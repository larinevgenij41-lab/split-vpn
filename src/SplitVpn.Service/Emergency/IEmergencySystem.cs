using SplitVpn.Core.Recovery;

namespace SplitVpn.Service.Emergency;

/// <summary>Состояние службы по ответу диспетчера служб.</summary>
internal enum ServiceRunState
{
    Stopped,
    Running,

    /// <summary>Запускается, останавливается, приостановлена.</summary>
    Pending,
}

internal sealed record ServiceSnapshot(ServiceRunState State, uint ProcessId);

/// <summary>Итог шага до учёта времени.</summary>
internal sealed record StepResult(EmergencyStepOutcome Outcome, string? Detail = null)
{
    public static StepResult Done(string? detail = null) => new(EmergencyStepOutcome.Done, detail);

    public static StepResult Already(string? detail = null) => new(EmergencyStepOutcome.Already, detail);

    public static StepResult Skipped(string? detail = null) => new(EmergencyStepOutcome.Skipped, detail);

    public static StepResult Failed(string? detail) => new(EmergencyStepOutcome.Failed, detail);
}

/// <summary>
/// Системные действия экстренного отключения. Каждое идемпотентно: повторный запуск отвечает «уже». Шаги вызываются
/// каждый в своём потоке и со своим сроком (<see cref="EmergencyOrchestrator"/>), поэтому зависший системный вызов
/// (RasHangUp, BFE, диспетчер служб) не задерживает остальные. В тестах подменяется фейком.
/// </summary>
internal interface IEmergencySystem
{
    bool IsElevated();

    /// <summary>Общая блокировка команд; null — занята дольше <paramref name="wait"/>.</summary>
    IDisposable? TryAcquireLock(TimeSpan wait);

    /// <summary>
    /// Выполняется ли другая команда восстановления этой программы (emergency-off, emergency-on, recover из того же файла
    /// службы, кроме себя) — по живым процессам, а не по мьютексу.
    /// </summary>
    bool OtherRecoveryCommandRunning();

    StepResult WriteFlag(DateTimeOffset now);

    StepResult ClearFlag();

    /// <summary>Ручной запуск службы; прежний тип запоминается (если ещё не запомнен).</summary>
    StepResult SetManualStart();

    /// <summary>Тип запуска, запомненный при отключении (по умолчанию — автозапуск).</summary>
    StepResult RestoreStartType();

    StepResult SuspendFailureActions();

    StepResult RestoreFailureActions();

    /// <summary>Состояние службы; null — служба не установлена. Исключение — диспетчер служб не ответил.</summary>
    ServiceSnapshot? QueryService();

    void RequestStop();

    void RequestStart();

    /// <summary>Завершает процесс службы по номеру (проверив, что это наш файл); true — процесс завершился.</summary>
    bool KillServiceProcess(uint processId, TimeSpan wait);

    /// <summary>Завершает все процессы SplitVpn.Service.exe из каталога программы, кроме себя. Ответ — сколько.</summary>
    int KillOwnServiceProcesses();

    /// <summary>Сколько процессов SplitVpn.Service.exe из каталога программы работает, кроме себя.</summary>
    int CountOwnServiceProcesses();

    StepResult StopHelpers();

    /// <summary>Флаг приостановки защиты в state.json (вторая линия после флага в реестре).</summary>
    StepResult SuspendProtection();

    StepResult RemoveFilters();

    Task<StepResult> HangUpConnectionsAsync(CancellationToken cancellationToken);

    StepResult RemoveRoutes();

    /// <summary>DNS адаптеров; <paramref name="serviceStopped"/> — служба подтверждённо остановлена.</summary>
    StepResult RestoreDns(bool serviceStopped);

    StepResult RestoreWcm();

    StepResult FlushDns();
}
