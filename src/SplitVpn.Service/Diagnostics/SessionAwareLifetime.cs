using System.ServiceProcess;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Options;
using SplitVpn.Windows.Diagnostics;

namespace SplitVpn.Service.Diagnostics;

/// <summary>
/// Жизненный цикл службы Windows плюс события сеансов: вход, выход, блокировка, переключение пользователя,
/// подключение по RDP. Пишутся всегда — события редкие, а без них не понять, что происходило, когда
/// проблема появляется при входе под другим пользователем.
/// </summary>
public sealed class SessionAwareLifetime : WindowsServiceLifetime
{
    private readonly ILogger _logger;
    private readonly IServiceProvider _services;

    /// <param name="services">
    /// Откуда взять координатор при пробуждении. Не сам координатор: время жизни хоста создаётся раньше служб хоста, и
    /// координатор (с чтением хранилищ) создавался бы до того, как служба сообщит диспетчеру служб о запуске.
    /// </param>
    public SessionAwareLifetime(IHostEnvironment environment, IHostApplicationLifetime applicationLifetime, ILoggerFactory loggerFactory,
        IOptions<HostOptions> optionsAccessor, IOptions<WindowsServiceLifetimeOptions> windowsServiceOptionsAccessor, IServiceProvider services)
        : base(environment, applicationLifetime, loggerFactory, optionsAccessor, windowsServiceOptionsAccessor)
    {
        ArgumentNullException.ThrowIfNull(loggerFactory);
        _logger = loggerFactory.CreateLogger("SplitVpn.Sessions");
        _services = services;
        CanHandleSessionChangeEvent = true;
        CanHandlePowerEvent = true;
    }

    /// <summary>
    /// Сон и пробуждение. После пробуждения соединения туннелей проверяются сразу: проводная сеть с прежним адресом
    /// может проснуться без уведомлений о смене интерфейса, и оборванный за время сна туннель выглядел бы подключённым
    /// до своей очередной проверки.
    /// </summary>
    protected override bool OnPowerEvent(PowerBroadcastStatus powerStatus)
    {
        try
        {
            if (IsResume(powerStatus))
            {
                _services.GetService<Coordination.Coordinator>()?.OnSystemResumed();
            }
            else if (powerStatus == PowerBroadcastStatus.Suspend)
            {
                _logger.LogInformation("Windows уходит в сон");
            }
        }
        catch (Exception ex)
        {
            // Уведомление SCM не должно ронять службу: без него соединения проверит обычный контроль.
            _logger.LogWarning(ex, "Событие питания Windows {Status} не обработано", powerStatus);
        }

        return base.OnPowerEvent(powerStatus);
    }

    /// <summary>
    /// Выключение или перезагрузка Windows (SERVICE_CONTROL_SHUTDOWN): у службы без PreShutdown на остановку есть секунды,
    /// поэтому координатор узнаёт об этом до остановки хоста — помощники AnyConnect сразу прощаются со шлюзом, без
    /// применения политики. Остановку хоста запускает базовый класс.
    /// </summary>
    protected override void OnShutdown()
    {
        try
        {
            _logger.LogInformation("Windows выключается или перезагружается");
            _services.GetService<Coordination.Coordinator>()?.OnSystemShutdown();
        }
        catch (Exception ex)
        {
            // Уведомление SCM не должно ронять службу: без признака остановка пойдёт обычным путём.
            _logger.LogWarning(ex, "Выключение Windows не передано координатору");
        }

        base.OnShutdown();
    }

    /// <summary>
    /// Пробуждение: ResumeAutomatic приходит при каждом пробуждении, ResumeCritical — после аварийного сна. ResumeSuspend
    /// (пользователь за компьютером) приходит вслед за ResumeAutomatic и второй проверки не требует.
    /// </summary>
    internal static bool IsResume(PowerBroadcastStatus status) =>
        status is PowerBroadcastStatus.ResumeAutomatic or PowerBroadcastStatus.ResumeCritical;

    protected override void OnSessionChange(SessionChangeDescription changeDescription)
    {
        try
        {
            var id = changeDescription.SessionId;
            _logger.LogInformation("Сеанс Windows {Session}: {Change}; пользователь {User}; станция {Station}",
                id, ReasonText(changeDescription.Reason), Nonempty(WtsSessions.UserOf(id)), Nonempty(WtsSessions.WinStationOf(id)));
        }
        catch (Exception ex)
        {
            // Уведомление SCM не должно ронять службу: журнал сеансов — только диагностика.
            _logger.LogDebug(ex, "Событие сеанса Windows не записано");
        }

        base.OnSessionChange(changeDescription);
    }

    internal static string ReasonText(SessionChangeReason reason) => reason switch
    {
        SessionChangeReason.ConsoleConnect => "подключение к консоли",
        SessionChangeReason.ConsoleDisconnect => "отключение от консоли",
        SessionChangeReason.RemoteConnect => "подключение по RDP",
        SessionChangeReason.RemoteDisconnect => "отключение RDP",
        SessionChangeReason.SessionLogon => "вход",
        SessionChangeReason.SessionLogoff => "выход",
        SessionChangeReason.SessionLock => "блокировка",
        SessionChangeReason.SessionUnlock => "разблокировка",
        SessionChangeReason.SessionRemoteControl => "удалённое управление",
        _ => reason.ToString(),
    };

    private static string Nonempty(string value) => value.Length == 0 ? "—" : value;
}
