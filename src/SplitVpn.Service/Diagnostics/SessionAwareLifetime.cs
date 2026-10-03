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

    public SessionAwareLifetime(IHostEnvironment environment, IHostApplicationLifetime applicationLifetime, ILoggerFactory loggerFactory,
        IOptions<HostOptions> optionsAccessor, IOptions<WindowsServiceLifetimeOptions> windowsServiceOptionsAccessor)
        : base(environment, applicationLifetime, loggerFactory, optionsAccessor, windowsServiceOptionsAccessor)
    {
        ArgumentNullException.ThrowIfNull(loggerFactory);
        _logger = loggerFactory.CreateLogger("SplitVpn.Sessions");
        CanHandleSessionChangeEvent = true;
    }

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
