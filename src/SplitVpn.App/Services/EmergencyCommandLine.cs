using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using SplitVpn.Core.Diagnostics;

namespace SplitVpn.App.Services;

/// <summary>
/// «SplitVpn.exe ‐‐emergency-off» — ярлык «Экстренно выключить Раздельный VPN» в меню «Пуск» и на рабочем столе.
/// Выполняется в самом начале запуска: до окон, трея, проверки единственного экземпляра, WebView2 и канала службы,
/// поэтому работает, когда приложение уже открыто и когда служба не отвечает. Сначала — одно подтверждение (системное
/// окно поверх всех, по умолчанию «Нет»), затем окно UAC. Итог — системное окно сообщения поверх всех; если сделано не
/// всё, в нём же предлагается последнее средство — recover-network.cmd с правами администратора. Код завершения
/// процесса — код команды (1223 — отказ в подтверждении или в окне UAC).
/// </summary>
public static partial class EmergencyCommandLine
{
    public const string OffArgument = "--emergency-off";

    internal const string Caption = "Раздельный VPN — экстренное выключение";

    internal const string ConfirmText =
        "Экстренно выключить «Раздельный VPN»?\n\nVPN и защита от утечек будут отключены, служба программы остановится и сама не запустится — даже после перезагрузки. "
        + "Включить обратно — кнопкой «Включить программу» в приложении.\n\nДалее Windows запросит права администратора.";

    internal const string FallbackText =
        "Экстренное выключение не выполнено из-за непредвиденной ошибки (подробности — в журнале ошибок интерфейса ui-errors.log).\n\n"
        + "Если интернет не работает, запустите от имени администратора recover-network.cmd из папки программы (подпапка scripts) или перезагрузите компьютер.";

    internal const string LastResortQuestion = "Запустить последнее средство — recover-network.cmd с правами администратора? Оно вернёт сеть встроенными средствами Windows.";

    public static bool IsEmergencyOff(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        return args.Any(a => string.Equals(a?.Trim(), OffArgument, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Выполнить и показать итог; возвращает код завершения процесса. Исключений не бросает.</summary>
    public static int Run() => Run(new EmergencyCommandLineHost());

    /// <summary>Шов для тестов: окна, запуск команды и скрипта подменяются.</summary>
    internal static int Run(IEmergencyCommandLineHost host)
    {
        ArgumentNullException.ThrowIfNull(host);
        try
        {
            if (!host.Confirm(ConfirmText))
            {
                return EmergencyLauncher.UacCancelled;
            }

            // Ожидание — в пуле потоков: продолжения не ждут поток интерфейса, который здесь занят этим вызовом.
            var result = Task.Run(() => RunAsync(host.Launcher, host.RevertProxy)).GetAwaiter().GetResult();
            if (result.Kind == EmergencyRunKind.Cancelled)
            {
                return result.ProcessExitCode;
            }

            var script = result.OffersLastResort ? host.FindRecoveryScript() : null;
            if (script is null)
            {
                host.ShowResult(result.ToMessageText(), result.IsError);
            }
            else if (host.AskResult(result.ToMessageText() + "\n\n" + LastResortQuestion))
            {
                host.StartRecoveryScript(script);
            }

            return result.ProcessExitCode;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            host.Record(ex);
            try
            {
                host.ShowResult(FallbackText, error: true);
            }
            catch (Exception shown) when (shown is not OutOfMemoryException)
            {
                host.Record(shown);
            }

            return Core.Recovery.EmergencyExitCodes.Unexpected;
        }
    }

    /// <summary>
    /// Сначала свой прокси шлюза (служба от SYSTEM прокси пользователя не трогает), затем команда с правами
    /// администратора. Команда не уложилась в ожидание — ждём её окончания (она не прерывается) и отдаём итоговый результат.
    /// </summary>
    internal static async Task<EmergencyRunResult> RunAsync(IEmergencyLauncher launcher, Func<Task>? revertProxy)
    {
        ArgumentNullException.ThrowIfNull(launcher);
        if (revertProxy is not null)
        {
            try
            {
                await revertProxy();
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                Verbose.Write("Ui", "прокси перед экстренным выключением не снят: " + ex.GetType().Name + " «" + ex.Message + "»");
            }
        }

        var result = await launcher.RunAsync(on: false);
        return result is { Kind: EmergencyRunKind.Overdue, Completion: { } completion } ? await completion : result;
    }

    // ---------- Системные окна: поверх всех и на переднем плане (ярлык запускают, когда окно программы может быть скрыто) ----------

    private const uint MbOk = 0x0;
    private const uint MbYesNo = 0x4;
    private const uint MbIconWarning = 0x30;
    private const uint MbIconInformation = 0x40;
    private const uint MbDefButton2 = 0x100;
    private const uint MbSetForeground = 0x10000;
    private const uint MbTopmost = 0x40000;
    private const int IdYes = 6;

    internal static bool NativeYesNo(string text, bool defaultNo) =>
        MessageBoxW(0, text, Caption, MbYesNo | MbIconWarning | (defaultNo ? MbDefButton2 : 0) | MbSetForeground | MbTopmost) == IdYes;

    internal static void NativeOk(string text, bool error) =>
        _ = MessageBoxW(0, text, Caption, MbOk | (error ? MbIconWarning : MbIconInformation) | MbSetForeground | MbTopmost);

    [LibraryImport("user32.dll", EntryPoint = "MessageBoxW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int MessageBoxW(nint owner, string text, string caption, uint type);

    private static async Task RevertOwnProxyAsync()
    {
        using var proxy = new ProxyService(new WinInetProxySettings());
        await proxy.UpdateAsync(null, stopped: true);
    }

    /// <summary>Настоящие окна, команда и скрипт.</summary>
    private sealed class EmergencyCommandLineHost : IEmergencyCommandLineHost
    {
        public IEmergencyLauncher Launcher { get; } = new EmergencyLauncher();

        public Func<Task>? RevertProxy => RevertOwnProxyAsync;

        public bool Confirm(string text) => NativeYesNo(text, defaultNo: true);

        public void ShowResult(string text, bool error) => NativeOk(text, error);

        public bool AskResult(string text) => NativeYesNo(text, defaultNo: false);

        public string? FindRecoveryScript() => NetworkRecovery.FindRecoveryScript();

        public void StartRecoveryScript(string script)
        {
            try
            {
                using var _ = Process.Start(NetworkRecovery.RecoveryScriptStartInfo(script));
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == EmergencyLauncher.UacCancelled)
            {
                // Отказ в окне UAC: ничего не запускается.
            }
        }

        public void Record(Exception exception) => App.RecordHandled(exception);
    }
}

/// <summary>Окна и запуски ярлыка «Экстренно выключить»; в проверках подменяются.</summary>
internal interface IEmergencyCommandLineHost
{
    IEmergencyLauncher Launcher { get; }

    Func<Task>? RevertProxy { get; }

    /// <summary>Подтверждение до окна UAC; true — «Да».</summary>
    bool Confirm(string text);

    void ShowResult(string text, bool error);

    /// <summary>Итог с вопросом о последнем средстве; true — «Да».</summary>
    bool AskResult(string text);

    string? FindRecoveryScript();

    void StartRecoveryScript(string script);

    /// <summary>Ошибка — в журнал ошибок интерфейса (ui-errors.log).</summary>
    void Record(Exception exception);
}
