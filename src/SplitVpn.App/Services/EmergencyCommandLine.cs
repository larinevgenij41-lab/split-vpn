using System.Windows;
using SplitVpn.Core.Diagnostics;

namespace SplitVpn.App.Services;

/// <summary>
/// «SplitVpn.exe ‐‐emergency-off» — ярлык «Экстренно выключить Раздельный VPN» в меню «Пуск» и на рабочем столе.
/// Выполняется в самом начале запуска: до окон, трея, проверки единственного экземпляра, WebView2 и канала службы,
/// поэтому работает, когда приложение уже открыто и когда служба не отвечает. Подтверждения в приложении нет: ярлык
/// выбран явно, а права администратора Windows всё равно спросит. Итог — обычное окно сообщения; код завершения
/// процесса — код команды (1223 — отказ в окне UAC).
/// </summary>
public static class EmergencyCommandLine
{
    public const string OffArgument = "--emergency-off";

    public static bool IsEmergencyOff(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        return args.Any(a => string.Equals(a?.Trim(), OffArgument, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Выполнить и показать итог; возвращает код завершения процесса.</summary>
    public static int Run()
    {
        // Ожидание — в пуле потоков: продолжения не ждут поток интерфейса, который здесь занят этим вызовом.
        var result = Task.Run(() => RunAsync(new EmergencyLauncher(), RevertOwnProxyAsync)).GetAwaiter().GetResult();
        if (result.Kind != EmergencyRunKind.Cancelled)
        {
            MessageBox.Show(result.ToMessageText(), "Раздельный VPN — " + result.Title, MessageBoxButton.OK,
                result.IsError ? MessageBoxImage.Warning : MessageBoxImage.Information);
        }

        return result.ProcessExitCode;
    }

    /// <summary>Сначала свой прокси шлюза (служба от SYSTEM прокси пользователя не трогает), затем команда с правами администратора.</summary>
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

        return await launcher.RunAsync(on: false);
    }

    private static async Task RevertOwnProxyAsync()
    {
        using var proxy = new ProxyService(new WinInetProxySettings());
        await proxy.UpdateAsync(null, stopped: true);
    }
}
