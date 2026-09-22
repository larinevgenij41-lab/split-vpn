using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using Microsoft.Win32;
using SplitVpn.Core.State;

namespace SplitVpn.App.Services;

/// <summary>
/// Служба Windows «SplitVpn» глазами диспетчера служб: состояние и версия читаются без прав администратора,
/// а запуск, остановка и перезапуск идут отдельным процессом с повышением (UAC) — как «Восстановить сеть».
/// </summary>
public static class WindowsServiceHost
{
    /// <summary>ERROR_SERVICE_DOES_NOT_EXIST.</summary>
    private const int ServiceDoesNotExist = 1060;

    /// <summary>ERROR_CANCELLED: пользователь отказался в окне UAC.</summary>
    private const int Cancelled = 1223;

    /// <summary>Сколько ждать итогового состояния после команды: остановка закрывает сеансы AnyConnect.</summary>
    private static readonly TimeSpan SettleTimeout = TimeSpan.FromSeconds(30);

    public static ServiceHostState Query()
    {
        try
        {
            using var controller = new ServiceController(ServiceConnection.ServiceName);
            return controller.Status switch
            {
                ServiceControllerStatus.Stopped => ServiceHostState.Stopped,
                ServiceControllerStatus.StartPending => ServiceHostState.StartPending,
                ServiceControllerStatus.StopPending => ServiceHostState.StopPending,
                _ => ServiceHostState.Running,
            };
        }
        catch (InvalidOperationException ex) when (ex.InnerException is Win32Exception { NativeErrorCode: ServiceDoesNotExist })
        {
            return ServiceHostState.NotInstalled;
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
        {
            return ServiceHostState.Unknown;
        }
    }

    /// <summary>Версия файла службы по пути из её регистрации; null — служба не установлена или файл не прочитан.</summary>
    public static string? Version()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + ServiceConnection.ServiceName);
            if (key?.GetValue("ImagePath") is not string image || ExecutablePath(image) is not { } path || !File.Exists(path))
            {
                return null;
            }

            var info = FileVersionInfo.GetVersionInfo(path);
            return $"{info.FileMajorPart}.{info.FileMinorPart}.{info.FileBuildPart}";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return null;
        }
    }

    /// <summary>
    /// Выполнить действие с правами администратора и дождаться итогового состояния службы.
    /// Возвращает текст ошибки для пользователя; null — выполнено или отменено в окне UAC.
    /// </summary>
    public static async Task<string?> RunElevatedAsync(ServiceHostAction action)
    {
        var (file, arguments) = ServiceHostCommands.For(action, ServiceConnection.ServiceName);
        try
        {
            using var process = Process.Start(new ProcessStartInfo(file, arguments)
            {
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
            })!;
            await process.WaitForExitAsync();
            if (!ServiceHostCommands.Succeeded(action, process.ExitCode))
            {
                return $"{Failure(action)} (код {process.ExitCode}). Проверьте службу «Раздельный VPN» в «Службах» Windows или перезагрузите компьютер.";
            }
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == Cancelled)
        {
            return null;
        }
        catch (Win32Exception ex)
        {
            return $"{Failure(action)}: {ex.Message}";
        }

        var target = ServiceHostCommands.Target(action);
        var deadline = DateTimeOffset.UtcNow + SettleTimeout;
        while (Query() != target)
        {
            if (DateTimeOffset.UtcNow >= deadline)
            {
                return target == ServiceHostState.Stopped
                    ? "Служба не остановилась за 30 с. Проверьте её в «Службах» Windows."
                    : "Служба не запустилась за 30 с. Проверьте её в «Службах» Windows или журнал в «Диагностике».";
            }

            await Task.Delay(300);
        }

        return null;
    }

    private static string Failure(ServiceHostAction action) => action switch
    {
        ServiceHostAction.Start => "Службу запустить не удалось",
        ServiceHostAction.Stop => "Службу остановить не удалось",
        _ => "Службу перезапустить не удалось",
    };

    /// <summary>Путь к exe из ImagePath: в кавычках или до «.exe», с переменными окружения.</summary>
    private static string? ExecutablePath(string image)
    {
        image = Environment.ExpandEnvironmentVariables(image.Trim());
        if (image.StartsWith('"'))
        {
            var end = image.IndexOf('"', 1);
            return end > 1 ? image[1..end] : null;
        }

        var exe = image.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        return exe > 0 ? image[..(exe + 4)] : null;
    }
}
