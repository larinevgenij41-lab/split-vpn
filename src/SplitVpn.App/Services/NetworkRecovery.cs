using System.ComponentModel;
using System.Diagnostics;
using System.IO;

namespace SplitVpn.App.Services;

/// <summary>
/// «Восстановить сеть», когда служба недоступна: запуск «SplitVpn.Service.exe recover» с повышением (UAC).
/// </summary>
public static class NetworkRecovery
{
    public static string? FindServiceExecutable()
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        return new[]
        {
            Path.Combine(programFiles, "SplitVpn", "SplitVpn.Service.exe"),
            Path.Combine(programFiles, "SplitVpn.Dev", "service", "SplitVpn.Service.exe"),
        }.FirstOrDefault(File.Exists);
    }

    /// <summary>Возвращает текст результата для пользователя.</summary>
    public static async Task<string> RunElevatedAsync()
    {
        var exe = FindServiceExecutable();
        if (exe is null)
        {
            return "Служба не установлена: восстановление недоступно. Используйте recover-network.cmd.";
        }

        try
        {
            using var process = Process.Start(new ProcessStartInfo(exe, "recover")
            {
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
            })!;
            await process.WaitForExitAsync();
            return process.ExitCode == 0
                ? "Сеть восстановлена: защита снята, служба остановлена и сама не запустится до перезагрузки. Чтобы вернуть защиту, нажмите «Запустить службу», затем «Подключить»."
                : $"Восстановление завершилось с ошибкой (код {process.ExitCode}). Перезагрузите компьютер.";
        }
        catch (Win32Exception)
        {
            return "Запуск с правами администратора отменён.";
        }
    }

    /// <summary>Запуск службы после аварийного восстановления: «sc start» с повышением (UAC). Возвращает текст для пользователя.</summary>
    public static async Task<(bool Success, string Text)> StartServiceElevatedAsync()
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo("sc.exe", "start " + ServiceConnection.ServiceName)
            {
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
            })!;
            await process.WaitForExitAsync();
            // 1056 — служба уже запущена.
            return process.ExitCode is 0 or 1056
                ? (true, "Служба запущена. Защита включится после «Подключить».")
                : (false, $"Службу запустить не удалось (код {process.ExitCode}). Проверьте её в «Службах» Windows или перезагрузите компьютер.");
        }
        catch (Win32Exception)
        {
            return (false, "Запуск с правами администратора отменён.");
        }
    }
}
