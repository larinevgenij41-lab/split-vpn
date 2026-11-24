using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using SplitVpn.Core.State;

namespace SplitVpn.App.Services;

/// <summary>
/// «Восстановить сеть», когда служба недоступна: запуск «SplitVpn.Service.exe recover» с повышением (UAC).
/// </summary>
public static class NetworkRecovery
{
    /// <summary>Файл службы по её регистрации; известные пути установки — запасной вариант, если регистрация не читается.</summary>
    public static string? FindServiceExecutable()
    {
        if (WindowsServiceHost.RegisteredExecutable() is { } registered)
        {
            return registered;
        }

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        return new[]
        {
            Path.Combine(programFiles, "SplitVpn", "SplitVpn.Service.exe"),
            Path.Combine(programFiles, "SplitVpn.Dev", "service", "SplitVpn.Service.exe"),
        }.FirstOrDefault(File.Exists);
    }

    /// <summary>Возвращает текст результата для пользователя.</summary>
    public static async Task<(bool Success, string Text)> RunElevatedAsync()
    {
        var exe = FindServiceExecutable();
        if (exe is null)
        {
            return (false, "Служба не установлена: восстановление недоступно. Используйте recover-network.cmd.");
        }

        try
        {
            using var process = Process.Start(new ProcessStartInfo(exe, "recover")
            {
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
                WorkingDirectory = Environment.SystemDirectory,
            })!;
            // Сама команда recover ограничена тремя минутами и коротким сроком завершения.
            using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(4));
            await process.WaitForExitAsync(deadline.Token);
            return process.ExitCode == 0
                ? (true, "Сеть восстановлена: защита снята, служба остановлена и сама не запустится до перезагрузки. Чтобы вернуть защиту, нажмите «Запустить службу», затем «Подключить».")
                : (false, $"Восстановление завершилось с ошибкой (код {process.ExitCode}). Перезагрузите компьютер.");
        }
        catch (OperationCanceledException)
        {
            return (false, "Восстановление ещё не подтвердилось. Проверьте состояние службы и сети.");
        }
        catch (Win32Exception ex)
        {
            return (false, ex.NativeErrorCode == 1223 ? "Запуск с правами администратора отменён." : "Не удалось запустить восстановление: " + ex.Message);
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
                WorkingDirectory = Environment.SystemDirectory,
            })!;
            using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
            await process.WaitForExitAsync(deadline.Token);
            // 1056 — служба уже запущена.
            if (process.ExitCode is not (0 or 1056))
            {
                return (false, $"Службу запустить не удалось (код {process.ExitCode}).");
            }
            while (WindowsServiceHost.Query() is ServiceHostState.StartPending)
            {
                await Task.Delay(500, deadline.Token);
            }
            return WindowsServiceHost.Query() == ServiceHostState.Running
                ? (true, "Служба запущена. Защита включится после «Подключить».")
                : (false, "Служба не перешла в рабочее состояние. Проверьте журнал событий.");
        }
        catch (OperationCanceledException)
        {
            return (false, "Служба не подтвердила запуск за две минуты.");
        }
        catch (Win32Exception ex)
        {
            return (false, ex.NativeErrorCode == 1223 ? "Запуск с правами администратора отменён." : "Не удалось запустить службу: " + ex.Message);
        }
    }
}
