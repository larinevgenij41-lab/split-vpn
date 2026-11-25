using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using SplitVpn.Core.State;

namespace SplitVpn.App.Services;

/// <summary>
/// Файл службы для команд с правами администратора (экстренное выключение — <see cref="EmergencyLauncher"/>) и запуск
/// службы из «Диагностики».
/// </summary>
public static class NetworkRecovery
{
    private const string ServiceFileName = "SplitVpn.Service.exe";

    /// <summary>
    /// Файл службы: по её регистрации (путь пишет установщик, каталог закрыт для записи пользователям); если регистрация
    /// не читается или службы нет — из каталога установки рядом с приложением, затем известные пути установки.
    /// </summary>
    public static string? FindServiceExecutable() => FindServiceExecutable(WindowsServiceHost.RegisteredExecutable(), AppContext.BaseDirectory, File.Exists);

    internal static string? FindServiceExecutable(string? registered, string appDirectory, Func<string, bool> exists)
    {
        if (registered is not null)
        {
            return registered;
        }

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        return new[]
        {
            Path.Combine(appDirectory, ServiceFileName),
            Path.Combine(appDirectory, "service", ServiceFileName),
            Path.Combine(programFiles, "SplitVpn", ServiceFileName),
            Path.Combine(programFiles, "SplitVpn.Dev", "service", ServiceFileName),
        }.FirstOrDefault(exists);
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
            SplitVpn.Core.Diagnostics.Verbose.Write("Ui", "служба не запущена: " + ex.Message);
            return (false, ex.NativeErrorCode == 1223 ? "Запуск с правами администратора отменён."
                : $"Не удалось запустить службу с правами администратора (код {ex.NativeErrorCode}). Проверьте службу «Раздельный VPN» в «Службах» Windows.");
        }
    }
}
