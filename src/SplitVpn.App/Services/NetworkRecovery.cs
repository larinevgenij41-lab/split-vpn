using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using SplitVpn.Core.Recovery;
using SplitVpn.Core.State;

namespace SplitVpn.App.Services;

/// <summary>
/// Файл службы для команд с правами администратора (экстренное выключение — <see cref="EmergencyLauncher"/>) и запуск
/// службы из «Диагностики».
/// </summary>
public static class NetworkRecovery
{
    private const string ServiceFileName = "SplitVpn.Service.exe";

    /// <summary>Скрипт последнего средства в каталоге установки (подпапка scripts).</summary>
    internal const string RecoveryScriptName = "recover-network.cmd";

    /// <summary>
    /// Файл службы для запуска с правами администратора: путь из регистрации службы (ImagePath) или
    /// %ProgramFiles%\SplitVpn\SplitVpn.Service.exe — и только если файл и каждый каталог до корня диска не ссылки и
    /// закрыты для записи обычным пользователям (<see cref="AdminOnlyAccess.ElevationTargetProblem(string)"/>). Файл рядом с
    /// приложением или в каталоге, куда может писать пользователь, не годится: окно UAC запустило бы его подмену от имени
    /// администратора. Не найден — null (совет: recover-network.cmd от имени администратора).
    /// </summary>
    public static string? FindServiceExecutable() =>
        FindServiceExecutable(WindowsServiceHost.RegisteredExecutable(), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            AdminOnlyAccess.ElevationTargetProblem);

    /// <summary>Шов для тестов: <paramref name="problem"/> — почему файл нельзя запускать с повышением (null — можно).</summary>
    internal static string? FindServiceExecutable(string? registered, string programFiles, Func<string, string?> problem)
    {
        ArgumentNullException.ThrowIfNull(problem);
        foreach (var candidate in new[] { registered, Path.Combine(programFiles, "SplitVpn", ServiceFileName) })
        {
            if (candidate is null)
            {
                continue;
            }

            if (problem(candidate) is not { } why)
            {
                return candidate;
            }

            SplitVpn.Core.Diagnostics.Verbose.Write("Ui", "файл службы не годится для запуска с правами администратора: " + why);
        }

        return null;
    }

    /// <summary>
    /// Скрипт последнего средства (scripts\recover-network.cmd и recover-network.ps1 рядом) в каталоге найденного файла
    /// службы — по тем же правилам, что и сам файл службы. null — не найден или не годится.
    /// </summary>
    public static string? FindRecoveryScript() => FindRecoveryScript(FindServiceExecutable(), AdminOnlyAccess.ElevationTargetProblem);

    internal static string? FindRecoveryScript(string? serviceExecutable, Func<string, string?> problem)
    {
        ArgumentNullException.ThrowIfNull(problem);
        if (serviceExecutable is null || Path.GetDirectoryName(serviceExecutable) is not { } installDirectory)
        {
            return null;
        }

        var script = Path.Combine(installDirectory, "scripts", RecoveryScriptName);
        var powershell = Path.ChangeExtension(script, ".ps1");
        return problem(script) is null && problem(powershell) is null ? script : null;
    }

    /// <summary>Запуск скрипта последнего средства с правами администратора (окно UAC); ожидания нет — у скрипта своё окно.</summary>
    public static ProcessStartInfo RecoveryScriptStartInfo(string script) => new(script)
    {
        UseShellExecute = true,
        Verb = "runas",
        WorkingDirectory = Environment.SystemDirectory,
    };

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
