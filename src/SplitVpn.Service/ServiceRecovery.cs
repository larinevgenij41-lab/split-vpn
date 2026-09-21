using System.Diagnostics;
using System.Text.Json;
using SplitVpn.Core.Settings;
using SplitVpn.Windows.Diagnostics;
using SplitVpn.Windows.Recovery;
using SplitVpn.Windows.Wfp;

namespace SplitVpn.Service;

/// <summary>
/// Команда «SplitVpn.Service.exe recover»: приостанавливает защиту, останавливает службу без её
/// автоперезапуска и снимает все изменения приложения. Флаг приостановки снимается действием «Подключить».
/// </summary>
public static class ServiceRecovery
{
    private const string FailureActions = "reset= 86400 actions= restart/5000/restart/5000/restart/30000";

    /// <summary>Сторож времени: удаление программы не должно висеть на зависшем восстановлении.</summary>
    private static readonly TimeSpan Watchdog = TimeSpan.FromMinutes(3);

    /// <summary>Запас на завершение уже начатых шагов после срабатывания сторожа.</summary>
    private static readonly TimeSpan WatchdogGrace = TimeSpan.FromSeconds(15);

    /// <summary>Действия восстановления службы сброшены: при неудаче их нужно вернуть.</summary>
    private static volatile bool _failureActionsCleared;

    public static async Task<int> RunAsync(ServicePaths paths, bool uninstall)
    {
        using var deadline = new CancellationTokenSource(Watchdog);
        var work = Task.Run(() => RunCoreAsync(paths, uninstall, deadline.Token), CancellationToken.None);
        try
        {
            return await work.WaitAsync(Watchdog + WatchdogGrace, CancellationToken.None);
        }
        catch (Exception ex)
        {
            // Ни зависание, ни неожиданная ошибка не должны оставить удаление программы без ответа:
            // выходим с ненулевым кодом, вернув службе автоперезапуск, если успели его сбросить.
            Console.Error.WriteLine(ex is TimeoutException
                ? $"Восстановление сети не уложилось в {(int)Watchdog.TotalMinutes} мин и прервано."
                : "Восстановление сети прервано ошибкой: " + ex.Message);
            RestoreFailureActions();
            return 1;
        }
    }

    private static async Task<int> RunCoreAsync(ServicePaths paths, bool uninstall, CancellationToken cancellationToken)
    {
        // Сначала останавливаем службу, а потом пишем флаг приостановки: иначе работающая служба успевает
        // сохранить своё состояние поверх флага и после перезапуска снова применяет защиту.
        var serviceExists = RunSc($"query {ServicePaths.ServiceName}") == 0;
        if (serviceExists)
        {
            RunSc($"failure {ServicePaths.ServiceName} reset= 0 actions= \"\"");
            _failureActionsCleared = true;
            StopService(cancellationToken);
        }

        SuspendProtection(paths);

        var report = await NetworkRecovery.RunAsync(new RecoveryOptions
        {
            Phonebooks = [paths.Phonebook],
            WfpIdentities = [WfpIdentity.Product],
            DnsBackupPath = paths.DnsBackup,
        }, cancellationToken);

        // При удалении действия восстановления не нужны, но если снять изменения не удалось, удаление
        // откатится — и служба останется без автоперезапуска.
        if (serviceExists && (!uninstall || !report.Success))
        {
            RestoreFailureActions();
        }

        Console.WriteLine(JsonSerializer.Serialize(report, JsonDefaults.Options));
        if (uninstall && report.Success)
        {
            DeleteData(paths.Root);
        }

        return report.Success ? 0 : 1;
    }

    /// <summary>
    /// Флаг приостановки защиты: служба после запуска ничего не применяет до действия «Подключить».
    /// Повреждённое или недоступное состояние не отменяет восстановление — снять изменения важнее.
    /// </summary>
    private static void SuspendProtection(ServicePaths paths)
    {
        if (!Directory.Exists(paths.Root))
        {
            return;
        }

        try
        {
            var stores = new ServiceStores(paths) { OnCorrupt = file => Console.Error.WriteLine(file.Describe()) };
            stores.SaveState(stores.LoadState() with { ProtectionSuspended = true });
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Флаг приостановки защиты не записан: " + ex.Message);
        }
    }

    private static void RestoreFailureActions()
    {
        if (!_failureActionsCleared)
        {
            return;
        }

        _failureActionsCleared = false;
        RunSc($"failure {ServicePaths.ServiceName} {FailureActions}");
    }

    /// <summary>При удалении программы данные (настройки, секреты, база, журналы) не остаются на диске.</summary>
    private static void DeleteData(string root)
    {
        try
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine("Данные не удалены: " + ex.Message);
        }
    }

    private static void StopService(CancellationToken cancellationToken)
    {
        var (pid, _) = SystemMetrics.ServiceStatus(ServicePaths.ServiceName);
        RunSc($"stop {ServicePaths.ServiceName}");
        for (var i = 0; i < 40 && !cancellationToken.IsCancellationRequested
            && SystemMetrics.ServiceStatus(ServicePaths.ServiceName).State != "SERVICE_STOPPED"; i++)
        {
            Thread.Sleep(500);
        }

        if (pid != 0 && SystemMetrics.ServiceStatus(ServicePaths.ServiceName).State != "SERVICE_STOPPED")
        {
            try
            {
                using var process = Process.GetProcessById((int)pid);
                process.Kill();
            }
            catch (ArgumentException)
            {
                // Процесс уже завершился.
            }
        }
    }

    private static int RunSc(string arguments)
    {
        using var process = Process.Start(new ProcessStartInfo("sc.exe", arguments)
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
        })!;
        if (!process.WaitForExit(30_000))
        {
            // Зависший sc.exe не должен задерживать восстановление: чтение кода завершения на нём же и падало.
            process.Kill(entireProcessTree: true);
            return -1;
        }

        process.StandardOutput.ReadToEnd();
        return process.ExitCode;
    }
}
