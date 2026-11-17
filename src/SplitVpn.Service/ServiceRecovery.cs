using System.Diagnostics;
using System.Globalization;
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

    /// <summary>Код sc.exe «служба не установлена» (ERROR_SERVICE_DOES_NOT_EXIST).</summary>
    private const int ServiceDoesNotExist = 1060;

    /// <summary>Действия восстановления службы сброшены: при неудаче их нужно вернуть.</summary>
    private static volatile bool _failureActionsCleared;

    /// <summary>
    /// Сторож уже сообщил о прерывании, либо восстановление уже перешло к завершению (отчёт, удаление данных).
    /// Под замком: после сообщения «прервано» фоновая работа не должна удалить данные, а начатое удаление
    /// сторож дожидается, а не обрывает.
    /// </summary>
    private static readonly Lock FinishGate = new();
    private static bool _abandoned;
    private static bool _finishing;

    public static async Task<int> RunAsync(ServicePaths paths, bool uninstall)
    {
        using var deadline = new CancellationTokenSource(Watchdog);
        var work = Task.Run(() => RunCoreAsync(paths, uninstall, deadline.Token), CancellationToken.None);
        try
        {
            return await work.WaitAsync(Watchdog + WatchdogGrace, CancellationToken.None);
        }
        catch (TimeoutException) when (!work.IsCompleted)
        {
            bool finishing;
            lock (FinishGate)
            {
                _abandoned = true;
                finishing = _finishing;
            }

            if (finishing)
            {
                // Отчёт уже выведен, идёт удаление данных: оно конечно, его дожидаемся и отдаём его итог.
                return await work;
            }

            Console.Error.WriteLine($"Восстановление сети не уложилось в {(int)Watchdog.TotalMinutes} мин и прервано.");
            RestoreFailureActions();
            return 1;
        }
        catch (Exception ex)
        {
            // Ни зависание, ни неожиданная ошибка не должны оставить удаление программы без ответа:
            // выходим с ненулевым кодом, вернув службе автоперезапуск, если успели его сбросить.
            Console.Error.WriteLine("Восстановление сети прервано ошибкой: " + ex.Message);
            RestoreFailureActions();
            return 1;
        }
    }

    private static async Task<int> RunCoreAsync(ServicePaths paths, bool uninstall, CancellationToken cancellationToken)
    {
        // Сначала останавливаем службу, а потом пишем флаг приостановки: иначе работающая служба успевает
        // сохранить своё состояние поверх флага и после перезапуска снова применяет защиту.
        // Остановку пропускает только ответ «службы нет»: сбой, отказ в доступе или зависание sc.exe не значат,
        // что служба не работает, — снятые изменения она тут же применила бы снова, а при удалении у неё
        // из-под ног удалились бы данные. Тогда восстановление не выполняется и завершается ошибкой.
        var query = RunSc($"query {ServicePaths.ServiceName}");
        if (query is not (0 or ServiceDoesNotExist))
        {
            Console.Error.WriteLine(string.Create(CultureInfo.InvariantCulture,
                $"Состояние службы не получено (sc query: код {query}): восстановление сети не выполнено."));
            return 1;
        }

        var serviceExists = query == 0;
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

        lock (FinishGate)
        {
            if (_abandoned)
            {
                // Сторож уже сообщил о прерывании: ни отчёта об успехе, ни удаления данных.
                return 1;
            }

            _finishing = true;
        }

        Console.WriteLine(JsonSerializer.Serialize(report, JsonDefaults.Options));
        if (uninstall && report.Success)
        {
            DeleteData(paths.Root);
            DeleteRegistryKey();
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
    /// <summary>
    /// Ключ программы в реестре (каталог данных, имя канала, срок подробного журнала) удаляется здесь, при настоящем
    /// удалении: MSI удалял бы его и при обновлении (оно удаляет прежнюю версию целиком), и включённый подробный
    /// журнал выключался бы установкой обновления.
    /// </summary>
    private static void DeleteRegistryKey()
    {
        try
        {
            Microsoft.Win32.Registry.LocalMachine.DeleteSubKeyTree(Core.Ipc.IpcNames.RegistryKey, throwOnMissingSubKey: false);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            Console.Error.WriteLine("Ключ реестра программы не удалён: " + ex.Message);
        }
    }

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
