using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using SplitVpn.Core.Settings;
using SplitVpn.Windows.Diagnostics;
using SplitVpn.Windows.Recovery;
using SplitVpn.Windows.Security;
using SplitVpn.Windows.Wfp;

namespace SplitVpn.Service;

/// <summary>
/// Команда «SplitVpn.Service.exe recover»: приостанавливает защиту, останавливает службу без её
/// автоперезапуска и снимает все изменения приложения. Флаг приостановки снимается действием «Подключить».
/// </summary>
public static class ServiceRecovery
{
    /// <summary>Сторож времени: удаление программы не должно висеть на зависшем восстановлении.</summary>
    private static readonly TimeSpan Watchdog = TimeSpan.FromMinutes(3);

    /// <summary>Запас на завершение уже начатых шагов после срабатывания сторожа.</summary>
    private static readonly TimeSpan WatchdogGrace = TimeSpan.FromSeconds(15);

    /// <summary>Код sc.exe «служба не установлена» (ERROR_SERVICE_DOES_NOT_EXIST).</summary>
    private const int ServiceDoesNotExist = 1060;

    /// <summary>
    /// Если срок восстановления уже истёк, отложенная работа не начинает очистку данных.
    /// </summary>
    private static readonly Lock FinishGate = new();
    private static bool _abandoned;

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
            lock (FinishGate)
            {
                _abandoned = true;
            }

            Console.Error.WriteLine($"Восстановление сети не уложилось в {(int)Watchdog.TotalMinutes} мин и прервано.");
            return 1;
        }
        catch (Exception ex)
        {
            // Ни зависание, ни неожиданная ошибка не должны оставить удаление программы без ответа:
            // выходим с ненулевым кодом, вернув службе автоперезапуск, если успели его сбросить.
            Console.Error.WriteLine("Восстановление сети прервано ошибкой: " + ex.Message);
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
            StopService(cancellationToken);
        }

        var trusted = TrySecureRecoveryRoot(paths.Root, SecretStore.SecureDataRoot);
        var suspended = trusted && SuspendProtection(paths);

        var report = await NetworkRecovery.RunAsync(new RecoveryOptions
        {
            Phonebooks = trusted ? [paths.Phonebook] : [],
            WfpIdentities = [WfpIdentity.Product],
            DnsBackupPath = trusted ? paths.DnsBackup : null,
        }, cancellationToken);

        lock (FinishGate)
        {
            if (_abandoned)
            {
                // Сторож уже сообщил о прерывании: ни отчёта об успехе, ни удаления данных.
                return 1;
            }
        }

        Console.WriteLine(JsonSerializer.Serialize(report, JsonDefaults.Options));
        if (uninstall && report.Success && suspended)
        {
            DeleteData(paths.Root);
            DeleteRegistryKey();
        }

        return report.Success && suspended ? 0 : 1;
    }

    internal static bool TrySecureRecoveryRoot(string root, Func<string, IReadOnlyList<string>> secure)
    {
        try
        {
            foreach (var warning in secure(root)) Console.Error.WriteLine(warning);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or System.ComponentModel.Win32Exception)
        {
            Console.Error.WriteLine("Каталог данных недоступен для безопасного восстановления: " + ex.Message);
            return false;
        }
    }

    /// <summary>
    /// Флаг приостановки защиты: служба после запуска ничего не применяет до действия «Подключить».
    /// Повреждённое или недоступное состояние не отменяет восстановление — снять изменения важнее.
    /// </summary>
    private static bool SuspendProtection(ServicePaths paths)
    {
        try
        {
            var stores = new ServiceStores(paths) { OnCorrupt = file => Console.Error.WriteLine(file.Describe()) };
            stores.SaveState(stores.LoadState() with { ProtectionSuspended = true });
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Флаг приостановки защиты не записан: " + ex.Message);
            return false;
        }
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
            throw new IOException("Ключ реестра программы не удалён: " + ex.Message, ex);
        }
    }

    private static void DeleteData(string root)
    {
        try
        {
            Directory.Delete(root, recursive: true);
        }
        catch (DirectoryNotFoundException) { }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new IOException("Данные не удалены: " + ex.Message, ex);
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

        cancellationToken.ThrowIfCancellationRequested();
        var (currentPid, state) = SystemMetrics.ServiceStatus(ServicePaths.ServiceName);
        if (state == "SERVICE_STOPPED") return;
        if (pid == 0 || currentPid != pid) throw new InvalidOperationException("Во время остановки изменился процесс службы.");
        using var policy = ServiceFailurePolicy.Suspend(ServicePaths.ServiceName);
        try
        {
            using var process = Process.GetProcessById((int)pid);
            // Удерживаем дескриптор процесса и сверяем PID повторно, исключая его переиспользование.
            _ = process.Handle;
            if (SystemMetrics.ServiceStatus(ServicePaths.ServiceName).ProcessId != pid)
                throw new InvalidOperationException("Во время остановки изменился процесс службы.");
            process.Kill();
            if (!process.WaitForExit(10_000))
                throw new TimeoutException("Процесс службы не завершился.");
        }
        catch (ArgumentException)
        {
            // Процесс уже завершился.
        }

        for (var i = 0; i < 20; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (SystemMetrics.ServiceStatus(ServicePaths.ServiceName).State == "SERVICE_STOPPED") return;
            Thread.Sleep(250);
        }
        throw new TimeoutException("Диспетчер служб не подтвердил остановку службы.");
    }

    private static int RunSc(string arguments)
    {
        using var process = Process.Start(new ProcessStartInfo("sc.exe", arguments)
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
        })!;
        var output = process.StandardOutput.ReadToEndAsync();
        if (!process.WaitForExit(30_000))
        {
            // Зависший sc.exe не должен задерживать восстановление: чтение кода завершения на нём же и падало.
            process.Kill(entireProcessTree: true);
            return -1;
        }

        output.GetAwaiter().GetResult();
        return process.ExitCode;
    }
}
