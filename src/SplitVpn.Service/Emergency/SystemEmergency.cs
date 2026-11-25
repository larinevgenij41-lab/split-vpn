using System.Diagnostics;
using System.Globalization;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Win32;
using SplitVpn.Core.Recovery;
using SplitVpn.Windows.Diagnostics;
using SplitVpn.Windows.Native;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.Recovery;
using SplitVpn.Windows.Security;
using SplitVpn.Windows.SshTunnel;
using SplitVpn.Windows.Wfp;

namespace SplitVpn.Service.Emergency;

/// <summary>Настоящая система для <see cref="EmergencyOrchestrator"/>: реестр, диспетчер служб, процессы, сеть.</summary>
internal sealed class SystemEmergency(ServicePaths paths, string serviceDirectory) : IEmergencySystem
{
    /// <summary>ERROR_SERVICE_DOES_NOT_EXIST.</summary>
    private const uint ServiceDoesNotExist = 1060;

    private readonly string _serviceImage = Path.Combine(serviceDirectory, ServicePaths.ImageName);
    private FailureActionsSnapshot? _suspendedFailureActions;
    private volatile bool _trusted;

    /// <summary>
    /// Каталог данных свой и защищён: копии DNS и состоянию можно верить. Проверяет шаг DNS (только чтением, ничего не
    /// исправляя): шаг DNS не выполнен — и доверия нет.
    /// </summary>
    public bool Trusted => _trusted;

    public bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            return false;
        }

        try
        {
            // Право отладки (у администратора есть, но выключено): без него процесс службы от SYSTEM не всегда отдаёт
            // дескриптор для завершения.
            Process.EnterDebugMode();
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            Trace.TraceWarning("Право отладки не включено: {0}", ex.Message);
        }

        return true;
    }

    public IDisposable? TryAcquireLock(TimeSpan wait) => MutexLock.TryAcquire(EmergencyMutex.Name, wait);

    private static RegistryKey OpenOwnKey()
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        return root.CreateSubKey(EmergencyRegistry.KeyPath, writable: true);
    }

    public StepResult WriteFlag(DateTimeOffset now)
    {
        using var key = OpenOwnKey();
        if (EmergencyRegistry.Parse(key.GetValue(EmergencyRegistry.FlagValue), key.GetValue(EmergencyRegistry.SinceValue)) is { } existing)
        {
            return StepResult.Already(existing.SinceUtc is { } since ? "отключена с " + since.ToString("O", CultureInfo.InvariantCulture) : "отметка уже стоит");
        }

        key.SetValue(EmergencyRegistry.SinceValue, now.ToString("O", CultureInfo.InvariantCulture), RegistryValueKind.String);
        key.SetValue(EmergencyRegistry.FlagValue, 1, RegistryValueKind.DWord);
        return StepResult.Done(@"HKLM\Software\SplitVpn: EmergencyOff = 1");
    }

    public StepResult ClearFlag()
    {
        using var key = OpenOwnKey();
        var had = key.GetValue(EmergencyRegistry.FlagValue) is not null;
        key.DeleteValue(EmergencyRegistry.FlagValue, throwOnMissingValue: false);
        key.DeleteValue(EmergencyRegistry.SinceValue, throwOnMissingValue: false);
        return had ? StepResult.Done("отметка снята") : StepResult.Already("отметки не было");
    }

    public StepResult SetManualStart()
    {
        var current = ServiceStartType.Read(ServicePaths.ServiceName);
        if (current is null)
        {
            return StepResult.Skipped("служба не установлена");
        }

        using (var key = OpenOwnKey())
        {
            // Прежний тип запоминается всегда, в том числе «demand» (иначе включение поставило бы автозапуск службе,
            // которую человек держал в ручном), но один раз: повторное отключение не затирает «auto» своим «demand».
            if (key.GetValue(EmergencyRegistry.PreviousStartValue) is null)
            {
                key.SetValue(EmergencyRegistry.PreviousStartValue, current, RegistryValueKind.String);
            }
        }

        if (current == EmergencyRegistry.StartDemand)
        {
            return StepResult.Already("уже ручной запуск");
        }

        ServiceStartType.Set(ServicePaths.ServiceName, EmergencyRegistry.StartDemand);
        return StepResult.Done($"ручной запуск (было: {current})");
    }

    public StepResult RestoreStartType()
    {
        var current = ServiceStartType.Read(ServicePaths.ServiceName);
        if (current is null)
        {
            return StepResult.Failed("служба не установлена");
        }

        string target;
        using (var key = OpenOwnKey())
        {
            target = key.GetValue(EmergencyRegistry.PreviousStartValue) is string saved && saved is EmergencyRegistry.StartAuto
                or EmergencyRegistry.StartDelayedAuto or EmergencyRegistry.StartDemand or EmergencyRegistry.StartDisabled
                ? saved : EmergencyRegistry.StartAuto;
        }

        if (current != target)
        {
            ServiceStartType.Set(ServicePaths.ServiceName, target);
        }

        using (var key = OpenOwnKey())
        {
            key.DeleteValue(EmergencyRegistry.PreviousStartValue, throwOnMissingValue: false);
        }

        return current == target ? StepResult.Already("тип запуска: " + target) : StepResult.Done($"тип запуска: {target} (было: {current})");
    }

    /// <summary>
    /// Снимает действия при сбое, записав прежние в реестр (<see cref="EmergencyRegistry.SavedFailureActionsValue"/>).
    /// Запись осталась от прерванной команды — сейчас у службы снятые (пустые) действия, а настоящие — в записи: они сначала
    /// возвращаются, и только потом снимаются заново (иначе в запись попали бы пустые).
    /// </summary>
    public StepResult SuspendFailureActions()
    {
        if (_suspendedFailureActions is not null)
        {
            return StepResult.Already();
        }

        var notes = new List<string>();
        try
        {
            if (FailureActionsSnapshot.Parse(ServiceFailurePolicy.ReadSaved()) is { } leftover)
            {
                ServiceFailurePolicy.Apply(ServicePaths.ServiceName, leftover);
                notes.Add("возвращены действия, оставшиеся от прерванной команды");
            }

            _suspendedFailureActions = ServiceFailurePolicy.Suspend(ServicePaths.ServiceName, ServiceFailurePolicy.WriteSaved);
            notes.Add("действия при сбое службы сняты на время остановки (прежние записаны в реестр)");
            return StepResult.Done(string.Join("; ", notes));
        }
        catch (InvalidOperationException ex) when (IsNotInstalled(ex))
        {
            return StepResult.Skipped("служба не установлена");
        }
    }

    public StepResult RestoreFailureActions()
    {
        var snapshot = Interlocked.Exchange(ref _suspendedFailureActions, null) ?? FailureActionsSnapshot.Parse(ServiceFailurePolicy.ReadSaved());
        if (snapshot is null)
        {
            return StepResult.Skipped();
        }

        try
        {
            ServiceFailurePolicy.Apply(ServicePaths.ServiceName, snapshot);
        }
        catch (InvalidOperationException ex) when (IsNotInstalled(ex))
        {
            ServiceFailurePolicy.DeleteSaved();
            return StepResult.Skipped("служба не установлена");
        }

        ServiceFailurePolicy.DeleteSaved();
        return StepResult.Done("действия при сбое службы возвращены");
    }

    private static bool IsNotInstalled(Exception ex) =>
        ex.InnerException is System.ComponentModel.Win32Exception { NativeErrorCode: (int)ServiceDoesNotExist };

    public ServiceSnapshot? QueryService()
    {
        try
        {
            var (pid, state) = SystemMetrics.ServiceStatus(ServicePaths.ServiceName);
            return new ServiceSnapshot(state switch
            {
                "SERVICE_STOPPED" => ServiceRunState.Stopped,
                "SERVICE_RUNNING" => ServiceRunState.Running,
                _ => ServiceRunState.Pending,
            }, pid);
        }
        catch (NativeCallException ex) when (ex.Code == ServiceDoesNotExist)
        {
            return null;
        }
    }

    public void RequestStop()
    {
        using var service = new ServiceController(ServicePaths.ServiceName);
        if (service.Status is not (ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending))
        {
            service.Stop();
        }
    }

    public void RequestStart()
    {
        using var service = new ServiceController(ServicePaths.ServiceName);
        if (service.Status is ServiceControllerStatus.Stopped)
        {
            service.Start();
        }
    }

    public bool KillServiceProcess(uint processId, TimeSpan wait)
    {
        Process process;
        try
        {
            process = Process.GetProcessById((int)processId);
        }
        catch (ArgumentException)
        {
            return true;
        }

        using (process)
        {
            // Дескриптор удерживается, и номер сверяется с файлом: номер мог достаться другому процессу.
            _ = process.Handle;
            if (!string.Equals(Path.GetFileName(ProcessImage.TryGetPath(process)), ServicePaths.ImageName, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException($"процесс {processId} — уже не служба");
            }

            process.Kill(entireProcessTree: true);
            return process.WaitForExit(wait);
        }
    }

    public int KillOwnServiceProcesses() => SystemSshTunnelOps.StopOwn(_serviceImage, Environment.ProcessId, IsServiceHostProcess);

    public int CountOwnServiceProcesses() => SystemSshTunnelOps.FindOwn(_serviceImage, Environment.ProcessId, IsServiceHostProcess).Count;

    private static bool IsServiceHostProcess(int processId) => IsServiceHost(ProcessImage.TryGetArguments(processId));

    /// <summary>
    /// Процесс SplitVpn.Service.exe — служба (или её запуск без аргументов), а не другая команда из того же файла: команда
    /// восстановления (emergency-off/-on, recover — первый аргумент, как у <see cref="ServiceRecovery.IsRecoveryCommand"/>)
    /// не завершается — её мог запустить, например, установщик или вторая копия «Восстановить сеть». Командную строку не
    /// прочитать (<paramref name="arguments"/> = null) — процесс считается службой: живая служба опаснее.
    /// </summary>
    internal static bool IsServiceHost(IReadOnlyList<string>? arguments) =>
        arguments is null || arguments.Count < 2 || !ServiceRecovery.IsRecoveryCommand(arguments[1]);

    public StepResult StopHelpers() => FromRecovery(NetworkRecovery.StopHelpers(serviceDirectory), "процессов помощников нет");

    /// <summary>
    /// Флаг приостановки защиты в state.json. Каталог данных только проверяется (владелец и DACL, без исправления и без
    /// рекурсивного обхода прав): недоверенному каталогу состояние не пишется, шаг — предупреждение.
    /// </summary>
    public StepResult SuspendProtection()
    {
        var trust = DataRootTrust.Check(paths.Root, paths.DnsBackup);
        if (trust.Problem is { } problem)
        {
            return StepResult.Failed("каталог данных недоверенный (" + problem + "): состояние не записано");
        }

        if (!trust.Exists)
        {
            return StepResult.Skipped("каталога данных нет: приостанавливать нечего");
        }

        var stores = new ServiceStores(paths) { OnCorrupt = file => Console.Error.WriteLine(file.Describe()) };
        var state = stores.LoadState();
        if (state.ProtectionSuspended)
        {
            return StepResult.Already("защита уже приостановлена");
        }

        stores.SaveState(state with { ProtectionSuspended = true });
        return StepResult.Done("защита приостановлена до «Подключить»");
    }

    public StepResult RemoveFilters() => FromRecovery(NetworkRecovery.RemoveFilters([WfpIdentity.Product]), "фильтров программы нет");

    public async Task<StepResult> HangUpConnectionsAsync(CancellationToken cancellationToken) =>
        FromRecovery(await NetworkRecovery.CloseConnectionsAsync([paths.Phonebook], cancellationToken), "соединений программы нет");

    public StepResult RemoveRoutes() => FromRecovery(NetworkRecovery.RemoveRoutes(), "маршрутов программы нет");

    /// <summary>
    /// DNS адаптеров. Сначала — проверка каталога данных только чтением (владелец и DACL каталога и dns-backup.json): от неё
    /// зависят и копия DNS, и разрешение удалить данные при удалении программы (<see cref="Trusted"/>).
    /// </summary>
    public StepResult RestoreDns(bool serviceStopped)
    {
        var trust = DataRootTrust.Check(paths.Root, paths.DnsBackup);
        _trusted = trust.Problem is null;
        var result = FromRecovery(NetworkRecovery.RestoreDns(new RecoveryOptions
        {
            // Копии из недоверенного каталога не верим: её мог подложить пользователь, и DNS ушёл бы на его серверы.
            // Каталога нет — читать нечего (и он не появится чужим между проверкой и чтением).
            DnsBackupPath = _trusted && trust.Exists ? paths.DnsBackup : null,
        }, serviceStopped), "DNS адаптеров уже обычный");
        return trust.Problem is { } problem
            ? result with { Detail = string.Join("; ", new[] { result.Detail, "копия DNS не использована: каталог данных " + problem }.Where(d => !string.IsNullOrEmpty(d))) }
            : result;
    }

    public StepResult RestoreWcm() => WcmBadStateTracking.Restore()
        ? StepResult.Done("EnableBadStateTracking возвращено")
        : StepResult.Already("настройка не менялась или уже возвращена");

    public StepResult FlushDns() => NetworkRecovery.FlushDns()
        ? StepResult.Done()
        : StepResult.Failed("ipconfig /flushdns не подтвердил сброс за 10 секунд");

    private static StepResult FromRecovery(RecoveryStepResult result, string nothing)
    {
        var detail = string.Join("; ", result.Actions.Concat(result.Errors));
        if (!result.Success)
        {
            return StepResult.Failed(detail);
        }

        return result.Count > 0 || result.Actions.Count > 0
            ? StepResult.Done(detail.Length > 0 ? detail : string.Create(CultureInfo.InvariantCulture, $"снято: {result.Count}"))
            : StepResult.Already(nothing);
    }

    /// <summary>
    /// Именованный мьютекс принадлежит потоку, а команда асинхронная: захват и освобождение — в своём потоке. Право
    /// SeCreateGlobalPrivilege нужно только для объектов-разделов (file mapping) в Global\, а мьютекс там может создать и
    /// обычный пользователь — и держать его сколько угодно. Поэтому блокировка не обязательна: не получена за срок
    /// ожидания — команда выполняется без неё (EmergencyOrchestrator), а в итоге об этом сказано.
    /// </summary>
    private sealed class MutexLock : IDisposable
    {
        private readonly ManualResetEventSlim _release = new();
        private readonly Thread _thread;

        private MutexLock(Thread thread) => _thread = thread;

        public static MutexLock? TryAcquire(string name, TimeSpan wait)
        {
            using var acquired = new ManualResetEventSlim();
            var owned = false;
            Exception? failure = null;
            MutexLock? holder = null;
            var thread = new Thread(() =>
            {
                try
                {
                    using var mutex = new Mutex(false, name);
                    try
                    {
                        owned = mutex.WaitOne(wait);
                    }
                    catch (AbandonedMutexException)
                    {
                        // Прежний владелец завершился, не отпустив: блокировка наша.
                        owned = true;
                    }

                    acquired.Set();
                    if (!owned)
                    {
                        return;
                    }

                    holder!._release.Wait();
                    mutex.ReleaseMutex();
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or WaitHandleCannotBeOpenedException)
                {
                    failure = ex;
                    acquired.Set();
                }
            }) { IsBackground = true, Name = "SplitVpn.Recovery lock" };
            holder = new MutexLock(thread);
            thread.Start();
            acquired.Wait();
            if (failure is not null)
            {
                throw new IOException("Блокировка команд недоступна: " + failure.Message, failure);
            }

            if (!owned)
            {
                holder._release.Dispose();
                return null;
            }

            return holder;
        }

        public void Dispose()
        {
            _release.Set();
            _thread.Join(TimeSpan.FromSeconds(5));
            _release.Dispose();
        }
    }
}
