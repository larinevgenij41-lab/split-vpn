using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using SplitVpn.Core.Settings;
using SplitVpn.Windows.Diagnostics;
using SplitVpn.Windows.Recovery;
using SplitVpn.Windows.Security;
using SplitVpn.Windows.Wfp;

namespace SplitVpn.Service;

/// <summary>Что делает команда recover.</summary>
public enum RecoveryMode
{
    /// <summary>«recover»: снять изменения в сети и приостановить защиту до «Подключить».</summary>
    Recover,

    /// <summary>
    /// «recover ‐‐uninstall»: удаление программы целиком — сеть, затем данные и ключ реестра. Остаётся для
    /// скриптов разработки (cleanup-dev.ps1); установщик так больше не вызывает.
    /// </summary>
    Uninstall,

    /// <summary>
    /// «recover ‐‐uninstall-network»: шаг удаления программы в установщике (до StopServices). Сеть возвращается, а
    /// данные и ключ реестра остаются: их удаляет отдельное действие установщика уже после фиксации удаления
    /// (Execute="commit"), чтобы отменённое или откаченное удаление вернуло программу с настройками и паролями.
    /// Разрешение на это удаление — значение <see cref="PurgeMarkName"/> в ключе программы.
    /// </summary>
    UninstallNetwork,
}

/// <summary>
/// Команда «SplitVpn.Service.exe recover»: приостанавливает защиту, останавливает службу без её
/// автоперезапуска и снимает все изменения приложения. Флаг приостановки снимается действием «Подключить».
/// </summary>
public static class ServiceRecovery
{
    /// <summary>
    /// Значение в HKLM\Software\SplitVpn: сеть при удалении возвращена полностью, а каталог данных свой и защищён,
    /// поэтому его можно удалить после фиксации удаления. Его читает действие установщика (Package.wxs, PurgeData):
    /// без него данные остаются — копия исходных DNS ещё нужна повторному восстановлению. Ключ HKLM пишут только
    /// администраторы и SYSTEM.
    /// </summary>
    internal const string PurgeMarkName = "PurgeData";

    /// <summary>Режим по аргументам после «recover».</summary>
    public static RecoveryMode ParseMode(IReadOnlyCollection<string> args) =>
        args.Contains("--uninstall-network", StringComparer.OrdinalIgnoreCase) ? RecoveryMode.UninstallNetwork
        : args.Contains("--uninstall", StringComparer.OrdinalIgnoreCase) ? RecoveryMode.Uninstall
        : RecoveryMode.Recover;

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

    public static async Task<int> RunAsync(ServicePaths paths, RecoveryMode mode)
    {
        var uninstall = mode != RecoveryMode.Recover;
        using var deadline = new CancellationTokenSource(Watchdog);
        var work = Task.Run(() => RunCoreAsync(paths, mode, deadline.Token), CancellationToken.None);
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
            if (uninstall) WriteUninstallLog("Восстановление сети не уложилось в отведённое время и прервано.", trusted: false);
            return 1;
        }
        catch (Exception ex)
        {
            // Ни зависание, ни неожиданная ошибка не должны оставить удаление программы без ответа:
            // выходим с ненулевым кодом, вернув службе автоперезапуск, если успели его сбросить.
            Console.Error.WriteLine("Восстановление сети прервано ошибкой: " + ex.Message);
            if (uninstall) WriteUninstallLog("Восстановление сети прервано ошибкой: " + ex.Message, trusted: false);
            return 1;
        }
    }

    private static async Task<int> RunCoreAsync(ServicePaths paths, RecoveryMode mode, CancellationToken cancellationToken)
    {
        // Разрешение удалить данные даёт только этот запуск: прежнее (от отменённого удаления) снимается первым делом.
        // Не снялось - сеть всё равно возвращается (без неё удаление оставило бы человека без интернета), а сбой
        // попадает в журнал удаления.
        var staleMarkCleared = mode == RecoveryMode.Recover || TryStep("прежняя отметка очистки данных", ClearPurgeMark);

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

        var json = JsonSerializer.Serialize(report, JsonDefaults.Options);
        Console.WriteLine(json);
        if (mode == RecoveryMode.Recover)
        {
            return report.Success && suspended ? 0 : 1;
        }

        // Удаление программы. Флаг приостановки, записанный выше, остаётся: если удаление отменят, служба (её
        // остановил recover, а не MSI, поэтому откат может её и не запустить — тогда она стартует при загрузке)
        // ничего не применит до «Подключить», как после обычного восстановления; настройки и пароли при этом целы.
        // Данные удаляются, только если сеть возвращена полностью: иначе копия исходных DNS ещё нужна
        // повторному восстановлению. Каталог, который не удалось защитить, не удаляется рекурсивно.
        // Настройка Wi-Fi Windows возвращается при любом исходе: она не зависит от сети и данных программы, а
        // прежнее значение записано в ключе программы, который удаляется позже. При отмене удаления служба
        // при следующем запуске ставит её снова.
        var wifiRestored = TryStep("настройка Wi-Fi Windows", RestoreWifiBadStateTracking);
        var cleanable = report.Success && trusted && wifiRestored && staleMarkCleared;
        bool cleaned;
        if (mode == RecoveryMode.UninstallNetwork)
        {
            // Данные и ключ реестра удаляет установщик после фиксации удаления: здесь только разрешение на это.
            cleaned = cleanable && TryStep("отметка очистки данных", SetPurgeMark);
        }
        else
        {
            cleaned = cleanable && (TryStep("данные", () => DeleteData(paths.Root)) & TryStep("реестр", DeleteRegistryKey));
        }

        if (!cleaned)
        {
            WriteUninstallLog(staleMarkCleared ? json : "Прежняя отметка очистки данных не снята." + Environment.NewLine + json, trusted);
        }

        return cleaned ? 0 : 1;
    }

    /// <summary>
    /// Установщик не прерывает удаление программы при сбое восстановления (иначе её нельзя удалить вовсе,
    /// как было с 0.17.2), поэтому причина сбоя остаётся в файле вне каталога программы и её данных: каталог
    /// данных удаление стирает. Пишет SYSTEM, поэтому не в общий %WINDIR%\Temp под постоянным именем (там
    /// пользователь заранее создаёт файл или ссылку), а в свой каталог с правами только SYSTEM и Administrators.
    /// </summary>
    public static string UninstallLogDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SplitVpn.Uninstall");

    private static bool TryStep(string name, Action action)
    {
        try
        {
            action();
            return true;
        }
        catch (IOException ex)
        {
            Console.Error.WriteLine(name + ": " + ex.Message);
            return false;
        }
    }

    private static void WriteUninstallLog(string report, bool trusted)
    {
        var text = string.Create(CultureInfo.InvariantCulture,
            $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} удаление программы: сеть или данные очищены не полностью (каталог данных защищён: {trusted}).{Environment.NewLine}{report}{Environment.NewLine}");
        if (WriteUninstallLog(UninstallLogDirectory, text, SecretStore.SecureDataRoot, HasTrustedOwner) is { } path)
        {
            Console.Error.WriteLine("Журнал удаления: " + path);
        }
    }

    /// <summary>
    /// Записывает журнал удаления новым файлом в каталог <paramref name="directory"/>; null — не записан. Каталог,
    /// который уже есть и при этом оказался ссылкой, файлом или принадлежит посторонней учётной записи, не
    /// используется: его подготовил не установщик, и запись от SYSTEM ушла бы туда, куда укажет пользователь.
    /// Нового каталога нет — он создаётся сразу с правами только SYSTEM и Administrators (<paramref name="secure"/>,
    /// в службе — <see cref="SecretStore.SecureDataRoot"/>). Файл — с уникальным именем и FileMode.CreateNew:
    /// заранее созданный объект с тем же именем не открывается.
    /// </summary>
    internal static string? WriteUninstallLog(string directory, string text, Func<string, IReadOnlyList<string>> secure, Func<DirectoryInfo, bool> trustedOwner)
    {
        try
        {
            if (ForeignLogDirectory(directory, trustedOwner) is { } before)
            {
                Console.Error.WriteLine($"Журнал удаления не записан: каталог {directory} {before}.");
                return null;
            }

            foreach (var warning in secure(directory)) Console.Error.WriteLine(warning);

            // Каталог мог появиться между проверкой и созданием: после защиты он проверяется ещё раз.
            var after = Directory.Exists(directory) ? ForeignLogDirectory(directory, trustedOwner) : "не создан";
            if (after is not null)
            {
                Console.Error.WriteLine($"Журнал удаления не записан: каталог {directory} {after}.");
                return null;
            }

            var path = Path.Combine(directory, string.Create(CultureInfo.InvariantCulture,
                $"uninstall-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.log"));
            using var stream = new FileStream(path, new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
            });
            using var writer = new StreamWriter(stream, new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
            writer.Write(text);
            return path;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException
            or System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            Console.Error.WriteLine("Журнал удаления не записан: " + ex.Message);
            return null;
        }
    }

    /// <summary>Почему в уже существующий каталог журнала писать нельзя; null — каталога нет или он свой.</summary>
    private static string? ForeignLogDirectory(string directory, Func<DirectoryInfo, bool> trustedOwner)
    {
        if (File.Exists(directory))
        {
            return "оказался файлом";
        }

        var info = new DirectoryInfo(directory);
        if (!info.Exists)
        {
            return null;
        }

        if (info.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            return "оказался ссылкой на другой путь";
        }

        return trustedOwner(info) ? null : "принадлежит посторонней учётной записи";
    }

    private static bool HasTrustedOwner(DirectoryInfo directory) =>
        directory.GetAccessControl(System.Security.AccessControl.AccessControlSections.Owner)
                .GetOwner(typeof(System.Security.Principal.SecurityIdentifier)) is System.Security.Principal.SecurityIdentifier owner
            && (owner.IsWellKnown(System.Security.Principal.WellKnownSidType.LocalSystemSid)
                || owner.IsWellKnown(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid));

    /// <summary>Разрешение установщику удалить данные после фиксации удаления (<see cref="PurgeMarkName"/>).</summary>
    private static void SetPurgeMark()
    {
        try
        {
            using var root = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64);
            using var key = root.CreateSubKey(Core.Ipc.IpcNames.RegistryKey, writable: true);
            key.SetValue(PurgeMarkName, 1, Microsoft.Win32.RegistryValueKind.DWord);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            throw new IOException("Отметка очистки данных не записана: " + ex.Message, ex);
        }
    }

    /// <summary>
    /// Обычный старт службы снимает отметку <see cref="PurgeMarkName"/>: она остаётся от удаления, которое после
    /// «recover ‐‐uninstall-network» отменили или откатили (служба после этого снова запускается). Иначе следующее
    /// удаление, в котором восстановление сети не запустилось или не дошло до своей проверки, стёрло бы данные по
    /// устаревшему разрешению. Сбой не мешает запуску службы: только строка в журнал.
    /// </summary>
    public static void ClearStalePurgeMark(Action<string> warn) => ClearStalePurgeMark(ClearPurgeMark, warn);

    /// <summary>Шов для тестов: <paramref name="clear"/> снимает отметку; false - не снята (причина ушла в <paramref name="warn"/>).</summary>
    internal static bool ClearStalePurgeMark(Action clear, Action<string> warn)
    {
        try
        {
            clear();
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException
            or ObjectDisposedException or ArgumentException)
        {
            warn(ex.Message);
            return false;
        }
    }

    private static void ClearPurgeMark()
    {
        try
        {
            using var root = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64);
            using var key = root.OpenSubKey(Core.Ipc.IpcNames.RegistryKey, writable: true);
            key?.DeleteValue(PurgeMarkName, throwOnMissingValue: false);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            throw new IOException("Отметка очистки данных не снята: " + ex.Message, ex);
        }
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

    /// <summary>
    /// Возвращает настройку диспетчера подключений Windows, которую служба меняет при запуске
    /// (<see cref="Windows.Net.WcmBadStateTracking"/>). Только при удалении программы: после простого
    /// восстановления сети служба запустится снова и поставила бы её заново.
    /// </summary>
    private static void RestoreWifiBadStateTracking()
    {
        try
        {
            Windows.Net.WcmBadStateTracking.Restore();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            throw new IOException("Настройка EnableBadStateTracking не возвращена: " + ex.Message, ex);
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

    /// <summary>
    /// sc.exe — полным путём из System32 и с рабочим каталогом System32: по голому имени CreateProcess ищет файл
    /// и в текущем каталоге, а команду запускает SYSTEM (установщик), и подложенный там sc.exe выполнился бы от его имени.
    /// </summary>
    internal static ProcessStartInfo ScStartInfo(string arguments) => new(Path.Combine(Environment.SystemDirectory, "sc.exe"), arguments)
    {
        CreateNoWindow = true,
        UseShellExecute = false,
        RedirectStandardOutput = true,
        WorkingDirectory = Environment.SystemDirectory,
    };

    private static int RunSc(string arguments)
    {
        using var process = Process.Start(ScStartInfo(arguments))!;
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
