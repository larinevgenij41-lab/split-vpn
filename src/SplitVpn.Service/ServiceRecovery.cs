using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using SplitVpn.Core.Recovery;
using SplitVpn.Core.Settings;
using SplitVpn.Windows.Diagnostics;
using SplitVpn.Windows.Recovery;
using SplitVpn.Windows.Security;
using SplitVpn.Windows.Wfp;

namespace SplitVpn.Service;

/// <summary>Что делает команда recover.</summary>
public enum RecoveryMode
{
    /// <summary>«recover» без ключей: то же, что «emergency-off» (экстренное отключение программы).</summary>
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
    /// Разрешение на это удаление — значение <see cref="ServiceRecovery.PurgeMarkName"/> в ключе программы.
    /// </summary>
    UninstallNetwork,

    /// <summary>«emergency-off»: экстренное отключение (см. <see cref="Emergency.EmergencyOrchestrator"/>).</summary>
    EmergencyOff,

    /// <summary>«emergency-on»: снять экстренное отключение и запустить службу.</summary>
    EmergencyOn,
}

/// <summary>
/// Команды восстановления SplitVpn.Service.exe: экстренное отключение и включение программы (emergency-off/-on, recover)
/// и сетевой шаг удаления программы (recover ‐‐uninstall-network). Шаги и их порядок — в
/// <see cref="Emergency.EmergencyOrchestrator"/>; здесь — разбор команды, отчёт и действия удаления с данными.
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

    /// <summary>Первый аргумент — команда восстановления.</summary>
    public static bool IsRecoveryCommand(string argument) =>
        string.Equals(argument, EmergencyCommands.RecoverAlias, StringComparison.OrdinalIgnoreCase)
        || string.Equals(argument, EmergencyCommands.Off, StringComparison.OrdinalIgnoreCase)
        || string.Equals(argument, EmergencyCommands.On, StringComparison.OrdinalIgnoreCase);

    /// <summary>Режим по аргументам (первый — сама команда).</summary>
    public static RecoveryMode ParseMode(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        var command = args.Count > 0 ? args[0] : "";
        if (string.Equals(command, EmergencyCommands.On, StringComparison.OrdinalIgnoreCase))
        {
            return RecoveryMode.EmergencyOn;
        }

        if (string.Equals(command, EmergencyCommands.Off, StringComparison.OrdinalIgnoreCase))
        {
            return RecoveryMode.EmergencyOff;
        }

        return args.Contains("--uninstall-network", StringComparer.OrdinalIgnoreCase) ? RecoveryMode.UninstallNetwork
            : args.Contains("--uninstall", StringComparer.OrdinalIgnoreCase) ? RecoveryMode.Uninstall
            : RecoveryMode.Recover;
    }

    /// <summary>Сторож времени удаления программы: оставшиеся шаги пропускаются, удаление не висит на восстановлении.</summary>
    private static readonly TimeSpan Watchdog = TimeSpan.FromMinutes(3);

    /// <summary>Запас на завершение уже начатых шагов после срабатывания сторожа.</summary>
    private static readonly TimeSpan WatchdogGrace = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Если срок восстановления уже истёк, отложенная работа не начинает очистку данных.
    /// </summary>
    private static readonly Lock FinishGate = new();
    private static bool _abandoned;

    /// <param name="reportId">
    /// Метка запуска (<see cref="EmergencyCommands.ReportIdOption"/>) для emergency-off/-on: повторяется в отчёте, чтобы
    /// запустивший отличил свой отчёт от прежнего или подложенного.
    /// </param>
    public static async Task<int> RunAsync(ServicePaths paths, RecoveryMode mode, Guid? reportId = null)
    {
        if (mode is RecoveryMode.Recover or RecoveryMode.EmergencyOff or RecoveryMode.EmergencyOn)
        {
            return await RunEmergencyAsync(paths, mode == RecoveryMode.EmergencyOn, reportId);
        }

        using var deadline = new CancellationTokenSource(Watchdog);
        var work = Task.Run(() => RunUninstallAsync(paths, mode, deadline.Token), CancellationToken.None);
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
            WriteUninstallLog("Восстановление сети не уложилось в отведённое время и прервано.", trusted: false);
            PreserveNetworkRecovery(mode, null);
            return 1;
        }
        catch (Exception ex)
        {
            // Ни зависание, ни неожиданная ошибка не должны оставить удаление программы без ответа.
            Console.Error.WriteLine("Восстановление сети прервано ошибкой: " + ex.Message);
            WriteUninstallLog("Восстановление сети прервано ошибкой: " + ex.Message, trusted: false);
            PreserveNetworkRecovery(mode, null);
            return 1;
        }
    }

    /// <summary>
    /// Экстренное отключение или включение: отчёт — в stdout и в защищённый каталог (<see cref="EmergencyReportFiles"/>),
    /// код завершения — <see cref="EmergencyExitCodes"/>. У каждого шага свой срок, а у команды — общий, из договора
    /// (<see cref="EmergencyTimeouts.OffWorstCase"/>, <see cref="EmergencyTimeouts.OnWorstCase"/>).
    /// </summary>
    private static async Task<int> RunEmergencyAsync(ServicePaths paths, bool on, Guid? reportId)
    {
        try
        {
            var system = new Emergency.SystemEmergency(paths, AppContext.BaseDirectory);
            var orchestrator = new Emergency.EmergencyOrchestrator(system, new Emergency.EmergencyOptions());
            var report = on ? await orchestrator.OnAsync(CancellationToken.None, reportId) : await orchestrator.OffAsync(CancellationToken.None, reportId);
            var json = JsonSerializer.Serialize(report, JsonDefaults.Options);
            if (report.ExitCode != EmergencyExitCodes.NotElevated)
            {
                // Без прав администратора в защищённый каталог не записать. Не записался отчёт — он есть только в выводе
                // команды, и итог об этом говорит.
                if (Emergency.EmergencyReportWriter.Write(EmergencyReportFiles.DefaultDirectory, json,
                    Emergency.EmergencyReportWriter.SecureDirectory, HasTrustedOwner, Console.Error.WriteLine) is { } path)
                {
                    Console.Error.WriteLine("Отчёт: " + path);
                }
                else
                {
                    report = report with { Summary = report.Summary + " " + Emergency.EmergencyReportWriter.NotWrittenNote };
                    json = JsonSerializer.Serialize(report, JsonDefaults.Options);
                }
            }

            Console.WriteLine(json);
            Console.Error.WriteLine(report.Summary);
            return report.ExitCode;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Команда прервана непредвиденной ошибкой: " + ex.Message);
            return EmergencyExitCodes.Unexpected;
        }
    }

    private static async Task<int> RunUninstallAsync(ServicePaths paths, RecoveryMode mode, CancellationToken cancellationToken)
    {
        // Разрешение удалить данные даёт только этот запуск: прежнее (от отменённого удаления) снимается первым делом.
        // Не снялось - сеть всё равно возвращается (без неё удаление оставило бы человека без интернета), а сбой
        // попадает в журнал удаления.
        var staleMarkCleared = TryStep("прежняя отметка очистки данных", ClearPurgeMark);
        if (mode == RecoveryMode.UninstallNetwork)
        {
            ClearNetworkPendingFlag(UninstallLogDirectory, HasTrustedOwner, Console.Error.WriteLine);
        }

        // Те же шаги, что у экстренного отключения (остановка службы с запасными путями, затем сеть, начиная с WFP), но без
        // отметки отключения и без смены типа запуска: удаление, которое отменят, вернёт программу как была. Флаг
        // приостановки защиты в состоянии остаётся: служба после отмены ничего не применит до «Подключить».
        var system = new Emergency.SystemEmergency(paths, AppContext.BaseDirectory);
        var orchestrator = new Emergency.EmergencyOrchestrator(system, new Emergency.EmergencyOptions());
        var report = await orchestrator.UninstallNetworkAsync(cancellationToken);

        lock (FinishGate)
        {
            if (_abandoned)
            {
                // Сторож уже сообщил о прерывании: ни отчёта об успехе, ни удаления данных.
                return 1;
            }
        }

        // Данные удаляются, только если сеть возвращена полностью (вместе с настройкой Wi-Fi Windows) и служба
        // подтверждённо остановлена: иначе копия исходных DNS ещё нужна повторному восстановлению, а работающая служба
        // осталась бы без данных. Каталог, который не удалось защитить, не удаляется рекурсивно.
        var trusted = system.Trusted;
        var cleanable = MayPurgeData(report, trusted, staleMarkCleared);

        var finish = FinishUninstall(mode, cleanable, report.Steps, new UninstallActions(
            SetPurgeMark,
            () => DeleteData(paths.Root),
            DeleteRegistryKey,
            () => DeleteSecretFiles(paths.Root, HasTrustedOwner),
            () => DeleteRasEntries(paths.Phonebook)), RasEntriesTimeout);
        var cleaned = finish.Cleaned;
        report = report with { Steps = [.. report.Steps, finish.Secrets, finish.RasEntries] };

        var json = JsonSerializer.Serialize(report, JsonDefaults.Options);
        Console.WriteLine(json);

        if (!cleaned)
        {
            WriteUninstallLog(staleMarkCleared ? json : "Прежняя отметка очистки данных не снята." + Environment.NewLine + json, trusted);
        }

        if (NetworkIncomplete(report))
        {
            PreserveNetworkRecovery(mode, report.Steps);
        }

        return cleaned ? 0 : 1;
    }

    /// <summary>Сеть возвращена не полностью: не каждый сетевой шаг есть в отчёте и выполнен (<see cref="Emergency.EmergencyOrchestrator.IsNetworkClean"/>).</summary>
    internal static bool NetworkIncomplete(EmergencyReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        return !(report.NetworkClean && Emergency.EmergencyOrchestrator.IsNetworkClean(report.Steps));
    }

    /// <summary>Скрипт последнего средства (scripts\recover-network.*): ему не нужен SplitVpn.Service.exe.</summary>
    internal static readonly string[] RecoveryScriptNames = ["recover-network.ps1", "recover-network.cmd"];

    /// <summary>
    /// Удаление программы из установщика (<see cref="RecoveryMode.UninstallNetwork"/>) вернуло сеть не полностью, а MSI всё
    /// равно удаляет службу, её exe и scripts\recover-network.*: DNS адаптеров на 127.0.0.1 (сохраняемая настройка) и маршруты
    /// остались бы без инструмента, который прочтёт копию DNS (dns-backup.json остаётся в данных). Скрипт копируется рядом с
    /// журналом удаления (<see cref="UninstallLogDirectory"/>), и там же — понятная инструкция. Сбой — только в stderr.
    /// </summary>
    private static void PreserveNetworkRecovery(RecoveryMode mode, IReadOnlyList<EmergencyStepReport>? steps)
    {
        if (mode != RecoveryMode.UninstallNetwork)
        {
            return;
        }

        try
        {
            if (PreserveNetworkRecovery(UninstallLogDirectory, Path.Combine(AppContext.BaseDirectory, "scripts"), steps,
                SecretStore.SecureDataRoot, HasTrustedOwner, Console.Error.WriteLine) is { } note)
            {
                Console.Error.WriteLine("Как вернуть сеть: " + note);
            }
        }
        catch (Exception ex)
        {
            // Любой тип исключения: удаление программы не должно остаться без ответа из-за инструкции.
            Console.Error.WriteLine("Инструкция по возврату сети не записана: " + ex.Message);
        }
    }

    /// <summary>
    /// Копирует <see cref="RecoveryScriptNames"/> из <paramref name="scriptsDirectory"/> в <paramref name="directory"/> и пишет там
    /// инструкцию (новый файл network-not-restored-*.txt); ответ — путь инструкции или null. Каталог — по правилам
    /// <see cref="WriteProtectedFile"/>: чужой, ссылка или файл не используются. Прежняя копия скрипта (от прошлого неудачного
    /// удаления) заменяется: в каталог пишут только SYSTEM и Administrators, а ссылка с именем скрипта удаляется сама, не её цель.
    /// </summary>
    internal static string? PreserveNetworkRecovery(string directory, string scriptsDirectory, IReadOnlyList<EmergencyStepReport>? steps,
        Func<string, IReadOnlyList<string>> secure, Func<DirectoryInfo, bool> trustedOwner, Action<string> warn)
    {
        ArgumentNullException.ThrowIfNull(secure);
        ArgumentNullException.ThrowIfNull(warn);
        var copied = CopyRecoveryScripts(directory, scriptsDirectory, secure, trustedOwner, warn);
        if (copied)
        {
            SetNetworkPendingFlag(directory, warn);
        }

        var text = NetworkRecoveryNote(directory, copied, steps, DateTime.Now);
        return WriteProtectedFile(directory, string.Create(CultureInfo.InvariantCulture, $"network-not-restored-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.txt"),
            text, secure, trustedOwner, new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: true), "Инструкция по возврату сети", warn);
    }

    /// <summary>
    /// Отметка «сеть этого удаления не возвращена» с постоянным именем: по ней действие установщика может запустить
    /// скопированный скрипт (имя инструкции уникально, а копия скрипта остаётся и от прежних удалений). Снимается в начале
    /// каждого «recover ‐‐uninstall-network» (<see cref="ClearNetworkPendingFlag"/>).
    /// </summary>
    internal const string NetworkPendingFlagName = "network-not-restored.flag";

    private static void SetNetworkPendingFlag(string directory, Action<string> warn)
    {
        try
        {
            var path = Path.Combine(directory, NetworkPendingFlagName);
            File.Delete(path);
            File.WriteAllText(path, DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            warn("Отметка невозвращённой сети не записана: " + ex.Message);
        }
    }

    /// <summary>Снимает <see cref="NetworkPendingFlagName"/> прежнего удаления; каталог чужой или ссылка — не трогается.</summary>
    internal static void ClearNetworkPendingFlag(string directory, Func<DirectoryInfo, bool> trustedOwner, Action<string> warn)
    {
        ArgumentNullException.ThrowIfNull(warn);
        try
        {
            if (Directory.Exists(directory) && ForeignLogDirectory(directory, trustedOwner) is null)
            {
                File.Delete(Path.Combine(directory, NetworkPendingFlagName));
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or InvalidOperationException)
        {
            warn("Прежняя отметка невозвращённой сети не снята: " + ex.Message);
        }
    }

    private static bool CopyRecoveryScripts(string directory, string scriptsDirectory, Func<string, IReadOnlyList<string>> secure,
        Func<DirectoryInfo, bool> trustedOwner, Action<string> warn)
    {
        try
        {
            if (ForeignLogDirectory(directory, trustedOwner) is { } before)
            {
                warn($"Скрипт возврата сети не скопирован: каталог {directory} {before}.");
                return false;
            }

            foreach (var warning in secure(directory)) warn(warning);
            var after = Directory.Exists(directory) ? ForeignLogDirectory(directory, trustedOwner) : "не создан";
            if (after is not null)
            {
                warn($"Скрипт возврата сети не скопирован: каталог {directory} {after}.");
                return false;
            }

            var all = true;
            foreach (var name in RecoveryScriptNames)
            {
                var source = Path.Combine(scriptsDirectory, name);
                if (!File.Exists(source))
                {
                    warn("Скрипт возврата сети не скопирован: нет файла " + source + ".");
                    all = false;
                    continue;
                }

                var target = Path.Combine(directory, name);
                if (Directory.Exists(target))
                {
                    warn("Скрипт возврата сети не скопирован: на месте " + target + " каталог.");
                    all = false;
                    continue;
                }

                // Копия от прошлого неудачного удаления (или ссылка с тем же именем) удаляется сама; новая копия — CreateNew.
                File.Delete(target);
                File.Copy(source, target, overwrite: false);
            }

            return all;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException
            or System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            warn("Скрипт возврата сети не скопирован: " + ex.Message);
            return false;
        }
    }

    /// <summary>Текст инструкции: что не вернулось и как вернуть сеть без программы.</summary>
    internal static string NetworkRecoveryNote(string directory, bool scriptsCopied, IReadOnlyList<EmergencyStepReport>? steps, DateTime now)
    {
        var text = new System.Text.StringBuilder();
        text.AppendLine(CultureInfo.InvariantCulture, $"Удаление «Раздельного VPN» {now:dd.MM.yyyy HH:mm}: обычная сеть возвращена не полностью.");
        text.AppendLine();
        var failed = steps?.Where(s => s.Required && !s.Succeeded).ToList() ?? [];
        if (steps is null)
        {
            text.AppendLine("Возврат сети прерван (не уложился в срок или завершился ошибкой) — что именно не выполнено, неизвестно.");
        }
        else if (failed.Count > 0)
        {
            text.AppendLine("Не выполнено:");
            foreach (var step in failed)
            {
                text.AppendLine(CultureInfo.InvariantCulture, $"  - {step.Title}{(string.IsNullOrWhiteSpace(step.Detail) ? "" : ": " + step.Detail)}");
            }
        }
        else
        {
            text.AppendLine("Не все шаги возврата сети подтвердили успех (подробности — в журнале uninstall-*.log в этом каталоге).");
        }

        text.AppendLine();
        text.AppendLine("Что могло остаться: DNS адаптеров на 127.0.0.1 (без программы такой DNS не отвечает, сайты не открываются, и");
        text.AppendLine("перезагрузка этого не исправит), маршруты программы, фильтры защиты (их Windows перестаёт применять после");
        text.AppendLine("перезагрузки: служба программы удалена). Исходные DNS сохранены в %ProgramData%\\SplitVpn\\dns-backup.json.");
        text.AppendLine();
        text.AppendLine("Как вернуть сеть:");
        text.AppendLine("  1. Перезагрузите компьютер.");
        if (scriptsCopied)
        {
            text.AppendLine("  2. Если интернет не появился, откройте командную строку от имени администратора и выполните:");
            text.AppendLine("       powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"" + Path.Combine(directory, RecoveryScriptNames[0]) + "\"");
            text.AppendLine("     Скрипт вернёт DNS адаптеров по сохранённой копии (а без копии — на «автоматически»), снимет маршруты");
            text.AppendLine("     программы и сбросит кеш DNS. Программа для этого не нужна.");
        }
        else
        {
            text.AppendLine("  2. Если интернет не появился: «Параметры» → «Сеть и Интернет» → свойства адаптера → «Назначение DNS-сервера» —");
            text.AppendLine("     «Автоматически (DHCP)» (или прежние адреса DNS) для каждого адаптера, где указан 127.0.0.1.");
            text.AppendLine("     Скрипт возврата сети в этот каталог скопировать не удалось.");
        }

        text.AppendLine();
        text.AppendLine("Если программу установят снова, может понадобиться «Включить программу»: скрипт оставляет отметку экстренного");
        text.AppendLine("отключения. Когда сеть вернётся, каталоги %ProgramData%\\SplitVpn и %ProgramData%\\SplitVpn.Uninstall можно удалить.");
        return text.ToString();
    }

    /// <summary>
    /// Можно ли разрешить удаление данных (<see cref="PurgeMarkName"/>) или удалить их самим: команда завершилась успехом,
    /// каждый сетевой шаг есть в отчёте и выполнен (шаг, не запущенный из-за общего срока, — «timeout», не успех),
    /// служба подтверждённо остановлена, каталог данных свой и защищён, прежняя отметка снята. Иначе копия исходных DNS
    /// (dns-backup.json) ещё нужна повторному восстановлению.
    /// </summary>
    internal static bool MayPurgeData(EmergencyReport report, bool trusted, bool staleMarkCleared)
    {
        ArgumentNullException.ThrowIfNull(report);
        return report.ExitCode == EmergencyExitCodes.Success && report.NetworkClean && report.ServiceConfirmed && trusted && staleMarkCleared
            && Emergency.EmergencyOrchestrator.IsNetworkClean(report.Steps);
    }

    /// <summary>
    /// Установщик не прерывает удаление программы при сбое восстановления (иначе её нельзя удалить вовсе,
    /// как было с 0.17.2), поэтому причина сбоя остаётся в файле вне каталога программы и её данных: каталог
    /// данных удаление стирает. Пишет SYSTEM, поэтому не в общий %WINDIR%\Temp под постоянным именем (там
    /// пользователь заранее создаёт файл или ссылку), а в свой каталог с правами только SYSTEM и Administrators.
    /// </summary>
    public static string UninstallLogDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SplitVpn.Uninstall");

    /// <summary>Шаги удаления программы, которых нет у экстренного отключения: в отчёте «recover ‐‐uninstall-network».</summary>
    internal const string UninstallRasStep = "uninstall-ras-entries";

    internal const string UninstallSecretsStep = "uninstall-secrets";

    private const string SecretsStepTitle = "Пароли и ключи на диске";

    /// <summary>Основной файл паролей: ключи IPsec и SSH — рядом с ним (secrets.bin.ipsec, secrets.bin.sshkey).</summary>
    internal const string SecretsFileName = "secrets.bin";

    private const string RasEntriesStepTitle = "Записи RAS программы";

    /// <summary>
    /// Срок удаления записей RAS: RasEnumEntries и RasDeleteEntry синхронны и при зависшей службе RasMan ждали бы
    /// бесконечно, а сторож удаления (<see cref="Watchdog"/>) тогда бросил бы весь запуск без отчёта. Укладывается в
    /// запас сторожа (<see cref="WatchdogGrace"/>).
    /// </summary>
    internal static readonly TimeSpan RasEntriesTimeout = TimeSpan.FromSeconds(15);

    /// <summary>Действия завершения удаления программы; в тестах подменяются.</summary>
    internal sealed record UninstallActions(
        Action SetPurgeMark,
        Action DeleteData,
        Action DeleteRegistry,
        Func<string> DeleteSecrets,
        Func<string> DeleteRasEntries);

    /// <summary>Итог завершения удаления: разрешена (или выполнена) полная очистка данных и шаги для отчёта.</summary>
    internal sealed record UninstallFinish(bool Cleaned, EmergencyStepReport Secrets, EmergencyStepReport RasEntries);

    /// <summary>
    /// Завершение удаления после сетевых шагов. Порядок: сначала отметка очистки данных (или удаление данных самим),
    /// затем файлы паролей, и только потом записи RAS — их удаление идёт через RasMan и может зависнуть, поэтому оно
    /// последнее, со своим сроком, и пропускается, если служба RAS уже не ответила при восстановлении сети. Каждый шаг
    /// изолирован от исключений любого типа: сбой одного не отменяет следующих.
    /// <para>
    /// Полная очистка разрешена — пароли и записи RAS не трогаются здесь: их удалит установщик вместе с каталогом данных
    /// (там и телефонная книга) после фиксации удаления, а отменённое или откаченное удаление вернёт программу с
    /// настройками, паролями и ключами IPsec. Не разрешена — данные остаются для повторного восстановления, но пароли,
    /// ключи и записи RAS программы (с общим ключом IPsec в хранилище RAS) удаляются сразу.
    /// </para>
    /// </summary>
    internal static UninstallFinish FinishUninstall(RecoveryMode mode, bool cleanable, IReadOnlyList<EmergencyStepReport> networkSteps,
        UninstallActions actions, TimeSpan rasTimeout)
    {
        ArgumentNullException.ThrowIfNull(networkSteps);
        ArgumentNullException.ThrowIfNull(actions);
        bool cleaned;
        if (mode == RecoveryMode.UninstallNetwork)
        {
            // Данные и ключ реестра удаляет установщик после фиксации удаления: здесь только разрешение на это.
            cleaned = cleanable && TryStep("отметка очистки данных", actions.SetPurgeMark);
        }
        else
        {
            cleaned = cleanable && (TryStep("данные", actions.DeleteData) & TryStep("реестр", actions.DeleteRegistry));
        }

        if (cleaned)
        {
            var later = mode == RecoveryMode.UninstallNetwork;
            return new UninstallFinish(true,
                new EmergencyStepReport(UninstallSecretsStep, SecretsStepTitle, EmergencyStepOutcome.Skipped,
                    later ? "удаляются вместе с данными после фиксации удаления" : "удалены вместе с данными", 0, Required: false),
                new EmergencyStepReport(UninstallRasStep, RasEntriesStepTitle, EmergencyStepOutcome.Skipped,
                    later ? "удаляются вместе с телефонной книгой в каталоге данных после фиксации удаления" : "удалены вместе с телефонной книгой в каталоге данных", 0, Required: false));
        }

        // Секреты не ждут полной очистки: без неё данные остаются (dns-backup.json нужен повторному восстановлению), но
        // пароли, ключи IPsec и SSH в них оставались бы на диске после удаления программы. Туда же - файл закреплений
        // (pins.json): по нему видно, какие сайты открывались.
        var secrets = RunUninstallStep(UninstallSecretsStep, SecretsStepTitle, actions.DeleteSecrets);
        var rasHung = networkSteps.Any(s => s.Step == EmergencySteps.Ras && s.Outcome == EmergencyStepOutcome.Timeout);
        var ras = rasHung
            ? new EmergencyStepReport(UninstallRasStep, RasEntriesStepTitle, EmergencyStepOutcome.Timeout,
                "не запущен: служба RAS не ответила при восстановлении сети", 0, Required: false)
            : RunBoundedUninstallStep(UninstallRasStep, RasEntriesStepTitle, actions.DeleteRasEntries, rasTimeout);
        return new UninstallFinish(false, secrets, ras);
    }

    /// <summary>Шаг удаления с итогом в отчёте; необязательный — сеть он не касается и код команды не меняет.</summary>
    private static EmergencyStepReport RunUninstallStep(string id, string title, Func<string> action)
    {
        var watch = Stopwatch.StartNew();
        try
        {
            var detail = action();
            return new EmergencyStepReport(id, title, EmergencyStepOutcome.Done, detail, watch.ElapsedMilliseconds, Required: false);
        }
        catch (Exception ex)
        {
            // Любой тип исключения: сбой шага не должен отменять следующие шаги удаления и отчёт.
            Console.Error.WriteLine(title + ": " + ex.Message);
            return new EmergencyStepReport(id, title, EmergencyStepOutcome.Failed, ex.Message, watch.ElapsedMilliseconds, Required: false);
        }
    }

    /// <summary>
    /// Шаг со своим сроком: синхронный вызов идёт в пуле потоков, и по истечении срока отчёт получает «timeout», а
    /// зависший поток остаётся ждать до выхода процесса.
    /// </summary>
    private static EmergencyStepReport RunBoundedUninstallStep(string id, string title, Func<string> action, TimeSpan timeout)
    {
        var watch = Stopwatch.StartNew();
        var work = Task.Run(() => RunUninstallStep(id, title, action));
        try
        {
            if (work.Wait(timeout))
            {
                return work.Result;
            }
        }
        catch (AggregateException ex)
        {
            return new EmergencyStepReport(id, title, EmergencyStepOutcome.Failed, ex.InnerException?.Message ?? ex.Message, watch.ElapsedMilliseconds, Required: false);
        }

        Console.Error.WriteLine(title + ": не завершено за " + timeout.TotalSeconds.ToString("F0", CultureInfo.InvariantCulture) + " с");
        return new EmergencyStepReport(id, title, EmergencyStepOutcome.Timeout,
            string.Create(CultureInfo.InvariantCulture, $"не завершено за {timeout.TotalSeconds:F0} с: служба RAS не ответила"), watch.ElapsedMilliseconds, Required: false);
    }

    /// <summary>
    /// Файл с секретами программы: secrets.bin, его соседи .ipsec и .sshkey и копии всех трёх (.v095, .corrupt-*,
    /// .undecryptable-*, недописанные .tmp атомарной записи) — всё, что начинается с «secrets.bin».
    /// </summary>
    internal static bool IsSecretFileName(string fileName) =>
        string.Equals(fileName, SecretsFileName, StringComparison.OrdinalIgnoreCase)
        || fileName.StartsWith(SecretsFileName + ".", StringComparison.OrdinalIgnoreCase);

    /// <summary>Файл закреплений по правилам для доменов (<see cref="ServicePaths.Pins"/>): по нему видно, какие сайты открывались.</summary>
    internal const string PinsFileName = "pins.json";

    /// <summary>Файл закреплений или его недописанная копия атомарной записи (pins.json.*.tmp).</summary>
    internal static bool IsPinFileName(string fileName) =>
        string.Equals(fileName, PinsFileName, StringComparison.OrdinalIgnoreCase)
        || fileName.StartsWith(PinsFileName + ".", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Удаляет файлы секретов и файл закреплений по правилам для доменов (история открытых сайтов) прямо в каталоге
    /// данных (без обхода подкаталогов: перенесённое в сторону «.untrusted-*» служба не читала). Каталог-ссылка или каталог посторонней учётной записи не трогается: удаление от SYSTEM ушло
    /// бы туда, куда он указывает. Ссылка с именем секрета удаляется сама, не её цель. Возвращает итог для отчёта;
    /// не удалось удалить хоть один файл — исключение с перечнем.
    /// </summary>
    internal static string DeleteSecretFiles(string root, Func<DirectoryInfo, bool> trustedOwner)
    {
        ArgumentNullException.ThrowIfNull(trustedOwner);
        var directory = new DirectoryInfo(root);
        if (!directory.Exists)
        {
            return "каталога данных нет";
        }

        if (directory.Attributes.HasFlag(FileAttributes.ReparsePoint) || !trustedOwner(directory))
        {
            throw new IOException($"Каталог данных {root} оказался ссылкой или принадлежит посторонней учётной записи: файлы паролей не удалены.");
        }

        var deleted = 0;
        List<string> failed = [];
        foreach (var file in directory.EnumerateFiles(SecretsFileName + "*").Concat(directory.EnumerateFiles(PinsFileName + "*")))
        {
            if (!IsSecretFileName(file.Name) && !IsPinFileName(file.Name))
            {
                continue;
            }

            try
            {
                file.Attributes = FileAttributes.Normal;
                file.Delete();
                deleted++;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                failed.Add(file.Name + " (" + ex.Message + ")");
            }
        }

        return failed.Count > 0
            ? throw new IOException("Не удалены файлы паролей: " + string.Join("; ", failed))
            : deleted == 0 ? "файлов паролей нет" : string.Create(CultureInfo.InvariantCulture, $"удалено файлов: {deleted}");
    }

    /// <summary>
    /// Удаляет файл закреплений и его недописанные копии (<see cref="IsPinFileName"/>) прямо в каталоге данных, без обхода
    /// подкаталогов. Доверие каталогу проверяет вызывающий. Ссылка с таким именем удаляется сама, не её цель. Возвращает
    /// число удалённых; не удалось удалить хоть один файл — исключение с перечнем (остальные всё равно удаляются).
    /// </summary>
    internal static int DeletePinFiles(string root)
    {
        var directory = new DirectoryInfo(root);
        if (!directory.Exists)
        {
            return 0;
        }

        var deleted = 0;
        List<string> failed = [];
        foreach (var file in directory.EnumerateFiles(PinsFileName + "*"))
        {
            if (!IsPinFileName(file.Name))
            {
                continue;
            }

            try
            {
                file.Attributes = FileAttributes.Normal;
                file.Delete();
                deleted++;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                failed.Add(file.Name + " (" + ex.Message + ")");
            }
        }

        return failed.Count > 0 ? throw new IOException("Не удалены файлы закреплений: " + string.Join("; ", failed)) : deleted;
    }

    /// <summary>
    /// Удаляет записи своей телефонной книги через RasDeleteEntry: вместе с записью RAS убирает и её учётные данные, в
    /// том числе общий ключ IPsec (RasSetCredentials). Книга-ссылка не читается.
    /// </summary>
    private static string DeleteRasEntries(string phonebook)
    {
        var file = new FileInfo(phonebook);
        if (!file.Exists)
        {
            return "телефонной книги нет";
        }

        if (file.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new IOException($"Телефонная книга {phonebook} оказалась ссылкой: записи не удалены.");
        }

        var names = Windows.Ras.RasPhonebook.EnumerateEntryNames(phonebook);
        foreach (var name in names)
        {
            Windows.Ras.RasPhonebook.Delete(phonebook, name);
        }

        return string.Create(CultureInfo.InvariantCulture, $"удалено записей: {names.Count}");
    }

    private static bool TryStep(string name, Action action)
    {
        try
        {
            action();
            return true;
        }
        catch (Exception ex)
        {
            // Любой тип исключения: шаг изолирован, следующие шаги удаления и отчёт выполняются.
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
    internal static string? WriteUninstallLog(string directory, string text, Func<string, IReadOnlyList<string>> secure, Func<DirectoryInfo, bool> trustedOwner) =>
        WriteProtectedFile(directory, string.Create(CultureInfo.InvariantCulture, $"uninstall-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.log"),
            text, secure, trustedOwner, new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: true), "Журнал удаления", Console.Error.WriteLine);

    /// <summary>
    /// Новый файл <paramref name="fileName"/> в защищённом каталоге (журнал удаления, отчёт экстренного отключения); null — не
    /// записан, причина ушла в <paramref name="warn"/>. Правила — у <see cref="WriteUninstallLog(string, string, Func{string, IReadOnlyList{string}}, Func{DirectoryInfo, bool})"/>.
    /// </summary>
    internal static string? WriteProtectedFile(string directory, string fileName, string text, Func<string, IReadOnlyList<string>> secure,
        Func<DirectoryInfo, bool> trustedOwner, System.Text.Encoding encoding, string what, Action<string> warn)
    {
        ArgumentNullException.ThrowIfNull(secure);
        ArgumentNullException.ThrowIfNull(warn);
        try
        {
            if (ForeignLogDirectory(directory, trustedOwner) is { } before)
            {
                warn($"{what} не записан: каталог {directory} {before}.");
                return null;
            }

            foreach (var warning in secure(directory)) warn(warning);

            // Каталог мог появиться между проверкой и созданием: после защиты он проверяется ещё раз.
            var after = Directory.Exists(directory) ? ForeignLogDirectory(directory, trustedOwner) : "не создан";
            if (after is not null)
            {
                warn($"{what} не записан: каталог {directory} {after}.");
                return null;
            }

            var path = Path.Combine(directory, fileName);
            using var stream = new FileStream(path, new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
            });
            using var writer = new StreamWriter(stream, encoding);
            writer.Write(text);
            return path;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException
            or System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            warn($"{what} не записан: " + ex.Message);
            return null;
        }
    }

    /// <summary>Почему в уже существующий каталог журнала писать нельзя; null — каталога нет или он свой.</summary>
    internal static string? ForeignLogDirectory(string directory, Func<DirectoryInfo, bool> trustedOwner)
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

    internal static bool HasTrustedOwner(DirectoryInfo directory) =>
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

    /// <summary>
    /// Сколько ждать штатной остановки службы, прежде чем завершить её процесс: срок остановки хоста
    /// (<see cref="CoordinatorHost.ShutdownTimeout"/>) и 2 с на выход процесса. Меньший срок обрывал бы ещё идущую
    /// штатную остановку - возврат DNS, снятие фильтров и прощание помощников со шлюзом.
    /// </summary>
    internal static readonly TimeSpan StopWaitBeforeKill = CoordinatorHost.ShutdownTimeout + TimeSpan.FromSeconds(2);

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
}
