using System.Net;
using System.Net.NetworkInformation;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Native;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.Ras;
using SplitVpn.Windows.Wfp;

namespace SplitVpn.Windows.Recovery;

public sealed record RecoveryOptions
{
    /// <summary>Телефонные книги приложения: соединения из них разрываются.</summary>
    public IReadOnlyList<string> Phonebooks { get; init; } = [];

    public IReadOnlyList<WfpIdentity> WfpIdentities { get; init; } = [WfpIdentity.Product, WfpIdentity.Prototype];

    public string ServiceDirectory { get; init; } = AppContext.BaseDirectory;

    /// <summary>
    /// Ещё каталоги службы, помощники из которых тоже завершаются (команда разработчика восстанавливает и прототип, и
    /// установленный продукт). Сравнивается полный путь файла процесса: чужие процессы с тем же именем не трогаются.
    /// </summary>
    public IReadOnlyList<string> AdditionalServiceDirectories { get; init; } = [];

    public string? AdditionalDnsBackupPath { get; init; }

    public string? DnsBackupPath { get; init; }
}

public sealed record RecoveryReport(
    int ConnectionsClosed,
    int RoutesRemoved,
    int FiltersRemoved,
    IReadOnlyList<string> DnsActions,
    IReadOnlyList<string> Errors)
{
    public bool Success => Errors.Count == 0;
}

/// <summary>Итог одного шага восстановления: сколько снято, что сделано, что не получилось.</summary>
public sealed record RecoveryStepResult(int Count, IReadOnlyList<string> Actions, IReadOnlyList<string> Errors)
{
    public bool Success => Errors.Count == 0;
}

/// <summary>
/// Возвращает сеть в обычное состояние, снимая только изменения приложения. Идемпотентно:
/// повторный запуск ничего не ломает. Работает без службы и без настроек. Шаги доступны и по отдельности —
/// экстренное отключение выполняет каждый в своём потоке и со своим сроком.
/// </summary>
public static class NetworkRecovery
{
    private const uint ErrorFileNotFound = 2;

    public static async Task<RecoveryReport> RunAsync(RecoveryOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        var errors = new List<string>();
        var dnsActions = new List<string>();

        var closed = await Step(errors, "RAS", async () => Collect(await CloseConnectionsAsync(options.Phonebooks, cancellationToken), errors), 0);
        closed += await Step(errors, "помощники", () => Task.FromResult(Collect(StopHelpers([options.ServiceDirectory, .. options.AdditionalServiceDirectories]), errors)), 0);
        var routes = await Step(errors, "маршруты", () => Task.FromResult(Collect(RemoveRoutes(), errors)), 0);
        await Step(errors, "DNS", () =>
        {
            var dns = RestoreDns(options, serviceStopped: false);
            dnsActions.AddRange(dns.Actions);
            return Task.FromResult(Collect(dns, errors));
        }, 0);
        var filters = await Step(errors, "WFP", () => Task.FromResult(Collect(RemoveFilters(options.WfpIdentities), errors)), 0);
        await Step(errors, "кеш DNS", () =>
        {
            if (!FlushDns())
            {
                errors.Add("кеш DNS: сброс не подтверждён — ipconfig /flushdns не завершился за 10 секунд");
            }

            return Task.FromResult(0);
        }, 0);

        return new RecoveryReport(closed, routes, filters, dnsActions, errors);
    }

    private static int Collect(RecoveryStepResult result, List<string> errors)
    {
        errors.AddRange(result.Errors);
        return result.Count;
    }

    /// <summary>
    /// Разрывает соединения RAS из телефонных книг программы. Свои соединения находятся перечислением всех соединений
    /// и сравнением пути книги: саму книгу читать не нужно, поэтому шаг годится и для недоверенного каталога данных.
    /// Записи книги не удаляются: по ним программа подключится снова после включения.
    /// </summary>
    public static async Task<RecoveryStepResult> CloseConnectionsAsync(IReadOnlyList<string> phonebooks, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(phonebooks);
        var errors = new List<string>();
        var actions = new List<string>();
        var ours = RasClient.EnumerateConnections()
            .Where(c => phonebooks.Any(p => RasClient.SamePhonebook(p, c.Phonebook)))
            .ToList();
        var closed = 0;
        foreach (var connection in ours)
        {
            // Сбой на одном соединении не должен оставить остальные поднятыми и не отменяет следующих шагов.
            try
            {
                await RasClient.HangUpAsync(connection.Handle, cancellationToken);
                closed++;
                actions.Add($"разорвано «{connection.EntryName}»");
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                errors.Add($"RAS «{connection.EntryName}»: {ex.Message}");
            }
        }

        return new RecoveryStepResult(closed, actions, errors);
    }

    /// <summary>Помощники AnyConnect и движок «VPN поверх SSH» — только свои, из каталога программы.</summary>
    public static RecoveryStepResult StopHelpers(string serviceDirectory) => StopHelpers([serviceDirectory]);

    /// <summary>
    /// Помощники из нескольких каталогов программы (прототип и установленный продукт). Совпадающие каталоги
    /// обходятся один раз; в каждом завершаются только процессы, запущенные именно из его файлов.
    /// </summary>
    public static RecoveryStepResult StopHelpers(IReadOnlyList<string> serviceDirectories)
    {
        ArgumentNullException.ThrowIfNull(serviceDirectories);
        var directories = DistinctDirectories(serviceDirectories);
        var errors = new List<string>();
        var stopped = 0;
        foreach (var directory in directories)
        {
            foreach (var (name, file) in new[]
            {
                ("AnyConnect", OpenConnect.SystemAnyConnectOps.HelperFileName),
                ("движок SSH", SshTunnel.SystemSshTunnelOps.EngineFileName),
            })
            {
                try
                {
                    stopped += SshTunnel.SystemSshTunnelOps.StopOwn(Path.Combine(directory, file));
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    errors.Add((directories.Count > 1 ? $"{name} ({directory})" : name) + ": " + ex.Message);
                }
            }
        }

        return new RecoveryStepResult(stopped, stopped > 0 ? [$"завершено процессов: {stopped}"] : [], errors);
    }

    /// <summary>Полные пути каталогов без повторов (регистр и завершающий разделитель не в счёт); пустые пропускаются.</summary>
    internal static IReadOnlyList<string> DistinctDirectories(IEnumerable<string?> directories) => directories
        .Where(d => !string.IsNullOrWhiteSpace(d))
        .Select(d => Path.TrimEndingDirectorySeparator(Path.GetFullPath(d!)))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

    /// <summary>
    /// Каталог файла службы по её регистрации (ImagePath в HKLM\SYSTEM\CurrentControlSet\Services\имя); null — служба
    /// не установлена, значение не читается или путь не полный.
    /// </summary>
    public static string? RegisteredServiceDirectory(string serviceName)
    {
        ArgumentException.ThrowIfNullOrEmpty(serviceName);
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + serviceName);
            return key?.GetValue("ImagePath") is string image ? ServiceDirectoryFromImagePath(image) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return null;
        }
    }

    /// <summary>
    /// Каталог exe из ImagePath: путь в кавычках или до «.exe», с переменными окружения; только полный путь. Префикс
    /// пространства имён NT «\??\» (так ImagePath пишут некоторые установщики и sc.exe для путей драйверов) отбрасывается —
    /// и перед кавычкой, и внутри неё.
    /// </summary>
    internal static string? ServiceDirectoryFromImagePath(string image)
    {
        ArgumentNullException.ThrowIfNull(image);
        image = StripNtPrefix(Environment.ExpandEnvironmentVariables(image.Trim()));
        string? exe;
        if (image.StartsWith('"'))
        {
            var end = image.IndexOf('"', 1);
            exe = end > 1 ? StripNtPrefix(image[1..end]) : null;
        }
        else
        {
            var extension = image.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            exe = extension > 0 ? image[..(extension + 4)] : null;
        }

        try
        {
            return exe is not null && Path.IsPathFullyQualified(exe) ? Path.GetDirectoryName(Path.GetFullPath(exe)) : null;
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return null;
        }

        static string StripNtPrefix(string path) => path.StartsWith(@"\??\", StringComparison.Ordinal) ? path[4..] : path;
    }

    /// <summary>Маршруты с меткой-метрикой программы.</summary>
    public static RecoveryStepResult RemoveRoutes()
    {
        var result = RouteOps.RemoveAllMarked();
        return new RecoveryStepResult(result.Removed, [],
            result.Failed > 0 ? ["Не удалось удалить маршрутов: " + result.Failed + ". " + string.Join("; ", result.Errors)] : []);
    }

    /// <summary>Сброс системного кеша DNS; false — не подтверждён.</summary>
    public static bool FlushDns() => InterfaceDnsOps.FlushResolverCache();

    /// <summary>
    /// Возвращает DNS всем адаптерам, а не только тем, у кого сейчас есть адрес: на выключенном Wi-Fi
    /// иначе остался бы наш 127.0.0.1. Запись в копии — отметка того, что loopback поставила служба. Адаптер без записи
    /// решают правила <see cref="OrphanDns"/>: при работающей службе (<paramref name="serviceStopped"/> = false) и
    /// исправном файле копии loopback без записи — статический DNS пользователя, пока его резолвер слушает порт 53;
    /// при остановленной службе (экстренное отключение) или без копии — сбрасывается на DHCP всё, что выглядит нашим, кроме
    /// адаптеров, где 127.0.0.1:53 слушает резолвер пользователя, и IPv4-списка адаптеров со статическим IPv4-адресом.
    /// Записи копии, которым не нашлось адаптера, обрабатываются отдельно.
    /// <para>При остановленной службе дополнительно: IPv6-список, который не вернулся из копии (на адаптере остался ::1),
    /// сбрасывается на «автоматически», а список поиска адаптера без копии, состоящий только из наших суффиксов, очищается.</para>
    /// </summary>
    public static RecoveryStepResult RestoreDns(RecoveryOptions options, bool serviceStopped)
    {
        ArgumentNullException.ThrowIfNull(options);
        var actions = new List<string>();
        var errors = new List<string>();
        var marksKnown = false;
        var backups = new Dictionary<Guid, InterfaceDnsBackup>();
        var all = new List<InterfaceDnsBackup>();
        var owners = new Dictionary<Guid, List<DnsBackupStore>>();
        foreach (var path in new[] { options.DnsBackupPath, options.AdditionalDnsBackupPath }.OfType<string>().Where(File.Exists))
        {
            var valid = true;
            var store = new DnsBackupStore(path)
            {
                OnCorrupt = file => { valid = false; actions.Add(file.Describe()); },
            };
            if (LoadBackups(store, actions) is not { } entries)
            {
                continue;
            }

            marksKnown |= valid;
            foreach (var (id, backup) in entries)
            {
                all.Add(backup);
                if (!owners.TryGetValue(id, out var stores))
                {
                    stores = [];
                    owners.Add(id, stores);
                }

                stores.Add(store);
                if (!backups.TryGetValue(id, out var previous) || backup.SavedUtc < previous.SavedUtc)
                {
                    backups[id] = backup;
                }
            }
        }

        var ourSuffixes = OrphanDns.OurSuffixes(all);
        var handled = new HashSet<Guid>();
        var listeners = new Lazy<LoopbackListeners>(LoopbackResolverListeners);
        IReadOnlyList<SplitVpn.Core.Net.AdapterCandidate> adapters;
        try
        {
            adapters = NetInventory.Capture().Adapters;
        }
        catch (Exception ex) when (ex is NativeCallException or IOException or UnauthorizedAccessException)
        {
            errors.Add("Инвентаризация адаптеров: " + ex.Message);
            adapters = [];
        }

        foreach (var adapter in adapters)
        {
            handled.Add(adapter.InterfaceGuid);
            if (backups.TryGetValue(adapter.InterfaceGuid, out var backup))
            {
                RestoreAdapterDns(owners.GetValueOrDefault(adapter.InterfaceGuid), adapter.InterfaceGuid, adapter.Name, backup, serviceStopped, present: true, actions, errors);
                continue;
            }

            ResetOrphanAdapter(adapter.InterfaceGuid, adapter.Name, serviceStopped || !marksKnown, serviceStopped ? ourSuffixes : null, listeners, actions, errors);
        }

        foreach (var backup in backups.Values.Where(b => !handled.Contains(b.InterfaceGuid)))
        {
            RestoreAdapterDns(owners[backup.InterfaceGuid], backup.InterfaceGuid, "интерфейс " + backup.InterfaceGuid, backup, serviceStopped, present: false, actions, errors);
        }

        return new RecoveryStepResult(actions.Count, actions, errors);
    }

    /// <summary>Адаптер без записи в копии: см. <see cref="OrphanDns.Decide"/>. У части интерфейсов (loopback, Teredo) DNS-настроек нет.</summary>
    private static void ResetOrphanAdapter(Guid interfaceGuid, string name, bool serviceStopped, IReadOnlySet<string>? ourSuffixes,
        Lazy<LoopbackListeners> listeners, List<string> actions, List<string> errors)
    {
        try
        {
            InterfaceDnsState v4;
            try
            {
                v4 = InterfaceDnsOps.Read(interfaceGuid, ipv6: false);
            }
            catch (NativeCallException)
            {
                // Нет DNS-настроек (loopback, Teredo) — сбрасывать нечего.
                return;
            }

            var v6 = InterfaceDnsOps.TryReadIpv6(interfaceGuid, warn: false)?.NameServer;
            var looksOurs = InterfaceDnsOps.IsProxySet(v4.NameServer) || (v6 is not null && InterfaceDnsOps.IsLoopback(v6));
            var reset = looksOurs
                ? OrphanDns.Decide(v4.NameServer, v6, serviceStopped, listeners.Value, IsStaticIpv4(interfaceGuid))
                : default;
            if (reset.KeptStatic)
            {
                // Шаг остаётся успешным: сбросить нельзя, а что сделать — сказано в подробностях.
                actions.Add(OrphanDnsReset.StaticNote(name, v4.NameServer));
            }

            if (reset.V4)
            {
                InterfaceDnsOps.SetNameServer(interfaceGuid, "", ipv6: false);
                actions.Add($"{name}: DNS «{v4.NameServer}» без копии — сброшен, DNS по DHCP");
            }

            if (reset.V6)
            {
                if (InterfaceDnsOps.TrySetIpv6NameServer(interfaceGuid, ""))
                {
                    actions.Add($"{name}: IPv6 DNS «{v6}» без копии — сброшен на автоматический");
                }
                else
                {
                    errors.Add($"DNS «{name}»: IPv6-список «{v6}» не сброшен");
                }
            }

            if (ourSuffixes is not null && OrphanDns.ShouldClearSearchList(v4.SearchList, ourSuffixes))
            {
                InterfaceDnsOps.SetSearchList(interfaceGuid, "");
                actions.Add($"{name}: список суффиксов «{v4.SearchList}» программы очищен");
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            errors.Add($"DNS «{name}»: {ex.Message}");
        }
    }

    /// <summary>
    /// Слушатели UDP-порта 53, которым доходят запросы к 127.0.0.1 и к [::1]. Слушатель берётся из таблицы UDP
    /// (GetExtendedUdpTable через IPGlobalProperties), а не пробной привязкой к порту 53: проба на мгновение заняла бы
    /// порт у резолвера, стартующего в этот момент.
    /// </summary>
    public static LoopbackListeners LoopbackResolverListeners() =>
        ClassifyListeners(IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners());

    /// <summary>Сводка слушателей (для тестов — по готовому списку).</summary>
    internal static LoopbackListeners ClassifyListeners(IReadOnlyCollection<IPEndPoint> listeners) => new(
        listeners.Any(ServesLoopbackResolver),
        listeners.Any(ServesIpv6LoopbackResolver),
        listeners.Any(l => l.Port == 53 && (l.Address.Equals(IPAddress.Loopback) || l.Address.Equals(IPAddress.Loopback.MapToIPv6()))),
        listeners.Any(l => l.Port == 53 && l.Address.Equals(IPAddress.IPv6Loopback)));

    /// <summary>
    /// IPv4-адрес адаптера задан вручную: EnableDHCP = 0 в Tcpip\Parameters\Interfaces\{guid}. Нет раздела или значения
    /// (или они не читаются) — не статический: так было до этой проверки.
    /// </summary>
    public static bool IsStaticIpv4(Guid interfaceGuid)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\" + interfaceGuid.ToString("B"));
            return key?.GetValue("EnableDHCP") is int dhcp && dhcp == 0;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Слушатель порта 53, которому доходят запросы к 127.0.0.1: на 127.0.0.1, на 0.0.0.0 или на [::] — сокет
    /// двойного стека (так слушают многие резолверы) принимает и IPv4. Сокет [::] только для IPv6 по таблице
    /// не отличить: в сомнении DNS пользователя не сбрасывается.
    /// </summary>
    internal static bool ServesLoopbackResolver(IPEndPoint listener) =>
        listener.Port == 53 && (listener.Address.Equals(IPAddress.Loopback) || listener.Address.Equals(IPAddress.Any)
            || listener.Address.Equals(IPAddress.IPv6Any) || listener.Address.Equals(IPAddress.Loopback.MapToIPv6()));

    /// <summary>Слушатель порта 53, которому доходят запросы к [::1]: на [::1] или на [::].</summary>
    internal static bool ServesIpv6LoopbackResolver(IPEndPoint listener) =>
        listener.Port == 53 && (listener.Address.Equals(IPAddress.IPv6Loopback) || listener.Address.Equals(IPAddress.IPv6Any));

    /// <summary>Сбой на одном адаптере не должен останавливать восстановление остальных.</summary>
    private static void RestoreAdapterDns(List<DnsBackupStore>? stores, Guid interfaceGuid, string name, InterfaceDnsBackup backup, bool serviceStopped,
        bool present, List<string> actions, List<string> errors)
    {
        try
        {
            var outcome = TryRestore(interfaceGuid, backup);
            if (outcome == DnsRestoreOutcome.Incomplete && serviceStopped && InterfaceDnsOps.TrySetIpv6NameServer(interfaceGuid, ""))
            {
                // Служба остановлена: ::1 без посредника не отвечает. Исходный IPv6-список вернуть не удалось — лучше
                // «автоматически», чем мёртвый ::1; IPv4 уже возвращён, и копия больше ничего не вернёт.
                actions.Add($"{name}: IPv4 DNS восстановлен, IPv6 DNS сброшен на автоматический (исходный «{backup.NameServerV6}» вернуть не удалось)");
                Forget(stores, interfaceGuid);
                return;
            }

            if (outcome != DnsRestoreOutcome.NothingToRestore)
            {
                actions.Add($"{name}: {Describe(outcome, backup)}");
            }

            if (outcome == DnsRestoreOutcome.Restored
                || (serviceStopped && present && outcome is DnsRestoreOutcome.ChangedByUser or DnsRestoreOutcome.NothingToRestore))
            {
                // Своё вернули — копия больше не нужна. При остановленной службе не нужна и копия адаптера, на котором
                // уже не наш DNS: устаревшая копия вернула бы потом давно сменённые серверы. Копия адаптера, которого сейчас
                // нет (отключённый USB-адаптер), остаётся: он может вернуться с нашим loopback.
                Forget(stores, interfaceGuid);
            }
            else if (outcome == DnsRestoreOutcome.Incomplete)
            {
                // ::1 остался на адаптере: копия сохраняется, чтобы повторный запуск вернул исходные IPv6 DNS.
                errors.Add($"DNS «{name}»: IPv6-серверы DNS не восстановлены, резервная копия сохранена");
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            errors.Add($"DNS «{name}»: {ex.Message}");
        }
    }

    private static void Forget(List<DnsBackupStore>? stores, Guid interfaceGuid)
    {
        foreach (var store in stores ?? [])
        {
            store.Remove(interfaceGuid);
        }
    }

    /// <summary>
    /// Нечитаемая копия — null (отметок нет): адаптеры с loopback всё равно вернутся на DHCP, поэтому
    /// это не ошибка восстановления, а строка в списке действий.
    /// </summary>
    private static IReadOnlyDictionary<Guid, InterfaceDnsBackup>? LoadBackups(DnsBackupStore? store, List<string> actions)
    {
        try
        {
            return store?.Load() ?? new Dictionary<Guid, InterfaceDnsBackup>();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            actions.Add("резервная копия DNS не прочитана: " + ex.Message);
            return null;
        }
    }

    /// <summary>У части интерфейсов (loopback, Teredo) нет DNS-настроек: ERROR_FILE_NOT_FOUND означает «нечего возвращать».</summary>
    private static DnsRestoreOutcome TryRestore(Guid interfaceGuid, InterfaceDnsBackup? backup)
    {
        try
        {
            return InterfaceDnsOps.Restore(interfaceGuid, backup);
        }
        catch (NativeCallException ex) when (ex.Code == ErrorFileNotFound)
        {
            return DnsRestoreOutcome.NothingToRestore;
        }
    }

    /// <summary>
    /// Фильтры каждого провайдера снимаются, даже если у предыдущего удаление не удалось. Очистка проверяет себя
    /// перечислением, не зависящим от слоёв: «успех» при оставшихся фильтрах оставлял бы блокировку трафика без
    /// единого сообщения (так было в 0.17.2).
    /// </summary>
    public static RecoveryStepResult RemoveFilters(IReadOnlyList<WfpIdentity> identities)
    {
        ArgumentNullException.ThrowIfNull(identities);
        var errors = new List<string>();
        using var engine = WfpEngine.Open(dynamicSession: false);
        var removed = 0;
        foreach (var identity in identities)
        {
            try
            {
                removed += WfpOps.DeleteAll(engine, identity);
                var left = WfpOps.ListFiltersEverywhere(engine, identity).Count;
                if (left > 0)
                {
                    errors.Add($"WFP: после очистки осталось фильтров «{identity.Name}»: {left}");
                }
            }
            catch (NativeCallException ex)
            {
                errors.Add("WFP: " + ex.Message);
            }
        }

        return new RecoveryStepResult(removed, [], errors);
    }

    private static string Describe(DnsRestoreOutcome outcome, InterfaceDnsBackup? backup) => outcome switch
    {
        DnsRestoreOutcome.Restored when backup is null => "loopback сброшен, DNS по DHCP",
        DnsRestoreOutcome.Restored => "восстановлены исходные DNS «" + backup.NameServerV4 + "»",
        DnsRestoreOutcome.ChangedByUser => "DNS изменён после применения — не трогаем",
        DnsRestoreOutcome.Incomplete => "IPv4 DNS восстановлен, IPv6 — нет",
        _ => "без изменений",
    };

    /// <summary>
    /// Шаг восстановления. Ловится всё, кроме нехватки памяти: неожиданная ошибка одного шага (разбор файла,
    /// запуск ipconfig, пустой путь телефонной книги) не должна оставить систему без снятия фильтров WFP.
    /// </summary>
    private static async Task<T> Step<T>(List<string> errors, string name, Func<Task<T>> action, T fallback)
    {
        try
        {
            return await action();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            errors.Add(name + ": " + ex.Message);
            return fallback;
        }
    }
}
