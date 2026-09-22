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

/// <summary>
/// Возвращает сеть в обычное состояние, снимая только изменения приложения. Идемпотентно:
/// повторный запуск ничего не ломает. Работает без службы и без настроек.
/// </summary>
public static class NetworkRecovery
{
    private const uint ErrorFileNotFound = 2;

    public static async Task<RecoveryReport> RunAsync(RecoveryOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        var errors = new List<string>();
        var dnsActions = new List<string>();

        var closed = await Step(errors, "RAS", () => CloseConnectionsAsync(options.Phonebooks, errors, cancellationToken), 0);
        closed += await Step(errors, "AnyConnect", () => Task.FromResult(StopAnyConnectHelpers()), 0);
        var routes = await Step(errors, "маршруты", () => Task.FromResult(RemoveRoutes()), 0);
        await Step(errors, "DNS", () => Task.FromResult(RestoreDns(options.DnsBackupPath, dnsActions, errors)), 0);
        var filters = await Step(errors, "WFP", () => Task.FromResult(RemoveFilters(options.WfpIdentities)), 0);
        await Step(errors, "кеш DNS", () =>
        {
            InterfaceDnsOps.FlushResolverCache();
            return Task.FromResult(0);
        }, 0);

        return new RecoveryReport(closed, routes, filters, dnsActions, errors);
    }

    private static async Task<int> CloseConnectionsAsync(IReadOnlyList<string> phonebooks, List<string> errors, CancellationToken cancellationToken)
    {
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
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                errors.Add($"RAS «{connection.EntryName}»: {ex.Message}");
            }
        }

        return closed;
    }

    /// <summary>Помощники AnyConnect: с процессом исчезает и адаптер Wintun.</summary>
    private static int StopAnyConnectHelpers()
    {
        var helpers = System.Diagnostics.Process.GetProcessesByName(Path.GetFileNameWithoutExtension(OpenConnect.SystemAnyConnectOps.HelperFileName));
        foreach (var helper in helpers)
        {
            using (helper)
            {
                try
                {
                    helper.Kill();
                    helper.WaitForExit(5000);
                }
                catch (System.ComponentModel.Win32Exception ex)
                {
                    throw new InvalidOperationException("Не удалось завершить помощника AnyConnect: " + ex.Message, ex);
                }
                catch (InvalidOperationException)
                {
                    // Процесс уже завершился.
                }
            }
        }

        return helpers.Length;
    }

    private static int RemoveRoutes()
    {
        var result = RouteOps.RemoveAllMarked();
        if (result.Failed > 0)
        {
            throw new InvalidOperationException("Не удалось удалить маршрутов: " + result.Failed + ". " + string.Join("; ", result.Errors));
        }

        return result.Removed;
    }

    /// <summary>
    /// Возвращает DNS всем адаптерам, а не только тем, у кого сейчас есть адрес: на выключенном Wi-Fi
    /// иначе остался бы наш 127.0.0.1. Адаптеры без записи в копии сбрасываются на DHCP только там, где
    /// стоит один наш loopback. Записи копии, которым не нашлось адаптера, обрабатываются отдельно.
    /// </summary>
    private static int RestoreDns(string? backupPath, List<string> actions, List<string> errors)
    {
        var store = backupPath is null ? null : new DnsBackupStore(backupPath) { OnCorrupt = file => actions.Add(file.Describe()) };
        var backups = LoadBackups(store, actions);
        var handled = new HashSet<Guid>();
        foreach (var adapter in NetInventory.Capture().Adapters)
        {
            handled.Add(adapter.InterfaceGuid);
            backups.TryGetValue(adapter.InterfaceGuid, out var backup);
            RestoreAdapterDns(store, adapter.InterfaceGuid, adapter.Name, backup, actions, errors);
        }

        foreach (var backup in backups.Values.Where(b => !handled.Contains(b.InterfaceGuid)))
        {
            RestoreAdapterDns(store, backup.InterfaceGuid, "интерфейс " + backup.InterfaceGuid, backup, actions, errors);
        }

        return actions.Count;
    }

    /// <summary>Сбой на одном адаптере не должен останавливать восстановление остальных и шаг WFP.</summary>
    private static void RestoreAdapterDns(DnsBackupStore? store, Guid interfaceGuid, string name, InterfaceDnsBackup? backup, List<string> actions, List<string> errors)
    {
        try
        {
            var outcome = TryRestore(interfaceGuid, backup);
            if (outcome != DnsRestoreOutcome.NothingToRestore)
            {
                actions.Add($"{name}: {Describe(outcome, backup)}");
            }

            if (outcome == DnsRestoreOutcome.Restored)
            {
                store?.Remove(interfaceGuid);
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            errors.Add($"DNS «{name}»: {ex.Message}");
        }
    }

    /// <summary>
    /// Нечитаемая копия — пустой набор: адаптеры с нашим loopback всё равно вернутся на DHCP, поэтому
    /// это не ошибка восстановления, а строка в списке действий.
    /// </summary>
    private static IReadOnlyDictionary<Guid, InterfaceDnsBackup> LoadBackups(DnsBackupStore? store, List<string> actions)
    {
        try
        {
            return store?.Load() ?? new Dictionary<Guid, InterfaceDnsBackup>();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            actions.Add("резервная копия DNS не прочитана: " + ex.Message);
            return new Dictionary<Guid, InterfaceDnsBackup>();
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

    private static int RemoveFilters(IReadOnlyList<WfpIdentity> identities)
    {
        using var engine = WfpEngine.Open(dynamicSession: false);
        return identities.Sum(identity => WfpOps.DeleteAll(engine, identity));
    }

    private static string Describe(DnsRestoreOutcome outcome, InterfaceDnsBackup? backup) => outcome switch
    {
        DnsRestoreOutcome.Restored when backup is null => "loopback сброшен, DNS по DHCP",
        DnsRestoreOutcome.Restored => "восстановлены исходные DNS «" + backup.NameServerV4 + "»",
        DnsRestoreOutcome.ChangedByUser => "DNS изменён после применения — не трогаем",
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
