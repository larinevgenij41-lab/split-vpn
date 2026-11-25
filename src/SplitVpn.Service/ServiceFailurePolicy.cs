using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using Microsoft.Win32;
using SplitVpn.Core.Recovery;

namespace SplitVpn.Service;

/// <summary>
/// Действия диспетчера служб при сбое службы (SERVICE_FAILURE_ACTIONS): срок сброса счётчика и список действий.
/// Сообщение перезагрузки и команда не сохраняются: команды экстренного отключения их не меняют (при записи пустые указатели
/// оставляют их как есть).
/// </summary>
internal sealed record FailureActionsSnapshot(uint ResetPeriod, IReadOnlyList<(int Type, uint Delay)> Actions)
{
    private const string Prefix = "v1;";

    /// <summary>Строка для реестра: <c>v1;reset=&lt;с&gt;;actions=&lt;тип&gt;:&lt;мс&gt;,…</c>.</summary>
    public string Serialize() => string.Create(CultureInfo.InvariantCulture,
        $"{Prefix}reset={ResetPeriod};actions={string.Join(",", Actions.Select(a => string.Create(CultureInfo.InvariantCulture, $"{a.Type}:{a.Delay}")))}");

    /// <summary>Разбор строки <see cref="Serialize"/>; null — пусто или не тот формат.</summary>
    public static FailureActionsSnapshot? Parse(string? text)
    {
        if (text is null || !text.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return null;
        }

        var parts = text[Prefix.Length..].Split(';');
        if (parts.Length != 2 || !parts[0].StartsWith("reset=", StringComparison.Ordinal) || !parts[1].StartsWith("actions=", StringComparison.Ordinal)
            || !uint.TryParse(parts[0]["reset=".Length..], NumberStyles.None, CultureInfo.InvariantCulture, out var reset))
        {
            return null;
        }

        var actions = new List<(int, uint)>();
        var list = parts[1]["actions=".Length..];
        foreach (var item in list.Length == 0 ? [] : list.Split(','))
        {
            var pair = item.Split(':');
            if (pair.Length != 2
                || !int.TryParse(pair[0], NumberStyles.None, CultureInfo.InvariantCulture, out var type) || type is < 0 or > 3
                || !uint.TryParse(pair[1], NumberStyles.None, CultureInfo.InvariantCulture, out var delay))
            {
                return null;
            }

            actions.Add((type, delay));
        }

        return new FailureActionsSnapshot(reset, actions);
    }

    public bool Equals(FailureActionsSnapshot? other) =>
        other is not null && ResetPeriod == other.ResetPeriod && Actions.SequenceEqual(other.Actions);

    public override int GetHashCode() => HashCode.Combine(ResetPeriod, Actions.Count);
}

/// <summary>
/// Снимает и возвращает действия диспетчера служб при сбое службы на время принудительной остановки её процесса. Снятые
/// действия до снятия записываются в HKLM\Software\SplitVpn (<see cref="EmergencyRegistry.SavedFailureActionsValue"/>):
/// команда, прерванная между снятием и возвратом, не оставит службу без автоперезапуска навсегда — их вернёт следующая
/// команда или запуск службы (<see cref="RestoreLeftover"/>).
/// </summary>
internal static class ServiceFailurePolicy
{
    private const int FailureActions = 2;

    /// <summary>
    /// Читает текущие действия, записывает их через <paramref name="persist"/> и только потом снимает. Сбой записи —
    /// исключение, и действия не снимаются.
    /// </summary>
    public static FailureActionsSnapshot Suspend(string serviceName, Action<string> persist)
    {
        ArgumentNullException.ThrowIfNull(persist);
        using var service = new ServiceController(serviceName);
        var handle = service.ServiceHandle;
        var original = Query(handle);
        persist(original.Serialize());

        // При ненулевом массиве и нулевом числе действий SCM очищает только действия.
        var array = Marshal.AllocHGlobal(Marshal.SizeOf<ScAction>());
        try
        {
            var empty = new FailureActionConfiguration { Actions = array };
            if (!ChangeServiceConfig2(handle, FailureActions, ref empty)) throw new Win32Exception();
        }
        finally
        {
            Marshal.FreeHGlobal(array);
        }

        return original;
    }

    /// <summary>Записывает действия <paramref name="snapshot"/> службе.</summary>
    public static void Apply(string serviceName, FailureActionsSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        using var service = new ServiceController(serviceName);
        var size = Marshal.SizeOf<ScAction>();
        var array = Marshal.AllocHGlobal(size * Math.Max(1, snapshot.Actions.Count));
        try
        {
            for (var i = 0; i < snapshot.Actions.Count; i++)
            {
                Marshal.StructureToPtr(new ScAction { Type = snapshot.Actions[i].Type, Delay = snapshot.Actions[i].Delay }, array + (i * size), false);
            }

            var configuration = new FailureActionConfiguration
            {
                ResetPeriod = snapshot.ResetPeriod,
                Count = (uint)snapshot.Actions.Count,
                Actions = array,
            };
            if (!ChangeServiceConfig2(service.ServiceHandle, FailureActions, ref configuration)) throw new Win32Exception();
        }
        finally
        {
            Marshal.FreeHGlobal(array);
        }
    }

    private static FailureActionsSnapshot Query(SafeHandle handle)
    {
        _ = QueryServiceConfig2(handle, FailureActions, 0, 0, out var size);
        if (size == 0) throw new Win32Exception();
        var buffer = Marshal.AllocHGlobal(checked((int)size));
        try
        {
            if (!QueryServiceConfig2(handle, FailureActions, buffer, size, out _)) throw new Win32Exception();
            var configuration = Marshal.PtrToStructure<FailureActionConfiguration>(buffer);
            var actions = new List<(int, uint)>();
            for (var i = 0; i < configuration.Count; i++)
            {
                var action = Marshal.PtrToStructure<ScAction>(configuration.Actions + (i * Marshal.SizeOf<ScAction>()));
                actions.Add((action.Type, action.Delay));
            }

            return new FailureActionsSnapshot(configuration.ResetPeriod, actions);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>Записанные действия из реестра; null — нет.</summary>
    public static string? ReadSaved()
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = root.OpenSubKey(EmergencyRegistry.KeyPath);
        return key?.GetValue(EmergencyRegistry.SavedFailureActionsValue) as string;
    }

    public static void WriteSaved(string value)
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = root.CreateSubKey(EmergencyRegistry.KeyPath, writable: true);
        key.SetValue(EmergencyRegistry.SavedFailureActionsValue, value, RegistryValueKind.String);
    }

    public static void DeleteSaved()
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = root.OpenSubKey(EmergencyRegistry.KeyPath, writable: true);
        key?.DeleteValue(EmergencyRegistry.SavedFailureActionsValue, throwOnMissingValue: false);
    }

    /// <summary>
    /// Запуск службы: осталась запись от прерванной команды — действия при сбое возвращаются и запись удаляется. Сбой — только
    /// строка в <paramref name="warn"/>: запуск службы он не останавливает.
    /// </summary>
    public static void RestoreLeftover(string serviceName, Action<string> warn) =>
        RestoreLeftover(ReadSaved, snapshot => Apply(serviceName, snapshot), DeleteSaved, warn);

    /// <summary>Шов для тестов. Ответ — действия возвращены.</summary>
    internal static bool RestoreLeftover(Func<string?> read, Action<FailureActionsSnapshot> apply, Action delete, Action<string> warn)
    {
        ArgumentNullException.ThrowIfNull(warn);
        try
        {
            var text = read();
            if (text is null)
            {
                return false;
            }

            if (FailureActionsSnapshot.Parse(text) is not { } snapshot)
            {
                warn("записанные действия при сбое службы не разобраны («" + text + "»): запись удалена, действия не изменены");
                delete();
                return false;
            }

            apply(snapshot);
            delete();
            warn("действия при сбое службы, снятые прерванной командой экстренного отключения, возвращены");
            return true;
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or IOException or UnauthorizedAccessException
            or System.Security.SecurityException)
        {
            warn("действия при сбое службы, снятые прерванной командой, не возвращены: " + ex.Message);
            return false;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FailureActionConfiguration
    {
        public uint ResetPeriod;
        public nint RebootMessage;
        public nint Command;
        public uint Count;
        public nint Actions;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ScAction
    {
        public int Type;
        public uint Delay;
    }

    [DllImport("advapi32.dll", EntryPoint = "QueryServiceConfig2W", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfig2(SafeHandle service, int level, nint buffer, uint size, out uint needed);

    [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig2W", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig2(SafeHandle service, int level, ref FailureActionConfiguration configuration);
}
