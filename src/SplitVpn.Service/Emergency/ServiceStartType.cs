using System.ComponentModel;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using Microsoft.Win32;
using SplitVpn.Core.Recovery;

namespace SplitVpn.Service.Emergency;

/// <summary>
/// Тип запуска службы. Читается из раздела службы в реестре, меняется только через диспетчер служб
/// (ChangeServiceConfig): прямая запись в реестр не дошла бы до его кеша до перезагрузки.
/// </summary>
internal static class ServiceStartType
{
    private const uint ServiceNoChange = 0xFFFFFFFF;
    private const uint AutoStart = 2;
    private const uint DemandStart = 3;
    private const uint Disabled = 4;
    private const int DelayedAutoStartInfo = 3;

    /// <summary>Текущий тип (<see cref="EmergencyRegistry.StartAuto"/> и т. д.); null — службы нет.</summary>
    public static string? Read(string serviceName)
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + serviceName);
        if (key?.GetValue("Start") is not int start)
        {
            return null;
        }

        return start switch
        {
            (int)AutoStart => key.GetValue("DelayedAutostart") is int delayed && delayed != 0 ? EmergencyRegistry.StartDelayedAuto : EmergencyRegistry.StartAuto,
            (int)Disabled => EmergencyRegistry.StartDisabled,
            _ => EmergencyRegistry.StartDemand,
        };
    }

    public static void Set(string serviceName, string type)
    {
        using var service = new ServiceController(serviceName);
        var handle = service.ServiceHandle;
        var start = type switch
        {
            EmergencyRegistry.StartAuto or EmergencyRegistry.StartDelayedAuto => AutoStart,
            EmergencyRegistry.StartDisabled => Disabled,
            _ => DemandStart,
        };
        if (!ChangeServiceConfig(handle, ServiceNoChange, start, ServiceNoChange, null, null, 0, null, null, null, null))
        {
            throw new Win32Exception();
        }

        if (start == AutoStart)
        {
            var info = new DelayedAutoStart { Delayed = type == EmergencyRegistry.StartDelayedAuto ? 1 : 0 };
            if (!ChangeServiceConfig2(handle, DelayedAutoStartInfo, ref info))
            {
                throw new Win32Exception();
            }
        }
    }

    /// <summary>Ставит ручной запуск, если он не ручной. Ответ — прежний тип; null — уже был ручной.</summary>
    public static string? EnsureManual(string serviceName)
    {
        var current = Read(serviceName);
        if (current is null or EmergencyRegistry.StartDemand)
        {
            return null;
        }

        Set(serviceName, EmergencyRegistry.StartDemand);
        return current;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DelayedAutoStart
    {
        public int Delayed;
    }

    [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfigW", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig(SafeHandle service, uint serviceType, uint startType, uint errorControl,
        string? binaryPathName, string? loadOrderGroup, nint tagId, string? dependencies, string? serviceStartName, string? password, string? displayName);

    [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig2W", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig2(SafeHandle service, int level, ref DelayedAutoStart info);
}
