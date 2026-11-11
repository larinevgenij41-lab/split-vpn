using System.Diagnostics;
using System.Runtime.InteropServices;
using SplitVpn.Windows.Native;
using Windows.Win32;
using Windows.Win32.System.ProcessStatus;
using Windows.Win32.System.Services;

namespace SplitVpn.Windows.Diagnostics;

/// <summary>Системные показатели для замеров прототипа.</summary>
public static unsafe class SystemMetrics
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;

    public static ulong KernelNonpagedBytes()
    {
        var info = new PERFORMANCE_INFORMATION { cb = (uint)sizeof(PERFORMANCE_INFORMATION) };
        if (!PInvoke.GetPerformanceInfo(ref info, info.cb))
        {
            throw new NativeCallException("GetPerformanceInfo", (uint)Marshal.GetLastPInvokeError());
        }

        return (ulong)info.KernelNonpaged * info.PageSize;
    }

    public static (uint ProcessId, string State) ServiceStatus(string serviceName)
    {
        using var manager = PInvoke.OpenSCManager(null, null, ScManagerConnect);
        if (manager.IsInvalid)
        {
            throw new NativeCallException("OpenSCManager", (uint)Marshal.GetLastPInvokeError());
        }

        using var service = PInvoke.OpenService(manager, serviceName, ServiceQueryStatus);
        if (service.IsInvalid)
        {
            throw new NativeCallException("OpenService " + serviceName, (uint)Marshal.GetLastPInvokeError());
        }

        Span<byte> buffer = stackalloc byte[sizeof(SERVICE_STATUS_PROCESS)];
        if (!PInvoke.QueryServiceStatusEx(service, SC_STATUS_TYPE.SC_STATUS_PROCESS_INFO, buffer, out _))
        {
            throw new NativeCallException("QueryServiceStatusEx", (uint)Marshal.GetLastPInvokeError());
        }

        var status = MemoryMarshal.Read<SERVICE_STATUS_PROCESS>(buffer);
        return (status.dwProcessId, status.dwCurrentState.ToString());
    }

    /// <summary>Приватная память процесса, в котором работает служба (для BFE — общий svchost).</summary>
    public static long ServicePrivateBytes(string serviceName)
    {
        var (pid, _) = ServiceStatus(serviceName);
        using var process = Process.GetProcessById((int)pid);
        return process.PrivateMemorySize64;
    }
}
