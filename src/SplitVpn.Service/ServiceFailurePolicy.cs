using System.ComponentModel;
using System.Runtime.InteropServices;
using System.ServiceProcess;

namespace SplitVpn.Service;

/// <summary>Сохраняет конфигурацию восстановления SCM на время принудительной остановки процесса службы.</summary>
internal sealed class ServiceFailurePolicy : IDisposable
{
    private const int FailureActions = 2;
    private readonly ServiceController _service;
    private readonly nint _original;

    private ServiceFailurePolicy(ServiceController service, nint original)
    {
        _service = service;
        _original = original;
    }

    internal static ServiceFailurePolicy Suspend(string serviceName)
    {
        var service = new ServiceController(serviceName);
        nint original = 0;
        try
        {
            var handle = service.ServiceHandle;
            _ = QueryServiceConfig2(handle, FailureActions, 0, 0, out var size);
            if (size == 0) throw new Win32Exception();
            original = Marshal.AllocHGlobal(checked((int)size));
            if (!QueryServiceConfig2(handle, FailureActions, original, size, out _)) throw new Win32Exception();

            // При ненулевом массиве и нулевом числе действий SCM очищает только действия.
            var empty = new FailureActionConfiguration { Actions = original };
            if (!ChangeServiceConfig2(handle, FailureActions, ref empty)) throw new Win32Exception();
            return new ServiceFailurePolicy(service, original);
        }
        catch
        {
            Marshal.FreeHGlobal(original);
            service.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        try
        {
            var original = Marshal.PtrToStructure<FailureActionConfiguration>(_original);
            if (!ChangeServiceConfig2(_service.ServiceHandle, FailureActions, ref original)) throw new Win32Exception();
        }
        finally
        {
            Marshal.FreeHGlobal(_original);
            _service.Dispose();
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

    [DllImport("advapi32.dll", EntryPoint = "QueryServiceConfig2W", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfig2(SafeHandle service, int level, nint buffer, uint size, out uint needed);

    [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig2W", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig2(SafeHandle service, int level, ref FailureActionConfiguration configuration);
}
