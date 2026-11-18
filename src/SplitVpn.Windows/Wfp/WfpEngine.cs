using SplitVpn.Windows.Native;
using Windows.Win32;
using Windows.Win32.NetworkManagement.WindowsFilteringPlatform;

namespace SplitVpn.Windows.Wfp;

/// <summary>Сессия движка WFP. Динамическая сессия удаляет свои объекты при закрытии.</summary>
public sealed unsafe class WfpEngine : IDisposable
{
    private const uint RpcAuthnWinNt = 10;
    private const uint SessionFlagDynamic = 0x00000001;

    private readonly FwpmEngineClose0SafeHandle _handle;

    private WfpEngine(FwpmEngineClose0SafeHandle handle)
    {
        _handle = handle;
    }

    internal FWPM_ENGINE_HANDLE Handle => new(_handle.DangerousGetHandle());

    public static WfpEngine Open(bool dynamicSession)
    {
        var session = new FWPM_SESSION0
        {
            flags = dynamicSession ? SessionFlagDynamic : 0,
            txnWaitTimeoutInMSec = 15_000,
        };
        var code = PInvoke.FwpmEngineOpen0(RpcAuthnWinNt, null, session, out var handle);
        NativeCallException.ThrowIfFailed(code, "FwpmEngineOpen0");
        return new WfpEngine(handle);
    }

    public void Dispose() => _handle.Dispose();

    /// <summary>Выполняет действия в транзакции: при исключении транзакция прерывается, изменений нет.</summary>
    public void InTransaction(Action<WfpEngine> body)
    {
        ArgumentNullException.ThrowIfNull(body);
        NativeCallException.ThrowIfFailed(PInvoke.FwpmTransactionBegin0(Handle, 0), "FwpmTransactionBegin0");
        try
        {
            body(this);
            NativeCallException.ThrowIfFailed(PInvoke.FwpmTransactionCommit0(Handle), "FwpmTransactionCommit0");
        }
        catch
        {
            _ = PInvoke.FwpmTransactionAbort0(Handle);
            throw;
        }
    }
}
