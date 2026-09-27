using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace SplitVpn.Core.Ipc;

/// <summary>
/// Учётная запись процесса-клиента канала — сразу после подключения, без первого кадра: олицетворение
/// клиента возможно только после чтения из канала. Номер процесса клиента сообщает сам канал, поэтому
/// ответ годится только на отказ: подтверждение прав остаётся за олицетворением по первому кадру.
/// </summary>
[SupportedOSPlatform("windows")]
public static partial class PipeClientIdentity
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;

    /// <summary>Токен процесса клиента; null — определить не удалось (процесс завершился, доступа нет).</summary>
    public static WindowsIdentity? TryOpen(SafePipeHandle pipe)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        if (!GetNamedPipeClientProcessId(pipe, out var processId) || processId == 0)
        {
            return null;
        }

        var process = OpenProcess(ProcessQueryLimitedInformation, false, processId);
        if (process == 0)
        {
            return null;
        }

        try
        {
            if (!OpenProcessToken(process, TokenQuery, out var token))
            {
                return null;
            }

            try
            {
                // Конструктор дублирует токен: исходный дескриптор закрывается здесь же.
                return new WindowsIdentity(token);
            }
            finally
            {
                CloseHandle(token);
            }
        }
        finally
        {
            CloseHandle(process);
        }
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint clientProcessId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(nint process, uint desiredAccess, out nint token);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint handle);
}
