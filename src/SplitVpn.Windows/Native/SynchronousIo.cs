using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SplitVpn.Windows.Native;

/// <summary>
/// Отмена синхронного ввода-вывода чужого потока (CancelSynchronousIo). Ею прерывается и открытие файла, которое ждёт
/// снятия oplock другим процессом: само по себе такое открытие ждёт без предела.
/// </summary>
public static partial class SynchronousIo
{
    private const uint ThreadTerminate = 0x0001;

    /// <summary>Дескриптор текущего потока с правом отмены его ввода-вывода; null — не открылся.</summary>
    public static SafeWaitHandle? OpenCurrentThread()
    {
        var handle = OpenThread(ThreadTerminate, false, GetCurrentThreadId());
        if (handle.IsInvalid)
        {
            handle.Dispose();
            return null;
        }

        return handle;
    }

    /// <summary>
    /// Отменить синхронную операцию потока. true — операция была и отменена; false — поток сейчас ничего не ждёт
    /// (ERROR_NOT_FOUND) или отмена не удалась.
    /// </summary>
    public static bool Cancel(SafeWaitHandle thread)
    {
        ArgumentNullException.ThrowIfNull(thread);
        return CancelSynchronousIo(thread);
    }

    [LibraryImport("kernel32.dll")]
    private static partial uint GetCurrentThreadId();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial SafeWaitHandle OpenThread(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint threadId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CancelSynchronousIo(SafeWaitHandle thread);
}
