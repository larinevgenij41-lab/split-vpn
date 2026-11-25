using System.Diagnostics;
using Windows.Win32;
using Windows.Win32.System.Threading;

namespace SplitVpn.Windows.Native;

/// <summary>Полный путь исполняемого файла процесса.</summary>
public static class ProcessImage
{
    /// <summary>
    /// Путь файла процесса или null, если его не узнать. Сначала QueryFullProcessImageName — ему хватает права
    /// PROCESS_QUERY_LIMITED_INFORMATION, которое администратор получает и к процессу службы от SYSTEM; MainModule
    /// требует чтения памяти процесса и на таких процессах часто отказывает.
    /// </summary>
    public static string? TryGetPath(Process process)
    {
        ArgumentNullException.ThrowIfNull(process);
        try
        {
            using var handle = PInvoke.OpenProcess_SafeHandle(PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)process.Id);
            if (!handle.IsInvalid)
            {
                Span<char> buffer = stackalloc char[1024];
                var size = (uint)buffer.Length;
                if (PInvoke.QueryFullProcessImageName(handle, PROCESS_NAME_FORMAT.PROCESS_NAME_WIN32, buffer, ref size))
                {
                    return new string(buffer[..(int)size]);
                }
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or ArgumentException)
        {
            // Процесс уже завершился.
        }

        try
        {
            return process.MainModule?.FileName;
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
        {
            return null;
        }
    }
}
