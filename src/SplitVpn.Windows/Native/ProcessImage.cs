using System.Diagnostics;
using System.Runtime.InteropServices;
using Windows.Win32;
using Windows.Win32.System.Threading;

namespace SplitVpn.Windows.Native;

/// <summary>Полный путь исполняемого файла процесса и его командная строка.</summary>
public static partial class ProcessImage
{
    /// <summary>ProcessCommandLineInformation (Windows 8.1+): достаточно права PROCESS_QUERY_LIMITED_INFORMATION.</summary>
    private const int ProcessCommandLineInformation = 60;

    private const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);

    /// <summary>
    /// Аргументы командной строки процесса, разобранные как у CommandLineToArgvW (первый — сам файл); null — не узнать
    /// (процесс завершился, нет доступа).
    /// </summary>
    public static IReadOnlyList<string>? TryGetArguments(int processId)
    {
        try
        {
            using var handle = PInvoke.OpenProcess_SafeHandle(PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)processId);
            if (handle.IsInvalid)
            {
                return null;
            }

            var status = NtQueryInformationProcess(handle, ProcessCommandLineInformation, 0, 0, out var needed);
            if (status != StatusInfoLengthMismatch || needed <= 0 || needed > 1 << 20)
            {
                return null;
            }

            var buffer = Marshal.AllocHGlobal(needed);
            try
            {
                if (NtQueryInformationProcess(handle, ProcessCommandLineInformation, buffer, needed, out _) != 0)
                {
                    return null;
                }

                // UNICODE_STRING: Length (байты), MaximumLength, выравнивание, указатель на текст внутри того же буфера.
                var length = (ushort)Marshal.ReadInt16(buffer);
                var text = Marshal.ReadIntPtr(buffer, IntPtr.Size);
                return text == 0 ? null : SplitCommandLine(Marshal.PtrToStringUni(text, length / 2));
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>Разбор командной строки по правилам Windows (CommandLineToArgvW).</summary>
    public static IReadOnlyList<string> SplitCommandLine(string commandLine)
    {
        ArgumentNullException.ThrowIfNull(commandLine);
        if (commandLine.Trim().Length == 0)
        {
            return [];
        }

        var argv = CommandLineToArgvW(commandLine, out var count);
        if (argv == 0)
        {
            return [];
        }

        try
        {
            var result = new string[count];
            for (var i = 0; i < count; i++)
            {
                result[i] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv, i * IntPtr.Size)) ?? "";
            }

            return result;
        }
        finally
        {
            _ = LocalFree(argv);
        }
    }

    [LibraryImport("ntdll.dll")]
    private static partial int NtQueryInformationProcess(SafeHandle process, int informationClass, nint information, int length, out int returnLength);

    [LibraryImport("shell32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint CommandLineToArgvW(string commandLine, out int count);

    [LibraryImport("kernel32.dll")]
    private static partial nint LocalFree(nint memory);

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
