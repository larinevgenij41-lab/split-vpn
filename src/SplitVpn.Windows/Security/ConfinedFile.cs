using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SplitVpn.Windows.Security;

/// <summary>
/// Чтение файла из каталога, которым распоряжается обычный пользователь, процессом SYSTEM. Пользователь
/// может подложить вместо своего файла ссылку (symlink, junction на промежуточный каталог, жёсткую ссылку)
/// на чужой защищённый файл — служба прочла бы его своими правами. Поэтому файл открывается, а затем
/// проверяется уже открытый дескриптор: настоящий путь лежит внутри разрешённого корня, и у файла одно имя.
/// </summary>
public static unsafe partial class ConfinedFile
{
    /// <summary>Поток на чтение или null, если файл уводит за пределы корня или имеет несколько имён.</summary>
    public static FileStream? OpenRead(string path, string root)
    {
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        try
        {
            if (IsConfined(stream.SafeFileHandle, root))
            {
                return stream;
            }
        }
        catch
        {
            stream.Dispose();
            throw;
        }

        stream.Dispose();
        return null;
    }

    private static bool IsConfined(SafeFileHandle handle, string root)
    {
        if (!GetFileInformationByHandle(handle, out var info) || info.NumberOfLinks != 1)
        {
            return false;
        }

        var buffer = new char[1024];
        uint length;
        fixed (char* chars = buffer)
        {
            length = GetFinalPathNameByHandleW(handle, chars, (uint)buffer.Length, 0);
        }

        if (length == 0 || length >= buffer.Length)
        {
            return false;
        }

        var final = StripPrefix(new string(buffer, 0, (int)length));
        var expected = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)) + Path.DirectorySeparatorChar;
        return final.StartsWith(expected, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>«\\?\C:\…» → «C:\…»; сетевые пути («\\?\UNC\…») корнем профиля не бывают и отвергаются сравнением.</summary>
    private static string StripPrefix(string path) =>
        path.StartsWith(@"\\?\", StringComparison.Ordinal) && !path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase) ? path[4..] : path;

    // FILETIME — два DWORD без выравнивания на 8: отсюда Pack = 4.
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct FileInformation
    {
        public uint FileAttributes;
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation information);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static unsafe partial uint GetFinalPathNameByHandleW(SafeFileHandle file, char* path, uint length, uint flags);
}
