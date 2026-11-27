using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SplitVpn.Windows.Security;

/// <summary>
/// Чтение файла из каталога, которым распоряжается обычный пользователь, процессом SYSTEM. Пользователь
/// может подложить вместо своего файла ссылку (symlink, junction на промежуточный каталог, жёсткую ссылку)
/// на чужой защищённый файл — служба прочла бы его своими правами — или путь на сетевой ресурс (служба
/// отправила бы туда NTLM-аутентификацию учётной записи компьютера). Поэтому путь и корень до открытия
/// должны быть локальными (<see cref="LocalPath"/>), сам файл открывается без перехода по ссылке на последнем
/// компоненте (FILE_FLAG_OPEN_REPARSE_POINT: открытая ссылка отвергается по тегу точки повторного анализа), а затем
/// проверяется уже открытый дескриптор: настоящий путь локальный и лежит внутри разрешённого корня, и у файла одно
/// имя. Ссылки на промежуточных каталогах (junction) по-прежнему отсекает сверка настоящего пути с корнем.
/// </summary>
public static unsafe partial class ConfinedFile
{
    /// <summary>
    /// Поток на чтение или null, если путь не локальный, файл сам является ссылкой (или облачной заглушкой), уводит
    /// за пределы корня или имеет несколько имён. Ошибка открытия - FileNotFoundException, DirectoryNotFoundException,
    /// UnauthorizedAccessException или IOException (в том числе файл, открытый другим процессом без общего доступа на
    /// чтение и запись). Открытие файла, на котором другой процесс держит oplock, ждёт его снятия без предела: вызов
    /// может зависнуть, и вызывающий код не должен ждать его бесконечно.
    /// </summary>
    public static FileStream? OpenRead(string path, string root)
    {
        if (!LocalPath.IsLocalFixed(path) || !LocalPath.IsLocalFixed(root))
        {
            return null;
        }

        // Символическая ссылка каталога на сетевой ресурс где-то в пути увела бы уже само открытие на чужой узел, до
        // сверки настоящего пути с корнем: каталоги проверяются и закрепляются до открытия файла.
        using var pin = ReparseFreePath.Pin(path, includeFile: false);
        if (pin is null)
        {
            return null;
        }

        var handle = Open(path, FileFlagOpenReparsePoint);
        try
        {
            if (Inspect(handle, root) is not { } first)
            {
                handle.Dispose();
                return null;
            }

            if (first.Transparent)
            {
                // Сжатие WOF и дедупликация: при открытии самой точки повторного анализа фильтр не участвует, и чтение
                // вернуло бы заглушку, а не данные. Файл открывается ещё раз обычным образом и должен оказаться тем же
                // самым (том и номер файла): подмена между открытиями на ссылку дала бы другой файл.
                var plain = Open(path, 0);
                Inspected? again;
                try
                {
                    again = Inspect(plain, root);
                }
                catch
                {
                    plain.Dispose();
                    throw;
                }

                if (again is not { } second || second.Volume != first.Volume || second.Index != first.Index)
                {
                    plain.Dispose();
                    handle.Dispose();
                    return null;
                }

                handle.Dispose();
                handle = plain;
            }

            return new FileStream(handle, FileAccess.Read);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static SafeFileHandle Open(string path, uint flags)
    {
        var handle = CreateFileW(path, GenericRead, FileShareRead | FileShareWrite | FileShareDelete, 0, OpenExisting, flags, 0);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw OpenError(error);
        }

        return handle;
    }

    /// <summary>
    /// Исключение для кода ошибки CreateFile. Не COMException (его даёт Marshal.GetExceptionForHR для части кодов):
    /// вызывающие (обнаружение конфликтов, сбор диагностики) ловят только исключения ввода-вывода и доступа.
    /// </summary>
    internal static Exception OpenError(int error)
    {
        var message = new System.ComponentModel.Win32Exception(error).Message;
        return error switch
        {
            2 => new FileNotFoundException(message),
            3 => new DirectoryNotFoundException(message),
            5 => new UnauthorizedAccessException(message),
            _ => new IOException(message, unchecked((int)0x80070000 | (error & 0xFFFF))),
        };
    }

    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x1;
    private const uint FileShareWrite = 0x2;
    private const uint FileShareDelete = 0x4;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileAttributeDirectory = 0x10;
    private const uint FileAttributeReparsePoint = 0x400;

    /// <summary>Сжатие WOF (compact.exe, CompactOS): данные отдаёт фильтр wof.sys.</summary>
    internal const uint ReparseTagWof = 0x80000017;

    /// <summary>Дедупликация данных Windows Server: данные отдаёт фильтр дедупликации.</summary>
    internal const uint ReparseTagDedup = 0x80000013;

    /// <summary>Как читать открытый объект.</summary>
    internal enum ReparseVerdict
    {
        /// <summary>Каталог, ссылка (symlink, junction), облачная заглушка или незнакомая точка повторного анализа.</summary>
        Reject,

        /// <summary>Обычный файл.</summary>
        Plain,

        /// <summary>Обычный файл, данные которого отдаёт фильтр (WOF, дедупликация): читать после обычного открытия.</summary>
        Transparent,
    }

    /// <summary>
    /// Классификация по атрибутам и тегу точки повторного анализа. Атрибут FILE_ATTRIBUTE_REPARSE_POINT бывает и у
    /// обычных файлов (сжатие WOF, дедупликация), поэтому решает тег: пропускаются только заведомо прозрачные теги.
    /// Ссылки (IO_REPARSE_TAG_SYMLINK, IO_REPARSE_TAG_MOUNT_POINT), облачные заглушки (IO_REPARSE_TAG_CLOUD_*: SYSTEM не
    /// должен запускать их загрузку) и любые незнакомые теги отвергаются.
    /// </summary>
    internal static ReparseVerdict Classify(uint attributes, uint reparseTag)
    {
        if ((attributes & FileAttributeDirectory) != 0)
        {
            return ReparseVerdict.Reject;
        }

        if ((attributes & FileAttributeReparsePoint) == 0)
        {
            return ReparseVerdict.Plain;
        }

        return reparseTag is ReparseTagWof or ReparseTagDedup ? ReparseVerdict.Transparent : ReparseVerdict.Reject;
    }

    /// <summary>Сведения о проверенном дескрипторе: прозрачная точка повторного анализа, том и номер файла.</summary>
    private readonly record struct Inspected(bool Transparent, uint Volume, ulong Index);

    /// <summary>null - объект читать нельзя (ссылка, каталог, несколько имён, путь вне корня).</summary>
    private static Inspected? Inspect(SafeFileHandle handle, string root)
    {
        if (!GetFileInformationByHandle(handle, out var info) || info.NumberOfLinks != 1
            || !GetFileInformationByHandleEx(handle, FileAttributeTagInfoClass, out var tag, (uint)sizeof(FileAttributeTagInfo)))
        {
            return null;
        }

        var verdict = Classify(tag.FileAttributes, tag.ReparseTag);
        if (verdict == ReparseVerdict.Reject || Classify(info.FileAttributes, tag.ReparseTag) == ReparseVerdict.Reject || !IsConfined(handle, root))
        {
            return null;
        }

        return new Inspected(verdict == ReparseVerdict.Transparent, info.VolumeSerialNumber, ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow);
    }

    private static bool IsConfined(SafeFileHandle handle, string root)
    {
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

        return IsFinalPathConfined(new string(buffer, 0, (int)length), root);
    }

    /// <summary>Настоящий путь открытого файла (как его вернул GetFinalPathNameByHandle) локальный и внутри корня.</summary>
    internal static bool IsFinalPathConfined(string finalPath, string root)
    {
        var final = StripPrefix(finalPath);
        if (!LocalPath.IsDriveLetterPath(final))
        {
            return false;
        }

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

    /// <summary>FileAttributeTagInfo из FILE_INFO_BY_HANDLE_CLASS.</summary>
    private const int FileAttributeTagInfoClass = 9;

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfo
    {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileInformationByHandleEx(SafeFileHandle file, int informationClass, out FileAttributeTagInfo information, uint size);

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial SafeFileHandle CreateFileW(string fileName, uint desiredAccess, uint shareMode, nint securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, nint templateFile);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static unsafe partial uint GetFinalPathNameByHandleW(SafeFileHandle file, char* path, uint length, uint flags);
}
