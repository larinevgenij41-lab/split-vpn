using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SplitVpn.Windows.Security;

/// <summary>
/// Путь из данных пользователя без точек повторного анализа. <see cref="LocalPath.IsLocalFixed(string?)"/> смотрит
/// только на текст: «C:\Users\u\AppData\...» проходит, даже если «AppData» - символическая ссылка каталога на
/// \\attacker\share. Тогда File.Exists, CreateFile или RasGetEntryProperties от имени SYSTEM ушли бы на чужой узел
/// с NTLM-аутентификацией учётной записи компьютера (ссылку создаёт пользователь с правом на символические ссылки
/// или в режиме разработчика). Поэтому путь проходится от корня диска: каждый компонент открывается без перехода
/// по ссылке (FILE_FLAG_OPEN_REPARSE_POINT) и отвергается, если он сам точка повторного анализа (symlink, junction,
/// облачная заглушка). Открытые каталоги держатся без FILE_SHARE_DELETE до <see cref="Dispose"/>: пока путь
/// закреплён, компонент нельзя переименовать или удалить и подставить на его место ссылку.
/// </summary>
/// <remarks>
/// Системные junction («Documents and Settings», «All Users», «Application Data» в профиле) отвергаются тоже: служба
/// получает пути книг и профилей в их настоящем виде, и такие имена в них не встречаются.
/// </remarks>
public sealed partial class ReparseFreePath : IDisposable
{
    private readonly List<SafeFileHandle> _handles;

    private ReparseFreePath(List<SafeFileHandle> handles) => _handles = handles;

    /// <summary>
    /// Закрепляет каталоги пути (и сам файл, если <paramref name="includeFile"/>). null - путь не локальный,
    /// компонент - точка повторного анализа или не того вида (файл вместо каталога, каталог вместо файла).
    /// Ошибка открытия компонента - исключение ввода-вывода или доступа (как у <see cref="ConfinedFile"/>):
    /// отсутствующий каталог - DirectoryNotFoundException, отсутствующий файл - FileNotFoundException.
    /// </summary>
    public static ReparseFreePath? Pin(string path, bool includeFile)
    {
        if (!LocalPath.IsLocalFixed(path))
        {
            return null;
        }

        var full = Path.GetFullPath(path);
        var root = Path.GetPathRoot(full)!;
        var parts = full[root.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
        var count = includeFile ? parts.Length : parts.Length - 1;
        var handles = new List<SafeFileHandle>(Math.Max(count, 0));
        var current = root;
        try
        {
            for (var i = 0; i < count; i++)
            {
                current = Path.Combine(current, parts[i]);
                var last = i == parts.Length - 1;
                var handle = Open(current, last);
                handles.Add(handle);
                if (!Acceptable(handle, directory: !last))
                {
                    Release(handles);
                    return null;
                }
            }
        }
        catch
        {
            Release(handles);
            throw;
        }

        return new ReparseFreePath(handles);
    }

    /// <summary>Объект без точек повторного анализа (кроме прозрачных для данных файла: WOF, дедупликация) и нужного вида.</summary>
    private static bool Acceptable(SafeFileHandle handle, bool directory)
    {
        if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfoClass, out var info, (uint)Marshal.SizeOf<FileAttributeTagInfo>()))
        {
            return false;
        }

        var isDirectory = (info.FileAttributes & FileAttributeDirectory) != 0;
        if (directory)
        {
            return isDirectory && (info.FileAttributes & FileAttributeReparsePoint) == 0;
        }

        return ConfinedFile.Classify(info.FileAttributes, info.ReparseTag) != ConfinedFile.ReparseVerdict.Reject;
    }

    private static SafeFileHandle Open(string path, bool file)
    {
        // Чтение данных (список каталога) нужно ради режима общего доступа: доступ только к атрибутам в проверке
        // совместного доступа не участвует, и запрет FILE_SHARE_DELETE не держал бы компонент на месте.
        var flags = FileFlagOpenReparsePoint | (file ? 0 : FileFlagBackupSemantics);
        var handle = CreateFileW(path, FileReadData | FileReadAttributes, FileShareRead | FileShareWrite, 0, OpenExisting, flags, 0);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            // Нет промежуточного каталога: для вызывающего это отсутствующий путь, а не отсутствующий файл.
            throw ConfinedFile.OpenError(!file && error == ErrorFileNotFound ? ErrorPathNotFound : error);
        }

        return handle;
    }

    private static void Release(List<SafeFileHandle> handles)
    {
        foreach (var handle in handles)
        {
            handle.Dispose();
        }

        handles.Clear();
    }

    public void Dispose() => Release(_handles);

    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;
    private const uint FileReadData = 0x1;
    private const uint FileReadAttributes = 0x80;
    private const uint FileShareRead = 0x1;
    private const uint FileShareWrite = 0x2;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileAttributeDirectory = 0x10;
    private const uint FileAttributeReparsePoint = 0x400;

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
}
