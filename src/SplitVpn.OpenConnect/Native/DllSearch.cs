using System.Runtime.InteropServices;

namespace SplitVpn.OpenConnect.Native;

/// <summary>
/// Порядок поиска DLL помощника. Он работает от LocalSystem, а стандартный поиск Windows заглядывает в текущий
/// каталог и в каталоги PATH, куда обычный пользователь может положить свою DLL с именем зависимости
/// libopenconnect (libgnutls-30.dll, zlib1.dll…) или библиотеки, которую она грузит позже. Все нативные
/// библиотеки поставки лежат рядом с exe (SplitVpn.OpenConnect.csproj, scripts\build-openconnect.sh), их
/// зависимости, кроме собственных, - системные, поэтому достаточно каталога приложения и System32. Каталог
/// приложения - каталог exe, а он доступен на запись только администраторам.
/// </summary>
internal static partial class DllSearch
{
    private const uint LoadLibrarySearchApplicationDir = 0x00000200;
    private const uint LoadLibrarySearchSystem32 = 0x00000800;

    /// <summary>false - порядок поиска не изменён (код ошибки - в Marshal.GetLastPInvokeError).</summary>
    public static bool Harden() =>
        SetDefaultDllDirectories(LoadLibrarySearchApplicationDir | LoadLibrarySearchSystem32)
        // Пустая строка убирает текущий каталог из поиска и для вызовов, которые идут мимо каталогов по умолчанию.
        && SetDllDirectoryW("");

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetDefaultDllDirectories(uint directoryFlags);

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetDllDirectoryW(string pathName);
}
