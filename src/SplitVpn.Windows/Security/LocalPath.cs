namespace SplitVpn.Windows.Security;

/// <summary>
/// Проверка пути, полученного от пользователя или из его данных (телефонная книга из RasEnumConnections,
/// папка AppData из HKU), до того как служба (SYSTEM) к нему обратится. Сетевой путь служба открыла бы с
/// учётной записью компьютера: \\attacker\share\x.pbk вызывает NTLM-аутентификацию на чужом узле. Поэтому
/// допускается только полный путь вида «X:\…» на несъёмном локальном диске; UNC (\\server\share), пути
/// устройств и пространства имён (\\?\, \\.\, \\?\UNC\, \\?\GLOBALROOT), относительные и «X:файл» отвергаются
/// без обращения к файловой системе.
/// </summary>
public static class LocalPath
{
    /// <summary>Полный путь на несъёмном локальном диске.</summary>
    public static bool IsLocalFixed(string? path) => IsLocalFixed(path, static root => new DriveInfo(root).DriveType);

    /// <summary><paramref name="driveType"/> - тип диска по корню «X:\» (шов для тестов).</summary>
    internal static bool IsLocalFixed(string? path, Func<string, DriveType> driveType)
    {
        ArgumentNullException.ThrowIfNull(driveType);
        if (!IsDriveLetterPath(path))
        {
            return false;
        }

        try
        {
            // GetDriveType по корню буквы: подключённый сетевой диск - Network, флешка - Removable.
            return driveType(char.ToUpperInvariant(path![0]) + @":\") == DriveType.Fixed;
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Чистая классификация без обращения к системе: только «X:\…» (или «X:/…») без нулевых символов. Всё, что
    /// начинается с двух разделителей (UNC, \\?\, \\.\), относительные пути и «X:файл» - нет.
    /// </summary>
    internal static bool IsDriveLetterPath(string? path) =>
        !string.IsNullOrEmpty(path)
        && path.Length >= 3
        && char.IsAsciiLetter(path[0])
        && path[1] == ':'
        && path[2] is '\\' or '/'
        && !path.Contains('\0', StringComparison.Ordinal)
        && Path.IsPathFullyQualified(path);
}
