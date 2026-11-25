using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SplitVpn.Core.Recovery;

/// <summary>
/// Объект файловой системы «под контролем только администраторов» — одно правило для службы (каталог данных и копия DNS,
/// DataRootTrust), приложения (отчёт last.json, файл службы и скрипт восстановления, которые запускаются с повышением) и
/// скрипта recover-network.ps1 (повторяет те же правила на PowerShell). Проверка только читает: ничего не исправляет и
/// потомков не обходит.
/// </summary>
[SupportedOSPlatform("windows")]
public static class AdminOnlyAccess
{
    /// <summary>
    /// Право изменить сам объект: запись и дописывание (в каталоге — создание файлов и подкаталогов), атрибуты, удаление,
    /// удаление потомков, смена прав и владельца, а также общие GENERIC_ALL и GENERIC_WRITE.
    /// </summary>
    public const FileSystemRights WriteRights = FileSystemRights.WriteData | FileSystemRights.AppendData
        | FileSystemRights.WriteExtendedAttributes | FileSystemRights.WriteAttributes | FileSystemRights.Delete
        | FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership
        | GenericAll | GenericWrite;

    /// <summary>
    /// Право подменить уже существующий путь через каталог-предок: удалить или переименовать его самого или его потомка,
    /// сменить права или владельца. Создание новых файлов и каталогов в предке (у «Прошедших проверку» на корне диска оно
    /// есть) существующий компонент пути не подменяет и здесь не учитывается.
    /// </summary>
    public const FileSystemRights ReplaceRights = FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles
        | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership | GenericAll | GenericWrite;

    private const FileSystemRights GenericAll = (FileSystemRights)0x10000000;
    private const FileSystemRights GenericWrite = (FileSystemRights)0x40000000;

    /// <summary>NT SERVICE\TrustedInstaller.</summary>
    public static readonly SecurityIdentifier TrustedInstaller = new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    /// <summary>SYSTEM, Administrators или TrustedInstaller.</summary>
    public static bool IsAdminPrincipal(SecurityIdentifier sid)
    {
        ArgumentNullException.ThrowIfNull(sid);
        return sid.IsWellKnown(WellKnownSidType.LocalSystemSid) || sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) || sid.Equals(TrustedInstaller);
    }

    /// <summary>
    /// Почему объекту нельзя верить; null — можно. Нельзя, если он — точка повторной обработки (ссылка, junction), его
    /// владелец не принят <paramref name="ownerAccepted"/> или разрешающее правило, относящееся к самому объекту, даёт
    /// кому-то кроме SYSTEM, Administrators и TrustedInstaller хоть одно право из <paramref name="forbidden"/>. Правило
    /// только для потомков и CREATOR OWNER в действующем правиле ничего не дают и не учитываются.
    /// </summary>
    public static string? Problem(FileAttributes attributes, FileSystemSecurity security, FileSystemRights forbidden, Func<SecurityIdentifier, bool> ownerAccepted)
    {
        ArgumentNullException.ThrowIfNull(security);
        ArgumentNullException.ThrowIfNull(ownerAccepted);
        if (attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            return "оказался ссылкой на другой путь";
        }

        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !ownerAccepted(owner))
        {
            return "принадлежит посторонней учётной записи";
        }

        foreach (FileSystemAccessRule rule in security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow || rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly)
                || (rule.FileSystemRights & forbidden) == 0 || rule.IdentityReference is not SecurityIdentifier sid
                || IsAdminPrincipal(sid) || sid.IsWellKnown(WellKnownSidType.CreatorOwnerSid))
            {
                continue;
            }

            return "даёт право записи посторонней учётной записи (" + sid.Value + ")";
        }

        return null;
    }

    /// <summary>
    /// Файл, который приложение запускает с правами администратора (файл службы, скрипт восстановления): полный путь на
    /// несъёмном локальном диске; сам файл и каждый каталог до корня диска — не ссылки и принадлежат SYSTEM, Administrators
    /// или TrustedInstaller; файл и его каталог не дают права записи никому, кроме них, а каталоги выше — права подменить
    /// путь (<see cref="ReplaceRights"/>). Иначе обычный пользователь подложил бы свой файл (или библиотеку рядом с ним), и
    /// окно UAC запустило бы его от имени администратора. Ответ — почему нельзя; null — можно.
    /// </summary>
    public static string? ElevationTargetProblem(string path) => ElevationTargetProblem(path, ReadEntry);

    /// <summary>Шов для тестов: <paramref name="read"/> — атрибуты и дескриптор объекта (каталога, если второй аргумент true).</summary>
    public static string? ElevationTargetProblem(string path, Func<string, bool, (FileAttributes Attributes, FileSystemSecurity Security)?> read)
    {
        ArgumentNullException.ThrowIfNull(read);
        if (string.IsNullOrEmpty(path) || path.Length < 4 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\'
            || path.Contains('\0', StringComparison.Ordinal) || !Path.IsPathFullyQualified(path)
            || !string.Equals(Path.GetFullPath(path), path, StringComparison.OrdinalIgnoreCase))
        {
            return "путь не полный локальный";
        }

        try
        {
            var current = path;
            var level = 0;
            while (current is not null)
            {
                var directory = level > 0;
                if (read(current, directory) is not { } entry)
                {
                    return current + ": не найден";
                }

                if (!directory && entry.Attributes.HasFlag(FileAttributes.Directory))
                {
                    return current + ": не файл";
                }

                // Файл и его каталог: никакой записи; выше — никакой подмены пути.
                var forbidden = level <= 1 ? WriteRights : ReplaceRights;
                if (Problem(entry.Attributes, entry.Security, forbidden, IsAdminPrincipal) is { } problem)
                {
                    return current + ": " + problem;
                }

                current = Path.GetDirectoryName(current);
                level++;
            }

            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException
            or InvalidOperationException or PlatformNotSupportedException or ArgumentException)
        {
            return "не проверяется: " + ex.Message;
        }
    }

    private static (FileAttributes, FileSystemSecurity)? ReadEntry(string path, bool directory)
    {
        if (directory)
        {
            var info = new DirectoryInfo(path);
            return info.Exists ? (info.Attributes, info.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access)) : null;
        }

        var file = new FileInfo(path);
        return file.Exists ? (file.Attributes, file.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access)) : null;
    }

    /// <summary>
    /// Каталог или файл, записанный службой или командой с правами администратора (отчёт last.json): не ссылка и
    /// принадлежит SYSTEM или Administrators. Права на чтение не проверяются — только кто мог создать объект.
    /// </summary>
    public static string? OwnedByAdminsProblem(FileSystemInfo entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        try
        {
            entry.Refresh();
            if (!entry.Exists)
            {
                return entry.FullName + ": не найден";
            }

            if (entry.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                return entry.FullName + ": оказался ссылкой на другой путь";
            }

            var security = entry is DirectoryInfo directory
                ? (FileSystemSecurity)directory.GetAccessControl(AccessControlSections.Owner)
                : ((FileInfo)entry).GetAccessControl(AccessControlSections.Owner);
            return security.GetOwner(typeof(SecurityIdentifier)) is SecurityIdentifier owner
                && (owner.IsWellKnown(WellKnownSidType.LocalSystemSid) || owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
                ? null
                : entry.FullName + ": принадлежит посторонней учётной записи";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException
            or InvalidOperationException or PlatformNotSupportedException)
        {
            return entry.FullName + ": не проверяется (" + ex.Message + ")";
        }
    }
}
