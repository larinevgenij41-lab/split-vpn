using System.Security.AccessControl;
using System.Security.Principal;

namespace SplitVpn.Service.Emergency;

/// <summary>Итог проверки каталога данных: <paramref name="Problem"/> = null — каталогу можно верить.</summary>
/// <param name="Exists">Каталог данных есть.</param>
internal sealed record DataRootTrustResult(bool Exists, string? Problem);

/// <summary>
/// Проверка каталога данных (%ProgramData%\SplitVpn) и копии DNS только чтением: ничего не исправляется, права потомков не
/// обходятся. Можно верить, если каталог и dns-backup.json — не ссылки, их владелец SYSTEM или Administrators и право
/// записи (создание, изменение, удаление, смена прав и владельца) есть только у SYSTEM, Administrators и TrustedInstaller.
/// Иначе копию мог подложить пользователь — и DNS ушёл бы на его серверы, — а удалять такой каталог рекурсивно нельзя.
/// </summary>
internal static class DataRootTrust
{
    private const FileSystemRights WriteRights = FileSystemRights.WriteData | FileSystemRights.AppendData
        | FileSystemRights.WriteExtendedAttributes | FileSystemRights.WriteAttributes | FileSystemRights.Delete
        | FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

    /// <summary>NT SERVICE\TrustedInstaller.</summary>
    private static readonly SecurityIdentifier TrustedInstaller = new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    public static DataRootTrustResult Check(string root, string backupFile)
    {
        try
        {
            if (File.Exists(root))
            {
                return new DataRootTrustResult(true, "оказался файлом");
            }

            var directory = new DirectoryInfo(root);
            if (!directory.Exists)
            {
                return new DataRootTrustResult(false, null);
            }

            if (Problem(directory.Attributes, directory.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access)) is { } rootProblem)
            {
                return new DataRootTrustResult(true, rootProblem);
            }

            var file = new FileInfo(backupFile);
            if (file.Exists && Problem(file.Attributes, file.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access)) is { } fileProblem)
            {
                return new DataRootTrustResult(true, "копия DNS: " + fileProblem);
            }

            return new DataRootTrustResult(true, null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException
            or InvalidOperationException or PlatformNotSupportedException)
        {
            return new DataRootTrustResult(true, "не проверяется: " + ex.Message);
        }
    }

    /// <summary>Почему объекту нельзя верить; null — можно. Отдельно — для тестов на дескрипторах в памяти.</summary>
    internal static string? Problem(FileAttributes attributes, FileSystemSecurity security)
    {
        ArgumentNullException.ThrowIfNull(security);
        if (attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            return "оказался ссылкой на другой путь";
        }

        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !IsTrusted(owner))
        {
            return "принадлежит посторонней учётной записи";
        }

        foreach (FileSystemAccessRule rule in security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)))
        {
            // Правило только для потомков к самому объекту не относится; CREATOR OWNER в действующем правиле ничего не даёт.
            if (rule.AccessControlType != AccessControlType.Allow || rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly)
                || (rule.FileSystemRights & WriteRights) == 0 || rule.IdentityReference is not SecurityIdentifier sid
                || IsTrusted(sid) || sid.IsWellKnown(WellKnownSidType.CreatorOwnerSid))
            {
                continue;
            }

            return "даёт право записи посторонней учётной записи (" + sid.Value + ")";
        }

        return null;
    }

    private static bool IsTrusted(SecurityIdentifier sid) =>
        sid.IsWellKnown(WellKnownSidType.LocalSystemSid) || sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) || sid.Equals(TrustedInstaller);
}
