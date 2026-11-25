using System.Security.AccessControl;
using System.Security.Principal;
using SplitVpn.Core.Recovery;
using SplitVpn.Windows.Security;

namespace SplitVpn.Service.Emergency;

/// <summary>Итог проверки каталога данных: <paramref name="Problem"/> = null — каталогу можно верить.</summary>
/// <param name="Exists">Каталог данных есть.</param>
internal sealed record DataRootTrustResult(bool Exists, string? Problem);

/// <summary>
/// Проверка каталога данных (%ProgramData%\SplitVpn) и копии DNS только чтением: ничего не исправляется, права потомков не
/// обходятся. Можно верить, если каталог и dns-backup.json — не ссылки, их владелец свой и право записи (создание,
/// изменение, удаление, смена прав и владельца) есть только у SYSTEM, Administrators и TrustedInstaller
/// (<see cref="AdminOnlyAccess"/>). Свой владелец — тот же, что у хранилища секретов (<see cref="SecretStore.IsAcceptedOwner"/>:
/// SYSTEM, Administrators или прямой член локальной группы Administrators — файл, созданный повышенным администратором),
/// а также TrustedInstaller. Иначе копию мог подложить пользователь — и DNS ушёл бы на его серверы, — а удалять такой
/// каталог рекурсивно нельзя. Те же правила повторяет recover-network.ps1.
/// </summary>
internal static class DataRootTrust
{
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
            or InvalidOperationException or PlatformNotSupportedException or System.ComponentModel.Win32Exception)
        {
            return new DataRootTrustResult(true, "не проверяется: " + ex.Message);
        }
    }

    /// <summary>Почему объекту нельзя верить; null — можно.</summary>
    internal static string? Problem(FileAttributes attributes, FileSystemSecurity security) =>
        Problem(attributes, security, SecretStore.IsLocalAdministrator);

    /// <summary>Шов для тестов на дескрипторах в памяти: <paramref name="isLocalAdministrator"/> — членство в Administrators.</summary>
    internal static string? Problem(FileAttributes attributes, FileSystemSecurity security, Func<SecurityIdentifier, bool> isLocalAdministrator) =>
        AdminOnlyAccess.Problem(attributes, security, AdminOnlyAccess.WriteRights,
            owner => owner.Equals(AdminOnlyAccess.TrustedInstaller) || SecretStore.IsAcceptedOwner(owner, isLocalAdministrator));
}
