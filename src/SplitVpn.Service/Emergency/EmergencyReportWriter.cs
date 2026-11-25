using System.Globalization;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using SplitVpn.Core.Recovery;

namespace SplitVpn.Service.Emergency;

/// <summary>
/// Отчёт команды — новым файлом в защищённом каталоге (<see cref="EmergencyReportFiles"/>) и копией <c>last.json</c>,
/// которую приложение читает, не зная имени. Защита — как у журнала удаления (ServiceRecovery.WriteUninstallLog): уже
/// существующий каталог-ссылка, файл или каталог посторонней учётной записи не используется; новый каталог создаётся сразу
/// с правами SYSTEM и Administrators — полный доступ, Users — только чтение (пользователь не подложит туда файл или ссылку).
/// </summary>
internal static class EmergencyReportWriter
{
    /// <summary>Пишет отчёт; ответ — путь нового файла или null (причина — в <paramref name="warn"/>).</summary>
    public static string? Write(string directory, string json, Func<string, IReadOnlyList<string>> secure,
        Func<DirectoryInfo, bool> trustedOwner, Action<string> warn)
    {
        ArgumentNullException.ThrowIfNull(warn);
        var name = string.Create(CultureInfo.InvariantCulture, $"emergency-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}.json");
        var path = ServiceRecovery.WriteProtectedFile(directory, name, json, secure, trustedOwner, new UTF8Encoding(false), "Отчёт", warn);
        if (path is null)
        {
            return null;
        }

        try
        {
            // Копия последнего: новый временный файл и замена, чтобы читатель не увидел половину отчёта.
            var temporary = Path.Combine(directory, "last-" + Guid.NewGuid().ToString("N") + ".tmp");
            File.Copy(path, temporary);
            File.Move(temporary, Path.Combine(directory, EmergencyReportFiles.LastFileName), overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            warn("Копия last.json не записана: " + ex.Message);
        }

        return path;
    }

    /// <summary>
    /// Каталог отчётов: нет — создаётся сразу с нужными правами, есть (и он свой, это проверено раньше) — права ставятся заново.
    /// </summary>
    public static IReadOnlyList<string> SecureDirectory(string directory)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
        {
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        }

        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
            FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
        if (Directory.Exists(directory))
        {
            new DirectoryInfo(directory).SetAccessControl(security);
        }
        else
        {
            security.CreateDirectory(directory);
        }

        return [];
    }
}
