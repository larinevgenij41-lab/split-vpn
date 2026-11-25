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
    /// <summary>Добавка к итогу, когда отчёт не записан в каталог.</summary>
    public const string NotWrittenNote = "Отчёт не записан в %ProgramData%\\SplitVpn.Recovery: он есть только в выводе команды.";

    /// <summary>Сколько раз переносить в сторону чужой каталог отчётов.</summary>
    private const int SetAsideAttempts = 3;

    /// <summary>
    /// Пишет отчёт; ответ — путь нового файла или null (причина — в <paramref name="warn"/>). Каталог отчётов, который
    /// заранее создал кто-то другой (обычный пользователь, ссылка, файл), не используется, но и не блокирует отчёты навсегда:
    /// он переносится в сторону под уникальное имя <c>&lt;каталог&gt;.untrusted-…</c> (переносится сама ссылка, не то, на что
    /// она указывает; внутрь ничего не пишется), и каталог создаётся заново с защищёнными правами. До трёх попыток;
    /// не вышло — отчёт только в выводе команды.
    /// </summary>
    public static string? Write(string directory, string json, Func<string, IReadOnlyList<string>> secure,
        Func<DirectoryInfo, bool> trustedOwner, Action<string> warn)
    {
        ArgumentNullException.ThrowIfNull(warn);
        ArgumentNullException.ThrowIfNull(secure);
        if (!PrepareDirectory(directory, secure, trustedOwner, warn))
        {
            return null;
        }

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

    /// <summary>Каталог свой (или его нет); чужой — в сторону и заново. false — так и не стал своим.</summary>
    private static bool PrepareDirectory(string directory, Func<string, IReadOnlyList<string>> secure, Func<DirectoryInfo, bool> trustedOwner, Action<string> warn)
    {
        for (var attempt = 1; ; attempt++)
        {
            string? problem;
            try
            {
                problem = ServiceRecovery.ForeignLogDirectory(directory, trustedOwner);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException or InvalidOperationException)
            {
                problem = "не проверяется: " + ex.Message;
            }

            if (problem is null)
            {
                return true;
            }

            if (attempt > SetAsideAttempts)
            {
                warn($"Отчёт не записан: каталог {directory} {problem}, перенести его в сторону не удалось.");
                return false;
            }

            var aside = string.Create(CultureInfo.InvariantCulture,
                $"{directory}.untrusted-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid().ToString("N")[..8]}");
            try
            {
                // Переносится сам объект: для ссылки — ссылка, не каталог, на который она указывает.
                if (File.Exists(directory))
                {
                    File.Move(directory, aside);
                }
                else
                {
                    Directory.Move(directory, aside);
                }

                warn($"Каталог отчётов {directory} {problem}: перенесён в {aside}.");

                // Сразу создаётся заново с защищёнными правами; успел появиться снова чужой — следующая попытка.
                if (!Directory.Exists(directory) && !File.Exists(directory))
                {
                    foreach (var warning in secure(directory)) warn(warning);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException
                or System.ComponentModel.Win32Exception or InvalidOperationException)
            {
                warn($"Каталог отчётов {directory} {problem}: перенос в сторону не удался ({ex.Message}).");
            }
        }
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
