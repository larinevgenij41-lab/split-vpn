using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Claims;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Diagnostics;

/// <summary>
/// Кто и где запустил клиент — то, от чего зависит доступ к службе: учётная запись, сеанс Windows,
/// Administrators (в том числе без повышения UAC), INTERACTIVE, имя канала, автозапуск.
/// </summary>
[SupportedOSPlatform("windows")]
public static class ClientEnvironment
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";

    /// <summary>Сведения построчно — и для файла environment.json, и для первой строки подробного журнала.</summary>
    public static Dictionary<string, string?> Describe()
    {
        using var identity = WindowsIdentity.GetCurrent();
        using var process = Process.GetCurrentProcess();
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value;
        var admin = identity.Groups?.Any(g => g.Value == administrators) == true ? "да, с повышением"
            : identity.Claims.Any(c => c.Type == ClaimTypes.DenyOnlySid && c.Value == administrators) ? "да, без повышения (UAC)"
            : "нет";
        return new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["user"] = identity.Name,
            ["sid"] = identity.User?.Value,
            ["session"] = process.SessionId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["processId"] = Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["process"] = Environment.ProcessPath,
            ["administrators"] = admin,
            ["interactive"] = identity.Groups?.Contains(new SecurityIdentifier(WellKnownSidType.InteractiveSid, null)) == true ? "да" : "нет",
            ["authentication"] = identity.AuthenticationType,
            ["pipe"] = IpcNames.CurrentPipeName(),
            ["verboseUntilUtc"] = VerboseRegistry.ReadRaw(),
            ["autostart"] = AutostartEntries(),
            ["os"] = Environment.OSVersion.VersionString,
            ["machine"] = Environment.MachineName,
            ["timeZone"] = TimeZoneInfo.Local.Id,
        };
    }

    public static string Json(IReadOnlyDictionary<string, string?>? extra = null)
    {
        var values = Describe();
        foreach (var (key, value) in extra ?? new Dictionary<string, string?>())
        {
            values[key] = value;
        }

        return JsonSerializer.Serialize(values, JsonDefaults.Options);
    }

    /// <summary>Записи автозапуска этого пользователя, относящиеся к программе.</summary>
    private static string AutostartEntries()
    {
        try
        {
            using var run = Registry.CurrentUser.OpenSubKey(RunKey);
            var entries = (run?.GetValueNames() ?? [])
                .Select(name => (name, value: run!.GetValue(name) as string ?? ""))
                .Where(e => e.name.Contains("SplitVpn", StringComparison.OrdinalIgnoreCase) || e.value.Contains("SplitVpn", StringComparison.OrdinalIgnoreCase))
                .Select(e => e.name + " = " + e.value)
                .ToList();
            return entries.Count == 0 ? "нет" : string.Join("; ", entries);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or IOException or UnauthorizedAccessException)
        {
            return "не прочитан: " + ex.Message;
        }
    }
}
