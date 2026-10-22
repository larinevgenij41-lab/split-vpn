using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Win32;
using SplitVpn.Core.Ipc;

namespace SplitVpn.Core.Diagnostics;

/// <summary>
/// Срок подробного журнала — одно значение в HKLM. Пишет только служба (SYSTEM), читают все: и интерфейс,
/// которому служба отказала, должен знать, что режим включён, и записать причину отказа.
/// В settings.json срок не хранится: интерфейс сохраняет настройки целиком и затёр бы его устаревшей копией.
/// </summary>
public static class VerboseRegistry
{
    public const string ValueName = "VerboseUntilUtc";

    /// <summary>Самый долгий срок: и записанное в реестр вручную значение дальше не действует.</summary>
    public static readonly TimeSpan MaxDuration = TimeSpan.FromHours(24);

    /// <summary>Срок, если режим сейчас действует; истёкшее, слишком дальнее и неразборчивое значение — выключено.</summary>
    public static DateTimeOffset? Effective(string? stored, DateTimeOffset now)
    {
        if (!DateTimeOffset.TryParse(stored, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var until) || until <= now)
        {
            return null;
        }

        return until - now > MaxDuration ? now + MaxDuration : until;
    }

    public static string Format(DateTimeOffset until) => until.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    [SupportedOSPlatform("windows")]
    public static string? ReadRaw()
    {
        try
        {
            using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = root.OpenSubKey(IpcNames.RegistryKey);
            return key?.GetValue(ValueName) as string;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    [SupportedOSPlatform("windows")]
    public static DateTimeOffset? Read(DateTimeOffset now) => Effective(ReadRaw(), now);

    /// <summary>Записать срок; null удаляет значение. Только для службы.</summary>
    [SupportedOSPlatform("windows")]
    public static void Write(DateTimeOffset? until)
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = root.CreateSubKey(IpcNames.RegistryKey, writable: true);
        if (until is { } value)
        {
            key.SetValue(ValueName, Format(value), RegistryValueKind.String);
        }
        else
        {
            key.DeleteValue(ValueName, throwOnMissingValue: false);
        }
    }
}
