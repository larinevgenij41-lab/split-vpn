using System.Text.Json;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Diagnostics;

/// <summary>Прокси пользователя: флаги INTERNET_PER_CONN_FLAGS и адрес PAC-скрипта.</summary>
public sealed record ProxyState(int Flags, string? AutoConfigUrl)
{
    /// <summary>PROXY_TYPE_AUTO_PROXY_URL: браузеры берут прокси из PAC-скрипта.</summary>
    public const int AutoProxyUrl = 4;

    public bool Uses(string url) => (Flags & AutoProxyUrl) != 0 && string.Equals(AutoConfigUrl, url, StringComparison.Ordinal);
}

/// <summary>Чтение и запись прокси пользователя (WinINet); в тестах — фейк.</summary>
public interface IProxySettings
{
    ProxyState Read();

    void Write(ProxyState state);
}

/// <summary>
/// Что было до применения PAC шлюза. Overridden — пользователь сам поменял прокси, пока PAC шлюза был применён:
/// тогда программа прокси больше не трогает.
/// </summary>
public sealed record ProxyBackup(ProxyState Original, string AppliedUrl, bool Overridden = false);

public enum ProxyOutcome
{
    None,
    Unchanged,
    Applied,
    Restored,
    ChangedByUser,
}

/// <summary>
/// Прокси шлюза AnyConnect (PAC) в настройках пользователя. Исходные настройки сохраняются в файл до изменения,
/// поэтому откат возможен и после аварийного выхода интерфейса. Изменения пользователя не перезаписываются.
/// </summary>
public sealed class ProxyApplier(IProxySettings settings, string backupPath)
{
    /// <summary>Приводит прокси к нужному PAC; null — вернуть исходные настройки.</summary>
    public ProxyOutcome Sync(string? desiredUrl)
    {
        var backup = LoadBackup();
        if (desiredUrl is null)
        {
            return backup is null ? ProxyOutcome.None : Restore(backup);
        }

        if (backup is null)
        {
            var original = settings.Read();
            SaveBackup(new ProxyBackup(original, desiredUrl));
            settings.Write(new ProxyState(original.Flags | ProxyState.AutoProxyUrl, desiredUrl));
            return ProxyOutcome.Applied;
        }

        if (backup.Overridden)
        {
            return ProxyOutcome.Unchanged;
        }

        var current = settings.Read();
        if (!current.Uses(backup.AppliedUrl))
        {
            SaveBackup(backup with { Overridden = true });
            return ProxyOutcome.ChangedByUser;
        }

        if (backup.AppliedUrl == desiredUrl)
        {
            return ProxyOutcome.Unchanged;
        }

        SaveBackup(backup with { AppliedUrl = desiredUrl });
        settings.Write(new ProxyState(current.Flags, desiredUrl));
        return ProxyOutcome.Applied;
    }

    private ProxyOutcome Restore(ProxyBackup backup)
    {
        var outcome = ProxyOutcome.ChangedByUser;
        if (!backup.Overridden && settings.Read().Uses(backup.AppliedUrl))
        {
            settings.Write(backup.Original);
            outcome = ProxyOutcome.Restored;
        }

        File.Delete(backupPath);
        return outcome;
    }

    private ProxyBackup? LoadBackup()
    {
        try
        {
            return File.Exists(backupPath) ? JsonSerializer.Deserialize<ProxyBackup>(File.ReadAllText(backupPath), JsonDefaults.Options) : null;
        }
        catch (JsonException)
        {
            // Повреждённая копия: исходные настройки неизвестны, трогать прокси нельзя.
            return new ProxyBackup(new ProxyState(0, null), "", Overridden: true);
        }
    }

    private void SaveBackup(ProxyBackup backup)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(backupPath)!);
        File.WriteAllText(backupPath, JsonSerializer.Serialize(backup, JsonDefaults.Options));
    }
}
