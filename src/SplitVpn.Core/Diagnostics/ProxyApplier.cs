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
/// <summary>
/// Копия исходного прокси. <paramref name="PendingUrl"/> - адрес, который записывается в Windows прямо сейчас:
/// обрыв между записью в Windows и обновлением копии оставляет в системе уже его, и это тоже наша запись.
/// </summary>
public sealed record ProxyBackup(ProxyState Original, string AppliedUrl, bool Overridden = false, string? PendingUrl = null);

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
            try
            {
                settings.Write(new ProxyState(original.Flags | ProxyState.AutoProxyUrl, desiredUrl));
            }
            catch
            {
                // Windows прежний прокси не менял: копия с «применённым» PAC была бы ложью и считалась бы чужой правкой.
                File.Delete(backupPath);
                throw;
            }

            return ProxyOutcome.Applied;
        }

        if (backup.Overridden)
        {
            return ProxyOutcome.Unchanged;
        }

        var current = settings.Read();
        // Обрыв между записью в Windows и копией оставляет в системе уже новый PAC — это тоже наша запись.
        if (!IsOurs(current, backup) && !current.Uses(desiredUrl))
        {
            SaveBackup(backup with { Overridden = true });
            return ProxyOutcome.ChangedByUser;
        }

        if (backup.AppliedUrl == desiredUrl && current.Uses(desiredUrl))
        {
            return ProxyOutcome.Unchanged;
        }

        // Копия заранее помнит записываемый адрес: если интерфейс упадёт между записью в Windows и обновлением
        // копии, откат при отключении узнает свой PAC, а не сочтёт его правкой пользователя.
        SaveBackup(backup with { PendingUrl = desiredUrl });
        settings.Write(new ProxyState(current.Flags, desiredUrl));
        SaveBackup(backup with { AppliedUrl = desiredUrl, PendingUrl = null });
        return ProxyOutcome.Applied;
    }

    private static bool IsOurs(ProxyState current, ProxyBackup backup) =>
        current.Uses(backup.AppliedUrl) || (backup.PendingUrl is { } pending && current.Uses(pending));

    private ProxyOutcome Restore(ProxyBackup backup)
    {
        var outcome = ProxyOutcome.ChangedByUser;
        if (!backup.Overridden && IsOurs(settings.Read(), backup))
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
        // Атомарно: оборванная запись оставила бы повреждённую копию, а с ней прокси считается переопределённым навсегда.
        AtomicFile.WriteAllText(backupPath, JsonSerializer.Serialize(backup, JsonDefaults.Options));
    }
}
