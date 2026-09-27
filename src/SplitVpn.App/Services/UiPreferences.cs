using System.IO;
using System.Text.Json;
using Microsoft.Win32;
using SplitVpn.Core.Settings;

namespace SplitVpn.App.Services;

public enum ThemeChoice
{
    System,
    Light,
    Dark,
}

/// <summary>Настройки интерфейса текущего пользователя (не службы): тема, уведомления, скрытый расширенный раздел.</summary>
public sealed record UiPreferences
{
    private static readonly string FilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SplitVpn", "ui.json");

    public ThemeChoice Theme { get; init; } = ThemeChoice.System;

    public bool Notifications { get; init; } = true;

    public bool ShowAdvanced { get; init; }

    public bool WizardDismissed { get; init; }

    /// <summary>Подсказка «окно свёрнуто в трей» уже показана.</summary>
    public bool TrayHintShown { get; init; }

    public static UiPreferences Load()
    {
        try
        {
            return File.Exists(FilePath)
                ? JsonSerializer.Deserialize<UiPreferences>(File.ReadAllText(FilePath), JsonDefaults.Options) ?? new UiPreferences()
                : new UiPreferences();
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            return new UiPreferences();
        }
    }

    public void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        AtomicFile.WriteAllText(FilePath, JsonSerializer.Serialize(this, JsonDefaults.Options));
    }
}

/// <summary>Автозапуск интерфейса в трее: запись HKCU\...\Run текущего пользователя.</summary>
public static class Autostart
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "SplitVpn";

    private static string Command => $"\"{Environment.ProcessPath}\" --tray";

    /// <summary>
    /// Включён автозапуск именно этого файла. Запись от другой копии (например, сборки разработчика или
    /// удалённой версии) считается выключенной: переключатель предложит записать путь заново.
    /// </summary>
    public static bool IsEnabled
    {
        get
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(RunKey);
                return key?.GetValue(ValueName) is string command && string.Equals(command, Command, StringComparison.OrdinalIgnoreCase);
            }
            catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
            {
                return false;
            }
        }
    }

    /// <summary>Записывает или удаляет автозапуск. Ошибка реестра — исключение с понятным текстом.</summary>
    public static void Set(bool enabled)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(RunKey);
            if (enabled)
            {
                key.SetValue(ValueName, Command);
            }
            else
            {
                key.DeleteValue(ValueName, throwOnMissingValue: false);
            }
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            throw new IOException("Не удалось изменить автозапуск в реестре: " + ex.Message, ex);
        }
    }
}
