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

    public UiPreferences SaveChanges(UiPreferences baseline)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        // Файловая блокировка в своём профиле и мьютекс (UserGate). Имя мьютекса может занять другой пользователь
        // компьютера: тогда остаётся файловая, а если недоступны обе — запись без блокировки. Файловую дольше
        // ожидания держит другая копия интерфейса — UserGateBusyException (IOException): настройки не записаны,
        // вызывающий показывает ошибку, пользователь повторит.
        using var gate = UserGate.Enter(@"Global\SplitVpn.UiPreferences." + identity.User!.Value,
            Path.Combine(Path.GetDirectoryName(FilePath)!, "ui.json.lock"), TimeSpan.FromSeconds(2), "Ui");
        var merged = ChangesOnto(baseline, Load());
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        AtomicFile.WriteAllText(FilePath, JsonSerializer.Serialize(merged, JsonDefaults.Options));
        return merged;
    }

    /// <summary>
    /// Правки этих настроек относительно <paramref name="baseline"/> поверх <paramref name="current"/>: изменённое здесь
    /// берётся отсюда, остальное — из <paramref name="current"/>.
    /// </summary>
    internal UiPreferences ChangesOnto(UiPreferences baseline, UiPreferences current)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        ArgumentNullException.ThrowIfNull(current);
        return current with
        {
            Theme = Theme == baseline.Theme ? current.Theme : Theme,
            Notifications = Notifications == baseline.Notifications ? current.Notifications : Notifications,
            ShowAdvanced = ShowAdvanced == baseline.ShowAdvanced ? current.ShowAdvanced : ShowAdvanced,
            WizardDismissed = WizardDismissed == baseline.WizardDismissed ? current.WizardDismissed : WizardDismissed,
            TrayHintShown = TrayHintShown == baseline.TrayHintShown ? current.TrayHintShown : TrayHintShown,
        };
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

    /// <summary>Имя файла приложения: запись автозапуска с другим именем — не наша и не трогается.</summary>
    internal const string ExecutableName = "SplitVpn.exe";

    /// <summary>
    /// Обновление ставит программу в фиксированный %ProgramFiles%\SplitVpn: если прежняя версия стояла в другом
    /// каталоге, запись автозапуска ведёт на удалённый файл, и приложение перестаёт запускаться при входе. При
    /// старте такая запись (наше имя файла, файла нет) переписывается на путь этого процесса с теми же аргументами.
    /// Запись, ведущая на существующий файл (другая копия, сборка разработчика), не меняется. Ошибки реестра
    /// не мешают запуску: пишутся в журнал интерфейса.
    /// </summary>
    public static void RepairStalePath()
    {
        if (Environment.ProcessPath is not { } exePath || !string.Equals(Path.GetFileName(exePath), ExecutableName, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKey, writable: true);
            if (key?.GetValue(ValueName) is string command && RepairedCommand(command, exePath, File.Exists) is { } repaired)
            {
                key.SetValue(ValueName, repaired);
                Core.Diagnostics.Verbose.Write("Ui", "автозапуск вёл на удалённый файл, путь исправлен: " + repaired);
            }
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            Core.Diagnostics.Verbose.Write("Ui", "не удалось проверить автозапуск: " + ex.Message);
        }
    }

    /// <summary>
    /// Команда автозапуска с путём <paramref name="exePath"/> вместо прежнего, если прежний — несуществующий файл
    /// <see cref="ExecutableName"/>; аргументы сохраняются как есть. Иначе null (исправлять нечего).
    /// Путь в кавычках или без них (тогда — до «.exe» включительно).
    /// </summary>
    internal static string? RepairedCommand(string command, string exePath, Func<string, bool> fileExists)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(exePath);
        ArgumentNullException.ThrowIfNull(fileExists);
        var text = command.TrimStart();
        string path;
        string arguments;
        if (text.StartsWith('"'))
        {
            var end = text.IndexOf('"', 1);
            if (end < 0)
            {
                return null;
            }

            path = text[1..end];
            arguments = text[(end + 1)..];
        }
        else
        {
            var end = text.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            if (end < 0 || (end + 4 < text.Length && !char.IsWhiteSpace(text[end + 4])))
            {
                return null;
            }

            path = text[..(end + 4)];
            arguments = text[(end + 4)..];
        }

        if (!string.Equals(Path.GetFileName(path), ExecutableName, StringComparison.OrdinalIgnoreCase)
            || string.Equals(path, exePath, StringComparison.OrdinalIgnoreCase) || fileExists(path))
        {
            return null;
        }

        return "\"" + exePath + "\"" + arguments;
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

            Core.Diagnostics.Verbose.Write("Ui", enabled ? "автозапуск включён: " + Command : "автозапуск выключен");
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            throw new IOException("Не удалось изменить автозапуск в реестре: " + ex.Message, ex);
        }
    }
}
