using System.Globalization;
using Microsoft.Win32;

namespace SplitVpn.Windows.Net;

/// <summary>Что сделала <see cref="WcmBadStateTracking.Apply()"/>.</summary>
public enum WcmBadStateTrackingResult
{
    /// <summary>Отслеживание уже было отключено: реестр не менялся.</summary>
    AlreadyDisabled,

    /// <summary>Отслеживание отключено сейчас; Windows учтёт это после перезагрузки.</summary>
    Disabled,
}

/// <summary>
/// «Отслеживание плохого состояния» диспетчера подключений Windows (WcmSvc). Если Wi-Fi подключён, а связь, по мнению
/// диспетчера, ограничена, он велит службе автонастройки WLAN восстановить адаптер: через 16 секунд после подключения
/// та повторяет проверку безопасности, через 32 перезапускает драйвер (событие 4003 в журнале «Система»), а через
/// 65 секунд после возврата отключает Wi-Fi ещё на минуту. Под защитой программы это случается почти при каждой
/// загрузке Windows и рвёт все подключения VPN (разбор 20-22.11.2026: ни проверка интернета Windows, ни подъём
/// туннелей причиной не оказались; без защиты сбросов нет). Отключает отслеживание значение
/// <c>EnableBadStateTracking = 0</c> в разделе <c>HKLM\SOFTWARE\Microsoft\WcmSvc</c> - известный обход для
/// VPN-клиентов с блокировкой трафика. Служба ставит его при запуске и запоминает прежнее значение, чтобы вернуть
/// его при удалении программы. Значение пользователя, уже равное нулю, считается его собственным и не возвращается.
/// </summary>
public static class WcmBadStateTracking
{
    internal const string WcmKey = @"SOFTWARE\Microsoft\WcmSvc";
    internal const string ValueName = "EnableBadStateTracking";

    /// <summary>Прежнее значение в разделе программы: число или <see cref="Absent"/>.</summary>
    internal const string OriginalValueName = "WcmBadStateTrackingOriginal";
    internal const string Absent = "absent";

    /// <summary>Отключить отслеживание. Нужны права администратора или службы.</summary>
    public static WcmBadStateTrackingResult Apply()
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        return Apply(root, WcmKey, Core.Ipc.IpcNames.RegistryKey);
    }

    /// <summary>Вернуть значение, которое было до программы. true - реестр изменён.</summary>
    public static bool Restore()
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        return Restore(root, WcmKey, Core.Ipc.IpcNames.RegistryKey);
    }

    internal static WcmBadStateTrackingResult Apply(RegistryKey root, string wcmPath, string ownPath)
    {
        using var wcm = root.CreateSubKey(wcmPath, writable: true);
        var current = wcm.GetValue(ValueName);
        if (current is int and 0)
        {
            return WcmBadStateTrackingResult.AlreadyDisabled;
        }

        using (var own = root.CreateSubKey(ownPath, writable: true))
        {
            // Прежнее значение запоминается один раз: повторный запуск после чужого изменения его не затирает.
            if (own.GetValue(OriginalValueName) is null)
            {
                own.SetValue(OriginalValueName, current is int number ? number.ToString(CultureInfo.InvariantCulture) : Absent, RegistryValueKind.String);
            }
        }

        wcm.SetValue(ValueName, 0, RegistryValueKind.DWord);
        return WcmBadStateTrackingResult.Disabled;
    }

    internal static bool Restore(RegistryKey root, string wcmPath, string ownPath)
    {
        using var own = root.OpenSubKey(ownPath, writable: true);
        if (own?.GetValue(OriginalValueName) is not string original)
        {
            return false;
        }

        var changed = false;
        using (var wcm = root.OpenSubKey(wcmPath, writable: true))
        {
            // Значение, которое после нас изменил кто-то другой, не трогаем.
            if (wcm?.GetValue(ValueName) is int and 0)
            {
                if (int.TryParse(original, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number))
                {
                    wcm.SetValue(ValueName, number, RegistryValueKind.DWord);
                }
                else
                {
                    wcm.DeleteValue(ValueName, throwOnMissingValue: false);
                }

                changed = true;
            }
        }

        own.DeleteValue(OriginalValueName, throwOnMissingValue: false);
        return changed;
    }
}
