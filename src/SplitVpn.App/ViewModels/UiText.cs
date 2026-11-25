using System.IO;
using Microsoft.Web.WebView2.Core;
using SplitVpn.Core.Diagnostics;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;

namespace SplitVpn.App.ViewModels;

/// <summary>
/// Тексты для пользователя вместо сообщений .NET и имён перечислений: системные сообщения английские и ничего
/// не говорят неспециалисту. Исходный текст уходит только в подробный журнал интерфейса.
/// </summary>
public static class UiText
{
    /// <summary>Ошибка записи файла: что случилось и что сделать.</summary>
    public static string FileWriteError(string? path) =>
        $"Не удалось записать файл «{FileName(path)}»: нет доступа или файл занят другой программой. Выберите другую папку.";

    /// <summary>Ошибка чтения или разбора файла.</summary>
    public static string FileReadError(string? path) => $"Файл «{FileName(path)}» не читается или повреждён.";

    /// <summary>
    /// Ошибка файла, место которой неизвестно (страница не сказала, какой файл читала или писала):
    /// по типу ошибки — запись или чтение. Исходное сообщение — в журнал.
    /// </summary>
    public static string FileError(Exception ex, string? path = null, bool writing = false)
    {
        ArgumentNullException.ThrowIfNull(ex);
        Verbose.Write("Ui", $"ошибка файла{(path is null ? "" : " «" + path + "»")}: {ex.GetType().Name} «{ex.Message}»");
        if (path is null)
        {
            return ex is System.Text.Json.JsonException
                ? "Файл не читается или повреждён."
                : "Не удалось прочитать или записать файл: нет доступа или файл занят другой программой.";
        }

        return writing && ex is not System.Text.Json.JsonException ? FileWriteError(path) : FileReadError(path);
    }

    private static string FileName(string? path) => string.IsNullOrEmpty(path) ? "без имени" : Path.GetFileName(path);

    /// <summary>Причина, по которой не открылась страница входа, словами (вместо имени перечисления WebView2).</summary>
    public static string WebError(CoreWebView2WebErrorStatus status) => status switch
    {
        CoreWebView2WebErrorStatus.HostNameNotResolved => "адрес сайта не найден",
        CoreWebView2WebErrorStatus.Timeout => "сайт не ответил",
        CoreWebView2WebErrorStatus.ConnectionAborted or CoreWebView2WebErrorStatus.ConnectionReset or CoreWebView2WebErrorStatus.Disconnected => "соединение прервано",
        CoreWebView2WebErrorStatus.CertificateCommonNameIsIncorrect or CoreWebView2WebErrorStatus.CertificateExpired
            or CoreWebView2WebErrorStatus.CertificateRevoked or CoreWebView2WebErrorStatus.CertificateIsInvalid => "сертификат сайта недействителен",
        CoreWebView2WebErrorStatus.CannotConnect => "не удалось подключиться к сайту",
        _ => "ошибка сети",
    };

    /// <summary>
    /// Отказ службы без текста: код ошибки пользователю ничего не скажет — он уходит в журнал, а на экране общая фраза.
    /// </summary>
    public static string ServiceRejected(IpcResponse response, string fallback = "Служба отклонила запрос.")
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.ErrorMessage is { Length: > 0 } message)
        {
            return message;
        }

        if (response.ErrorCode is { } code)
        {
            Verbose.Write("Ipc", "отказ службы без текста, код " + code);
        }

        return fallback;
    }

    /// <summary>
    /// Заголовок пункта меню: WPF считает «_» клавишей доступа и съедает его («work_vpn» → «workvpn»).
    /// Удвоенный «__» показывается как один символ.
    /// </summary>
    public static string MenuHeader(string? text) => (text ?? "").Replace("_", "__", StringComparison.Ordinal);

    /// <summary>Ошибка поля «Адрес VPN-сервера»: называет поле и показывает, как должен выглядеть адрес.</summary>
    public static string ServerFieldError(VpnProtocol protocol) => "Адрес VPN-сервера: " + protocol switch
    {
        VpnProtocol.Sstp => "укажите имя вида vpn.example.org или vpn.example.org:443 либо IP-адрес.",
        VpnProtocol.AnyConnect => "укажите адрес шлюза вида vpn.example.org или vpn.example.org/staff.",
        VpnProtocol.SshVpn => "укажите имя вида vpn.example.org или vpn.example.org:22 либо IP-адрес.",
        _ => "укажите имя вида vpn.example.org или IP-адрес, без порта.",
    };

    // ---------- Экстренное выключение ----------

    /// <summary>Пункт меню трея, кнопка «Диагностики» и единственное подтверждение перед окном UAC.</summary>
    public const string EmergencyOffAction = "Экстренно выключить";

    public const string EmergencyOnAction = "Включить программу";

    public const string EmergencyConfirmTitle = "Экстренно выключить «Раздельный VPN»?";

    public const string EmergencyConfirmText =
        "VPN будет отключён, защита от утечек снята — весь трафик пойдёт напрямую через провайдера. "
        + "Служба программы будет остановлена и не запустится сама, даже после перезагрузки компьютера. "
        + "Включить программу обратно — кнопкой «Включить программу» в окне программы или в меню её значка в трее. "
        + "Windows запросит права администратора.";

    /// <summary>Пояснение под кнопкой в «Диагностике».</summary>
    public const string EmergencyOffHint =
        "VPN и защита снимаются, служба останавливается и сама не запускается, пока программу не включат снова. Работает, даже когда служба не отвечает";

    /// <summary>Состояние в шапке меню, на главной и в меню трея.</summary>
    public const string EmergencyStateText = "Экстренно выключен";

    public const string EmergencySummaryText = "Windows работает без «Раздельного VPN».";

    public const string EmergencyBannerTitle = "Раздельный VPN экстренно выключен — Windows работает без него";

    /// <summary>Текст баннера: когда выключили и как включить.</summary>
    public static string EmergencyBannerText(DateTimeOffset? since) =>
        (since is { } when ? $"Выключен {when.ToLocalTime().ToString("dd.MM.yyyy 'в' HH:mm", System.Globalization.CultureInfo.GetCultureInfo("ru-RU"))}. " : "")
        + "VPN не подключается, защита снята, служба не запускается сама. Чтобы снова пользоваться программой, нажмите «Включить программу», затем «Подключить».";

    /// <summary>Пока идёт команда: окно UAC может быть за другими окнами, а сама команда — минуты.</summary>
    public static string EmergencyRunningText(bool on) => (on ? "Включение программы…" : "Экстренное выключение…")
        + " Подтвердите запрос Windows на права администратора. Команда может занять несколько минут.";

    /// <summary>Команда идёт дольше отведённого: она не прерывается, кнопки недоступны до её окончания.</summary>
    public static string EmergencyStillRunningText(bool on) => (on ? "Включение программы" : "Экстренное выключение")
        + " ещё выполняется. Дождитесь окончания: итог появится здесь сам.";

    /// <summary>Подсказка на главной, пока программа выключена: кнопка включения — одна, в баннере над страницей.</summary>
    public const string EmergencyHomeHint = "Программа экстренно выключена. Включите её кнопкой «Включить программу» над страницей.";

    /// <summary>
    /// Сводка путей трафика для окна. Формулировка «Остальные адреса» живёт в ядре (её печатает и командная строка),
    /// а в приложении эта цель везде называется «Остальной интернет», как карточка на доске маршрутизации.
    /// </summary>
    public static string StatusSummary(StatusDto status) =>
        StatusText.Format(status).Replace("Остальные адреса →", "Остальной интернет →", StringComparison.Ordinal);
}
