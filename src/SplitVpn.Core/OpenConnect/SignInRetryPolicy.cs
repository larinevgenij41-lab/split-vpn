namespace SplitVpn.Core.OpenConnect;

/// <summary>
/// Повтор загрузки страницы входа AnyConnect после сетевой ошибки. Страница организации (например, sso.lamoda.ru)
/// разрешается и открывается через опорный VPN, а он сразу после запуска Windows или обрыва может ещё подниматься: разбор
/// 09.11.2026 - «HostNameNotResolved», и пользователю пришлось закрыть окно и войти заново, хотя через 10 с всё работало.
/// Окно повторяет загрузку само; ошибки, которые повтор не исправит (сертификат, отмена), показываются сразу.
/// </summary>
public sealed class SignInRetryPolicy
{
    /// <summary>Сколько повторов подряд: вместе с паузой это полминуты, за которые опорный VPN обычно поднимается.</summary>
    public const int MaxAttempts = 6;

    public static readonly TimeSpan Delay = TimeSpan.FromSeconds(5);

    /// <summary>Сетевые ошибки WebView2 (имена CoreWebView2WebErrorStatus), которые проходят сами, когда сеть или VPN поднимутся.</summary>
    private static readonly HashSet<string> Transient = new(StringComparer.Ordinal)
    {
        "HostNameNotResolved", "Timeout", "CannotConnect", "ConnectionAborted", "ConnectionReset", "Disconnected", "ServerUnreachable",
    };

    private int _attempts;

    public static bool IsTransient(string webErrorStatus) => Transient.Contains(webErrorStatus);

    /// <summary>Загрузка не удалась: номер следующего повтора (1..<see cref="MaxAttempts"/>) или null - ошибка не сетевая или повторы исчерпаны.</summary>
    public int? NextAttempt(string webErrorStatus)
    {
        if (!IsTransient(webErrorStatus) || _attempts >= MaxAttempts)
        {
            return null;
        }

        return ++_attempts;
    }

    /// <summary>Страница загрузилась: следующая ошибка снова получает все повторы.</summary>
    public void Succeeded() => _attempts = 0;
}
