namespace SplitVpn.App.Services;

/// <summary>
/// Что разрешено встроенному браузеру окна входа SSO. В нём вводят корпоративный пароль, а cookie шлюза уходят
/// службе: страница с непроверенным сертификатом, загрузка без ведома программы, доступ к камере или буферу обмена
/// и фрейм без HTTPS в нём недопустимы. Решения — здесь, без WebView2: их можно проверить.
/// </summary>
internal static class SignInBrowserPolicy
{
    /// <summary>Ошибки сертификата сервера (имена CoreWebView2WebErrorStatus), которыми WebView2 завершает такой переход.</summary>
    private static readonly HashSet<string> CertificateErrors = new(StringComparer.Ordinal)
    {
        "CertificateCommonNameIsIncorrect", "CertificateExpired", "ClientCertificateContainsErrors", "CertificateRevoked", "CertificateIsInvalid",
    };

    /// <summary>Основная страница окна входа: только HTTPS.</summary>
    public static bool MainNavigationAllowed(string? uri) => uri is not null && uri.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

    /// <summary>Всплывающее окно входа (OAuth, выбор учётной записи): HTTPS или пустая страница, которую сайт заполнит сам.</summary>
    public static bool PopupNavigationAllowed(string? uri) => uri == "about:blank" || IsHttps(uri);

    /// <summary>
    /// Дочерний фрейм: из сети — только HTTPS, как у страницы. Фрейм с содержимым, которое написала сама страница,
    /// ничего не загружает из сети и разрешён: пустой и srcdoc (about:blank, about:srcdoc), data: и blob: — их создаёт
    /// уже открытая по HTTPS страница, и подменить их по дороге нельзя (такими фреймами встраивают виджеты входа и
    /// капчи). blob: — только созданный HTTPS-страницей. Запрещены http: и прочие схемы, в том числе file: и javascript:.
    /// </summary>
    public static bool FrameNavigationAllowed(string? uri) => uri is "about:blank" or "about:srcdoc" || IsHttps(uri)
        || (uri is not null && (uri.StartsWith("data:", StringComparison.OrdinalIgnoreCase) || uri.StartsWith("blob:https://", StringComparison.OrdinalIgnoreCase)));

    /// <summary>Текст для пользователя, когда фрейм страницы входа не открыт: без него на странице осталось бы пустое место.</summary>
    public const string FrameBlockedProblem = "Часть страницы входа не загружена: она открывалась без защищённого соединения (HTTPS)."
        + " Если войти не получается, сообщите администратору организации.";

    /// <summary>Переход завершился ошибкой сертификата сервера.</summary>
    public static bool IsCertificateError(string webErrorStatus) => CertificateErrors.Contains(webErrorStatus);

    /// <summary>
    /// Ошибка сертификата пришла для самой страницы или фрейма (а не для картинки или скрипта): о ней сообщается
    /// пользователю. Запрос отменяется в любом случае — продолжить на такой странице нельзя.
    /// </summary>
    public static bool IsDocumentRequest(string? requestUri, string? mainDocument, string? frameDocument) =>
        SameAddress(requestUri, mainDocument) || SameAddress(requestUri, frameDocument);

    /// <summary>Текст для пользователя: страница с непроверенным сертификатом не открыта, а пароль на ней вводить нельзя.</summary>
    public static string CertificateProblem(string? requestUri)
    {
        var host = Uri.TryCreate(requestUri, UriKind.Absolute, out var uri) && uri.Host.Length > 0 ? uri.Host : "организации";
        return $"Сертификат сайта {host} не прошёл проверку: страница входа не открыта, продолжить на ней нельзя."
            + " Так бывает при подмене соединения в сети: не входите через эту сеть и сообщите администратору организации.";
    }

    private static bool IsHttps(string? value) => Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps;

    private static bool SameAddress(string? left, string? right) =>
        Uri.TryCreate(left, UriKind.Absolute, out var a) && Uri.TryCreate(right, UriKind.Absolute, out var b)
        && Uri.Compare(a, b, UriComponents.HttpRequestUrl, UriFormat.SafeUnescaped, StringComparison.OrdinalIgnoreCase) == 0;
}
