namespace SplitVpn.Core.Diagnostics;

/// <summary>Приведение значений к виду, безопасному для журнала.</summary>
public static partial class LogText
{
    /// <summary>
    /// Адрес без query и fragment: в них страницы входа передают токены и коды (SAMLResponse, code, state).
    /// Схема, хост, порт и путь остаются — по ним видно, где оборвался вход; логин и пароль в адресе убираются.
    /// </summary>
    public static string UrlForLog(string? url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return "<неразбираемый адрес>";
        }

        // Authority — хост и порт без «логин:пароль@».
        var text = uri.Scheme + "://" + uri.Authority + uri.AbsolutePath;
        return uri.Query.Length > 0 || uri.Fragment.Length > 0 ? text + "?…" : text;
    }

    /// <summary>Все адреса http(s) в тексте (JSON настроек и т. п.) — через <see cref="UrlForLog"/>.</summary>
    public static string StripUrls(string text) => Urls().Replace(text, m => UrlForLog(m.Value));

    [System.Text.RegularExpressions.GeneratedRegex(@"https?://[^\s""'<>]+", System.Text.RegularExpressions.RegexOptions.IgnoreCase)]
    private static partial System.Text.RegularExpressions.Regex Urls();
}
