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

    /// <summary>
    /// Телефонная книга RAS без строк с паролями и ключами (PreSharedKey и т. п.): для разбора нужны адрес,
    /// тип туннеля и политики, а не секреты.
    /// </summary>
    public static string StripPhonebookSecrets(string text) =>
        string.Join(Environment.NewLine, text.ReplaceLineEndings("\n").Split('\n').Where(line => !PhonebookSecretLine().IsMatch(line)));

    [System.Text.RegularExpressions.GeneratedRegex(@"^\s*[^=;\[]*(pass|psk|preshared|secret|pwd|credential|token|key)[^=]*=", System.Text.RegularExpressions.RegexOptions.IgnoreCase)]
    private static partial System.Text.RegularExpressions.Regex PhonebookSecretLine();

    [System.Text.RegularExpressions.GeneratedRegex(@"https?://[^\s""'<>]+", System.Text.RegularExpressions.RegexOptions.IgnoreCase)]
    private static partial System.Text.RegularExpressions.Regex Urls();
}
