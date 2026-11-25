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

    /// <summary>Видимая отметка переноса строки внутри одной записи журнала.</summary>
    public const string LineBreakMarker = " ⏎ ";

    /// <summary>
    /// Текст из чужого источника (помощник AnyConnect, sing-box, Trace, сообщения системы и шлюза) — одной строкой
    /// журнала: перенос строки (CR, LF, CRLF, U+2028, U+2029) заменяется видимой отметкой <see cref="LineBreakMarker"/>,
    /// остальные управляющие символы C0 и C1 (кроме табуляции) и символы смены направления текста (U+202A–U+202E,
    /// U+2066–U+2069) — записью «\uXXXX». Иначе текст с переводом строки подделал бы в журнале и в списке событий
    /// программы отдельную запись с любым временем и уровнем, а символы направления — переставили бы её видимый текст.
    /// </summary>
    public static string SingleLine(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return text ?? "";
        }

        var clean = true;
        foreach (var c in text)
        {
            if (NeedsEscape(c))
            {
                clean = false;
                break;
            }
        }

        if (clean)
        {
            return text;
        }

        var builder = new System.Text.StringBuilder(text.Length + 16);
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c is '\r' or '\n' or '\u2028' or '\u2029')
            {
                if (c == '\r' && i + 1 < text.Length && text[i + 1] == '\n')
                {
                    i++;
                }

                builder.Append(LineBreakMarker);
            }
            else if (NeedsEscape(c))
            {
                builder.Append("\\u").Append(((int)c).ToString("X4", System.Globalization.CultureInfo.InvariantCulture));
            }
            else
            {
                builder.Append(c);
            }
        }

        return builder.ToString();
    }

    private static bool NeedsEscape(char c) =>
        (c < ' ' && c != '\t') || c is >= '\u007F' and <= '\u009F' or >= '\u202A' and <= '\u202E' or >= '\u2066' and <= '\u2069' or '\u2028' or '\u2029';

    [System.Text.RegularExpressions.GeneratedRegex(@"^\s*[^=;\[]*(pass|psk|preshared|secret|pwd|credential|token|key)[^=]*=", System.Text.RegularExpressions.RegexOptions.IgnoreCase)]
    private static partial System.Text.RegularExpressions.Regex PhonebookSecretLine();

    [System.Text.RegularExpressions.GeneratedRegex(@"https?://[^\s""'<>]+", System.Text.RegularExpressions.RegexOptions.IgnoreCase)]
    private static partial System.Text.RegularExpressions.Regex Urls();
}
