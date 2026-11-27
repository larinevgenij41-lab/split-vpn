using System.Globalization;

namespace SplitVpn.Core.Settings;

/// <summary>
/// Адрес шлюза AnyConnect из поля «Сервер»: «хост», «хост:порт», «хост/путь» или полная https-ссылка.
/// Путь — group-url шлюза (выбирает группу подключения на стороне ASA).
/// </summary>
public readonly record struct AnyConnectGateway(string Host, ushort Port, string Path)
{
    public const ushort DefaultPort = 443;

    /// <summary>Адрес для openconnect_parse_url.</summary>
    public string Url => Port == DefaultPort
        ? $"https://{Host}/{Path}"
        : string.Create(CultureInfo.InvariantCulture, $"https://{Host}:{Port}/{Path}");

    public static bool TryParse(string? text, out AnyConnectGateway gateway) => TryParse(text, out gateway, out _);

    /// <summary>
    /// Адрес отвергнут только из-за нестрогой записи IPv4 («10.1», «010.0.0.1», «0x7f.0.0.1», «3232235777»):
    /// System.Uri понял бы её как другой адрес. Такой адрес могли сохранить прежние версии (0.19.0 и раньше) - для понятного текста
    /// «исправьте адрес» вместо общего «неверный адрес».
    /// </summary>
    public static bool IsLooseIpv4(string? text) => !TryParse(text, out _, out var loose) && loose;

    private static bool TryParse(string? text, out AnyConnectGateway gateway, out bool looseIpv4)
    {
        gateway = default;
        looseIpv4 = false;
        if (string.IsNullOrWhiteSpace(text) || text.Length > 512 || text.Any(char.IsWhiteSpace))
        {
            return false;
        }

        var candidate = text.Contains("://", StringComparison.Ordinal) ? text : "https://" + text;
        if (!Uri.TryCreate(candidate, UriKind.Absolute, out var uri)
            || uri.Scheme != Uri.UriSchemeHttps
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment)
            || uri.HostNameType is not (UriHostNameType.Dns or UriHostNameType.IPv4)
            || uri.Port is <= 0 or > ushort.MaxValue)
        {
            return false;
        }

        // Остальная программа принимает IPv4 только строго (Ipv4.TryParse), а строгая запись совпадает с
        // канонической формой Uri. Иная запись хоста-IPv4 - сокращённая, восьмеричная, шестнадцатеричная или одно
        // число - молча стала бы другим адресом: «010.0.0.1» - 8.0.0.1.
        if (uri.HostNameType == UriHostNameType.IPv4 && !string.Equals(HostText(candidate), uri.Host, StringComparison.Ordinal))
        {
            looseIpv4 = true;
            return false;
        }

        gateway = new AnyConnectGateway(uri.IdnHost, (ushort)uri.Port, uri.AbsolutePath[1..]);
        return true;
    }

    /// <summary>Хост как он записан: между «://» и портом, путём, запросом или фрагментом (учётные данные уже отвергнуты).</summary>
    private static string HostText(string candidate)
    {
        var authority = candidate.AsSpan(candidate.IndexOf("://", StringComparison.Ordinal) + 3);
        var end = authority.IndexOfAny("/\\?#");
        if (end >= 0)
        {
            authority = authority[..end];
        }

        var colon = authority.LastIndexOf(':');
        return (colon >= 0 ? authority[..colon] : authority).ToString();
    }
}
