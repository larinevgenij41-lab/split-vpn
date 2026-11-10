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

    public static bool TryParse(string? text, out AnyConnectGateway gateway)
    {
        gateway = default;
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

        gateway = new AnyConnectGateway(uri.IdnHost, (ushort)uri.Port, uri.AbsolutePath.Trim('/'));
        return true;
    }
}
