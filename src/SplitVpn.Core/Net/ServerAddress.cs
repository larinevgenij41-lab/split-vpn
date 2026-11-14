using System.Globalization;

namespace SplitVpn.Core.Net;

/// <summary>Адрес SSTP-сервера «хост» или «хост:порт» (порт по умолчанию 443).</summary>
public readonly record struct ServerAddress(string Host, ushort Port)
{
    public const ushort DefaultPort = 443;

    public bool IsIpLiteral => Ipv4.TryParse(Host, out _);

    /// <summary>Строка для поля RASENTRY: порт указывается, только если он нестандартный.</summary>
    public string ForPhonebook => Port == DefaultPort ? Host : string.Create(CultureInfo.InvariantCulture, $"{Host}:{Port}");

    public static bool TryParse(string? text, out ServerAddress address)
    {
        address = default;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var trimmed = text.Trim();
        var colon = trimmed.LastIndexOf(':');
        if (colon < 0)
        {
            return IsHost(trimmed) && Assign(trimmed, DefaultPort, out address);
        }

        var host = trimmed[..colon];
        return ushort.TryParse(trimmed[(colon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var port)
            && port > 0
            && IsHost(host)
            && Assign(host, port, out address);
    }

    public static ServerAddress Parse(string text) =>
        TryParse(text, out var address) ? address : throw new FormatException($"Неверный адрес сервера: {text}");

    public override string ToString() => ForPhonebook;

    /// <summary>
    /// Uri.CheckHostName считает IPv4 и сокращённые или восьмеричные формы («1.2», «127.1», «010.0.0.1»);
    /// их принимаем, только если строгий разбор <see cref="Ipv4.TryParse"/> согласен, иначе проверки
    /// IP-литерала (IsIpLiteral, запрет служебных адресов) обходились бы.
    /// </summary>
    private static bool IsHost(string host) => Uri.CheckHostName(host) switch
    {
        UriHostNameType.Dns => true,
        UriHostNameType.IPv4 => Ipv4.TryParse(host, out _),
        _ => false,
    };

    private static bool Assign(string host, ushort port, out ServerAddress address)
    {
        address = new ServerAddress(host, port);
        return true;
    }
}
