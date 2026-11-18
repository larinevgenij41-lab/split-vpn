using System.Globalization;

namespace SplitVpn.Core.Net;

/// <summary>IPv4-подсеть с нулевыми битами хоста.</summary>
public readonly record struct Ipv4Cidr
{
    public Ipv4Cidr(uint network, int prefixLength)
    {
        if (prefixLength is < 0 or > 32)
        {
            throw new ArgumentOutOfRangeException(nameof(prefixLength));
        }

        if ((network & ~MaskOf(prefixLength)) != 0)
        {
            throw new ArgumentException("У подсети ненулевые биты хоста.", nameof(network));
        }

        Network = network;
        PrefixLength = prefixLength;
    }

    public uint Network { get; }

    public int PrefixLength { get; }

    public uint Mask => MaskOf(PrefixLength);

    public uint Last => Network | ~Mask;

    public Ipv4Range ToRange() => new(Network, Last);

    public bool Contains(uint address) => (address & Mask) == Network;

    public static uint MaskOf(int prefixLength) => prefixLength == 0 ? 0u : uint.MaxValue << (32 - prefixLength);

    /// <summary>Разбирает «a.b.c.d/n» или одиночный адрес (как /32). Биты хоста считаются ошибкой.</summary>
    public static bool TryParse(string? text, out Ipv4Cidr cidr)
    {
        cidr = default;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var trimmed = text.Trim();
        if (!trimmed.Contains('/', StringComparison.Ordinal))
        {
            if (!Ipv4.TryParse(trimmed, out var single))
            {
                return false;
            }

            cidr = new Ipv4Cidr(single, 32);
            return true;
        }

        // Свой разбор вместо IPNetwork.TryParse: тот понимает восьмеричные октеты («010» = 8)
        // и молча обнуляет биты хоста, а для базы это признак ошибки.
        if (!TryParseParts(trimmed, out var address, out var prefix) || (address & ~MaskOf(prefix)) != 0)
        {
            return false;
        }

        cidr = new Ipv4Cidr(address, prefix);
        return true;
    }

    public static Ipv4Cidr Parse(string text)
    {
        return TryParse(text, out var cidr) ? cidr : throw new FormatException($"Неверная IPv4-подсеть: {text}");
    }

    /// <summary>Проверяет, что строка — IPv4-подсеть, у которой установлены биты хоста.</summary>
    public static bool HasHostBits(string text)
    {
        return TryParseParts(text, out var address, out var prefix) && (address & ~MaskOf(prefix)) != 0;
    }

    private static bool TryParseParts(string text, out uint address, out int prefix)
    {
        prefix = 0;
        var parts = text.Trim().Split('/');
        if (parts.Length != 2 || !Ipv4.TryParse(parts[0], out address))
        {
            address = 0;
            return false;
        }

        return int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out prefix) && prefix is >= 0 and <= 32;
    }

    public override string ToString() => string.Create(CultureInfo.InvariantCulture, $"{Ipv4.Format(Network)}/{PrefixLength}");
}
