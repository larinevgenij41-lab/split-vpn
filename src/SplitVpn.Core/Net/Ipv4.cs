using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace SplitVpn.Core.Net;

/// <summary>Преобразования IPv4-адресов в число с порядком байтов «старший первым».</summary>
public static class Ipv4
{
    public static uint ToUInt(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new ArgumentException("Ожидается IPv4-адрес.", nameof(address));
        }

        Span<byte> bytes = stackalloc byte[4];
        address.TryWriteBytes(bytes, out _);
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }

    public static IPAddress ToAddress(uint value)
    {
        return new IPAddress(new[]
        {
            (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value,
        });
    }

    public static string Format(uint value)
    {
        return string.Create(CultureInfo.InvariantCulture, $"{value >> 24}.{(value >> 16) & 0xFF}.{(value >> 8) & 0xFF}.{value & 0xFF}");
    }

    public static bool TryParse(string? text, out uint value)
    {
        value = 0;
        if (text is null || !IPAddress.TryParse(text.Trim(), out var address) || address.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        // IPAddress.TryParse принимает сокращённые формы вроде "1.2"; требуем четыре октета.
        if (text.Trim().Split('.').Length != 4)
        {
            return false;
        }

        value = ToUInt(address);
        return true;
    }

    public static uint Parse(string text)
    {
        return TryParse(text, out var value) ? value : throw new FormatException($"Неверный IPv4-адрес: {text}");
    }
}
