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

    /// <summary>
    /// Разбирает строго «a.b.c.d»: четыре десятичных октета 0–255 без ведущих нулей.
    /// IPAddress.TryParse понимает сокращённые («1.2»), восьмеричные («010») и шестнадцатеричные формы,
    /// из-за чего «010.0.0.0» молча превращалось бы в 8.0.0.0.
    /// </summary>
    public static bool TryParse(string? text, out uint value)
    {
        value = 0;
        if (text is null)
        {
            return false;
        }

        var span = text.AsSpan().Trim();
        uint result = 0;
        for (var octetIndex = 0; octetIndex < 4; octetIndex++)
        {
            if (octetIndex > 0)
            {
                if (span.IsEmpty || span[0] != '.')
                {
                    return false;
                }

                span = span[1..];
            }

            if (!TryReadOctet(ref span, out var octet))
            {
                return false;
            }

            result = (result << 8) | octet;
        }

        if (!span.IsEmpty)
        {
            return false;
        }

        value = result;
        return true;
    }

    private static bool TryReadOctet(ref ReadOnlySpan<char> span, out uint octet)
    {
        octet = 0;
        var length = 0;
        while (length < span.Length && span[length] is >= '0' and <= '9')
        {
            length++;
        }

        // Ведущий ноль допустим только у самого «0».
        if (length is 0 or > 3 || (length > 1 && span[0] == '0'))
        {
            return false;
        }

        for (var i = 0; i < length; i++)
        {
            octet = (octet * 10) + (uint)(span[i] - '0');
        }

        span = span[length..];
        return octet <= 255;
    }

    public static uint Parse(string text)
    {
        return TryParse(text, out var value) ? value : throw new FormatException($"Неверный IPv4-адрес: {text}");
    }
}
