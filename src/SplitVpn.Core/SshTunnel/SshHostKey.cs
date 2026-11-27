using System.Buffers.Binary;
using System.Text;
using System.Security.Cryptography;

namespace SplitVpn.Core.SshTunnel;

/// <summary>
/// Закреплённый открытый ключ сервера SSH: «тип base64», как в known_hosts без имени сервера. Проверки «не
/// сверять ключ» нет намеренно: без закреплённого ключа подключение не поднимается.
/// </summary>
public sealed record SshHostKey(string Type, string Blob)
{
    private static readonly string[] s_types =
        ["ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"];

    /// <summary>Предел длины ключа в base64: RSA до ~24000 бит (OpenSSH создаёт до 16384).</summary>
    public const int MaxBlobChars = 4096;

    /// <summary>Предел длины <see cref="Text"/> разобранного ключа: самый длинный тип, пробел и ключ.</summary>
    public const int MaxTextChars = 19 + 1 + MaxBlobChars;

    /// <summary>Строка для настроек движка.</summary>
    public string Text => Type + " " + Blob;

    /// <summary>
    /// Алгоритмы ключа сервера, которые клиент предлагает при согласовании. Без них сервер с несколькими
    /// ключами может предъявить ключ другого типа, и сверка с закреплённым не сойдётся.
    /// </summary>
    public IReadOnlyList<string> Algorithms => Type == "ssh-rsa" ? ["rsa-sha2-512", "rsa-sha2-256"] : [Type];

    private static bool ValidExponent(ReadOnlySpan<byte> field)
    {
        if (field.IsEmpty || field[0] >= 128) { return false; }
        var significant = field.TrimStart((byte)0);
        return significant.Length is > 0 and <= 3 && (significant.Length > 1 || significant[0] >= 3)
            && (significant[^1] & 1) != 0;
    }

    private static bool ValidCurvePoint(string type, ReadOnlySpan<byte> point)
    {
        var (curve, size) = type switch
        {
            "ecdsa-sha2-nistp256" => (ECCurve.NamedCurves.nistP256, 32),
            "ecdsa-sha2-nistp384" => (ECCurve.NamedCurves.nistP384, 48),
            _ => (ECCurve.NamedCurves.nistP521, 66),
        };
        if (point.Length != 1 + size * 2 || point[0] != 4) { return false; }
        try
        {
            using var key = ECDsa.Create(new ECParameters
            {
                Curve = curve,
                Q = new ECPoint { X = point.Slice(1, size).ToArray(), Y = point[(1 + size)..].ToArray() },
            });
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    public static bool TryParse(string? text, out SshHostKey key)
    {
        key = null!;
        var parts = (text ?? "").Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || !s_types.Contains(parts[0], StringComparer.Ordinal))
        {
            return false;
        }

        if (parts[1].Length > MaxBlobChars)
        {
            return false;
        }

        var blob = new byte[parts[1].Length];
        if (!Convert.TryFromBase64String(parts[1], blob, out var written) || written < 4)
        {
            return false;
        }

        // Внутри ключа первым полем записан его тип: строка «ssh-rsa AAAA…» с ключом ed25519 внутри - ошибка вставки.
        var length = BinaryPrimitives.ReadUInt32BigEndian(blob);
        if (length != parts[0].Length || written < 4 + length || Encoding.ASCII.GetString(blob, 4, (int)length) != parts[0])
        {
            return false;
        }

        ReadOnlySpan<byte> fields = blob.AsSpan(4 + (int)length, written - 4 - (int)length);
        if (!SshPrivateKey.TakeField(ref fields, out var first))
        {
            return false;
        }

        var valid = parts[0] switch
        {
            "ssh-ed25519" => first.Length == 32,
            "ssh-rsa" => ValidExponent(first) && SshPrivateKey.TakeField(ref fields, out var modulus)
                && !modulus.IsEmpty && modulus[0] < 128 && modulus.ContainsAnyExcept((byte)0),
            _ => Encoding.ASCII.GetString(first) == parts[0]["ecdsa-sha2-".Length..]
                && SshPrivateKey.TakeField(ref fields, out var point)
                && ValidCurvePoint(parts[0], point),
        };
        if (!valid || !fields.IsEmpty)
        {
            return false;
        }

        key = new SshHostKey(parts[0], parts[1]);
        return true;
    }
}
