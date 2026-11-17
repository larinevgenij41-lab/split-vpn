using System.Buffers.Binary;
using System.Text;

namespace SplitVpn.Core.SshTunnel;

/// <summary>
/// Закреплённый открытый ключ сервера SSH: «тип base64», как в known_hosts без имени сервера. Проверки «не
/// сверять ключ» нет намеренно: без закреплённого ключа подключение не поднимается.
/// </summary>
public sealed record SshHostKey(string Type, string Blob)
{
    private static readonly string[] s_types =
        ["ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"];

    /// <summary>Строка для настроек движка.</summary>
    public string Text => Type + " " + Blob;

    /// <summary>
    /// Алгоритмы ключа сервера, которые клиент предлагает при согласовании. Без них сервер с несколькими
    /// ключами может предъявить ключ другого типа, и сверка с закреплённым не сойдётся.
    /// </summary>
    public IReadOnlyList<string> Algorithms => Type == "ssh-rsa" ? ["rsa-sha2-512", "rsa-sha2-256"] : [Type];

    public static bool TryParse(string? text, out SshHostKey key)
    {
        key = null!;
        var parts = (text ?? "").Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || !s_types.Contains(parts[0], StringComparer.Ordinal))
        {
            return false;
        }

        var blob = new byte[parts[1].Length];
        if (parts[1].Length > 4096 || !Convert.TryFromBase64String(parts[1], blob, out var written) || written < 4)
        {
            return false;
        }

        // Внутри ключа первым полем записан его тип: строка «ssh-rsa AAAA…» с ключом ed25519 внутри - ошибка вставки.
        var length = BinaryPrimitives.ReadUInt32BigEndian(blob);
        if (length != parts[0].Length || written < 4 + length || Encoding.ASCII.GetString(blob, 4, (int)length) != parts[0])
        {
            return false;
        }

        key = new SshHostKey(parts[0], parts[1]);
        return true;
    }
}
