using System.Buffers.Binary;
using System.Security.Cryptography;

namespace SplitVpn.Core.SshTunnel;

public enum SshPrivateKeyCheck
{
    Ok,

    /// <summary>Пусто или длиннее допустимого.</summary>
    WrongSize,

    /// <summary>Не файл закрытого ключа в формате OpenSSH.</summary>
    NotOpenSsh,

    /// <summary>Ключ защищён паролем: первая версия такие не принимает.</summary>
    Encrypted,
}

/// <summary>
/// Проверка файла закрытого ключа до сохранения в хранилище службы. Сам ключ не разбирается и не превращается
/// в строки: читается только заголовок контейнера, расшифрованная копия затирается.
/// </summary>
public static class SshPrivateKey
{
    public const int MaxChars = 16 * 1024;

    private const string Header = "-----BEGIN OPENSSH PRIVATE KEY-----";
    private const string Footer = "-----END OPENSSH PRIVATE KEY-----";
    private static readonly byte[] s_magic = "openssh-key-v1\0"u8.ToArray();

    public static SshPrivateKeyCheck Check(ReadOnlySpan<char> text)
    {
        var trimmed = text.Trim();
        if (trimmed.Length == 0 || text.Length > MaxChars)
        {
            return SshPrivateKeyCheck.WrongSize;
        }

        if (!trimmed.StartsWith(Header, StringComparison.Ordinal) || !trimmed.EndsWith(Footer, StringComparison.Ordinal))
        {
            return SshPrivateKeyCheck.NotOpenSsh;
        }

        var body = trimmed[Header.Length..^Footer.Length];
        var bytes = new byte[body.Length];
        try
        {
            if (!Convert.TryFromBase64Chars(body, bytes, out var written))
            {
                return SshPrivateKeyCheck.NotOpenSsh;
            }

            var data = bytes.AsSpan(0, written);
            if (!data.StartsWith(s_magic) || !TryReadString(data[s_magic.Length..], out var cipher))
            {
                return SshPrivateKeyCheck.NotOpenSsh;
            }

            return cipher.SequenceEqual("none"u8) ? SshPrivateKeyCheck.Ok : SshPrivateKeyCheck.Encrypted;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public static string Describe(SshPrivateKeyCheck check) => check switch
    {
        SshPrivateKeyCheck.Ok => "",
        SshPrivateKeyCheck.WrongSize => "Файл ключа SSH пуст или слишком велик (допустимо до 16 КБ).",
        SshPrivateKeyCheck.Encrypted => "Ключ SSH защищён паролем. Сохраните копию ключа без пароля (ssh-keygen -p) и загрузите её: служба хранит ключ зашифрованным.",
        _ => "Файл не похож на закрытый ключ OpenSSH: он должен начинаться со строки «-----BEGIN OPENSSH PRIVATE KEY-----».",
    };

    private static bool TryReadString(ReadOnlySpan<byte> data, out ReadOnlySpan<byte> value)
    {
        value = default;
        if (data.Length < 4)
        {
            return false;
        }

        var length = BinaryPrimitives.ReadUInt32BigEndian(data);
        if (length > data.Length - 4)
        {
            return false;
        }

        value = data.Slice(4, (int)length);
        return true;
    }
}
