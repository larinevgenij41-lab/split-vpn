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

    public static string ReadFile(string path)
    {
        using var reader = File.OpenText(path);
        var buffer = new char[MaxChars + 1];
        try
        {
            var count = reader.ReadBlock(buffer, 0, buffer.Length);
            var check = Check(buffer.AsSpan(0, count));
            if (check != SshPrivateKeyCheck.Ok)
            {
                throw new InvalidDataException(Describe(check));
            }

            return new string(buffer, 0, count);
        }
        finally
        {
            Array.Clear(buffer);
        }
    }

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

            ReadOnlySpan<byte> data = bytes.AsSpan(0, written);
            if (!data.StartsWith(s_magic))
            {
                return SshPrivateKeyCheck.NotOpenSsh;
            }

            data = data[s_magic.Length..];
            if (!TakeField(ref data, out var cipher)) { return SshPrivateKeyCheck.NotOpenSsh; }
            if (!cipher.SequenceEqual("none"u8)) { return SshPrivateKeyCheck.Encrypted; }
            if (!TakeField(ref data, out var kdf) || !kdf.SequenceEqual("none"u8)
                || !TakeField(ref data, out var options) || !options.IsEmpty
                || data.Length < 4 || BinaryPrimitives.ReadUInt32BigEndian(data) != 1)
            {
                return SshPrivateKeyCheck.NotOpenSsh;
            }

            data = data[4..];
            return TakeField(ref data, out var publicPart) && !publicPart.IsEmpty
                && TakeField(ref data, out var privatePart) && privatePart.Length > 8
                && privatePart[..4].SequenceEqual(privatePart.Slice(4, 4)) && data.IsEmpty
                ? SshPrivateKeyCheck.Ok : SshPrivateKeyCheck.NotOpenSsh;
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

    internal static bool TakeField(ref ReadOnlySpan<byte> data, out ReadOnlySpan<byte> value)
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
        data = data[(4 + (int)length)..];
        return true;
    }
}
