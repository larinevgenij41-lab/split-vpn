namespace SplitVpn.Core.SshTunnel;

/// <summary>Что строка вывода движка говорит о причине отказа.</summary>
public enum SshEngineFailure
{
    None,

    /// <summary>Сервер не принял ключ устройства или имя пользователя.</summary>
    Authentication,

    /// <summary>Сервер предъявил не тот ключ, что закреплён в подключении.</summary>
    HostKeyMismatch,

    /// <summary>Сервер и клиент не согласовали алгоритм ключа сервера.</summary>
    AlgorithmMismatch,

    /// <summary>Сервер и клиент не согласовали обмен ключами, шифр, MAC или сжатие: обычно сервер знает только устаревшие.</summary>
    NegotiationMismatch,
}

/// <summary>
/// Разбор вывода движка. Эти отказы повтором не лечатся, а частые повторы с неверным ключом сервер может
/// принять за подбор и закрыть доступ адресу: служба останавливает повторы до действия пользователя.
/// </summary>
public static class SshEngineLog
{
    public static bool IsDetailed(string line)
    {
        var plain = Plain(line);
        return plain.StartsWith("DEBUG", StringComparison.OrdinalIgnoreCase)
            || plain.StartsWith("TRACE", StringComparison.OrdinalIgnoreCase)
            || plain.StartsWith("INFO", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Строка без управляющих последовательностей ANSI (ESC[…m). Служба запускает движок с --disable-color, но
    /// раскрашенный уровень («ESC[37mDEBUG ESC[0m[0000] …») не должен ни прятать уровень, ни попадать в журнал.
    /// </summary>
    public static string Plain(string? line)
    {
        if (string.IsNullOrEmpty(line) || !line.Contains('\u001b', StringComparison.Ordinal))
        {
            return line ?? "";
        }

        var builder = new System.Text.StringBuilder(line.Length);
        for (var i = 0; i < line.Length; i++)
        {
            if (line[i] == '\u001b' && i + 1 < line.Length && line[i + 1] == '[')
            {
                // CSI: параметры и промежуточные байты 0x20-0x3F, завершающий байт 0x40-0x7E.
                var end = i + 2;
                while (end < line.Length && line[end] is >= ' ' and <= '?')
                {
                    end++;
                }

                if (end < line.Length && line[end] is >= '@' and <= '~')
                {
                    i = end;
                    continue;
                }
            }

            builder.Append(line[i]);
        }

        return builder.ToString();
    }

    public static SshEngineFailure Classify(string? line)
    {
        if (string.IsNullOrEmpty(line))
        {
            return SshEngineFailure.None;
        }

        line = Plain(line);
        if (line.Contains("no common algorithm for host key", StringComparison.OrdinalIgnoreCase))
        {
            return SshEngineFailure.AlgorithmMismatch;
        }

        // golang.org/x/crypto/ssh: «ssh: no common algorithm for key exchange; client offered: …» (или «we offered»),
        // так же для «client to server cipher», «server to client MAC», сжатия. Повтор этого не лечит.
        if (line.Contains("no common algorithm for ", StringComparison.OrdinalIgnoreCase))
        {
            return SshEngineFailure.NegotiationMismatch;
        }

        if (line.Contains("host key mismatch", StringComparison.OrdinalIgnoreCase))
        {
            return SshEngineFailure.HostKeyMismatch;
        }

        return line.Contains("unable to authenticate", StringComparison.OrdinalIgnoreCase)
            || line.Contains("no supported methods remain", StringComparison.OrdinalIgnoreCase)
            ? SshEngineFailure.Authentication
            : SshEngineFailure.None;
    }

    public static string Describe(SshEngineFailure failure) => failure switch
    {
        SshEngineFailure.Authentication => "сервер SSH не принял ключ или имя пользователя. Проверьте имя пользователя и загрузите верный ключ",
        SshEngineFailure.AlgorithmMismatch => "сервер SSH и клиент не согласовали алгоритм ключа сервера. Проверьте, что сервер поддерживает тип закрепленного ключа",
        SshEngineFailure.NegotiationMismatch => "сервер SSH и клиент не согласовали алгоритмы обмена ключами или шифрования: сервер, вероятно, поддерживает только устаревшие. Включите на сервере SSH современные алгоритмы (например, обмен ключами curve25519-sha256) или обновите его",
        SshEngineFailure.HostKeyMismatch => "сервер предъявил другой ключ, чем закреплён в подключении. Если ключ сервера действительно меняли, укажите новый; иначе это может быть подмена сервера",
        _ => "",
    };
}
