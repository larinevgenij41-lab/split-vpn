namespace SplitVpn.Core.SshTunnel;

/// <summary>Что строка вывода движка говорит о причине отказа.</summary>
public enum SshEngineFailure
{
    None,

    /// <summary>Сервер не принял ключ устройства или имя пользователя.</summary>
    Authentication,

    /// <summary>Сервер предъявил не тот ключ, что закреплён в подключении.</summary>
    HostKeyMismatch,
}

/// <summary>
/// Разбор вывода движка. Эти два отказа повтором не лечатся, а частые повторы с неверным ключом сервер может
/// принять за подбор и закрыть доступ адресу: служба останавливает повторы до действия пользователя.
/// </summary>
public static class SshEngineLog
{
    public static bool IsDetailed(string line) =>
        line.StartsWith("DEBUG", StringComparison.OrdinalIgnoreCase)
        || line.StartsWith("TRACE", StringComparison.OrdinalIgnoreCase)
        || line.StartsWith("INFO", StringComparison.OrdinalIgnoreCase);

    public static SshEngineFailure Classify(string? line)
    {
        if (string.IsNullOrEmpty(line))
        {
            return SshEngineFailure.None;
        }

        if (line.Contains("host key mismatch", StringComparison.OrdinalIgnoreCase)
            || line.Contains("no common algorithm for host key", StringComparison.OrdinalIgnoreCase))
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
        SshEngineFailure.HostKeyMismatch => "сервер предъявил другой ключ, чем закреплён в подключении. Если ключ сервера действительно меняли, укажите новый; иначе это может быть подмена сервера",
        _ => "",
    };
}
