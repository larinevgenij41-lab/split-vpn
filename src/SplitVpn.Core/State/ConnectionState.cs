namespace SplitVpn.Core.State;

/// <summary>Намерение пользователя, которое служба приводит в соответствие с системой.</summary>
public enum Intent
{
    /// <summary>VPN отключён, защита снята, обычный интернет.</summary>
    Off,

    /// <summary>VPN отключён, защита и маршруты сохранены.</summary>
    Protected,

    /// <summary>VPN подключён по политике.</summary>
    Connected,
}

/// <summary>Состояния из PLAN §6 и дополнительные состояния службы.</summary>
public enum ConnectionState
{
    Disconnected,
    PreparingProtection,
    Connecting,
    ApplyingRoutes,
    Connected,
    Reconnecting,
    TrafficBlocked,
    Error,
    DisconnectedExternally,
    PasswordRequired,
    PartiallyApplied,
}

public enum ErrorCategory
{
    None,
    NameResolution,
    ServerUnreachable,
    Certificate,
    Authentication,
    NoInternetInTunnel,
    Routes,
    Other,
}

/// <summary>Сохраняемое состояние службы (не пользовательские настройки).</summary>
/// <summary>
/// Что служба знает о подключении между запусками: адреса сервера и отпечаток параметров входа —
/// по нему решается, можно ли подхватить живое соединение.
/// </summary>
/// <param name="RevocationHosts">
/// Узлы, к которым Windows ходит за списком отзыва сертификата сервера: защита должна пропускать их
/// с первой же попытки после перезапуска службы, иначе исправный сертификат снова будет отклонён.
/// </param>
public sealed record ServerCacheEntry(
    Guid ProfileId,
    IReadOnlyList<string> Addresses,
    DateTimeOffset ResolvedUtc,
    string? Fingerprint = null,
    IReadOnlyList<string>? RevocationHosts = null);

public sealed record ServiceStateFile
{
    public string? ConnectionFingerprint { get; init; }
    public Intent Intent { get; init; } = Intent.Off;

    /// <summary>Выставляется командой recover: служба ничего не применяет до действия «Подключить».</summary>
    public bool ProtectionSuspended { get; init; }

    /// <summary>Последние известные адреса серверов по профилям: нужны до первого разрешения имени.</summary>
    public IReadOnlyList<ServerCacheEntry> Servers { get; init; } = [];

    /// <summary>
    /// Загрузка Windows (время старта системы, округлённое до минуты), для которой автоподключение уже
    /// применялось. Нужна, чтобы перезапуск службы после команды «Отключить» не подключал VPN заново.
    /// В старых файлах состояния поля нет — тогда автоподключение работает как прежде.
    /// </summary>
    public DateTimeOffset? AutoConnectBootUtc { get; init; }
}
