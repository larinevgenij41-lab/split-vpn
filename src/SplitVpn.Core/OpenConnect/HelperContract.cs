using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.OpenConnect;

/// <summary>
/// Контракт между службой и процессом-помощником AnyConnect. Кадры — <see cref="FrameCodec"/> поверх пары
/// анонимных труб, полезная нагрузка — JSON с полем "type". Помощник живёт один сеанс шлюза: сеанс ASA
/// не переносится между процессами (КТ0), поэтому команды «переподключиться по cookie» нет.
/// </summary>
public static class HelperContract
{
    public const int Version = 1;

    public static byte[] Serialize(HelperCommand command) => JsonSerializer.SerializeToUtf8Bytes(command, JsonDefaults.Compact);

    public static byte[] Serialize(HelperEvent helperEvent) => JsonSerializer.SerializeToUtf8Bytes(helperEvent, JsonDefaults.Compact);

    /// <summary>Разбирает команду службы; неизвестный тип и неверный JSON дают null.</summary>
    public static HelperCommand? TryDeserializeCommand(byte[] payload) => TryDeserialize<HelperCommand>(payload);

    /// <summary>Разбирает событие помощника; неизвестный тип и неверный JSON дают null.</summary>
    public static HelperEvent? TryDeserializeEvent(byte[] payload) => TryDeserialize<HelperEvent>(payload);

    private static T? TryDeserialize<T>(byte[] payload)
        where T : class
    {
        try
        {
            return JsonSerializer.Deserialize<T>(payload, JsonDefaults.Compact);
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException)
        {
            return null;
        }
    }
}

/// <summary>Команды службы помощнику.</summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "type", UnknownDerivedTypeHandling = JsonUnknownDerivedTypeHandling.FailSerialization)]
[JsonDerivedType(typeof(StartCommand), "start")]
[JsonDerivedType(typeof(WebviewLoadCommand), "webviewLoad")]
[JsonDerivedType(typeof(WebviewClosedCommand), "webviewClosed")]
[JsonDerivedType(typeof(FormReplyCommand), "formReply")]
[JsonDerivedType(typeof(ResolveReplyCommand), "resolveReply")]
[JsonDerivedType(typeof(StopCommand), "stop")]
public abstract record HelperCommand;

/// <summary>Начать сеанс: вход, CSTP, DTLS, адаптер Wintun. Пароль — если он сохранён и шлюз спросит.</summary>
public sealed record StartCommand(
    string GatewayUrl,
    string Group,
    string UserAgent,
    bool UseDtls,
    string? CertificateThumbprint,
    string InterfaceName,
    string? UserName,
    string? Password) : HelperCommand
{
    public override string ToString() => $"StartCommand {{ GatewayUrl = {GatewayUrl}, Group = {Group}, InterfaceName = {InterfaceName}, Password = {(Password is null ? "null" : "***")} }}";
}

/// <summary>Навигация встроенного браузера: библиотека ищет в cookie токен SSO.</summary>
public sealed record WebviewLoadCommand(Guid RequestId, string Uri, IReadOnlyList<SsoCookie> Cookies) : HelperCommand
{
    public override string ToString() => $"WebviewLoadCommand {{ RequestId = {RequestId}, Cookies = *** }}";
}

public sealed record WebviewClosedCommand(Guid RequestId) : HelperCommand;

public sealed record FormReplyCommand(Guid RequestId, IReadOnlyDictionary<string, string> Values, bool Cancel) : HelperCommand
{
    public override string ToString() => $"FormReplyCommand {{ RequestId = {RequestId}, Cancel = {Cancel}, Values = *** }}";
}

/// <summary>Адрес шлюза, разрешённый службой (она же открывает к нему фильтры и маршрут); null — не разрешился.</summary>
public sealed record ResolveReplyCommand(string Host, string? Address) : HelperCommand;

/// <summary>Завершить сеанс с выходом на шлюзе (BYE) и выйти.</summary>
public sealed record StopCommand : HelperCommand;

/// <summary>События помощника службе.</summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "type", UnknownDerivedTypeHandling = JsonUnknownDerivedTypeHandling.FailSerialization)]
[JsonDerivedType(typeof(HelloEvent), "hello")]
[JsonDerivedType(typeof(SsoOpenEvent), "ssoOpen")]
[JsonDerivedType(typeof(SsoResultEvent), "ssoResult")]
[JsonDerivedType(typeof(AuthFormEvent), "authForm")]
[JsonDerivedType(typeof(ResolveHostEvent), "resolveHost")]
[JsonDerivedType(typeof(EstablishedEvent), "established")]
[JsonDerivedType(typeof(IpInfoChangedEvent), "ipInfoChanged")]
[JsonDerivedType(typeof(StatsEvent), "stats")]
[JsonDerivedType(typeof(ReconnectingEvent), "reconnecting")]
[JsonDerivedType(typeof(LogEvent), "log")]
[JsonDerivedType(typeof(TerminatedEvent), "terminated")]
public abstract record HelperEvent;

public sealed record HelloEvent(int Contract, string OpenConnectVersion) : HelperEvent;

/// <summary>Шлюз требует SAML SSO: открыть встроенный браузер на адресе.</summary>
public sealed record SsoOpenEvent(Guid RequestId, string Uri, string GatewayHost) : HelperEvent;

/// <summary>Итог SSO: Done — токен принят, окно можно закрыть; иначе Error.</summary>
public sealed record SsoResultEvent(Guid RequestId, bool Done, string? Error) : HelperEvent;

public sealed record AuthFormEvent(Guid RequestId, string? Title, string? Message, string? Error, IReadOnlyList<AuthFieldDto> Fields) : HelperEvent;

public sealed record ResolveHostEvent(string Host) : HelperEvent;

/// <summary>Туннель поднят: адаптер Wintun создан, адрес назначен.</summary>
public sealed record EstablishedEvent(ulong Luid, string InterfaceName, SessionInfo Session) : HelperEvent;

/// <summary>Параметры сеанса изменились после переподключения внутри помощника.</summary>
public sealed record IpInfoChangedEvent(SessionInfo Session) : HelperEvent;

public sealed record StatsEvent(ulong BytesSent, ulong BytesReceived, bool DtlsActive) : HelperEvent;

public sealed record ReconnectingEvent(string Reason) : HelperEvent;

public sealed record LogEvent(string Level, string Text) : HelperEvent;

public sealed record TerminatedEvent(TerminationKind Kind, string Text) : HelperEvent;

public enum TerminationKind
{
    /// <summary>Сеть или шлюз недоступны: можно пробовать снова (с новым входом).</summary>
    NetworkError,

    /// <summary>Шлюз отверг вход или cookie: нужен новый вход пользователя.</summary>
    AuthRejected,

    /// <summary>Истёк срок сеанса на шлюзе.</summary>
    SessionExpired,

    /// <summary>Сертификат шлюза не прошёл проверку: без действия пользователя не повторять.</summary>
    CertificateRejected,

    /// <summary>Шлюз требует проверку состояния машины (HostScan/CSD), которую клиент не выполняет.</summary>
    HostScanRequired,

    /// <summary>Пользователь отменил вход или служба остановила сеанс.</summary>
    Cancelled,

    /// <summary>Внутренняя ошибка помощника или библиотеки.</summary>
    Internal,
}

/// <summary>Параметры сеанса шлюза (ip_info и заголовки CSTP).</summary>
public sealed record SessionInfo
{
    public string Address { get; init; } = "";

    public string Netmask { get; init; } = "";

    public int Mtu { get; init; }

    public IReadOnlyList<string> Dns { get; init; } = [];

    /// <summary>Суффиксы split DNS; у ASA приходят отдельным списком, поле domain пусто.</summary>
    public IReadOnlyList<string> SplitDns { get; init; } = [];

    /// <summary>Маршруты в виде «сеть/маска» (10.0.0.0/255.0.0.0), как их отдаёт libopenconnect.</summary>
    public IReadOnlyList<string> SplitIncludes { get; init; } = [];

    public IReadOnlyList<string> SplitExcludes { get; init; } = [];

    public string? ProxyPac { get; init; }

    /// <summary>X-CSTP-Session-Timeout; openconnect_get_auth_expiration у ASA возвращает 0.</summary>
    public int? SessionTimeoutSeconds { get; init; }

    public bool DtlsActive { get; init; }

    /// <summary>
    /// Сети шлюза как CIDR; неразборчивые маршруты пропускаются, слишком широкие — отбрасываются
    /// (<see cref="TooWideIncludes"/>): сеть шире /8 забрала бы заметную часть интернета в туннель шлюза.
    /// </summary>
    public IReadOnlyList<Ipv4Cidr> IncludeCidrs() => SplitIncludes.Select(ParseRoute).OfType<Ipv4Cidr>()
        .Where(c => c.PrefixLength >= PolicyCompiler.MinServerNetworkPrefix).Distinct().ToList();

    /// <summary>Отброшенные маршруты шлюза: разобрались, но шире /8. Для журнала и предупреждения пользователю.</summary>
    public IReadOnlyList<Ipv4Cidr> TooWideIncludes() => SplitIncludes.Select(ParseRoute).OfType<Ipv4Cidr>()
        .Where(c => c.PrefixLength < PolicyCompiler.MinServerNetworkPrefix).Distinct().ToList();

    /// <summary>DNS-серверы шлюза как IPv4.</summary>
    public IReadOnlyList<uint> DnsAddresses() => Dns.Select(d => Ipv4.TryParse(d, out var value) ? value : (uint?)null).OfType<uint>().Distinct().ToList();

    /// <summary>Маршрут libopenconnect: «сеть/маска», «сеть/префикс» или адрес узла.</summary>
    public static Ipv4Cidr? ParseRoute(string route)
    {
        if (string.IsNullOrWhiteSpace(route))
        {
            return null;
        }

        var parts = route.Trim().Split('/');
        if (parts.Length == 1)
        {
            return Ipv4.TryParse(parts[0], out var host) ? new Ipv4Cidr(host, 32) : null;
        }

        if (parts.Length != 2 || !Ipv4.TryParse(parts[0], out var network))
        {
            return null;
        }

        if (Ipv4.TryParse(parts[1], out var mask))
        {
            var prefix = System.Numerics.BitOperations.PopCount(mask);
            // Маска должна быть непрерывной: 255.0.255.0 — не маска.
            return mask == Ipv4Cidr.MaskOf(prefix) ? new Ipv4Cidr(network & mask, prefix) : null;
        }

        return int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var length) && length is >= 0 and <= 32
            ? new Ipv4Cidr(network & Ipv4Cidr.MaskOf(length), length)
            : null;
    }
}
