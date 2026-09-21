using System.Text.Json;
using System.Text.Json.Serialization;
using SplitVpn.Core.Geo;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Core.Update;

namespace SplitVpn.Core.Ipc;

public static class IpcNames
{
    public const string PipeName = "SplitVpn.Control";
    public const int ContractVersion = 6;
}

/// <summary>Запросы UI к службе. Служба принимает только эти типы (белый список).</summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "type", UnknownDerivedTypeHandling = JsonUnknownDerivedTypeHandling.FailSerialization)]
[JsonDerivedType(typeof(GetStatusRequest), "getStatus")]
[JsonDerivedType(typeof(GetEventsRequest), "getEvents")]
[JsonDerivedType(typeof(GetAdaptersRequest), "getAdapters")]
[JsonDerivedType(typeof(GetSettingsRequest), "getSettings")]
[JsonDerivedType(typeof(SaveSettingsRequest), "saveSettings")]
[JsonDerivedType(typeof(SaveConnectionRequest), "saveConnection")]
[JsonDerivedType(typeof(SetPasswordRequest), "setPassword")]
[JsonDerivedType(typeof(SetPreSharedKeyRequest), "setPreSharedKey")]
[JsonDerivedType(typeof(ConnectRequest), "connect")]
[JsonDerivedType(typeof(DisconnectRequest), "disconnect")]
[JsonDerivedType(typeof(SetProfileRoleRequest), "setProfileRole")]
[JsonDerivedType(typeof(TestProfileRequest), "testProfile")]
[JsonDerivedType(typeof(CheckAddressRequest), "checkAddress")]
[JsonDerivedType(typeof(GeoUpdateNowRequest), "geoUpdateNow")]
[JsonDerivedType(typeof(GeoImportRequest), "geoImport")]
[JsonDerivedType(typeof(GeoRollbackRequest), "geoRollback")]
[JsonDerivedType(typeof(GeoAcceptPendingRequest), "geoAcceptPending")]
[JsonDerivedType(typeof(GeoRejectPendingRequest), "geoRejectPending")]
[JsonDerivedType(typeof(GeoClearSkippedRequest), "geoClearSkipped")]
[JsonDerivedType(typeof(CheckUpdateRequest), "checkUpdate")]
[JsonDerivedType(typeof(DownloadUpdateRequest), "downloadUpdate")]
[JsonDerivedType(typeof(InstallUpdateRequest), "installUpdate")]
[JsonDerivedType(typeof(UpdateStartedRequest), "updateStarted")]
[JsonDerivedType(typeof(SkipUpdateRequest), "skipUpdate")]
[JsonDerivedType(typeof(ExportReportRequest), "exportReport")]
[JsonDerivedType(typeof(RecoverNetworkRequest), "recoverNetwork")]
[JsonDerivedType(typeof(BeginSignInRequest), "beginSignIn")]
[JsonDerivedType(typeof(CancelSignInRequest), "cancelSignIn")]
[JsonDerivedType(typeof(SsoNavigationRequest), "ssoNavigation")]
[JsonDerivedType(typeof(SubmitAuthFormRequest), "submitAuthForm")]
public abstract record IpcRequest
{
    public int ContractVersion { get; init; } = IpcNames.ContractVersion;
    /// <summary>Содержит ли запрос секрет: такие запросы не журналируются целиком.</summary>
    [JsonIgnore]
    public virtual bool ContainsSecret => false;
}

public sealed record GetStatusRequest : IpcRequest;

/// <summary>Пользователь готов войти в шлюз AnyConnect: служба запускает помощник и присылает запрос входа.</summary>
public sealed record BeginSignInRequest(Guid ProfileId) : IpcRequest;

/// <summary>Окно входа закрыто: вход отменяется, туннель ждёт следующей попытки.</summary>
public sealed record CancelSignInRequest(Guid ProfileId, Guid RequestId) : IpcRequest;

/// <summary>
/// Навигация встроенного браузера при SAML SSO: адрес страницы и cookie шлюза (только его хоста).
/// Среди cookie — токен входа, поэтому запрос секретный.
/// </summary>
public sealed record SsoNavigationRequest(Guid ProfileId, Guid RequestId, string Uri, IReadOnlyList<SsoCookie> Cookies) : IpcRequest
{
    public override bool ContainsSecret => true;

    public override string ToString() => $"SsoNavigationRequest {{ ProfileId = {ProfileId}, RequestId = {RequestId}, Cookies = *** }}";
}

public sealed record SsoCookie(string Name, string Value);

/// <summary>Ответ на форму шлюза (группа, логин, пароль, код): значения по имени поля.</summary>
public sealed record SubmitAuthFormRequest(Guid ProfileId, Guid RequestId, IReadOnlyDictionary<string, string> Values, bool Cancel) : IpcRequest
{
    public override bool ContainsSecret => true;

    public override string ToString() => $"SubmitAuthFormRequest {{ ProfileId = {ProfileId}, RequestId = {RequestId}, Cancel = {Cancel}, Values = *** }}";
}

public sealed record GetEventsRequest(long SinceId) : IpcRequest;

public sealed record GetAdaptersRequest : IpcRequest;

public sealed record GetSettingsRequest : IpcRequest;

public sealed record SaveSettingsRequest(AppSettings Settings) : IpcRequest;

/// <summary>Сохраняет профиль и изменённые секреты одним действием актора, до запуска дозвона.</summary>
public sealed record SaveConnectionRequest(AppSettings Settings, Guid ProfileId, string? Password, string? PreSharedKey) : IpcRequest
{
    public override bool ContainsSecret => true;
    public override string ToString() => $"SaveConnectionRequest {{ ProfileId = {ProfileId}, Secrets = *** }}";
}

public sealed record SetPasswordRequest(Guid ProfileId, string Password) : IpcRequest
{
    public override bool ContainsSecret => true;

    public override string ToString() => $"SetPasswordRequest {{ ProfileId = {ProfileId}, Password = *** }}";
}

public sealed record ConnectRequest(Guid? ProfileId, string? Password) : IpcRequest
{
    public override bool ContainsSecret => Password is not null;

    public override string ToString() => $"ConnectRequest {{ ProfileId = {ProfileId}, Password = {(Password is null ? "null" : "***")} }}";
}

public sealed record SetPreSharedKeyRequest(Guid ProfileId, string Key) : IpcRequest
{
    public override bool ContainsSecret => true;
    public override string ToString() => $"SetPreSharedKeyRequest {{ ProfileId = {ProfileId}, Key = *** }}";
}

public sealed record DisconnectRequest(bool KeepProtection) : IpcRequest;

/// <summary>Сменить роль подключения: опорное, дополнительное или выключенное.</summary>
public sealed record SetProfileRoleRequest(Guid ProfileId, ProfileRole Role) : IpcRequest;

public sealed record TestProfileRequest(Guid ProfileId) : IpcRequest;

public sealed record CheckAddressRequest(string Query) : IpcRequest;

/// <summary>
/// Запрос к одному из автообновляемых списков адресов. Без указания списка речь о RU-базе: так старые
/// клиенты и сохранённые команды продолжают работать.
/// </summary>
public abstract record GeoListRequest : IpcRequest
{
    public GeoListKind List { get; init; } = GeoListKind.Geo;
}

public sealed record GeoUpdateNowRequest : GeoListRequest;

public sealed record GeoImportRequest(string Content) : GeoListRequest;

public sealed record GeoRollbackRequest : GeoListRequest;

public sealed record GeoAcceptPendingRequest : GeoListRequest;

public sealed record GeoRejectPendingRequest : GeoListRequest;

public sealed record GeoClearSkippedRequest : GeoListRequest;

/// <summary>Проверить обновление немедленно: срок следующей проверки и лимитная сеть не учитываются.</summary>
public sealed record CheckUpdateRequest : IpcRequest;

/// <summary>Скачать найденный установщик, когда автозагрузка выключена.</summary>
public sealed record DownloadUpdateRequest(string Version) : IpcRequest;

/// <summary>
/// Приготовить установку: служба заново сверяет контрольную сумму скачанного установщика и отдаёт
/// готовую командную строку msiexec. Запускает её интерфейс с правами администратора — он же
/// закрывается следом, освобождая свои файлы для замены.
/// </summary>
public sealed record InstallUpdateRequest(string Version) : IpcRequest;

/// <summary>
/// Интерфейс сообщает, что установщик запущен, и передаёт его номер процесса: служба дожидается
/// кода завершения, если MSI не успеет её остановить. Ноль — запуск не состоялся (отказ в UAC).
/// </summary>
public sealed record UpdateStartedRequest(int ProcessId) : IpcRequest;

/// <summary>Больше не предлагать эту версию автоматически; пустая строка снимает пропуск.</summary>
public sealed record SkipUpdateRequest(string Version) : IpcRequest;

public sealed record ExportReportRequest(bool MaskPersonalData) : IpcRequest;

public sealed record RecoverNetworkRequest : IpcRequest;

/// <summary>Ответ службы: успех, код ошибки и результат произвольного типа.</summary>
public sealed record IpcResponse(bool Ok, string? ErrorCode, string? ErrorMessage, JsonElement? Result)
{
    public static IpcResponse Success<T>(T result) =>
        new(true, null, null, JsonSerializer.SerializeToElement(result, JsonDefaults.Compact));

    public static IpcResponse Success() => new(true, null, null, null);

    public static IpcResponse Failure(string code, string message) => new(false, code, message, null);

    public T? ResultAs<T>() => Result is { } element ? element.Deserialize<T>(JsonDefaults.Compact) : default;
}

public static class IpcErrorCodes
{
    public const string BadRequest = "bad-request";
    public const string Denied = "denied";
    public const string InvalidSettings = "invalid-settings";
    public const string NotFound = "not-found";
    public const string Busy = "busy";
    public const string Failed = "failed";
}

public static class IpcSerializer
{
    public static byte[] SerializeRequest(IpcRequest request) => JsonSerializer.SerializeToUtf8Bytes(request, JsonDefaults.Compact);

    public static byte[] SerializeResponse(IpcResponse response) => JsonSerializer.SerializeToUtf8Bytes(response, JsonDefaults.Compact);

    /// <summary>Разбирает запрос; неизвестный тип и неверный JSON дают null.</summary>
    public static IpcRequest? TryDeserializeRequest(byte[] payload)
    {
        try
        {
            using var document = JsonDocument.Parse(payload);
            var request = JsonSerializer.Deserialize<IpcRequest>(payload, JsonDefaults.Compact);
            var version = document.RootElement.TryGetProperty("contractVersion", out var value)
                && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var parsed) ? parsed : 1;
            return request is null ? null : request with { ContractVersion = version };
        }
        catch (JsonException)
        {
            return null;
        }
        catch (NotSupportedException)
        {
            return null;
        }
    }

    public static IpcResponse DeserializeResponse(byte[] payload) =>
        JsonSerializer.Deserialize<IpcResponse>(payload, JsonDefaults.Compact) ?? throw new IpcProtocolException("Пустой ответ службы.");
}

public sealed record StatusWarning(string Code, string Text, string? ActionCode)
{
    /// <summary>Кого касается предупреждение: имя чужого VPN-подключения, туннеля. Нужно для текста ошибки туннеля.</summary>
    public string? Subject { get; init; }
}

public sealed record StatusDto
{
    public int ContractVersion { get; init; }
    public VpnProtocol? Protocol { get; init; }
    public AuthMethod? AuthMethod { get; init; }
    public ConnectionState State { get; init; }

    public Intent Intent { get; init; }

    public bool ProtectionActive { get; init; }

    public bool ProtectionSuspended { get; init; }

    public OutageMode OutageMode { get; init; }

    /// <summary>Куда идёт «остальной интернет» и RU-база — словами, для интерфейса.</summary>
    public string DefaultTargetName { get; init; } = "";

    public string GeoTargetName { get; init; } = "";

    /// <summary>Состояние каждого поднимаемого туннеля; опорный первым.</summary>
    public IReadOnlyList<TunnelStatusDto> Tunnels { get; init; } = [];

    public string? ProfileName { get; init; }

    public string? PrimaryAdapterName { get; init; }

    public string? VpnAddress { get; init; }

    public DateTimeOffset? SessionStartedUtc { get; init; }

    public ulong BytesSent { get; init; }

    public ulong BytesReceived { get; init; }

    public ErrorCategory ErrorCategory { get; init; }

    public string? ErrorText { get; init; }

    public int? ErrorCode { get; init; }

    /// <summary>Расшифровка показанной ошибки: что значит код и что сделать по шагам.</summary>
    public ConnectionErrorHelp? ErrorHelp { get; init; }

    public bool DnsViaProvider { get; init; }

    public bool Ipv6Restricted { get; init; } = true;

    public string? GeoRevision { get; init; }

    public DateTimeOffset? GeoDownloadedUtc { get; init; }

    public int GeoV4Count { get; init; }

    public int GeoV6Count { get; init; }

    public string? GeoPendingRevision { get; init; }

    public string? GeoPendingReason { get; init; }

    public DateTimeOffset? GeoLastCheckUtc { get; init; }

    public DateTimeOffset? GeoNextCheckUtc { get; init; }

    public string? GeoLastResult { get; init; }

    public int GeoSkippedCount { get; init; }

    /// <summary>
    /// Состояние списка обхода блокировок. RU-база описана полями Geo* выше — они остались плоскими,
    /// чтобы не переписывать интерфейс и CLI, а второй список описывается одной записью.
    /// </summary>
    public GeoListStatusDto? Bypass { get; init; }

    public string? TunnelAddress { get; init; }

    public string? ServerAddress { get; init; }

    /// <summary>Обновление самой программы: найденная версия, ход загрузки, готовность к установке.</summary>
    public UpdateStatusDto? Update { get; init; }

    public IReadOnlyList<StatusWarning> Warnings { get; init; } = [];
}

/// <summary>Состояние одного туннеля в общем статусе службы.</summary>
/// <summary>Состояние автообновляемого списка адресов для интерфейса.</summary>
public sealed record GeoListStatusDto
{
    public GeoListKind List { get; init; }

    /// <summary>Куда направлены адреса списка, словами: «напрямую», «Нидерланды».</summary>
    public string TargetName { get; init; } = "";

    /// <summary>Список направлен туда же, куда «остальной интернет»: своей цели у него нет.</summary>
    public bool FollowsDefault { get; init; }

    public string? Revision { get; init; }

    public DateTimeOffset? DownloadedUtc { get; init; }

    public int V4Count { get; init; }

    public int V6Count { get; init; }

    public string? PendingRevision { get; init; }

    public string? PendingReason { get; init; }

    public DateTimeOffset? LastCheckUtc { get; init; }

    public DateTimeOffset? NextCheckUtc { get; init; }

    public string? LastResult { get; init; }

    public int SkippedCount { get; init; }
}

public sealed record TunnelStatusDto
{
    public Guid ProfileId { get; init; }

    public string Name { get; init; } = "";

    public ProfileRole Role { get; init; }

    public VpnProtocol Protocol { get; init; }

    public AuthMethod AuthMethod { get; init; }

    public ConnectionState State { get; init; }

    /// <summary>Опорный туннель: его обрыв включает защиту при обрыве, его DNS используется по умолчанию.</summary>
    public bool IsAnchor { get; init; }

    public string? VpnAddress { get; init; }

    public string? AdapterName { get; init; }

    public string? ServerAddress { get; init; }

    public DateTimeOffset? SessionStartedUtc { get; init; }

    public ulong BytesSent { get; init; }

    public ulong BytesReceived { get; init; }

    public ErrorCategory ErrorCategory { get; init; }

    public string? ErrorText { get; init; }

    public int? ErrorCode { get; init; }

    /// <summary>Расшифровка ошибки: что значит код и что сделать по шагам. null — ошибки нет.</summary>
    public ConnectionErrorHelp? ErrorHelp { get; init; }

    /// <summary>Сертификат, который предъявляет сервер (виден только у SSTP); null — пробы не было.</summary>
    public ServerCertificateFacts? ServerCertificate { get; init; }

    /// <summary>Шлюз ждёт входа пользователя (SSO или форма); null — не ждёт.</summary>
    public SignInPromptDto? SignIn { get; init; }

    /// <summary>Сети и DNS, присланные шлюзом AnyConnect в текущем сеансе; null — не AnyConnect или сеанса нет.</summary>
    public ServerNetworksDto? ServerNetworks { get; init; }
}

public enum SignInKind
{
    /// <summary>Туннель ждёт, пока пользователь нажмёт «Войти»: помощник ещё не запущен.</summary>
    Required,

    /// <summary>Встроенный браузер на адресе <see cref="SignInPromptDto.Uri"/>.</summary>
    Browser,

    /// <summary>Форма шлюза с полями <see cref="SignInPromptDto.Fields"/>.</summary>
    Form,
}

public enum AuthFieldKind
{
    Text,
    Password,
    Select,
}

public sealed record AuthFieldDto(string Name, string Label, AuthFieldKind Kind, IReadOnlyList<AuthChoiceDto> Choices, string? Value);

public sealed record AuthChoiceDto(string Name, string Label);

public sealed record SignInPromptDto
{
    public Guid RequestId { get; init; }

    public SignInKind Kind { get; init; }

    /// <summary>Хост шлюза: окно входа передаёт службе cookie только этого хоста.</summary>
    public string GatewayHost { get; init; } = "";

    public string? Uri { get; init; }

    public string? Title { get; init; }

    public string? Message { get; init; }

    /// <summary>Ошибка предыдущей попытки (неверный пароль, отказ шлюза).</summary>
    public string? Error { get; init; }

    public IReadOnlyList<AuthFieldDto> Fields { get; init; } = [];

    public DateTimeOffset ExpiresUtc { get; init; }
}

public sealed record ServerNetworksDto
{
    public IReadOnlyList<string> Networks { get; init; } = [];

    public IReadOnlyList<string> Dns { get; init; } = [];

    public IReadOnlyList<string> DnsSuffixes { get; init; } = [];

    public string? ProxyPac { get; init; }

    /// <summary>В профиле включено «Применять прокси шлюза»: интерфейс ставит PAC в настройки пользователя.</summary>
    public bool ApplyProxy { get; init; }

    /// <summary>Версия libopenconnect помощника — для диагностики.</summary>
    public string? ClientVersion { get; init; }

    public int Mtu { get; init; }

    public bool DtlsActive { get; init; }

    public DateTimeOffset? SessionExpiresUtc { get; init; }
}

/// <summary>Готовая команда установки: интерфейс запускает её с повышением прав и закрывается.</summary>
public sealed record UpdateInstallDto(string FileName, string Arguments, string Version, string LogPath);

/// <summary>Обновление программы глазами интерфейса: что найдено, что скачано и что можно сделать.</summary>
public sealed record UpdateStatusDto
{
    public string CurrentVersion { get; init; } = "";

    public UpdatePhase Phase { get; init; }

    public string? AvailableVersion { get; init; }

    public DateTimeOffset? ReleasedUtc { get; init; }

    public string? Notes { get; init; }

    public string? NotesUrl { get; init; }

    public long PackageSize { get; init; }

    public long DownloadedBytes { get; init; }

    public DateTimeOffset? LastCheckUtc { get; init; }

    public DateTimeOffset? NextCheckUtc { get; init; }

    public string? LastResult { get; init; }

    public string? SkippedVersion { get; init; }

    /// <summary>Подробный журнал msiexec последней попытки: открывается кнопкой в «О программе».</summary>
    public string? InstallLogPath { get; init; }

    public string? LastInstallResult { get; init; }
}

public sealed record ProfileTestDto(bool Success, string Text);

public sealed record ServiceEvent(long Id, DateTimeOffset TimeUtc, string Level, string Text);

public sealed record AdapterDto(Guid InterfaceGuid, string Name, string Description, string Type, bool IsUp, bool IsHardware, string? Gateway, bool IsPrimary);

public sealed record AddressCheckDto(
    string Query,
    IReadOnlyList<AddressCheckItem> Items,
    string? Note);

public sealed record AddressCheckItem(
    string Address,
    string Decision,
    string Source,
    string TargetName,
    string ExpectedInterface,
    string? ActualInterface,
    bool Blocked,
    string Explanation);
