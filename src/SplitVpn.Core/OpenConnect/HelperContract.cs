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

    /// <summary>
    /// Команда в UTF-8 в очищаемом буфере: кадр с паролем (<see cref="StartCommand"/>) не остаётся в куче копией,
    /// которую нельзя очистить. Буфер затирает Dispose — после записи в трубу. Формат тот же, что у <see cref="Serialize(HelperCommand)"/>.
    /// </summary>
    public static SerializedFrame SerializeToBuffer(HelperCommand command)
    {
        var frame = new SerializedFrame();
        try
        {
            // Те же кодировщик и отступы, что у SerializeToUtf8Bytes: байты кадра совпадают с прежними.
            using (var writer = new Utf8JsonWriter(frame, new JsonWriterOptions
            {
                Encoder = JsonDefaults.Compact.Encoder,
                Indented = JsonDefaults.Compact.WriteIndented,
                MaxDepth = JsonDefaults.Compact.MaxDepth,
            }))
            {
                JsonSerializer.Serialize(writer, command, JsonDefaults.Compact);
            }

            return frame;
        }
        catch
        {
            frame.Dispose();
            throw;
        }
    }

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

/// <summary>
/// Буфер кадра, который очищается: при росте прежний массив затирается, Dispose затирает текущий. Для кадров с
/// секретами (<see cref="HelperContract.SerializeToBuffer"/>).
/// </summary>
public sealed class SerializedFrame : System.Buffers.IBufferWriter<byte>, IDisposable
{
    private byte[] _buffer = new byte[1024];
    private int _written;

    /// <summary>Записанные байты; после Dispose — пусто.</summary>
    public ReadOnlyMemory<byte> Written => _buffer.AsMemory(0, _written);

    public void Advance(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        if (_written + count > _buffer.Length)
        {
            throw new InvalidOperationException("Запись за пределами буфера кадра.");
        }

        _written += count;
    }

    public Memory<byte> GetMemory(int sizeHint = 0)
    {
        Ensure(sizeHint);
        return _buffer.AsMemory(_written);
    }

    public Span<byte> GetSpan(int sizeHint = 0)
    {
        Ensure(sizeHint);
        return _buffer.AsSpan(_written);
    }

    private void Ensure(int sizeHint)
    {
        var needed = Math.Max(sizeHint, 1);
        if (_buffer.Length - _written >= needed)
        {
            return;
        }

        var grown = new byte[Math.Max(_buffer.Length * 2, _written + needed)];
        _buffer.AsSpan(0, _written).CopyTo(grown);
        Array.Clear(_buffer);
        _buffer = grown;
    }

    public void Dispose()
    {
        Array.Clear(_buffer);
        _written = 0;
    }
}

/// <summary>
/// Секрет как массив символов в JSON-строке: на проводе — та же строка, что и у string, но в памяти — массив,
/// который владелец очищает после использования. Промежуточный буфер чтения очищается.
/// </summary>
public sealed class SecretCharsJsonConverter : JsonConverter<char[]>
{
    public override char[]? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null)
        {
            return null;
        }

        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException("Ожидалась строка.");
        }

        // Символов UTF-16 не больше, чем байтов UTF-8 в записи (экранирование только удлиняет запись).
        var max = checked((int)(reader.HasValueSequence ? reader.ValueSequence.Length : reader.ValueSpan.Length));
        var scratch = new char[max];
        try
        {
            var length = reader.CopyString(scratch);
            return scratch.AsSpan(0, length).ToArray();
        }
        finally
        {
            Array.Clear(scratch);
        }
    }

    public override void Write(Utf8JsonWriter writer, char[] value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteStringValue(value);
    }
}

/// <summary>
/// Пределы данных шлюза, которые помощник передаёт службе, а служба — приложению в каждом ответе о состоянии.
/// Шлюз недоверенный: без пределов баннер в мегабайты или десятки тысяч сетей превысили бы кадр канала
/// (<see cref="FrameCodec.MaxFrameBytes"/>). Помощник и служба обрезают по одним и тем же числам.
/// </summary>
public static class HelperLimits
{
    /// <summary>
    /// Сетей split-include и, отдельно, split-exclude: столько же, сколько служба принимает после свёртки
    /// (<see cref="Policy.GatewayNetworkLimits.MaxRoutes"/>), — шлюз, работавший раньше, не урезается. Две полные
    /// таблицы записей наибольшей длины (<see cref="MaxRouteLength"/>, без экранирования) занимают около 1,1 МБ.
    /// </summary>
    public const int MaxSplitRoutes = Policy.GatewayNetworkLimits.MaxRoutes;

    /// <summary>Суффиксов split DNS (и DNS-серверов).</summary>
    public const int MaxSplitDns = 64;

    /// <summary>
    /// Длина записи сети или адреса: ровно «255.255.255.255/255.255.255.255». Длиннее запись не разберётся, а
    /// при 64 символах две таблицы по <see cref="MaxSplitRoutes"/> записей уже не влезли бы в кадр 2 МБ.
    /// </summary>
    public const int MaxRouteLength = 31;

    /// <summary>Длина имени DNS.</summary>
    public const int MaxDnsNameLength = 255;

    /// <summary>Длина домена по умолчанию и адреса PAC.</summary>
    public const int MaxSessionText = 4096;

    /// <summary>Заголовок, сообщение и ошибка формы входа.</summary>
    public const int MaxFormText = 4096;

    /// <summary>Подпись поля и варианта выбора.</summary>
    public const int MaxLabel = 256;

    /// <summary>Полей формы, которые показываются пользователю.</summary>
    public const int MaxFormFields = 32;

    /// <summary>Вариантов выбора одного поля.</summary>
    public const int MaxChoices = 256;

    /// <summary>Имя поля: длиннее служба не примет в ответе формы.</summary>
    public const int MaxFieldName = 256;

    /// <summary>Значение поля: длиннее служба не примет в ответе формы. Имя варианта - не длиннее <see cref="MaxLabel"/>.</summary>
    public const int MaxFieldValue = 1024;

    /// <summary>Адрес страницы входа SSO. Длиннее не обрезается (обрезанный адрес не откроет вход), а отклоняется.</summary>
    public const int MaxSsoUri = 8192;

    /// <summary>Строка не длиннее <paramref name="maxLength"/> символов; обрезанная кончается многоточием.</summary>
    public static string? Truncate(string? text, int maxLength)
    {
        if (text is null || text.Length <= maxLength)
        {
            return text;
        }

        var cut = Math.Max(0, maxLength - 1);
        if (cut > 0 && char.IsHighSurrogate(text[cut - 1]))
        {
            // Половина суррогатной пары дала бы недопустимый UTF-16, и сериализатор JSON отказался бы его писать.
            cut--;
        }

        return string.Concat(text.AsSpan(0, cut), "…");
    }

    /// <summary>
    /// Сколько символов всего занимают поля формы (имена, подписи, значения, варианты). Поштучные пределы вместе
    /// допускают 32 × 256 вариантов по 256 символов — больше кадра канала; общий бюджет держит форму в десятках
    /// килобайт даже при экранировании каждого символа в JSON.
    /// </summary>
    public const int MaxFormFieldChars = 32 * 1024;

    /// <summary>
    /// Поля формы в пределах: длинные подписи обрезаются, лишние поля и варианты отбрасываются, поля и варианты с
    /// именем длиннее допустимого в ответе формы пропускаются (выбрать их всё равно нельзя). Когда общий бюджет
    /// <see cref="MaxFormFieldChars"/> исчерпан, следующие варианты и поля не берутся.
    /// </summary>
    public static IReadOnlyList<AuthFieldDto> CapFields(IReadOnlyList<AuthFieldDto>? fields)
    {
        var budget = MaxFormFieldChars;
        var result = new List<AuthFieldDto>();
        foreach (var field in fields ?? [])
        {
            if (result.Count >= MaxFormFields)
            {
                break;
            }

            if (field is not { Name: { Length: > 0 and <= MaxFieldName } name })
            {
                continue;
            }

            var label = Truncate(field.Label ?? name, MaxLabel)!;
            var value = field.Value is { Length: > MaxFieldValue } ? null : field.Value;
            var cost = name.Length + label.Length + (value?.Length ?? 0);
            if (cost > budget)
            {
                break;
            }

            budget -= cost;
            var choices = new List<AuthChoiceDto>();
            foreach (var choice in field.Choices ?? [])
            {
                if (choices.Count >= MaxChoices)
                {
                    break;
                }

                if (choice is not { Name: { Length: <= MaxLabel } choiceName })
                {
                    continue;
                }

                var choiceLabel = Truncate(choice.Label ?? choiceName, MaxLabel)!;
                if (choiceName.Length + choiceLabel.Length > budget)
                {
                    break;
                }

                budget -= choiceName.Length + choiceLabel.Length;
                choices.Add(choice with { Label = choiceLabel });
            }

            result.Add(field with { Label = label, Value = value, Choices = choices });
        }

        return result;
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
    [property: JsonConverter(typeof(SecretCharsJsonConverter))] char[]? Password) : HelperCommand
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

/// <summary>
/// Адрес шлюза, разрешённый службой (она же открывает к нему фильтры и маршрут); null — не разрешился.
/// Addresses — все адреса узла по порядку (первый совпадает с Address): помощник берёт следующий, если первый
/// не принимает соединение. Служба прежних версий поля не присылает.
/// </summary>
public sealed record ResolveReplyCommand(string Host, string? Address, IReadOnlyList<string>? Addresses = null) : HelperCommand;

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

public sealed record AuthFormEvent(Guid RequestId, string? Title, string? Message, string? Error, IReadOnlyList<AuthFieldDto> Fields) : HelperEvent
{
    /// <summary>Форма в пределах <see cref="HelperLimits"/>: тексты шлюза уходят в каждый ответ о состоянии.</summary>
    public AuthFormEvent Capped() => this with
    {
        Title = HelperLimits.Truncate(Title, HelperLimits.MaxFormText),
        Message = HelperLimits.Truncate(Message, HelperLimits.MaxFormText),
        Error = HelperLimits.Truncate(Error, HelperLimits.MaxFormText),
        Fields = HelperLimits.CapFields(Fields),
    };
}

/// <summary>
/// Помощнику нужен адрес узла шлюза. Порт — тот, к которому библиотека будет подключаться (после перенаправления
/// он может отличаться от порта профиля), служба открывает к нему фильтры; 0 — помощник порт не сообщил.
/// </summary>
public sealed record ResolveHostEvent(string Host, int Port = 0) : HelperEvent;

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

    /// <summary>Суффиксы split DNS; у ASA обычно приходят отдельным списком, поле domain пусто.</summary>
    public IReadOnlyList<string> SplitDns { get; init; } = [];

    /// <summary>Домен по умолчанию (ip_info.domain, X-CSTP-Default-Domain); может содержать несколько имён через пробел.</summary>
    public string? Domain { get; init; }

    /// <summary>Маршруты в виде «сеть/маска» (10.0.0.0/255.0.0.0), как их отдаёт libopenconnect.</summary>
    public IReadOnlyList<string> SplitIncludes { get; init; } = [];

    public IReadOnlyList<string> SplitExcludes { get; init; } = [];

    public string? ProxyPac { get; init; }

    /// <summary>X-CSTP-Session-Timeout; openconnect_get_auth_expiration у ASA возвращает 0.</summary>
    public int? SessionTimeoutSeconds { get; init; }

    public bool DtlsActive { get; init; }

    /// <summary>Порт DTLS, назначенный шлюзом (X-DTLS-Port); null — шлюз его не прислал.</summary>
    public int? DtlsPort { get; init; }

    /// <summary>
    /// Суффиксы DNS шлюза: split DNS, а если шлюз его не прислал — домен по умолчанию. Так же поступает
    /// клиент Cisco: без split DNS имена домена по умолчанию разрешает DNS шлюза.
    /// </summary>
    public IReadOnlyList<string> DnsSuffixes() => SplitDns.Count > 0
        ? SplitDns
        : (Domain ?? "").Split([' ', ',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>
    /// Сети шлюза как CIDR; неразборчивые маршруты пропускаются, слишком широкие — отбрасываются
    /// (<see cref="TooWideIncludes"/>): сеть шире /8 забрала бы заметную часть интернета в туннель шлюза.
    /// Слой, который вместе выходит за пределы <see cref="GatewayNetworkLimits"/>, отбрасывается целиком
    /// (<see cref="RejectedIncludes"/>): список пуст, как если бы шлюз сетей не прислал.
    /// </summary>
    public IReadOnlyList<Ipv4Cidr> IncludeCidrs()
    {
        var cidrs = NarrowEnoughIncludes();
        return GatewayNetworkLimits.Violation(GatewayNetworkLimits.Union(cidrs)) is null ? cidrs : [];
    }

    /// <summary>
    /// Причина, по которой сети шлюза отброшены целиком (суммарное покрытие или число маршрутов выше предела),
    /// или null. Для журнала и предупреждения пользователю, как <see cref="TooWideIncludes"/>. Считается по тому же
    /// набору, что и <see cref="IncludeCidrs"/>: сети шире /8, отброшенные поштучно, в покрытие не входят.
    /// </summary>
    public string? RejectedIncludes() => GatewayNetworkLimits.Violation(GatewayNetworkLimits.Union(NarrowEnoughIncludes()));

    private List<Ipv4Cidr> NarrowEnoughIncludes() => SplitIncludes.Select(ParseRoute).OfType<Ipv4Cidr>()
        .Where(c => c.PrefixLength >= PolicyCompiler.MinServerNetworkPrefix).Distinct().ToList();

    /// <summary>Отброшенные маршруты шлюза: разобрались, но шире /8. Для журнала и предупреждения пользователю.</summary>
    public IReadOnlyList<Ipv4Cidr> TooWideIncludes() => SplitIncludes.Select(ParseRoute).OfType<Ipv4Cidr>()
        .Where(c => c.PrefixLength < PolicyCompiler.MinServerNetworkPrefix).Distinct().ToList();

    /// <summary>
    /// DNS-серверы шлюза как IPv4. Loopback, «этот хост» (0.0.0.0/8), multicast и широковещание отбрасываются:
    /// такой «DNS шлюза» нельзя спросить через туннель, а адрес лёг бы в политику маршрутом и разрешением в туннель.
    /// </summary>
    public IReadOnlyList<uint> DnsAddresses() => Dns.Select(d => Ipv4.TryParse(d, out var value) ? value : (uint?)null).OfType<uint>()
        .Where(a => !SpecialRanges.GatewayUnusable.Contains(a)).Distinct().ToList();

    /// <summary>
    /// Что урезано помощником из-за пределов <see cref="HelperLimits"/> (для журнала службы); пусто — ничего.
    /// Служба прежних версий поля не знает и пропускает его.
    /// </summary>
    public IReadOnlyList<string> Truncated { get; init; } = [];

    /// <summary>
    /// Почему адрес туннеля, выданный шлюзом, нельзя назначить адаптеру; null — адрес годится. Адрес из служебных
    /// диапазонов (<see cref="SpecialRanges.GatewayUnusable"/>) на адаптере с /32 и принудительным Preferred
    /// перехватил бы loopback, link-local или multicast всей машины.
    /// </summary>
    public string? TunnelAddressProblem()
    {
        if (!Ipv4.TryParse(Address ?? "", out var address))
        {
            return "шлюз не выдал IPv4-адрес туннеля";
        }

        return SpecialRanges.GatewayUnusable.Contains(address)
            ? $"шлюз выдал недопустимый адрес туннеля {Ipv4.Format(address)} (служебный диапазон: loopback, link-local, multicast или 0.0.0.0/8)"
            : null;
    }

    /// <summary>
    /// Параметры сеанса в пределах <see cref="HelperLimits"/>: списки и строки шлюза обрезаются, а что обрезано —
    /// в <see cref="Truncated"/>. Без этого десятки тысяч сетей split-include дали бы событие больше кадра канала
    /// (<see cref="FrameCodec.MaxFrameBytes"/>), и служба не узнала бы о сеансе. Повторный вызов ничего не меняет.
    /// </summary>
    public SessionInfo Capped()
    {
        var truncated = new List<string>(Truncated ?? []);
        var includes = CapList(SplitIncludes, HelperLimits.MaxSplitRoutes, HelperLimits.MaxRouteLength, "сети шлюза (split-include)", truncated, routeChars: true);
        var excludes = CapList(SplitExcludes, HelperLimits.MaxSplitRoutes, HelperLimits.MaxRouteLength, "исключения шлюза (split-exclude)", truncated, routeChars: true);
        var splitDns = CapList(SplitDns, HelperLimits.MaxSplitDns, HelperLimits.MaxDnsNameLength, "суффиксы split DNS", truncated);
        var dns = CapList(Dns, HelperLimits.MaxSplitDns, HelperLimits.MaxRouteLength, "DNS-серверы шлюза", truncated, routeChars: true);
        var domain = CapText(Domain, HelperLimits.MaxSessionText, "домен по умолчанию", truncated);
        var pac = ProxyPac is { Length: > HelperLimits.MaxSessionText } ? null : ProxyPac;
        if (!ReferenceEquals(pac, ProxyPac))
        {
            truncated.Add(string.Create(CultureInfo.InvariantCulture, $"адрес PAC длиннее {HelperLimits.MaxSessionText} символов отброшен"));
        }

        // Адрес и маска длиннее записи IPv4 не разбираются: обрезка лишь не даёт им раздуть событие.
        var address = CapText(Address, HelperLimits.MaxRouteLength, "адрес туннеля", null);
        var netmask = CapText(Netmask, HelperLimits.MaxRouteLength, "маска туннеля", null);
        var changed = !ReferenceEquals(includes, SplitIncludes) || !ReferenceEquals(excludes, SplitExcludes)
            || !ReferenceEquals(splitDns, SplitDns) || !ReferenceEquals(dns, Dns) || !ReferenceEquals(domain, Domain)
            || !ReferenceEquals(pac, ProxyPac) || !ReferenceEquals(address, Address) || !ReferenceEquals(netmask, Netmask);
        if (!changed)
        {
            return this;
        }

        return this with
        {
            Address = address ?? "",
            Netmask = netmask ?? "",
            SplitIncludes = includes,
            SplitExcludes = excludes,
            SplitDns = splitDns,
            Dns = dns,
            Domain = domain,
            ProxyPac = pac,
            Truncated = truncated.Distinct(StringComparer.Ordinal).ToList(),
        };
    }

    private static IReadOnlyList<string> CapList(IReadOnlyList<string>? list, int maxCount, int maxLength, string what, List<string> truncated, bool routeChars = false)
    {
        list ??= [];
        bool Valid(string? item) => item is not null && item.Length <= maxLength && (!routeChars || IsRouteText(item));

        // Сети IPv6 служба не использует (туннель только IPv4): они отбрасываются молча, без отметки об урезании.
        bool Ipv6(string? item) => routeChars && item is not null && item.Contains(':', StringComparison.Ordinal);
        var tooLong = list.Count(item => !Valid(item) && !Ipv6(item));
        if (list.Count <= maxCount && list.All(Valid))
        {
            return list;
        }

        var kept = list.Where(Valid).ToList();
        if (kept.Count > maxCount)
        {
            truncated.Add(string.Create(CultureInfo.InvariantCulture, $"{what}: взято {maxCount} из {kept.Count}"));
            kept = kept.Take(maxCount).ToList();
        }

        if (tooLong > 0)
        {
            truncated.Add(string.Create(CultureInfo.InvariantCulture, $"{what}: отброшено записей неверного вида или длины {tooLong}"));
        }

        return kept;
    }

    /// <summary>
    /// Запись сети или адреса из одних цифр, точек и косой черты. Такие символы JSON не экранирует, и предел
    /// <see cref="HelperLimits.MaxSplitRoutes"/> записей по <see cref="HelperLimits.MaxRouteLength"/> символов
    /// гарантированно укладывается в кадр канала; иная запись всё равно не разобралась бы как маршрут.
    /// </summary>
    private static bool IsRouteText(string item)
    {
        foreach (var c in item)
        {
            if (c is not (>= '0' and <= '9' or '.' or '/'))
            {
                return false;
            }
        }

        return true;
    }

    private static string? CapText(string? text, int maxLength, string what, List<string>? truncated)
    {
        if (text is null || text.Length <= maxLength)
        {
            return text;
        }

        truncated?.Add(string.Create(CultureInfo.InvariantCulture, $"{what} обрезан до {maxLength} символов"));
        return HelperLimits.Truncate(text, maxLength);
    }

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
