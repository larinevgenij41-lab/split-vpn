using SplitVpn.Core.Net;

namespace SplitVpn.Core.Settings;

public enum VpnProtocol
{
    Sstp,
    L2tpIpsec,
    Ikev2,
    Pptp,

    /// <summary>Cisco AnyConnect (CSTP/DTLS) через libopenconnect; не RAS.</summary>
    AnyConnect,

    /// <summary>VPN поверх SSH: только TCP, туннель поднимает отдельный процесс движка; не RAS.</summary>
    SshVpn,
}

public static class VpnProtocols
{
    public static string Name(VpnProtocol protocol) => protocol switch
    {
        VpnProtocol.Sstp => "SSTP", VpnProtocol.L2tpIpsec => "L2TP/IPsec", VpnProtocol.Ikev2 => "IKEv2", VpnProtocol.Pptp => "PPTP",
        VpnProtocol.AnyConnect => "Cisco AnyConnect", VpnProtocol.SshVpn => "VPN поверх SSH", _ => "—",
    };

    public static string AuthName(AuthMethod method) => method switch
    {
        AuthMethod.MsChapV2 => "MS-CHAPv2", AuthMethod.EapMsChapV2 => "EAP-MSCHAPv2", AuthMethod.PeapMsChapV2 => "PEAP / EAP-MSCHAPv2",
        AuthMethod.EapTls => "EAP-TLS", AuthMethod.TtlsMsChapV2 => "EAP-TTLS / MSCHAPv2", AuthMethod.TtlsPap => "EAP-TTLS / PAP",
        AuthMethod.Pap => "PAP", AuthMethod.Chap => "CHAP", AuthMethod.MachineCertificate => "сертификат компьютера",
        AuthMethod.GatewayForm => "SSO / форма шлюза", AuthMethod.SshKey => "ключ SSH", _ => "—",
    };
    public static string ConnectionKey(ConnectionProfile profile)
    {
        if (profile.Protocol == VpnProtocol.SshVpn && ServerAddress.TryParse(profile.Server, SshDefaultPort, out var ssh))
        {
            var host = ssh.Host.ToLowerInvariant();
            profile = profile with { Server = ssh.Port == SshDefaultPort ? host : FormattableString.Invariant($"{host}:{ssh.Port}") };
        }
        else if (UsesRas(profile.Protocol))
        {
            profile = profile with
            {
                AnyConnect = new(),
                Eap = IsEap(profile.AuthMethod) ? profile.Eap : new(),
                IpsecAuthentication = profile.Protocol == VpnProtocol.L2tpIpsec ? profile.IpsecAuthentication : IpsecAuthentication.PreSharedKey,
            };
        }
        return Fingerprint(profile);
    }

    public static bool MatchesConnectionKey(ConnectionProfile profile, string fingerprint) =>
        fingerprint == ConnectionKey(profile) || fingerprint == Fingerprint(profile);

    private static string Fingerprint(ConnectionProfile profile) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
        profile.Protocol == VpnProtocol.SshVpn
            // Отдельная форма только для SSH: у прежних типов состав ключа не меняется, иначе после обновления
            // служба сочла бы их сеансы чужими и разорвала.
            ? System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new { profile.Id, profile.Server, profile.Protocol, profile.AuthMethod,
                profile.UserName, SshVpn = new SshVpnSettings { HostKey = SshTunnel.SshHostKey.TryParse(profile.SshVpn?.HostKey, out var key) ? key.Text : profile.SshVpn?.HostKey ?? "" } }, JsonDefaults.Compact)
            : System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new { profile.Id, profile.Server, profile.Protocol, profile.AuthMethod,
                profile.UserName, profile.Domain, profile.IpsecAuthentication, profile.Eap, AnyConnect = AnyConnectKeyPart(profile.AnyConnect) },
                JsonDefaults.Compact)));

    /// <summary>
    /// Настройки шлюза для ключа подключения без того, что не касается самого сеанса: флага приоритета ручных правил,
    /// колонки карточки «Сети шлюза» и применения прокси шлюза (его читает приложение из состояния службы). Их смена
    /// не должна переподключать AnyConnect (а значит, требовать нового входа). Колонка и прокси не удаляются, а
    /// приводятся к значениям по умолчанию: у профилей с ними ключ совпадает с ключом прежних версий, и отпечаток в
    /// state после обновления остаётся верным.
    /// </summary>
    private static System.Text.Json.Nodes.JsonObject AnyConnectKeyPart(AnyConnectSettings settings)
    {
        var node = System.Text.Json.JsonSerializer.SerializeToNode(settings, JsonDefaults.Compact)!.AsObject();
        node.Remove(JsonName(nameof(AnyConnectSettings.UserRulesOverrideServerNetworks)));
        node[JsonName(nameof(AnyConnectSettings.ServerNetworksTarget))] = null;
        node[JsonName(nameof(AnyConnectSettings.ApplyServerProxy))] = false;
        return node;
    }

    private static string JsonName(string name) => JsonDefaults.Compact.PropertyNamingPolicy?.ConvertName(name) ?? name;
    public static bool IsEap(AuthMethod method) => method is AuthMethod.EapMsChapV2 or AuthMethod.PeapMsChapV2
        or AuthMethod.EapTls or AuthMethod.TtlsMsChapV2 or AuthMethod.TtlsPap;

    /// <summary>
    /// Протокол RAS: запись телефонной книги и дозвон Windows. Список явный: новый тип не должен молча пойти
    /// по пути RAS. У остальных туннель поднимает отдельный процесс.
    /// </summary>
    public static bool UsesRas(VpnProtocol protocol) => protocol is VpnProtocol.Sstp or VpnProtocol.L2tpIpsec
        or VpnProtocol.Ikev2 or VpnProtocol.Pptp;

    /// <summary>Пароль заранее в профиле. У AnyConnect пароль спрашивает шлюз формой, у SSH вход по ключу.</summary>
    public static bool NeedsPassword(AuthMethod method) => method is not (AuthMethod.EapTls or AuthMethod.MachineCertificate
        or AuthMethod.GatewayForm or AuthMethod.SshKey);

    /// <summary>Подключению нужен закрытый ключ SSH в хранилище службы.</summary>
    public static bool NeedsSshKey(ConnectionProfile profile) => profile.Protocol == VpnProtocol.SshVpn;

    public const ushort SshDefaultPort = 22;

    /// <summary>Порт сервера, когда в адресе он не указан.</summary>
    public static ushort DefaultPort(VpnProtocol protocol) => protocol == VpnProtocol.SshVpn ? SshDefaultPort : ServerAddress.DefaultPort;

    public static bool NeedsServerValidation(AuthMethod method) => method is AuthMethod.PeapMsChapV2
        or AuthMethod.EapTls or AuthMethod.TtlsMsChapV2 or AuthMethod.TtlsPap;

    public static bool NeedsPreSharedKey(ConnectionProfile profile) => profile.Protocol == VpnProtocol.L2tpIpsec
        && profile.IpsecAuthentication == IpsecAuthentication.PreSharedKey;

    public static bool Supports(VpnProtocol protocol, AuthMethod method) => Enum.IsDefined(protocol) && Enum.IsDefined(method)
        && (protocol switch
        {
            VpnProtocol.AnyConnect => method == AuthMethod.GatewayForm,
            VpnProtocol.SshVpn => method == AuthMethod.SshKey,
            _ when method is AuthMethod.GatewayForm or AuthMethod.SshKey => false,
            VpnProtocol.Ikev2 => IsEap(method) || method == AuthMethod.MachineCertificate,
            VpnProtocol.Pptp => method == AuthMethod.MsChapV2 || IsEap(method),
            _ => method != AuthMethod.MachineCertificate,
        });

    public static string NormalizeThumbprint(string value) => value.Replace(" ", "", StringComparison.Ordinal).ToUpperInvariant();

    public static bool IsThumbprint(string value) => NormalizeThumbprint(value) is { Length: 40 } clean && clean.All(Uri.IsHexDigit);

    public static IReadOnlyList<string> ValidateAuthentication(ConnectionProfile profile) => ValidateAuthentication(profile, true, true);

    /// <summary>Поле «Домен» RAS: короткое имя NetBIOS, не полное DNS-имя.</summary>
    public const int MaxDomainLength = 15;

    public const string DomainTooLong = "Домен — короткое имя (NetBIOS), до 15 знаков, например CORP, а не corp.example.com.";

    /// <summary>
    /// Почему способ входа не подходит протоколу — понятной фразой; null — подходит. IKEv2 с MS-CHAPv2 — частая
    /// ошибка: тот же пароль IKEv2 принимает только внутри EAP.
    /// </summary>
    public static string? UnsupportedAuthText(VpnProtocol protocol, AuthMethod method) =>
        Supports(protocol, method) ? null
        : protocol == VpnProtocol.Ikev2 && method == AuthMethod.MsChapV2
            ? "Способ входа: IKEv2 не принимает MS-CHAPv2 без EAP. Выберите «EAP-MSCHAPv2» — это тот же логин и пароль."
            : "Способ входа: прежний способ несовместим с выбранным протоколом. Выберите новый в блоке «Параметры входа и безопасности».";

    /// <param name="profile">Подключение.</param>
    /// <param name="protocolKnown">
    /// false - протокол подставлен вместо неизвестного этой версии: разделы AnyConnect и SSH и проверки способа входа
    /// не выполняются, остаются общие ограничения имени пользователя и домена.
    /// </param>
    /// <param name="authKnown">false - способ входа подставлен: раздел EAP не проверяется.</param>
    /// <param name="requireClientCertificate">
    /// false - отпечаток клиентского сертификата EAP-TLS может быть пуст: так выглядит выключенный импортированный
    /// профиль, сертификат для которого пользователь выберет сам. Включить такой профиль проверка не даст.
    /// </param>
    public static IReadOnlyList<string> ValidateAuthentication(ConnectionProfile profile, bool protocolKnown, bool authKnown, bool requireClientCertificate = true)
    {
        ArgumentNullException.ThrowIfNull(profile);
        authKnown &= protocolKnown;

        // Профиль приходит из файла настроек и по каналу управления: «null» вместо строки или раздела
        // не должен ронять проверку — сначала нормализация, потом разбор.
        profile = SettingsSerializer.NormalizeProfile(profile);
        var errors = new List<string>();
        // Каждое поле — своим текстом: «Имя пользователя…» переводит курсор в поле имени, «Домен…» — в блок безопасности.
        if (profile.UserName.Length > 256 || profile.UserName.Contains('\0'))
        {
            errors.Add("Имя пользователя: не длиннее 256 знаков; нулевой символ недопустим.");
        }

        if ((profile.Domain?.Length ?? 0) > MaxDomainLength || profile.Domain?.Contains('\0') == true)
        {
            errors.Add(DomainTooLong);
        }

        if (authKnown && NeedsServerValidation(profile.AuthMethod))
        {
            var names = profile.Eap.ServerNames.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            if (names.Length == 0 || names.Any(n => Uri.CheckHostName(n) != UriHostNameType.Dns))
            {
                errors.Add("Укажите DNS-имена сервера EAP через точку с запятой (имена из сертификата).");
            }

            if (profile.Eap.TrustedRootThumbprints.Count == 0 || profile.Eap.TrustedRootThumbprints.Any(t => !IsThumbprint(t)))
            {
                errors.Add("Выберите доверенные корневые CA для EAP: требуются SHA-1 отпечатки из 40 шестнадцатеричных знаков.");
            }
        }

        if (authKnown && profile.AuthMethod == AuthMethod.EapTls && !IsThumbprint(profile.Eap.ClientCertificateThumbprint)
            && (requireClientCertificate || profile.Eap.ClientCertificateThumbprint.Length > 0))
        {
            errors.Add("Укажите SHA-1 отпечаток клиентского сертификата EAP-TLS.");
        }

        if (protocolKnown && profile.Protocol == VpnProtocol.AnyConnect)
        {
            ValidateAnyConnect(profile.AnyConnect, errors);
        }

        if (protocolKnown && profile.Protocol == VpnProtocol.SshVpn)
        {
            ValidateSshVpn(profile, errors);
        }

        return errors;
    }

    private static void ValidateSshVpn(ConnectionProfile profile, List<string> errors)
    {
        // Имя пользователя уходит в настройки движка как есть: пробелы и управляющие символы - почти всегда опечатка.
        if (profile.UserName.Length == 0 || profile.UserName.Length > 64 || profile.UserName.Any(c => char.IsWhiteSpace(c) || char.IsControl(c)))
        {
            errors.Add("Укажите имя пользователя SSH: до 64 знаков без пробелов.");
        }

        if (profile.SshVpn.HostKey.Length == 0)
        {
            errors.Add("Укажите ключ сервера SSH (строка вида «ssh-ed25519 AAAA…»): без него подключение не поднимается.");
        }
        else if (!SshTunnel.SshHostKey.TryParse(profile.SshVpn.HostKey, out _))
        {
            errors.Add("Ключ сервера SSH не распознан: нужна строка «тип ключ», например «ssh-ed25519 AAAA…», как в файле known_hosts без имени сервера.");
        }
    }

    private static void ValidateAnyConnect(AnyConnectSettings settings, List<string> errors)
    {
        if (settings.ClientCertificateThumbprint.Length > 0 && !IsThumbprint(settings.ClientCertificateThumbprint))
        {
            errors.Add("Отпечаток клиентского сертификата AnyConnect: 40 шестнадцатеричных знаков SHA-1 или пусто.");
        }

        if (settings.Group.Length > 256 || settings.Group.Contains('\0'))
        {
            errors.Add("Группа подключения AnyConnect слишком длинная или содержит нулевой символ.");
        }

        if (string.IsNullOrWhiteSpace(settings.UserAgent) || settings.UserAgent.Length > 128 || settings.UserAgent.Any(char.IsControl))
        {
            errors.Add("Идентификатор клиента AnyConnect (User-Agent): до 128 печатных символов.");
        }
    }

    public static bool TryParseServer(string? text, VpnProtocol protocol, out ServerAddress address)
    {
        address = default;
        if (protocol == VpnProtocol.AnyConnect)
        {
            if (!AnyConnectGateway.TryParse(text, out var gateway))
            {
                return false;
            }

            address = new ServerAddress(gateway.Host, gateway.Port);
            return true;
        }

        if (protocol == VpnProtocol.SshVpn)
        {
            return ServerAddress.TryParse(text, SshDefaultPort, out address);
        }

        return Enum.IsDefined(protocol)
            && (protocol == VpnProtocol.Sstp || text?.Contains(':', StringComparison.Ordinal) != true)
            && ServerAddress.TryParse(text, out address)
            && address.ForPhonebook.Length <= 128;
    }

    public static string ServerHint(VpnProtocol protocol) => protocol switch
    {
        VpnProtocol.Sstp => "Адрес сервера: хост или хост:порт, например vpn.example.org:443.",
        VpnProtocol.AnyConnect => "Адрес шлюза: хост, хост:порт или хост/группа, например vpn.example.org или vpn.example.org/staff.",
        VpnProtocol.SshVpn => "Адрес сервера SSH: хост или хост:порт, например vpn.example.org:22. Без порта используется 22.",
        _ => "Адрес сервера: имя хоста или IPv4 без порта, например vpn.example.org.",
    };

}
