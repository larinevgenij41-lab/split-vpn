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
}

public static class VpnProtocols
{
    public static string Name(VpnProtocol protocol) => protocol switch
    {
        VpnProtocol.Sstp => "SSTP", VpnProtocol.L2tpIpsec => "L2TP/IPsec", VpnProtocol.Ikev2 => "IKEv2", VpnProtocol.Pptp => "PPTP",
        VpnProtocol.AnyConnect => "Cisco AnyConnect", _ => "—",
    };

    public static string AuthName(AuthMethod method) => method switch
    {
        AuthMethod.MsChapV2 => "MS-CHAPv2", AuthMethod.EapMsChapV2 => "EAP-MSCHAPv2", AuthMethod.PeapMsChapV2 => "PEAP / EAP-MSCHAPv2",
        AuthMethod.EapTls => "EAP-TLS", AuthMethod.TtlsMsChapV2 => "EAP-TTLS / MSCHAPv2", AuthMethod.TtlsPap => "EAP-TTLS / PAP",
        AuthMethod.Pap => "PAP", AuthMethod.Chap => "CHAP", AuthMethod.MachineCertificate => "сертификат компьютера",
        AuthMethod.GatewayForm => "SSO / форма шлюза", _ => "—",
    };
    public static string ConnectionKey(ConnectionProfile profile) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
        System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new { profile.Id, profile.Server, profile.Protocol, profile.AuthMethod,
            profile.UserName, profile.Domain, profile.IpsecAuthentication, profile.Eap, profile.AnyConnect }, JsonDefaults.Compact)));
    public static bool IsEap(AuthMethod method) => method is AuthMethod.EapMsChapV2 or AuthMethod.PeapMsChapV2
        or AuthMethod.EapTls or AuthMethod.TtlsMsChapV2 or AuthMethod.TtlsPap;

    /// <summary>Протокол без RAS: туннель поднимает процесс-помощник, телефонная книга не используется.</summary>
    public static bool UsesRas(VpnProtocol protocol) => protocol != VpnProtocol.AnyConnect;

    /// <summary>Пароль заранее в профиле. У AnyConnect пароль спрашивает шлюз формой, если он вообще нужен.</summary>
    public static bool NeedsPassword(AuthMethod method) => method is not (AuthMethod.EapTls or AuthMethod.MachineCertificate or AuthMethod.GatewayForm);

    public static bool NeedsServerValidation(AuthMethod method) => method is AuthMethod.PeapMsChapV2
        or AuthMethod.EapTls or AuthMethod.TtlsMsChapV2 or AuthMethod.TtlsPap;

    public static bool NeedsPreSharedKey(ConnectionProfile profile) => profile.Protocol == VpnProtocol.L2tpIpsec
        && profile.IpsecAuthentication == IpsecAuthentication.PreSharedKey;

    public static bool Supports(VpnProtocol protocol, AuthMethod method) => Enum.IsDefined(protocol) && Enum.IsDefined(method)
        && (protocol switch
        {
            VpnProtocol.AnyConnect => method == AuthMethod.GatewayForm,
            _ when method == AuthMethod.GatewayForm => false,
            VpnProtocol.Ikev2 => IsEap(method) || method == AuthMethod.MachineCertificate,
            VpnProtocol.Pptp => method == AuthMethod.MsChapV2 || IsEap(method),
            _ => method != AuthMethod.MachineCertificate,
        });

    public static string NormalizeThumbprint(string value) => value.Replace(" ", "", StringComparison.Ordinal).ToUpperInvariant();

    public static bool IsThumbprint(string value) => NormalizeThumbprint(value) is { Length: 40 } clean && clean.All(Uri.IsHexDigit);

    public static IReadOnlyList<string> ValidateAuthentication(ConnectionProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);

        // Профиль приходит из файла настроек и по каналу управления: «null» вместо строки или раздела
        // не должен ронять проверку — сначала нормализация, потом разбор.
        profile = SettingsSerializer.NormalizeProfile(profile);
        var errors = new List<string>();
        if (profile.UserName.Length > 256 || (profile.Domain?.Length ?? 0) > 15 || profile.UserName.Contains('\0') || profile.Domain?.Contains('\0') == true)
        {
            errors.Add("Имя пользователя/домен не помещаются в поля RAS или содержат нулевой символ.");
        }

        if (NeedsServerValidation(profile.AuthMethod))
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

        if (profile.AuthMethod == AuthMethod.EapTls && !IsThumbprint(profile.Eap.ClientCertificateThumbprint))
        {
            errors.Add("Укажите SHA-1 отпечаток клиентского сертификата EAP-TLS.");
        }

        if (profile.Protocol == VpnProtocol.AnyConnect)
        {
            ValidateAnyConnect(profile.AnyConnect, errors);
        }

        return errors;
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

        return Enum.IsDefined(protocol)
            && (protocol == VpnProtocol.Sstp || text?.Contains(':', StringComparison.Ordinal) != true)
            && ServerAddress.TryParse(text, out address)
            && address.ForPhonebook.Length <= 128;
    }

    public static string ServerHint(VpnProtocol protocol) => protocol switch
    {
        VpnProtocol.Sstp => "Адрес сервера: хост или хост:порт, например vpn.example.org:443.",
        VpnProtocol.AnyConnect => "Адрес шлюза: хост, хост:порт или хост/группа, например vpn.example.org или vpn.example.org/staff.",
        _ => "Адрес сервера: имя хоста или IPv4 без порта, например vpn.example.org.",
    };

}
