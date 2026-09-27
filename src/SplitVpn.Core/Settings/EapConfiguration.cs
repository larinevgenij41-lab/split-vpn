using System.Xml.Linq;

namespace SplitVpn.Core.Settings;

/// <summary>Типизированная конфигурация EAPHost. Здесь никогда нет пароля или закрытого ключа.</summary>
public static class EapConfiguration
{
    private const string Provisioning = "http://www.microsoft.com/provisioning/";
    private static readonly XNamespace Host = Provisioning + "EapHostConfig";
    private static readonly XNamespace Common = Provisioning + "EapCommon";
    private static readonly XNamespace Base = Provisioning + "BaseEapConnectionPropertiesV1";

    public static uint TypeId(AuthMethod method) => method switch
    {
        AuthMethod.EapMsChapV2 => 26,
        AuthMethod.PeapMsChapV2 => 25,
        AuthMethod.EapTls => 13,
        AuthMethod.TtlsMsChapV2 or AuthMethod.TtlsPap => 21,
        _ => throw new ArgumentException("Не является методом EAP.", nameof(method)),
    };

    public static string Build(ConnectionProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var type = TypeId(profile.AuthMethod);
        var config = profile.AuthMethod switch
        {
            AuthMethod.EapMsChapV2 => MsChap(),
            AuthMethod.PeapMsChapV2 => Peap(profile.Eap),
            AuthMethod.EapTls => Tls(profile.Eap),
            _ => Ttls(profile),
        };
        return new XElement(Host + "EapHostConfig",
            new XElement(Host + "EapMethod", new XElement(Common + "Type", type),
                new XElement(Common + "VendorId", 0), new XElement(Common + "VendorType", 0),
                new XElement(Common + "AuthorId", type == 21 ? 311 : 0)),
            new XElement(Host + "Config", config)).ToString(SaveOptions.DisableFormatting);
    }

    private static XElement MsChap()
    {
        XNamespace ns = Provisioning + "MsChapV2ConnectionPropertiesV1";
        return new XElement(Base + "Eap", new XElement(Base + "Type", 26),
            new XElement(ns + "EapType", new XElement(ns + "UseWinLogonCredentials", false)));
    }

    private static XElement Validation(XNamespace ns, EapSettings settings) => new(ns + "ServerValidation",
        new XElement(ns + "DisableUserPromptForServerValidation", true),
        new XElement(ns + "ServerNames", settings.ServerNames),
        settings.TrustedRootThumbprints.Select(t => new XElement(ns + "TrustedRootCA", VpnProtocols.NormalizeThumbprint(t))));

    private static XElement Peap(EapSettings settings)
    {
        XNamespace ns = Provisioning + "MsPeapConnectionPropertiesV1";
        XNamespace v2 = Provisioning + "MsPeapConnectionPropertiesV2";
        return new XElement(Base + "Eap", new XElement(Base + "Type", 25), new XElement(ns + "EapType",
            Validation(ns, settings), new XElement(ns + "FastReconnect", true), new XElement(ns + "InnerEapOptional", false),
            MsChap(), new XElement(ns + "EnableQuarantineChecks", false), new XElement(ns + "RequireCryptoBinding", false),
            new XElement(ns + "PeapExtensions", new XElement(v2 + "PerformServerValidation", true), new XElement(v2 + "AcceptServerName", true))));
    }

    private static XElement Tls(EapSettings settings)
    {
        XNamespace ns = Provisioning + "EapTlsConnectionPropertiesV1";
        XNamespace v2 = Provisioning + "EapTlsConnectionPropertiesV2";
        return new XElement(Base + "Eap", new XElement(Base + "Type", 13), new XElement(ns + "EapType",
            new XElement(ns + "CredentialsSource", new XElement(ns + "CertificateStore", new XElement(ns + "SimpleCertSelection", true))),
            Validation(ns, settings), new XElement(ns + "DifferentUsername", false),
            new XElement(v2 + "PerformServerValidation", true), new XElement(v2 + "AcceptServerName", true)));
    }

    private static XElement Ttls(ConnectionProfile profile)
    {
        XNamespace ns = Provisioning + "EapTtlsConnectionPropertiesV1";
        return new XElement(ns + "EapTtls",
            new XElement(ns + "ServerValidation", new XElement(ns + "ServerNames", profile.Eap.ServerNames),
                profile.Eap.TrustedRootThumbprints.Select(t => new XElement(ns + "TrustedRootCAHash", string.Join(" ", VpnProtocols.NormalizeThumbprint(t).Chunk(2).Select(c => new string(c))))),
                new XElement(ns + "DisablePrompt", true)),
            new XElement(ns + "Phase2Authentication", new XElement(ns + (profile.AuthMethod == AuthMethod.TtlsPap ? "PAPAuthentication" : "MSCHAPv2Authentication"),
                profile.AuthMethod == AuthMethod.TtlsPap ? null : new XElement(ns + "UseWinlogonCredentials", false))),
            new XElement(ns + "Phase1Identity", new XElement(ns + "IdentityPrivacy", true), new XElement(ns + "AnonymousIdentity", "anonymous")));
    }
}
