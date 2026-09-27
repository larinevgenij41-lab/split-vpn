using System.Runtime.InteropServices;
using System.Xml.Linq;
using SplitVpn.Core.Settings;
using SplitVpn.Windows.Native;

namespace SplitVpn.Windows.Ras;

/// <summary>Преобразование штатных XML-схем EAPHost; никакого собственного формата BLOB.</summary>
public static unsafe partial class EapNative
{
    [StructLayout(LayoutKind.Sequential)]
    private struct MethodType
    {
        public byte Type;
        public uint Vendor;
        public uint VendorType;
        public uint Author;
    }

    public static byte[] Configuration(ConnectionProfile profile) => ConvertXml(EapConfiguration.Build(profile), null);

    public static byte[] Identity(ConnectionProfile profile, byte[] config, ReadOnlySpan<char> password)
    {
        const string prefix = "http://www.microsoft.com/provisioning/";
        XNamespace host = prefix + "EapHostUserCredentials";
        XNamespace common = prefix + "EapCommon";
        XNamespace baseNs = prefix + "BaseEapUserPropertiesV1";
        XNamespace tls = prefix + "EapTlsUserPropertiesV1";
        XNamespace chap = prefix + "MsChapV2UserPropertiesV1";
        XNamespace peap = prefix + "MsPeapUserPropertiesV1";
        XNamespace ttls = prefix + "EapTtlsUserPropertiesV1";
        var type = EapConfiguration.TypeId(profile.AuthMethod);
        var user = profile.UserName;
        var inner = new XElement(baseNs + "Eap", new XElement(baseNs + "Type", 26), new XElement(chap + "EapType",
            new XElement(chap + "Username", user), new XElement(chap + "Password", password.ToString()), new XElement(chap + "LogonDomain", profile.Domain ?? "")));
        var credentials = profile.AuthMethod switch
        {
            AuthMethod.EapTls => new XElement(baseNs + "Eap", new XElement(baseNs + "Type", 13),
                new XElement(tls + "EapType", new XElement(tls + "Username", user),
                    new XElement(tls + "UserCert", VpnProtocols.NormalizeThumbprint(profile.Eap.ClientCertificateThumbprint)))),
            AuthMethod.PeapMsChapV2 => new XElement(baseNs + "Eap", new XElement(baseNs + "Type", 25),
                new XElement(peap + "EapType", new XElement(peap + "RoutingIdentity", user), inner)),
            AuthMethod.TtlsMsChapV2 or AuthMethod.TtlsPap => new XElement(ttls + "EapTtls",
                new XElement(ttls + "Username", string.IsNullOrEmpty(profile.Domain) ? user : profile.Domain + "\\" + user),
                new XElement(ttls + "Password", password.ToString())),
            _ => inner,
        };
        var xml = new XElement(host + "EapHostUserCredentials",
            new XElement(host + "EapMethod", new XElement(common + "Type", type), new XElement(common + "VendorId", 0),
                new XElement(common + "VendorType", 0), new XElement(common + "AuthorId", type == 21 ? 311 : 0)),
            new XElement(host + "Credentials", credentials));
        return ConvertXml(xml.ToString(SaveOptions.DisableFormatting), config);
    }

    private static byte[] ConvertXml(string xml, byte[]? config)
    {
        var document = Activator.CreateInstance(Type.GetTypeFromProgID("Msxml2.DOMDocument.6.0", throwOnError: true)!)!;
        nint unknown = 0, node = 0, output = 0, error = 0;
        uint size = 0;
        try
        {
            dynamic dom = document;
            dom.async = false;
            dom.resolveExternals = false;
            dom.validateOnParse = false;
            if (!(bool)dom.loadXML(xml))
            {
                throw new InvalidOperationException("Не удалось разобрать конфигурацию EAP.");
            }

            unknown = Marshal.GetIUnknownForObject(document);
            var nodeId = new Guid("2933BF80-7B36-11d2-B20E-00C04F983E60");
            Marshal.ThrowExceptionForHR(Marshal.QueryInterface(unknown, in nodeId, out node));
            uint code;
            fixed (byte* input = config)
            {
                code = config is null
                    ? EapHostPeerConfigXml2Blob(0, node, out size, out output, out _, out error)
                    : EapHostPeerCredentialsXml2Blob(0, node, (uint)config.Length, input, out size, out output, out _, out error);
            }

            
            NativeCallException.ThrowIfFailed(code, "EAPHost XML");
            return new ReadOnlySpan<byte>((void*)output, checked((int)size)).ToArray();
        }
        finally
        {
            if (output != 0) { new Span<byte>((void*)output, checked((int)size)).Clear(); EapHostPeerFreeMemory(output); }
            if (error != 0) { EapHostPeerFreeErrorMemory(error); }
            if (node != 0) { Marshal.Release(node); }
            if (unknown != 0) { Marshal.Release(unknown); }
            Marshal.FinalReleaseComObject(document);
        }
    }

    [LibraryImport("eappcfg.dll")]
    private static partial uint EapHostPeerConfigXml2Blob(uint flags, nint document, out uint size, out nint data, out MethodType method, out nint error);

    [LibraryImport("eappcfg.dll")]
    private static partial uint EapHostPeerCredentialsXml2Blob(uint flags, nint document, uint configSize, byte* config, out uint size, out nint data, out MethodType method, out nint error);

    [LibraryImport("eappcfg.dll")]
    private static partial void EapHostPeerFreeMemory(nint data);

    [LibraryImport("eappcfg.dll")]
    private static partial void EapHostPeerFreeErrorMemory(nint error);
}
