using System.Globalization;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Schema;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Settings;

/// <summary>
/// XML EAPHost для RAS. Контракт: корректный XML с тем методом, что выбран в профиле; отпечатки корневых CA
/// приведены к виду без пробелов в верхнем регистре; имена серверов экранированы, а не обрезаны; пароля и ключа нет.
/// </summary>
public sealed class EapConfigurationTests
{
    private const string Provisioning = "http://www.microsoft.com/provisioning/";
    private const string RootA = "0123456789ABCDEF0123456789ABCDEF01234567";
    private const string RootB = "FEDCBA9876543210FEDCBA9876543210FEDCBA98";

    private static ConnectionProfile Profile(AuthMethod method, string serverNames = "nps.example.org", params string[] roots) => new()
    {
        Name = "EAP",
        Server = "vpn.example.org",
        Protocol = VpnProtocol.Ikev2,
        AuthMethod = method,
        UserName = "user",
        Eap = new EapSettings
        {
            ServerNames = serverNames,
            TrustedRootThumbprints = roots.Length == 0 ? [RootA] : roots,
            ClientCertificateThumbprint = RootB,
        },
    };

    private static XDocument Parse(ConnectionProfile profile) => XDocument.Parse(EapConfiguration.Build(profile));

    private static IEnumerable<XElement> Named(XDocument document, string localName) =>
        document.Descendants().Where(e => e.Name.LocalName == localName);

    [Theory]
    [InlineData(AuthMethod.EapMsChapV2, 26u)]
    [InlineData(AuthMethod.PeapMsChapV2, 25u)]
    [InlineData(AuthMethod.EapTls, 13u)]
    [InlineData(AuthMethod.TtlsMsChapV2, 21u)]
    [InlineData(AuthMethod.TtlsPap, 21u)]
    public void TypeId_MatchesIanaEapType_AndHeaderOfBuiltXml(AuthMethod method, uint expected)
    {
        Assert.Equal(expected, EapConfiguration.TypeId(method));

        var method0 = Assert.Single(Named(Parse(Profile(method)), "EapMethod"));
        var common = (XNamespace)(Provisioning + "EapCommon");
        Assert.Equal(expected.ToString(CultureInfo.InvariantCulture), method0.Element(common + "Type")!.Value);
        // AuthorId 311 (Microsoft) нужен только TTLS: встроенный метод TTLS зарегистрирован под автором Microsoft.
        Assert.Equal(expected == 21 ? "311" : "0", method0.Element(common + "AuthorId")!.Value);
        Assert.Equal("0", method0.Element(common + "VendorId")!.Value);
        Assert.Equal("0", method0.Element(common + "VendorType")!.Value);
    }

    public static TheoryData<AuthMethod> NonEapMethods() =>
        [.. Enum.GetValues<AuthMethod>().Where(m => !VpnProtocols.IsEap(m))];

    [Theory]
    [MemberData(nameof(NonEapMethods))]
    public void TypeId_AndBuild_RejectNonEapMethods(AuthMethod method)
    {
        Assert.Throws<ArgumentException>(() => EapConfiguration.TypeId(method));
        Assert.Throws<ArgumentException>(() => EapConfiguration.Build(Profile(method)));
    }

    [Theory]
    [InlineData((AuthMethod)999)]
    [InlineData((AuthMethod)(-1))]
    public void TypeId_RejectsUndefinedEnumValues(AuthMethod method) =>
        Assert.Throws<ArgumentException>(() => EapConfiguration.TypeId(method));

    [Fact]
    public void Build_RejectsNullProfile() => Assert.Throws<ArgumentNullException>(() => EapConfiguration.Build(null!));

    /// <summary>Отпечаток в любом регистре и с пробелами (как его копирует оснастка сертификатов) пишется одной формой.</summary>
    [Theory]
    [InlineData(AuthMethod.PeapMsChapV2, "TrustedRootCA")]
    [InlineData(AuthMethod.EapTls, "TrustedRootCA")]
    public void PeapAndTls_WriteRootsAsContiguousUppercaseHex_InGivenOrder(AuthMethod method, string element)
    {
        var spaced = "fe dc ba 98 76 54 32 10 fe dc ba 98 76 54 32 10 fe dc ba 98";

        var roots = Named(Parse(Profile(method, "nps.example.org", RootA.ToLowerInvariant(), spaced)), element).Select(e => e.Value).ToList();

        Assert.Equal([RootA, RootB], roots);
    }

    /// <summary>
    /// TTLS пишет отпечаток парами через пробел, PEAP и EAP-TLS - слитно. Все три элемента в схемах Windows
    /// (C:\Windows\schemas\EAPMethods) имеют тип xs:hexBinary, по которому слитная запись - каноническая; пробелы
    /// между парами Microsoft при этом сама пишет в примерах (IssuerHash того же типа). Тест фиксирует текущую форму:
    /// какую из двух EAPHost TTLS принимает на деле, без стенда не проверено.
    /// </summary>
    [Fact]
    public void Ttls_WritesRootHashAsSpacedPairs_CurrentBehavior()
    {
        var hashes = Named(Parse(Profile(AuthMethod.TtlsMsChapV2, "nps.example.org", RootA)), "TrustedRootCAHash").Select(e => e.Value).ToList();

        Assert.Equal(["01 23 45 67 89 AB CD EF 01 23 45 67 89 AB CD EF 01 23 45 67"], hashes);
    }

    [Theory]
    [InlineData(AuthMethod.PeapMsChapV2)]
    [InlineData(AuthMethod.EapTls)]
    [InlineData(AuthMethod.TtlsMsChapV2)]
    [InlineData(AuthMethod.TtlsPap)]
    public void ServerNames_WithXmlSpecialCharacters_AreEscapedAndRoundTrip(AuthMethod method)
    {
        const string names = "a&b.example.org;<c>.example.org;\"q'\".example.org;сервер.пример.рф";

        var xml = EapConfiguration.Build(Profile(method, names));

        Assert.Contains("a&amp;b", xml, StringComparison.Ordinal);
        Assert.DoesNotContain("<c>", xml, StringComparison.Ordinal);
        Assert.Equal(names, Assert.Single(Named(XDocument.Parse(xml), "ServerNames")).Value);
    }

    [Fact]
    public void LongServerNameList_IsNotTruncated()
    {
        var names = string.Join(';', Enumerable.Range(0, 200).Select(i => $"nps{i}.example.org"));

        Assert.Equal(names, Assert.Single(Named(Parse(Profile(AuthMethod.PeapMsChapV2, names)), "ServerNames")).Value);
    }

    [Theory]
    [InlineData(AuthMethod.PeapMsChapV2, "TrustedRootCA")]
    [InlineData(AuthMethod.EapTls, "TrustedRootCA")]
    [InlineData(AuthMethod.TtlsPap, "TrustedRootCAHash")]
    public void NoRoots_WritesNoRootElements_ButKeepsServerValidation(AuthMethod method, string element)
    {
        var profile = Profile(method) with { Eap = new EapSettings { ServerNames = "nps.example.org" } };

        var document = Parse(profile);

        Assert.Empty(Named(document, element));
        Assert.Single(Named(document, "ServerValidation"));
    }

    [Theory]
    [InlineData(AuthMethod.PeapMsChapV2, "DisableUserPromptForServerValidation")]
    [InlineData(AuthMethod.EapTls, "DisableUserPromptForServerValidation")]
    [InlineData(AuthMethod.TtlsMsChapV2, "DisablePrompt")]
    public void ServerValidation_NeverFallsBackToUserPrompt(AuthMethod method, string element) =>
        Assert.Equal("true", Assert.Single(Named(Parse(Profile(method)), element)).Value);

    [Fact]
    public void EapMsChapV2_HasNoServerValidation_AndDoesNotUseWindowsLogon()
    {
        var document = Parse(Profile(AuthMethod.EapMsChapV2));

        Assert.Empty(Named(document, "ServerValidation"));
        Assert.Equal("false", Assert.Single(Named(document, "UseWinLogonCredentials")).Value);
    }

    [Fact]
    public void Peap_InnerMethodIsMsChapV2()
    {
        var document = Parse(Profile(AuthMethod.PeapMsChapV2));
        var baseNs = (XNamespace)(Provisioning + "BaseEapConnectionPropertiesV1");

        var types = document.Descendants(baseNs + "Type").Select(t => t.Value).ToList();

        Assert.Equal(["25", "26"], types);
    }

    [Theory]
    [InlineData(AuthMethod.TtlsPap, "PAPAuthentication", false)]
    [InlineData(AuthMethod.TtlsMsChapV2, "MSCHAPv2Authentication", true)]
    public void Ttls_Phase2MatchesMethod_AndHidesIdentity(AuthMethod method, string phase2, bool hasWinlogon)
    {
        var document = Parse(Profile(method));

        var inner = Assert.Single(Assert.Single(Named(document, "Phase2Authentication")).Elements());
        Assert.Equal(phase2, inner.Name.LocalName);
        Assert.Equal(hasWinlogon, inner.Elements().Any(e => e.Name.LocalName == "UseWinlogonCredentials"));
        // Схема PAPAuthentication - пустая строка (maxLength 0).
        Assert.True(hasWinlogon || inner.IsEmpty);
        Assert.Equal("true", Assert.Single(Named(document, "IdentityPrivacy")).Value);
        Assert.Equal("anonymous", Assert.Single(Named(document, "AnonymousIdentity")).Value);
    }

    [Theory]
    [InlineData(AuthMethod.EapTls)]
    [InlineData(AuthMethod.PeapMsChapV2)]
    public void ClientCertificateThumbprint_IsNotWrittenToMethodConfig(AuthMethod method) =>
        Assert.DoesNotContain(RootB, EapConfiguration.Build(Profile(method, "nps.example.org", RootA)), StringComparison.OrdinalIgnoreCase);

    [Theory]
    [InlineData("ru-RU")]
    [InlineData("tr-TR")]
    [InlineData("ar-SA")]
    public void Output_DoesNotDependOnCurrentCulture(string culture)
    {
        var profile = Profile(AuthMethod.TtlsMsChapV2, "nps.example.org", "ab cd ef 01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef 01");
        var invariant = TestCulture.Run(CultureInfo.InvariantCulture, () => EapConfiguration.Build(profile));

        var local = TestCulture.Run(CultureInfo.GetCultureInfo(culture), () => EapConfiguration.Build(profile));

        Assert.Equal(invariant, local);
        Assert.Contains("AB CD EF 01", local, StringComparison.Ordinal);
    }

    /// <summary>
    /// Соответствие XSD, которые Windows кладёт в C:\Windows\schemas. Схем нет (не Windows, урезанный образ) - пропуск.
    /// Методы PEAP и EAP-TLS здесь, TTLS - в <see cref="Ttls_ValidatesAgainstWindowsSchema"/>.
    /// </summary>
    [Theory]
    [InlineData(AuthMethod.EapMsChapV2)]
    [InlineData(AuthMethod.PeapMsChapV2)]
    [InlineData(AuthMethod.EapTls)]
    public void PeapTlsMsChap_ValidateAgainstWindowsSchemas(AuthMethod method)
    {
        var errors = WindowsSchemas.Validate(EapConfiguration.Build(Profile(method, "nps.example.org", RootA, RootB)));

        Assert.Empty(errors);
    }

    /// <summary>
    /// TTLS: в EapTtlsConnectionPropertiesv1.xsd корневой элемент объявлен как «eapTtls» (со строчной), а программа,
    /// как и экспорт самой Windows, пишет «EapTtls»; под нестрогим (lax) Config такой элемент схемой не проверяется
    /// вовсе. Поэтому для проверки корень переименовывается. TrustedRootCAHash - xs:hexBinary; проверка .NET принимает
    /// и пары через пробел, и слитную запись, так что схема спор о формате не решает.
    /// </summary>
    [Theory]
    [InlineData(AuthMethod.TtlsMsChapV2)]
    [InlineData(AuthMethod.TtlsPap)]
    public void Ttls_ValidatesAgainstWindowsSchema(AuthMethod method)
    {
        var document = ForTtlsSchema(Parse(Profile(method, "nps.example.org", RootA, RootB)));
        Assert.Empty(WindowsSchemas.Validate(document.ToString(SaveOptions.DisableFormatting)));

        // Слитная запись того же отпечатка схеме тоже соответствует.
        foreach (var hash in Named(document, "TrustedRootCAHash"))
        {
            hash.Value = hash.Value.Replace(" ", "", StringComparison.Ordinal);
        }

        Assert.Empty(WindowsSchemas.Validate(document.ToString(SaveOptions.DisableFormatting)));
    }

    /// <summary>Проверка по схемам действительно строгая: испорченный отпечаток и чужой элемент она находит.</summary>
    [Theory]
    [InlineData(AuthMethod.PeapMsChapV2, "TrustedRootCA")]
    [InlineData(AuthMethod.EapTls, "TrustedRootCA")]
    [InlineData(AuthMethod.TtlsMsChapV2, "TrustedRootCAHash")]
    public void WindowsSchemaCheck_DetectsBrokenDocument(AuthMethod method, string element)
    {
        var document = ForTtlsSchema(Parse(Profile(method, "nps.example.org", RootA)));
        Named(document, element).Single().Value = "ZZ";

        Assert.NotEmpty(WindowsSchemas.Validate(document.ToString(SaveOptions.DisableFormatting)));
    }

    /// <summary>Как пишет программа, TTLS схемой не проверяется: корня «EapTtls» в ней нет.</summary>
    [Fact]
    public void Ttls_AsWritten_IsNotCoveredBySchema()
    {
        var document = Parse(Profile(AuthMethod.TtlsMsChapV2, "nps.example.org", RootA));
        Named(document, "TrustedRootCAHash").Single().Value = "ZZ";

        Assert.Empty(WindowsSchemas.Validate(document.ToString(SaveOptions.DisableFormatting)));
    }

    private static XDocument ForTtlsSchema(XDocument document)
    {
        foreach (var root in Named(document, "EapTtls").ToList())
        {
            root.Name = root.Name.Namespace + "eapTtls";
        }

        return document;
    }

    private static class WindowsSchemas
    {
        private static readonly Lazy<XmlSchemaSet?> s_set = new(Load);

        public static List<string> Validate(string xml)
        {
            var set = s_set.Value;
            if (set is null)
            {
                Assert.Skip("Схемы EAP Windows не найдены.");
            }

            var errors = new List<string>();
            var document = XDocument.Parse(xml);
            document.Validate(set, (sender, e) => errors.Add(e.Message + " " + (sender as XElement)?.Name.LocalName));
            return errors;
        }

        private static XmlSchemaSet? Load()
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var host = Path.Combine(windows, "schemas", "EAPHost");
            var methods = Path.Combine(windows, "schemas", "EAPMethods");
            string[] files =
            [
                Path.Combine(host, "eapcommon.xsd"),
                Path.Combine(host, "baseeapconnectionpropertiesv1.xsd"),
                Path.Combine(host, "eaphostconfig.xsd"),
                Path.Combine(methods, "mschapv2connectionpropertiesv1.xsd"),
                Path.Combine(methods, "mspeapconnectionpropertiesv1.xsd"),
                Path.Combine(methods, "mspeapconnectionpropertiesv2.xsd"),
                Path.Combine(methods, "mspeapconnectionpropertiesv3.xsd"),
                Path.Combine(methods, "eaptlsconnectionpropertiesv1.xsd"),
                Path.Combine(methods, "eaptlsconnectionpropertiesv2.xsd"),
                Path.Combine(methods, "eaptlsconnectionpropertiesv3.xsd"),
                Path.Combine(methods, "EapTtlsConnectionPropertiesv1.xsd"),
            ];
            if (!files.All(File.Exists))
            {
                return null;
            }

            var set = new XmlSchemaSet { XmlResolver = new XmlUrlResolver() };
            foreach (var file in files)
            {
                using var reader = XmlReader.Create(file, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit });
                var schema = XmlSchema.Read(reader, null)!;
                if (!set.Contains(schema.TargetNamespace))
                {
                    set.Add(schema);
                }
            }

            set.Compile();
            return set;
        }
    }
}
