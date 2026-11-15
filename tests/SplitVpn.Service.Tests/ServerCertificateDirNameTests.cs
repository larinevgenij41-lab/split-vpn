using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SplitVpn.Windows.Security;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Круг 3 код-ревью, S10: имя DirName в точке распространения CRL (или в cRLIssuer) содержит SET. Разбор читал его
/// как SEQUENCE и падал с ArgumentException, которую никто не ловил: проба возвращала пустоту, и за kill switch
/// подключиться было нельзя - адреса отзыва не открывались.
/// </summary>
public sealed class ServerCertificateDirNameTests
{
    private const string CrlUrl = "http://crl.splitvpn-test.invalid/dirname.crl";

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CrlDistributionPoint_WithDirName_StillYieldsHttpUrl(bool unsortedSet)
    {
        using var leaf = CreateLeaf(CrlDistributionPoints(unsortedSet));

        var facts = ServerCertificateProbe.Facts([leaf.RawData], nameMatches: true);

        Assert.Contains(CrlUrl, facts.RevocationUrls);
        Assert.Contains("crl.splitvpn-test.invalid", facts.RevocationHosts);
    }

    /// <summary>CRLDistributionPoints: точка с fullName из DirName и URI, затем cRLIssuer с DirName.</summary>
    private static byte[] CrlDistributionPoints(bool unsortedSet)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                {
                    WriteDirName(writer, unsortedSet);
                    writer.WriteCharacterString(UniversalTagNumber.IA5String, CrlUrl, new Asn1Tag(TagClass.ContextSpecific, 6));
                }

                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2, isConstructed: true)))
                {
                    WriteDirName(writer, unsortedSet);
                }
            }
        }

        return writer.Encode();
    }

    /// <summary>
    /// directoryName [4] с RDN из двух атрибутов. Несортированный SET - нарушение DER, которое встречается в
    /// настоящих сертификатах: разбор не должен на нём останавливаться.
    /// </summary>
    private static void WriteDirName(AsnWriter writer, bool unsortedSet)
    {
        var organization = Attribute("2.5.4.10", "SplitVpn Test");
        var commonName = Attribute("2.5.4.3", "CA");
        var set = new AsnWriter(AsnEncodingRules.DER);
        using (set.PushSetOf())
        {
            set.WriteEncodedValue(organization);
            set.WriteEncodedValue(commonName);
        }

        // Писатель DER сортирует SET OF при закрытии (CN раньше O): обратный порядок собирается вручную.
        byte[] rdn = unsortedSet
            ? [0x31, (byte)(organization.Length + commonName.Length), .. organization, .. commonName]
            : set.Encode();

        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4, isConstructed: true)))
        using (writer.PushSequence())
        {
            writer.WriteEncodedValue(rdn);
        }
    }

    private static byte[] Attribute(string oid, string value)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(oid);
            writer.WriteCharacterString(UniversalTagNumber.UTF8String, value);
        }

        return writer.Encode();
    }

    private static X509Certificate2 CreateLeaf(byte[] crlDistributionPoints)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=vpn.splitvpn-test.invalid", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509Extension("2.5.29.31", crlDistributionPoints, critical: false));
        var now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddDays(-1), now.AddDays(30));
    }
}
