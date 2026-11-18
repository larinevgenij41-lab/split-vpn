using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SplitVpn.Windows.Security;

namespace SplitVpn.Service.Tests;

/// <summary>Разбор предъявленного сертификата: неполная цепочка и адреса издателя (AIA caIssuers) отдельно от CRL и OCSP.</summary>
public sealed class ServerCertificateProbeTests
{
    private const string IssuerUrl = "http://ca.splitvpn-test.invalid/intermediate.crt";
    private const string OcspUrl = "http://ocsp.splitvpn-test.invalid";
    private const string CrlUrl = "http://crl.splitvpn-test.invalid/intermediate.crl";

    [Fact]
    public void MissingIntermediate_IsRecognized_AndIssuerHostsExcludeCrlAndOcsp()
    {
        using var root = CreateCa("SplitVpn Test Root", null);
        using var intermediate = CreateCa("SplitVpn Test Intermediate", root);
        using var leaf = CreateLeaf(intermediate);

        var facts = ServerCertificateProbe.Facts([leaf.RawData], nameMatches: true);

        Assert.True(facts.MissingIntermediateOnly);
        Assert.NotNull(facts.ChainProblem);
        Assert.Equal(["ca.splitvpn-test.invalid"], facts.IssuerHosts);
        Assert.Contains("crl.splitvpn-test.invalid", facts.RevocationHosts);
        Assert.Contains("ocsp.splitvpn-test.invalid", facts.RevocationHosts);
    }

    [Fact]
    public void UntrustedRoot_IsNotMissingIntermediate()
    {
        using var root = CreateCa("SplitVpn Test Root", null);
        using var intermediate = CreateCa("SplitVpn Test Intermediate", root);
        using var leaf = CreateLeaf(intermediate);

        var facts = ServerCertificateProbe.Facts([leaf.RawData, intermediate.RawData, root.RawData], nameMatches: true);

        Assert.NotNull(facts.ChainProblem);
        Assert.False(facts.MissingIntermediateOnly);
    }

    /// <summary>Скачанный издатель принимается, только если с ним цепочка листа доходит до доверенного корня.</summary>
    [Fact]
    public void DownloadedIntermediate_AcceptedOnlyWhenItCompletesTheChain()
    {
        using var root = CreateCa("SplitVpn Test Root", null);
        using var intermediate = CreateCa("SplitVpn Test Intermediate", root);
        using var impostor = CreateCa("SplitVpn Test Intermediate", null);
        using var leaf = CreateLeaf(intermediate);
        var roots = new X509Certificate2Collection(root);

        using (var accepted = IntermediateCertificateInstaller.SelectIntermediate(leaf, intermediate.RawData, roots))
        {
            Assert.Equal(intermediate.Thumbprint, accepted?.Thumbprint);
        }

        // Набор PKCS#7 (.p7c), как отдают многие издатели: из него берётся нужный сертификат.
        var bundle = new X509Certificate2Collection(new[] { impostor, intermediate }).Export(X509ContentType.Pkcs7)!;
        using (var fromBundle = IntermediateCertificateInstaller.SelectIntermediate(leaf, bundle, roots))
        {
            Assert.Equal(intermediate.Thumbprint, fromBundle?.Thumbprint);
        }

        // Одноимённый сертификат с другим ключом, недоверенный корень и мусор не принимаются.
        Assert.Null(IntermediateCertificateInstaller.SelectIntermediate(leaf, impostor.RawData, roots));
        Assert.Null(IntermediateCertificateInstaller.SelectIntermediate(leaf, intermediate.RawData, new X509Certificate2Collection(impostor)));
        Assert.Null(IntermediateCertificateInstaller.SelectIntermediate(leaf, [1, 2, 3, 4], roots));
        Assert.Null(IntermediateCertificateInstaller.SelectIntermediate(leaf, leaf.RawData, roots));
    }

    private static X509Certificate2 CreateCa(string name, X509Certificate2? issuer)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=" + name, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        var now = DateTimeOffset.UtcNow;
        if (issuer is null)
        {
            return request.CreateSelfSigned(now.AddDays(-1), now.AddYears(1));
        }

        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false));
        using var signed = request.Create(issuer, now.AddDays(-1), now.AddMonths(6), [1, 2, 3, 4]);
        return signed.CopyWithPrivateKey(key);
    }

    private static X509Certificate2 CreateLeaf(X509Certificate2 issuer)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=vpn.splitvpn-test.invalid", key, HashAlgorithmName.SHA256);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName("vpn.splitvpn-test.invalid");
        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false));
        request.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension([OcspUrl], [IssuerUrl]));
        request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([CrlUrl]));
        var now = DateTimeOffset.UtcNow;
        return request.Create(issuer, now.AddDays(-1), now.AddDays(30), [5, 6, 7, 8]);
    }
}
