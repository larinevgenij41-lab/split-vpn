using System.Security.Cryptography;
using System.Text;
using SplitVpn.Core.Update;

namespace SplitVpn.Core.Tests.Update;

public class ManifestSignatureTests
{
    private const string KeyId = "test-key";

    [Fact]
    public void ValidSignature_IsAccepted()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var manifest = Manifest();

        Assert.Null(Verifier(key).Verify(manifest, Sign(key, manifest), KeyId));
    }

    [Fact]
    public void TamperedManifest_IsRejected()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var manifest = Manifest();
        var signature = Sign(key, manifest);
        manifest[manifest.Length / 2] ^= 0x01;

        Assert.NotNull(Verifier(key).Verify(manifest, signature, KeyId));
    }

    [Fact]
    public void OtherKey_IsRejected()
    {
        using var signing = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var trusted = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var manifest = Manifest();

        Assert.NotNull(Verifier(trusted).Verify(manifest, Sign(signing, manifest), KeyId));
    }

    /// <summary>Формат подписи закреплён: DER-последовательность вместо IEEE P1363 не принимается.</summary>
    [Fact]
    public void DerSignature_IsRejected()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var manifest = Manifest();
        var der = key.SignData(manifest, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        Assert.NotNull(Verifier(key).Verify(manifest, der, KeyId));
    }

    [Fact]
    public void UnknownKeyId_IsRejected()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var manifest = Manifest();

        Assert.NotNull(Verifier(key).Verify(manifest, Sign(key, manifest), "другой-ключ"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void MissingKeyId_IsRejected(string? keyId)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var manifest = Manifest();

        Assert.NotNull(Verifier(key).Verify(manifest, Sign(key, manifest), keyId));
    }

    [Fact]
    public void GarbageSignature_IsRejectedWithoutThrowing()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var manifest = Manifest();

        Assert.NotNull(Verifier(key).Verify(manifest, [], KeyId));
        Assert.NotNull(Verifier(key).Verify(manifest, new byte[64], KeyId));
        Assert.NotNull(Verifier(key).Verify(manifest, new byte[70], KeyId));
    }

    [Fact]
    public void BrokenPublicKey_IsRejectedWithoutThrowing()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var manifest = Manifest();
        var signature = Sign(key, manifest);

        Assert.NotNull(new EcdsaManifestVerifier(new Dictionary<string, string> { [KeyId] = "не base64" }).Verify(manifest, signature, KeyId));
        Assert.NotNull(new EcdsaManifestVerifier(new Dictionary<string, string> { [KeyId] = "AAAA" }).Verify(manifest, signature, KeyId));
    }

    /// <summary>Смена ключа: версия, знающая старый и новый, принимает оба.</summary>
    [Fact]
    public void SecondTrustedKey_IsAccepted()
    {
        using var previous = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var next = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var verifier = new EcdsaManifestVerifier(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["sv-old"] = Convert.ToBase64String(previous.ExportSubjectPublicKeyInfo()),
            ["sv-new"] = Convert.ToBase64String(next.ExportSubjectPublicKeyInfo()),
        });
        var manifest = Manifest();

        Assert.Null(verifier.Verify(manifest, Sign(previous, manifest), "sv-old"));
        Assert.Null(verifier.Verify(manifest, Sign(next, manifest), "sv-new"));
    }

    /// <summary>В поставке ключ выпуска задан и читается: иначе обновления не проверялись бы ни разу.</summary>
    [Fact]
    public void ShippedKey_IsUsable()
    {
        Assert.NotEmpty(UpdateTrust.PublicKeys);
        foreach (var encoded in UpdateTrust.PublicKeys.Values)
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(encoded), out _);
            Assert.Equal(256, key.KeySize);
        }
    }

    private static byte[] Manifest() => Encoding.UTF8.GetBytes(UpdateManifestTests.Json());

    private static byte[] Sign(ECDsa key, byte[] manifest) =>
        key.SignData(manifest, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    private static EcdsaManifestVerifier Verifier(ECDsa key) =>
        new(new Dictionary<string, string>(StringComparer.Ordinal) { [KeyId] = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()) });
}
