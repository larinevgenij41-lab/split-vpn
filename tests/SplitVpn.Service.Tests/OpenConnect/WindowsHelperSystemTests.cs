using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SplitVpn.OpenConnect;
using SplitVpn.Windows.OpenConnect;
using static SplitVpn.Windows.OpenConnect.HelperCertificateStore;

namespace SplitVpn.Service.Tests.OpenConnect;

public sealed class WindowsHelperSystemTests
{
    private static readonly KeyLocation CapiMachineKey = new("Microsoft Enhanced RSA and AES Cryptographic Provider", "le-1234", 24, 0x20, 1);
    private static readonly KeyLocation ReimportedKey = CapiMachineKey with { Container = "le-5678" };

    private static CopyFacts Machine(string thumbprint = "AA", string keyId = "K1", KeyLocation? key = null) =>
        new(thumbprint, keyId, key ?? CapiMachineKey, true);

    /// <summary>Аудит ID38: копия сертификата без закрытого ключа не годится — её заменяет копия из хранилища компьютера.</summary>
    [Fact]
    public void PublicOnlyCopy_IsReplaced()
    {
        var (remove, add) = PlanCopies(Machine(), [new CopyFacts("AA", "K1", null, false)]);

        Assert.Equal([0], remove);
        Assert.True(add);
    }

    /// <summary>Годная копия (тот же сертификат, тот же ключ) не трогается: ею может пользоваться другой помощник посреди входа.</summary>
    [Fact]
    public void CurrentCopy_IsKept()
    {
        var (remove, add) = PlanCopies(Machine(), [Machine(), new CopyFacts("BB", "K2", CapiMachineKey with { Container = "other" }, true)]);

        Assert.Empty(remove);
        Assert.False(add);
    }

    /// <summary>Ревью круг 3, С16: PFX импортирован заново — у копии ссылка на удалённый контейнер ключа, она заменяется.</summary>
    [Fact]
    public void CopyPointingToOldKeyContainer_IsReplaced()
    {
        var (remove, add) = PlanCopies(Machine(key: ReimportedKey), [Machine()]);

        Assert.Equal([0], remove);
        Assert.True(add);
    }

    /// <summary>Ревью круг 3, С16: сертификат продлён с тем же ключом — копия прежнего сертификата удаляется, иначе GnuTLS найдёт по ключу её.</summary>
    [Fact]
    public void OtherCertificateWithSameKey_IsRemoved()
    {
        var (remove, add) = PlanCopies(Machine(thumbprint: "NEW"), [Machine(thumbprint: "OLD"), new CopyFacts("ELSE", "K9", CapiMachineKey, true)]);

        Assert.Equal([0], remove);
        Assert.True(add);
    }

    /// <summary>Ревью круг 3, С15: ключ компьютера в CNG (KSP или TPM) распознаётся, ключ CryptoAPI и ключ учётной записи — нет.</summary>
    [Fact]
    public void MachineCngKey_IsDetected()
    {
        var cng = new KeyLocation("Microsoft Platform Crypto Provider", "tpm-key", 0, 0x20, 0);

        Assert.True(cng.IsMachineCngKey);
        Assert.False(CapiMachineKey.IsMachineCngKey);
        Assert.False((cng with { Flags = 0 }).IsMachineCngKey);
        Assert.Contains("Microsoft Platform Crypto Provider", WindowsHelperSystem.CngKeyMessage(cng), StringComparison.Ordinal);
    }

    /// <summary>Сертификат без ссылки на ключ (эфемерный ключ, только открытая часть) читается без ошибки.</summary>
    [Fact]
    public void EphemeralCertificate_HasNoKeyLocation()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var certificate = new CertificateRequest("CN=SplitVpn test", key, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        using var publicOnly = X509CertificateLoader.LoadCertificate(certificate.RawData);

        Assert.Null(KeyLocationOf(publicOnly));
        Assert.NotEmpty(KeyIdentifier(publicOnly));
    }
}
