using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SplitVpn.OpenConnect;

namespace SplitVpn.Service.Tests.OpenConnect;

public sealed class WindowsHelperSystemTests
{
    /// <summary>Аудит ID38: копия сертификата без закрытого ключа не считается пригодной — её заменяет копия из хранилища компьютера.</summary>
    [Fact]
    public void PublicOnlyCopy_IsNotUsable_CopyWithKeyIs()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var withKey = new CertificateRequest("CN=SplitVpn test", key, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        using var publicOnly = X509CertificateLoader.LoadCertificate(withKey.RawData);
        Assert.False(publicOnly.HasPrivateKey);

        Assert.False(WindowsHelperSystem.HasUsableCopy([publicOnly]));
        Assert.True(WindowsHelperSystem.HasUsableCopy([publicOnly, withKey]));
        Assert.False(WindowsHelperSystem.HasUsableCopy([]));
    }
}
