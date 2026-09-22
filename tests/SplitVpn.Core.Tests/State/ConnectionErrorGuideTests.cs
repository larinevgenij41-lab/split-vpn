using SplitVpn.Core.Settings;
using SplitVpn.Core.State;

namespace SplitVpn.Core.Tests.State;

public class ConnectionErrorGuideTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 21, 12, 0, 0, TimeSpan.Zero);

    private static ServerCertificateFacts Certificate(DateTimeOffset notAfter) => new()
    {
        Subject = "vpn.example.org",
        Issuer = "Let's Encrypt",
        Names = ["vpn.example.org"],
        NotBefore = notAfter.AddDays(-7),
        NotAfter = notAfter,
        Thumbprint = "0102",
        RevocationUrls = ["http://ye1.c.lencr.org/112.crl"],
        RevocationHosts = ["ye1.c.lencr.org"],
        ProbedUtc = Now,
    };

    [Fact]
    public void RevocationOffline_ExplainsCheckAndNamesTheAddress()
    {
        var help = ConnectionErrorGuide.For(ErrorCategory.Certificate, ConnectionErrorGuide.RevocationOffline,
            VpnProtocol.Sstp, AuthMethod.MsChapV2, Certificate(Now.AddDays(6)), Now);

        Assert.Contains("отозван", help.Summary, StringComparison.Ordinal);
        Assert.Contains("(CRL)", help.Meaning, StringComparison.Ordinal);
        Assert.Contains(help.Steps, step => step.Contains("ye1.c.lencr.org", StringComparison.Ordinal));
        Assert.Equal("Код 0x80092013 (-2146885613, CryptoAPI)", help.CodeText);
        Assert.Contains("действует до", help.CertificateText, StringComparison.Ordinal);
    }

    [Fact]
    public void ExpiredCertificate_IsDescribedWithDate()
    {
        var help = ConnectionErrorGuide.For(ErrorCategory.Certificate, ConnectionErrorGuide.CertificateExpired,
            VpnProtocol.Sstp, AuthMethod.MsChapV2, Certificate(Now.AddDays(-1)), Now);

        Assert.Contains("срок истёк", help.CertificateText, StringComparison.Ordinal);
        Assert.Contains(help.Steps, step => step.Contains("Обновите сертификат", StringComparison.Ordinal));
    }

    [Fact]
    public void RasCode_IsShownAsDecimal()
    {
        var help = ConnectionErrorGuide.For(ErrorCategory.Authentication, 691, VpnProtocol.Sstp, AuthMethod.MsChapV2, null, Now);

        Assert.Equal("Код 691 (RAS)", help.CodeText);
        Assert.NotEmpty(help.Steps);
        Assert.Null(help.CertificateText);
    }

    [Fact]
    public void UnknownCode_FallsBackToCategory()
    {
        var help = ConnectionErrorGuide.For(ErrorCategory.ServerUnreachable, 65123, VpnProtocol.Ikev2, AuthMethod.EapMsChapV2, null, Now);

        Assert.Contains("Сервер недоступен", help.Summary, StringComparison.Ordinal);
        Assert.Contains("IKEv2", help.Meaning, StringComparison.Ordinal);
        Assert.NotEmpty(help.Steps);
    }

    [Fact]
    public void EveryCategory_HasSummaryAndSteps()
    {
        foreach (var category in Enum.GetValues<ErrorCategory>().Where(c => c != ErrorCategory.None))
        {
            var help = ConnectionErrorGuide.For(category, null, VpnProtocol.Sstp, AuthMethod.MsChapV2, null, Now);

            Assert.NotEmpty(help.Summary);
            Assert.NotEmpty(help.Meaning);
            Assert.NotEmpty(help.Steps);
            Assert.Null(help.CodeText);
        }
    }

    /// <summary>
    /// У кода, который классификатор знает по имени, должна быть и своя расшифровка: иначе пользователь
    /// увидит общий текст категории там, где программа знает точную причину.
    /// </summary>
    [Fact]
    public void EveryClassifiedCode_HasItsOwnExplanation()
    {
        foreach (var code in RasErrorClassifier.KnownCodes)
        {
            var category = RasErrorClassifier.Classify(code).Category;
            var help = ConnectionErrorGuide.For(category, code, VpnProtocol.Sstp, AuthMethod.MsChapV2, null, Now);
            var fallback = ConnectionErrorGuide.For(category, null, VpnProtocol.Sstp, AuthMethod.MsChapV2, null, Now);

            Assert.True(help.Summary != fallback.Summary, $"код {code} без собственной расшифровки");
        }
    }

    [Fact]
    public void Certificate_DescribesRemainingTime()
    {
        Assert.Contains("осталось 6 дней", Certificate(Now.AddDays(6)).Describe(Now), StringComparison.Ordinal);
        Assert.Contains("осталось 2 часа", Certificate(Now.AddHours(2)).Describe(Now), StringComparison.Ordinal);
        Assert.True(Certificate(Now.AddHours(-1)).Expired(Now));
    }
}
