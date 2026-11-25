using SplitVpn.Core.State;

namespace SplitVpn.Core.Tests.State;

/// <summary>
/// Ошибки проверки сертификата CryptoAPI, которые расшифровывает <see cref="ConnectionErrorGuide"/>: все они
/// «Ошибка сертификата VPN» без автоматических повторов. Повтор не исправит ни отозванный или просроченный
/// сертификат, ни чужой корень, ни сертификат не того назначения. Недоступная проверка отзыва (RevocationOffline)
/// тоже не повторяется сама по себе: служба даёт ей одну попытку отдельно, когда откроет адреса проверки.
/// </summary>
public sealed class CertificateErrorClassificationTests
{
    [Theory]
    [InlineData(ConnectionErrorGuide.RevocationOffline)]
    [InlineData(ConnectionErrorGuide.CertificateRevoked)]
    [InlineData(ConnectionErrorGuide.CertificateExpired)]
    [InlineData(ConnectionErrorGuide.UntrustedRoot)]
    [InlineData(ConnectionErrorGuide.NameMismatch)]
    [InlineData(ConnectionErrorGuide.WrongUsage)]
    public void CryptoApiCertificateErrors_AreCertificate_AndNotRetried(int code)
    {
        var info = RasErrorClassifier.Classify(code);

        Assert.Equal(ErrorCategory.Certificate, info.Category);
        Assert.False(info.Retryable);
        Assert.Contains(code, RasErrorClassifier.KnownCodes);
    }
}
