namespace SplitVpn.Core.Update;

/// <summary>
/// Открытые ключи выпуска. Установщик проекта не подписан Authenticode, поэтому подлинность обновления
/// держится на подписи манифеста: скачанному по HTTPS доверять нельзя — подложный корневой сертификат
/// в хранилище машины делает перехват незаметным, а программа рассчитана на работу под блокировками.
///
/// Ключей может быть несколько: смена ключа идёт через версию, которая знает и старый, и новый, —
/// иначе потеря ключа означала бы конец обновлений у всех установленных копий.
/// Закрытый ключ в репозитории не хранится, см. docs\RELEASE.md.
/// </summary>
public static class UpdateTrust
{
    /// <summary>Ключи по идентификатору из поля «kid» манифеста: SubjectPublicKeyInfo в base64.</summary>
    public static IReadOnlyDictionary<string, string> PublicKeys { get; } = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["sv-2026-09"] = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuf0c4N+FBR7EwLB7jKHg+ahhVcxuV4I5/fxYkyaJ7jnO5e2CW1T0dUwaF7WnCpPEaSA4imBpMTS74bjOCg/P2g==",

        // С 0.9.1: закрытый ключ sv-2026-09 остался на другом компьютере и был недоступен при выпуске.
        // Версии до 0.9.1 этот ключ не знают — на 0.9.1 они переходят ручной установкой.
        ["sv-2026-09-2"] = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeuRmfXlrITKrk7MMh2Av1gC9FrSDQ2dma58l/HAeGnFWKfIsidQHJq3rVBGav2rcsngqUbqHeSYY1p5IO1or8w==",
    };
}
