using System.Security.Cryptography;

namespace SplitVpn.Core.Update;

/// <summary>Проверка отсоединённой подписи манифеста релиза.</summary>
public interface IManifestVerifier
{
    /// <summary>Возвращает текст отказа; null — подпись верна.</summary>
    string? Verify(byte[] manifest, byte[] signature, string? keyId);
}

/// <summary>
/// ECDSA P-256 / SHA-256, подпись в формате IEEE P1363 (r и s подряд, 64 байта). Формат задан явно
/// и здесь, и в команде подписи: перепутать его с DER-последовательностью нельзя.
/// </summary>
public sealed class EcdsaManifestVerifier(IReadOnlyDictionary<string, string> publicKeys) : IManifestVerifier
{
    /// <summary>Длина подписи P-256 в формате IEEE P1363: два поля по 32 байта.</summary>
    public const int SignatureBytes = 64;

    public static EcdsaManifestVerifier Default { get; } = new(UpdateTrust.PublicKeys);

    public string? Verify(byte[] manifest, byte[] signature, string? keyId)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(signature);
        if (string.IsNullOrEmpty(keyId))
        {
            return "Манифест обновления не подписан.";
        }

        if (!publicKeys.TryGetValue(keyId, out var encoded))
        {
            return $"Манифест обновления подписан неизвестным ключом «{keyId}».";
        }

        if (signature.Length != SignatureBytes)
        {
            return "Подпись манифеста обновления имеет неверную длину.";
        }

        byte[] spki;
        try
        {
            spki = Convert.FromBase64String(encoded);
        }
        catch (FormatException)
        {
            return "Открытый ключ выпуска записан неверно: обновление не проверить.";
        }

        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(spki, out _);
            return ecdsa.VerifyData(manifest, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)
                ? null
                : "Подпись манифеста обновления неверна.";
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or NotSupportedException)
        {
            return "Подпись манифеста обновления не проверяется: " + ex.Message;
        }
    }
}
