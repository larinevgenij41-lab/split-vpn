using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace SplitVpn.Windows.OpenConnect;

/// <summary>
/// Копии клиентских сертификатов компьютера в хранилище учётной записи SYSTEM (CurrentUser\My у службы и
/// помощника — оба работают от LocalSystem). GnuTLS ищет клиентский сертификат только там и находит его по
/// идентификатору ключа (CERT_KEY_IDENTIFIER_PROP_ID): копия должна указывать на нынешний ключ, а других
/// сертификатов с тем же ключом рядом быть не должно — иначе GnuTLS возьмёт первый попавшийся.
/// </summary>
public static partial class HelperCertificateStore
{
    private const int CertKeyProvInfoPropId = 2;
    private const int CertKeyIdentifierPropId = 20;

    /// <summary>CRYPT_MACHINE_KEYSET у CryptoAPI и NCRYPT_MACHINE_KEY_FLAG у CNG: оба равны 0x20.</summary>
    private const uint MachineKeyFlag = 0x20;

    /// <summary>Где лежит закрытый ключ сертификата (CERT_KEY_PROV_INFO_PROP_ID). Тип поставщика 0 — CNG (KSP).</summary>
    public readonly record struct KeyLocation(string Provider, string Container, uint ProviderType, uint Flags, uint KeySpec)
    {
        /// <summary>Ключ компьютера, а не учётной записи: только такие копирует помощник.</summary>
        public bool IsMachineKey => (Flags & MachineKeyFlag) != 0;

        /// <summary>
        /// Ключ компьютера в поставщике CNG (программный KSP или TPM). GnuTLS открывает ключи CNG без
        /// NCRYPT_MACHINE_KEY_FLAG, то есть ищет их среди ключей учётной записи SYSTEM, и такой ключ не находит.
        /// </summary>
        public bool IsMachineCngKey => ProviderType == 0 && IsMachineKey;

        /// <summary>Тот же ключ: имена поставщика и контейнера в Windows сравниваются без учёта регистра.</summary>
        public bool SameKey(KeyLocation other) =>
            string.Equals(Provider, other.Provider, StringComparison.OrdinalIgnoreCase)
            && string.Equals(Container, other.Container, StringComparison.OrdinalIgnoreCase)
            && ProviderType == other.ProviderType && Flags == other.Flags && KeySpec == other.KeySpec;
    }

    /// <summary>Что известно о сертификате для решения, годится ли копия: отпечаток, идентификатор ключа, ссылка на ключ.</summary>
    internal readonly record struct CopyFacts(string Thumbprint, string? KeyId, KeyLocation? Key, bool HasPrivateKey);

    /// <summary>
    /// Что сделать с хранилищем учётной записи, чтобы GnuTLS нашёл нужный сертификат: какие копии удалить
    /// (номера в <paramref name="existing"/>) и надо ли добавить свежую копию.
    /// <list type="bullet">
    /// <item>копия того же сертификата остаётся, только если она ссылается на тот же ключ, что и сертификат в хранилище
    /// компьютера: после повторного импорта PFX прежний контейнер ключа удалён, и старая ссылка ведёт в никуда;</item>
    /// <item>другие сертификаты с тем же идентификатором ключа (прежний сертификат до продления с тем же ключом)
    /// удаляются: GnuTLS нашёл бы по ключу их.</item>
    /// </list>
    /// </summary>
    internal static (List<int> Remove, bool Add) PlanCopies(CopyFacts wanted, IReadOnlyList<CopyFacts> existing)
    {
        var remove = new List<int>();
        var current = false;
        for (var i = 0; i < existing.Count; i++)
        {
            var copy = existing[i];
            if (string.Equals(copy.Thumbprint, wanted.Thumbprint, StringComparison.OrdinalIgnoreCase))
            {
                var usable = copy.HasPrivateKey && (wanted.Key is not { } key || (copy.Key is { } copyKey && copyKey.SameKey(key)));
                if (usable && !current)
                {
                    current = true;
                    continue;
                }

                remove.Add(i);
                continue;
            }

            if (wanted.KeyId is { } id && string.Equals(copy.KeyId, id, StringComparison.OrdinalIgnoreCase))
            {
                remove.Add(i);
            }
        }

        return (remove, !current);
    }

    /// <summary>
    /// Готовит копию сертификата компьютера в хранилище учётной записи по <see cref="PlanCopies"/>. Годная копия
    /// не трогается: ею может пользоваться другой помощник (второй профиль с тем же сертификатом) посреди входа.
    /// </summary>
    public static void EnsureCopy(X509Certificate2 machineCertificate)
    {
        ArgumentNullException.ThrowIfNull(machineCertificate);
        var wanted = FactsOf(machineCertificate);
        using var account = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        account.Open(OpenFlags.ReadWrite);
        var all = account.Certificates;
        try
        {
            var existing = all.Select(FactsOf).ToList();
            var (remove, add) = PlanCopies(wanted, existing);
            foreach (var index in remove)
            {
                account.Remove(all[index]);
            }

            if (add)
            {
                account.Add(machineCertificate);
            }
        }
        finally
        {
            Dispose(all);
        }
    }

    /// <summary>
    /// Удаляет копии сертификата, которые сделал помощник (они ссылаются на ключ компьютера): сертификат больше не
    /// нужен ни одному профилю. Возвращает число удалённых копий.
    /// </summary>
    /// <summary>В личном хранилище учётной записи (у службы — SYSTEM) есть сертификат с этим отпечатком.</summary>
    public static bool HasCopy(string thumbprint)
    {
        try
        {
            using var account = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            account.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            var all = account.Certificates;
            try
            {
                return all.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false).Count > 0;
            }
            finally
            {
                foreach (var certificate in all)
                {
                    certificate.Dispose();
                }
            }
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            // Хранилища нет: копий в нём нет.
            return false;
        }
    }

    public static int RemoveCopies(string thumbprint)
    {
        using var account = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        account.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
        var all = account.Certificates;
        var found = all.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
        try
        {
            var removed = 0;
            foreach (var copy in found)
            {
                if (KeyLocationOf(copy) is { IsMachineKey: true })
                {
                    account.Remove(copy);
                    removed++;
                }
            }

            return removed;
        }
        finally
        {
            Dispose(found);
            Dispose(all);
        }
    }

    /// <summary>Идентификатор ключа сертификата — по нему GnuTLS ищет сертификат и ключ (system:win:id=…).</summary>
    public static byte[] KeyIdentifier(X509Certificate2 certificate) =>
        TryKeyIdentifier(certificate) ?? throw new Win32Exception(Marshal.GetLastPInvokeError(), "Нет идентификатора ключа сертификата");

    /// <summary>Ссылка сертификата на закрытый ключ; null — ссылки нет (только открытая часть) или она не читается.</summary>
    public static unsafe KeyLocation? KeyLocationOf(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        uint size = 0;
        if (!CertGetCertificateContextProperty(certificate.Handle, CertKeyProvInfoPropId, null, ref size) || size < (uint)sizeof(CryptKeyProvInfo))
        {
            return null;
        }

        var buffer = new byte[size];
        fixed (byte* pointer = buffer)
        {
            if (!CertGetCertificateContextProperty(certificate.Handle, CertKeyProvInfoPropId, pointer, ref size))
            {
                return null;
            }

            // Строки структуры лежат в том же буфере: указатели действительны, пока он закреплён.
            var info = (CryptKeyProvInfo*)pointer;
            return new KeyLocation(
                Marshal.PtrToStringUni(info->ProviderName) ?? "",
                Marshal.PtrToStringUni(info->ContainerName) ?? "",
                info->ProviderType,
                info->Flags,
                info->KeySpec);
        }
    }

    private static CopyFacts FactsOf(X509Certificate2 certificate) => new(
        certificate.Thumbprint,
        TryKeyIdentifier(certificate) is { } id ? Convert.ToHexString(id) : null,
        KeyLocationOf(certificate),
        certificate.HasPrivateKey);

    private static unsafe byte[]? TryKeyIdentifier(X509Certificate2 certificate)
    {
        uint size = 0;
        if (!CertGetCertificateContextProperty(certificate.Handle, CertKeyIdentifierPropId, null, ref size) || size == 0)
        {
            return null;
        }

        var buffer = new byte[size];
        fixed (byte* pointer = buffer)
        {
            if (!CertGetCertificateContextProperty(certificate.Handle, CertKeyIdentifierPropId, pointer, ref size))
            {
                return null;
            }
        }

        return buffer[..(int)size];
    }

    private static void Dispose(X509Certificate2Collection certificates)
    {
        foreach (var certificate in certificates)
        {
            certificate.Dispose();
        }
    }

    /// <summary>CRYPT_KEY_PROV_INFO.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct CryptKeyProvInfo
    {
        public nint ContainerName;
        public nint ProviderName;
        public uint ProviderType;
        public uint Flags;
        public uint ProviderParamCount;
        public nint ProviderParams;
        public uint KeySpec;
    }

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool CertGetCertificateContextProperty(nint context, int propId, byte* data, ref uint size);
}
