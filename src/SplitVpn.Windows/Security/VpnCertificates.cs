using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SplitVpn.Core.Settings;

namespace SplitVpn.Windows.Security;

public static class VpnCertificates
{
    /// <summary>Проверка от имени вызывающего (служба — LocalSystem). Сертификаты не импортируются.</summary>
    public static void Validate(ConnectionProfile profile)
    {
        if (VpnProtocols.NeedsServerValidation(profile.AuthMethod))
        {
            using var roots = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            roots.Open(OpenFlags.ReadOnly);
            var installed = roots.Certificates;
            try
            {
                foreach (var thumbprint in profile.Eap.TrustedRootThumbprints)
                {
                    if (!installed.Any(c => c.Thumbprint == VpnProtocols.NormalizeThumbprint(thumbprint)))
                    {
                        throw new InvalidOperationException("Доверенный CA для EAP не установлен в LocalMachine\\Root.");
                    }
                }
            }
            finally
            {
                Release(installed);
            }
        }

        var eapTls = profile.AuthMethod == AuthMethod.EapTls;
        var machine = profile.AuthMethod == AuthMethod.MachineCertificate ||
            (profile.Protocol == VpnProtocol.L2tpIpsec && profile.IpsecAuthentication == IpsecAuthentication.MachineCertificate);
        if (!eapTls && !machine) { return; }
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);
        var all = store.Certificates;
        try
        {
            var candidates = all.Where(c => c.HasPrivateKey && c.NotBefore <= DateTime.Now && c.NotAfter > DateTime.Now
                && (!eapTls || c.Thumbprint == VpnProtocols.NormalizeThumbprint(profile.Eap.ClientCertificateThumbprint))).ToList();
            if (!candidates.Any(IsUsable))
            {
                throw new InvalidOperationException("Нет подходящего клиентского сертификата с доступным службе закрытым ключом в LocalMachine\\My.");
            }
        }
        finally
        {
            Release(all);
        }
    }

    /// <summary>Сертификаты коллекции хранилища держат неуправляемые дескрипторы: их нужно освободить.</summary>
    private static void Release(X509Certificate2Collection certificates)
    {
        foreach (var certificate in certificates)
        {
            certificate.Dispose();
        }
    }

    private static bool IsUsable(X509Certificate2 certificate)
    {
        using var chain = new X509Chain(useMachineContext: true);
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2"));
        // Отзыв клиентского сертификата проверяет сервер VPN. Обращаться за CRL и OCSP перед дозвоном нельзя:
        // за kill switch эти адреса закрыты фильтрами, проверка отказывала бы после устаревания кеша и
        // останавливала повторы подключения (ошибка стала бы блокирующей).
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        if (!chain.Build(certificate)) { return false; }
        try
        {
            using var rsa = certificate.GetRSAPrivateKey();
            using var ec = certificate.GetECDsaPrivateKey();
            return rsa is not null || ec is not null;
        }
        catch (CryptographicException) { return false; }
    }
}
