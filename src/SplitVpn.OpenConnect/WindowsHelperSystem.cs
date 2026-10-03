using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using SplitVpn.Core.Net;
using SplitVpn.Core.OpenConnect;
using SplitVpn.Windows.Net;

namespace SplitVpn.OpenConnect;

/// <summary>Системные действия помощника в Windows: адаптер Wintun и сертификат компьютера для GnuTLS.</summary>
internal sealed partial class WindowsHelperSystem : IHelperSystem
{
    private const int CertKeyIdentifierPropId = 20;

    public ulong ConfigureInterface(string interfaceName, SessionInfo session)
    {
        var luid = TunnelInterfaceConfig.FindLuid(interfaceName)
            ?? throw new InvalidOperationException($"Адаптер «{interfaceName}» не найден после создания.");
        if (!Ipv4.TryParse(session.Address, out var address))
        {
            throw new InvalidOperationException("Шлюз не выдал IPv4-адрес туннеля.");
        }

        TunnelInterfaceConfig.Configure(luid, address, session.Mtu);
        return luid;
    }

    public int RemoveStaleInterface(string interfaceName) => TunnelInterfaceConfig.RemoveStaleWintunEntries(interfaceName);

    /// <summary>
    /// GnuTLS ищет ключи только в CurrentUser\MY: у помощника (LocalSystem) это хранилище учётной записи
    /// SYSTEM. Сертификат копируется туда из хранилища компьютера вместе со ссылкой на закрытый ключ
    /// (сам ключ остаётся на месте), адрес строится по CERT_KEY_IDENTIFIER_PROP_ID — как у GnuTLS.
    /// Копия нужна весь сеанс (переподключения снова открывают ключ) и при выходе не удаляется: ею может
    /// пользоваться другой помощник — второй профиль с тем же сертификатом или повторный дозвон, пока
    /// прежний помощник ещё не вышел. Удаление посреди чужого рукопожатия давало плавающий сбой входа.
    /// </summary>
    public (string Certificate, string Key) PrepareClientCertificate(string thumbprint)
    {
        using var machine = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        machine.Open(OpenFlags.ReadOnly);
        var all = machine.Certificates;
        var found = all.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
        try
        {
            if (found.Count == 0)
            {
                throw new InvalidOperationException("Клиентский сертификат не найден в хранилище компьютера: " + thumbprint);
            }

            var certificate = found[0];
            if (!certificate.HasPrivateKey)
            {
                throw new InvalidOperationException("У клиентского сертификата нет закрытого ключа в хранилище компьютера.");
            }

            CopyToAccountStore(certificate);
            var id = Convert.ToHexStringLower(KeyIdentifier(certificate));
            return ($"system:win:id={id};type=cert", $"system:win:id={id};type=privkey");
        }
        finally
        {
            Dispose(found);
            Dispose(all);
        }
    }

    /// <summary>Копия с тем же отпечатком уже есть (другой сеанс или прежний запуск) — повторно не добавляется.</summary>
    private static void CopyToAccountStore(X509Certificate2 certificate)
    {
        using var account = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        account.Open(OpenFlags.ReadWrite);
        var all = account.Certificates;
        var existing = all.Find(X509FindType.FindByThumbprint, certificate.Thumbprint, validOnly: false);
        try
        {
            if (existing.Count > 0)
            {
                return;
            }

            account.Add(certificate);
        }
        finally
        {
            Dispose(existing);
            Dispose(all);
        }
    }

    private static void Dispose(X509Certificate2Collection certificates)
    {
        foreach (var certificate in certificates)
        {
            certificate.Dispose();
        }
    }

    private static unsafe byte[] KeyIdentifier(X509Certificate2 certificate)
    {
        uint size = 0;
        if (!CertGetCertificateContextProperty(certificate.Handle, CertKeyIdentifierPropId, null, ref size))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "Нет идентификатора ключа сертификата");
        }

        var buffer = new byte[size];
        fixed (byte* pointer = buffer)
        {
            if (!CertGetCertificateContextProperty(certificate.Handle, CertKeyIdentifierPropId, pointer, ref size))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "Нет идентификатора ключа сертификата");
            }
        }

        return buffer[..(int)size];
    }

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool CertGetCertificateContextProperty(nint context, int propId, byte* data, ref uint size);
}
