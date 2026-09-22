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
    /// </summary>
    public (string Certificate, string Key) PrepareClientCertificate(string thumbprint)
    {
        using var machine = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        machine.Open(OpenFlags.ReadOnly);
        var found = machine.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
        if (found.Count == 0)
        {
            throw new InvalidOperationException("Клиентский сертификат не найден в хранилище компьютера: " + thumbprint);
        }

        using var certificate = found[0];
        if (!certificate.HasPrivateKey)
        {
            throw new InvalidOperationException("У клиентского сертификата нет закрытого ключа в хранилище компьютера.");
        }

        using (var account = new X509Store(StoreName.My, StoreLocation.CurrentUser))
        {
            account.Open(OpenFlags.ReadWrite);
            account.Add(certificate);
        }

        var id = Convert.ToHexStringLower(KeyIdentifier(certificate));
        return ($"system:win:id={id};type=cert", $"system:win:id={id};type=privkey");
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
