using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using SplitVpn.Core.Net;
using SplitVpn.Core.OpenConnect;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.OpenConnect;

namespace SplitVpn.OpenConnect;

/// <summary>Системные действия помощника в Windows: адаптер Wintun и сертификат компьютера для GnuTLS.</summary>
internal sealed class WindowsHelperSystem : IHelperSystem
{
    public bool CanConnect(string address, int port, TimeSpan timeout, CancellationToken cancellationToken)
    {
        if (!IPAddress.TryParse(address, out var ip))
        {
            return false;
        }

        using var socket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        limit.CancelAfter(timeout);
        try
        {
            socket.ConnectAsync(new IPEndPoint(ip, port), limit.Token).AsTask().GetAwaiter().GetResult();
            return true;
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            return false;
        }
    }

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
    /// Годная копия нужна весь сеанс (переподключения снова открывают ключ) и при выходе не удаляется: ею может
    /// пользоваться другой помощник — второй профиль с тем же сертификатом или повторный вход, пока прежний
    /// помощник ещё не вышел. Устаревшие копии (ключ переимпортирован, сертификат продлён с тем же ключом)
    /// заменяются, а копию сертификата, который больше не выбран ни в одном профиле, удаляет служба.
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

            if (HelperCertificateStore.KeyLocationOf(certificate) is { IsMachineCngKey: true } key)
            {
                throw new InvalidOperationException(CngKeyMessage(key));
            }

            HelperCertificateStore.EnsureCopy(certificate);
            var id = Convert.ToHexStringLower(HelperCertificateStore.KeyIdentifier(certificate));
            return ($"system:win:id={id};type=cert", $"system:win:id={id};type=privkey");
        }
        finally
        {
            Dispose(found);
            Dispose(all);
        }
    }

    /// <summary>Почему сертификат с ключом компьютера в CNG не подойдёт: без этого вход падал бы с невнятной ошибкой GnuTLS.</summary>
    internal static string CngKeyMessage(HelperCertificateStore.KeyLocation key) =>
        $"Закрытый ключ клиентского сертификата хранится в поставщике CNG «{key.Provider}» (программный KSP или TPM). "
        + "Библиотека GnuTLS, через которую работает AnyConnect, не открывает такие ключи компьютера, поэтому вход с этим сертификатом невозможен. "
        + "Выберите сертификат, ключ которого хранится в поставщике CryptoAPI (CSP), или перевыпустите сертификат с таким ключом.";

    private static void Dispose(X509Certificate2Collection certificates)
    {
        foreach (var certificate in certificates)
        {
            certificate.Dispose();
        }
    }
}
