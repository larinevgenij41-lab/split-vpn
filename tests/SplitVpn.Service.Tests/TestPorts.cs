using System.Net;
using System.Net.Sockets;

namespace SplitVpn.Service.Tests;

/// <summary>Подбор порта для тестов, которые сами занимают его на нескольких адресах.</summary>
internal static class TestPorts
{
    /// <summary>Сокеты, удерживающие один порт: UDP и TCP на каждом из адресов.</summary>
    internal sealed class HeldPort : IDisposable
    {
        private readonly Dictionary<IPAddress, (Socket Udp, Socket Tcp)> _sockets;

        internal HeldPort(int port, Dictionary<IPAddress, (Socket Udp, Socket Tcp)> sockets)
        {
            Port = port;
            _sockets = sockets;
        }

        public int Port { get; }

        public Socket Udp(IPAddress address) => _sockets[address].Udp;

        public Socket Tcp(IPAddress address) => _sockets[address].Tcp;

        /// <summary>Отпускает UDP и TCP на адресе: порт там снова свободен.</summary>
        public void Release(IPAddress address)
        {
            if (_sockets.Remove(address, out var pair))
            {
                pair.Udp.Dispose();
                pair.Tcp.Dispose();
            }
        }

        public void Dispose()
        {
            foreach (var (udp, tcp) in _sockets.Values)
            {
                udp.Dispose();
                tcp.Dispose();
            }

            _sockets.Clear();
        }
    }

    /// <summary>
    /// Эксклюзивно занимает случайный порт, свободный и для UDP, и для TCP на каждом из адресов (вне исключённых
    /// диапазонов обоих протоколов). Порт, выданный системой на одном адресе (Start(0) на ::1), на другом адресе
    /// (127.0.0.1) может быть занят: поэтому порт держится сразу на всех нужных адресах, а тест отпускает лишнее.
    /// Отпустить порт и занять его заново - гонка с другими процессами, поэтому захватчиком служит сам сокет пробы.
    /// </summary>
    public static HeldPort Hold(params IPAddress[] addresses)
    {
        for (var attempt = 1; ; attempt++)
        {
            var port = Random.Shared.Next(49152, 65536);
            var sockets = new Dictionary<IPAddress, (Socket Udp, Socket Tcp)>();
            try
            {
                foreach (var address in addresses)
                {
                    var tcp = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { ExclusiveAddressUse = true };
                    var udp = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp) { ExclusiveAddressUse = true };
                    sockets[address] = (udp, tcp);
                    tcp.Bind(new IPEndPoint(address, port));
                    tcp.Listen(1);
                    udp.Bind(new IPEndPoint(address, port));
                }

                return new HeldPort(port, sockets);
            }
            catch (SocketException)
            {
                foreach (var (udp, tcp) in sockets.Values)
                {
                    udp.Dispose();
                    tcp.Dispose();
                }

                if (attempt >= 50)
                {
                    throw;
                }
            }
        }
    }
}
