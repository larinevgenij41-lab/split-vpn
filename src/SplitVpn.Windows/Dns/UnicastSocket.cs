using System.Net;
using System.Net.Sockets;

namespace SplitVpn.Windows.Dns;

/// <summary>Сокеты, привязанные к интерфейсу через IP_UNICAST_IF: запрос уходит только через заданный адаптер.</summary>
public static class UnicastSocket
{
    private const int IpUnicastIf = 31;

    public static Socket CreateUdp(uint? interfaceIndex)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        Bind(socket, interfaceIndex);
        return socket;
    }

    public static Socket CreateTcp(uint? interfaceIndex)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        Bind(socket, interfaceIndex);
        return socket;
    }

    private static void Bind(Socket socket, uint? interfaceIndex)
    {
        if (interfaceIndex is { } index)
        {
            // Для IPv4 индекс интерфейса передаётся в сетевом порядке байтов.
            socket.SetSocketOption(SocketOptionLevel.IP, (SocketOptionName)IpUnicastIf, IPAddress.HostToNetworkOrder((int)index));
        }
    }
}
