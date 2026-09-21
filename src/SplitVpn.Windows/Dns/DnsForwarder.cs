using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using SplitVpn.Core.Dns;

namespace SplitVpn.Windows.Dns;

/// <summary>Пересылка одного DNS-запроса upstream-серверу: UDP, при усечении — TCP.</summary>
public static class DnsForwarder
{
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(2);

    public static async Task<byte[]?> ForwardAsync(byte[] query, IReadOnlyList<IPEndPoint> upstreams, uint? interfaceIndex, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(upstreams);
        foreach (var upstream in upstreams)
        {
            var response = await TryUdpAsync(query, upstream, interfaceIndex, timeout, cancellationToken);
            if (response is not null && DnsMessage.IsTruncated(response))
            {
                response = await TryTcpAsync(query, upstream, interfaceIndex, timeout, cancellationToken) ?? response;
            }

            if (response is not null)
            {
                return response;
            }
        }

        return null;
    }

    private static async Task<byte[]?> TryUdpAsync(byte[] query, IPEndPoint upstream, uint? interfaceIndex, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var socket = UnicastSocket.CreateUdp(interfaceIndex);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        var id = (ushort)Random.Shared.Next(0, 65536);
        var copy = query.ToArray();
        DnsMessage.SetId(copy, id);
        try
        {
            await socket.SendToAsync(copy, upstream, cts.Token);
            var buffer = new byte[4096];
            while (true)
            {
                var result = await socket.ReceiveFromAsync(buffer, new IPEndPoint(IPAddress.Any, 0), cts.Token);
                if (result.ReceivedBytes >= DnsMessage.HeaderLength && DnsMessage.GetId(buffer) == id && Equals(result.RemoteEndPoint, upstream))
                {
                    return Restore(buffer.AsSpan(0, result.ReceivedBytes), query);
                }
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException && !cancellationToken.IsCancellationRequested)
        {
            return null;
        }
    }

    private static async Task<byte[]?> TryTcpAsync(byte[] query, IPEndPoint upstream, uint? interfaceIndex, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var socket = UnicastSocket.CreateTcp(interfaceIndex);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        try
        {
            await socket.ConnectAsync(upstream, cts.Token);
            await using var stream = new NetworkStream(socket, ownsSocket: false);
            var framed = new byte[query.Length + 2];
            BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)query.Length);
            query.CopyTo(framed, 2);
            await stream.WriteAsync(framed, cts.Token);
            var header = new byte[2];
            await stream.ReadExactlyAsync(header, cts.Token);
            var response = new byte[BinaryPrimitives.ReadUInt16BigEndian(header)];
            await stream.ReadExactlyAsync(response, cts.Token);
            return response;
        }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException or IOException && !cancellationToken.IsCancellationRequested)
        {
            return null;
        }
    }

    private static byte[] Restore(ReadOnlySpan<byte> response, byte[] query)
    {
        var copy = response.ToArray();
        DnsMessage.SetId(copy, DnsMessage.GetId(query));
        return copy;
    }
}
