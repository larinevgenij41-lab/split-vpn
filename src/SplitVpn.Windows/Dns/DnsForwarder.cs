using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using SplitVpn.Core.Dns;

namespace SplitVpn.Windows.Dns;

/// <summary>
/// Пересылка одного DNS-запроса upstream-серверу: UDP, при усечении — TCP. Для пути, который UDP не переносит
/// («VPN поверх SSH»), — сразу TCP.
/// </summary>
public static class DnsForwarder
{
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(2);

    /// <summary>Срок для пути «только TCP»: каждое обращение - новое соединение через туннель, это дольше UDP.</summary>
    public static readonly TimeSpan TcpOnlyTimeout = TimeSpan.FromSeconds(4);

    /// <summary>Срок запроса по пути: у пути «только TCP» он длиннее.</summary>
    public static TimeSpan TimeoutFor(DnsRoute route) => (route ?? throw new ArgumentNullException(nameof(route))).TcpOnly ? TcpOnlyTimeout : DefaultTimeout;

    private const int MaxUdpDatagram = 65535;

    public static Task<byte[]?> ForwardAsync(byte[] query, IReadOnlyList<IPEndPoint> upstreams, uint? interfaceIndex, TimeSpan timeout, CancellationToken cancellationToken) =>
        ForwardAsync(query, upstreams, interfaceIndex, timeout, tcpOnly: false, cancellationToken);

    /// <summary>
    /// Окончательный ответ первого сервера пути или null — «ответа нет». Окончательный ответ — любой полный
    /// (без бита TC) ответ, кроме SERVFAIL (2) и REFUSED (5): NOERROR, NODATA и NXDOMAIN говорят об имени и
    /// возвращаются сразу. На SERVFAIL, REFUSED и молчание пробуется следующий сервер. Когда серверы кончились:
    /// <list type="bullet">
    /// <item>все серверы пути ответили REFUSED — это и есть окончательный ответ (отказ корпоративного DNS или
    /// фильтра — его решение об имени): возвращается REFUSED, и посредник не подменяет его просроченным ответом
    /// из кеша, который обошёл бы свежую блокировку;</item>
    /// <item>иначе, если был усечённый ответ UDP, который не удалось добрать по TCP, — он (как до разделения
    /// «окончательных» ответов): UDP-клиент получит бит TC и повторит запрос по TCP, а TCP-клиенту посредник
    /// вместо ответа с TC отдаёт SERVFAIL;</item>
    /// <item>иначе (молчание, SERVFAIL) — null: посредник отдаёт просроченный ответ из кеша или строит SERVFAIL сам.</item>
    /// </list>
    /// </summary>
    /// <param name="tcpOnly">
    /// Не пробовать UDP вовсе. Без этого запрос через путь без UDP ждал бы весь срок и кончался отказом:
    /// на TCP пересылка переходит только после усечённого ответа по UDP, а ответа не будет.
    /// </param>
    /// <param name="acceptServerFailure">
    /// Проверка пути (не разрешение имени): годится любой ответ сервера, в том числе SERVFAIL, REFUSED и
    /// усечённый, — он доказывает, что путь до сервера работает.
    /// </param>
    public static async Task<byte[]?> ForwardAsync(byte[] query, IReadOnlyList<IPEndPoint> upstreams, uint? interfaceIndex, TimeSpan timeout, bool tcpOnly, CancellationToken cancellationToken, bool acceptServerFailure = false)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(upstreams);
        byte[]? fallback = null;
        byte[]? refused = null;
        var allRefused = upstreams.Count > 0;
        foreach (var upstream in upstreams)
        {
            var response = tcpOnly
                ? await TryTcpAsync(query, upstream, interfaceIndex, timeout, cancellationToken)
                : await TryUdpAsync(query, upstream, interfaceIndex, timeout, cancellationToken);
            if (response is not null && !tcpOnly && DnsMessage.IsTruncated(response))
            {
                fallback ??= response;
                response = await TryTcpAsync(query, upstream, interfaceIndex, timeout, cancellationToken);
            }

            if (response is not null && acceptServerFailure)
            {
                return response;
            }

            // Усечённый ответ по TCP (сервер так не отвечает, но байты из сети) и отказ сервера — не ответ об имени.
            if (response is null || DnsMessage.IsTruncated(response) || DnsMessage.GetRcode(response) is 2 or 5)
            {
                if (response is not null && !DnsMessage.IsTruncated(response) && DnsMessage.GetRcode(response) == 5)
                {
                    refused ??= response;
                }
                else
                {
                    allRefused = false;
                }

                continue;
            }

            return response;
        }

        if (acceptServerFailure)
        {
            return fallback;
        }

        return allRefused ? refused : fallback;
    }

    private static async Task<byte[]?> TryUdpAsync(byte[] query, IPEndPoint upstream, uint? interfaceIndex, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var socket = UnicastSocket.CreateUdp(interfaceIndex);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        var id = (ushort)Random.Shared.Next(0, 65536);
        var copy = query.ToArray();
        DnsMessage.SetId(copy, id);

        // Клиент мог заявить в EDNS большой буфер, и upstream ответит датаграммой больше 4 КБ: в меньший
        // буфер она не поместится (MessageSize), и исправный сервер считался бы отказавшим.
        var buffer = ArrayPool<byte>.Shared.Rent(MaxUdpDatagram);
        try
        {
            await socket.SendToAsync(copy, upstream, cts.Token);
            while (true)
            {
                var result = await socket.ReceiveFromAsync(buffer, new IPEndPoint(IPAddress.Any, 0), cts.Token);
                var received = buffer.AsSpan(0, result.ReceivedBytes);

                // Совпадения адреса и идентификатора мало: ответ обязан отвечать именно на наш вопрос,
                // иначе он попадёт в кеш и в закрепления под чужим именем.
                if (result.ReceivedBytes >= DnsMessage.HeaderLength && DnsMessage.GetId(received) == id
                    && Equals(result.RemoteEndPoint, upstream) && DnsMessage.Answers(received, query))
                {
                    return Restore(received, query);
                }
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException && !cancellationToken.IsCancellationRequested)
        {
            return null;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
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
            // Как и по UDP: ответ с чужим идентификатором не наш, даже если вопрос совпал.
            return DnsMessage.GetId(response) == DnsMessage.GetId(query) && DnsMessage.Answers(response, query) ? response : null;
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
