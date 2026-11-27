using System.Buffers.Binary;
using System.IO.Pipes;
using SplitVpn.Core.Ipc;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Канал, в котором потеряна граница кадров, закрывается: следующий запрос сразу получает «служба недоступна», а не
/// читает хвост чужого ответа. Освобождение клиента посреди обмена будит и держателя очереди, и ждущих.
/// </summary>
public sealed class IpcBrokenChannelTests
{
    [Fact]
    public async Task OversizedFrameHeader_BreaksChannel_NextCallIsUnavailable()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var (server, pipe) = await ConnectPairAsync("splitvpn-oversize-", deadline.Token);
        await using (server)
        await using (pipe)
        {
            var handle = pipe.SafePipeHandle;
            await using var client = new IpcClient(pipe);
            var first = client.SendAsync(new GetStatusRequest(), deadline.Token);
            Assert.NotNull(await FrameCodec.ReadAsync(server, deadline.Token));
            var header = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(header, FrameCodec.MaxFrameBytes + 1);
            await server.WriteAsync(header, deadline.Token);
            await server.FlushAsync(deadline.Token);

            var error = await Assert.ThrowsAnyAsync<Exception>(() => first.WaitAsync(TimeSpan.FromSeconds(5), deadline.Token));
            Assert.True(error is IpcProtocolException or ServiceUnavailableException, error.ToString());
            Assert.True(handle.IsClosed);

            // Хвост «ответа» служба могла бы дослать: второй запрос его не читает, а сразу просит новое соединение.
            var second = await Assert.ThrowsAsync<ServiceUnavailableException>(
                () => client.SendAsync(new GetStatusRequest(), deadline.Token).WaitAsync(TimeSpan.FromSeconds(5), deadline.Token));
            Assert.True(second.RequestNotSent);
        }
    }

    [Fact]
    public async Task UnreadableResponseBody_KeepsChannel()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var (server, pipe) = await ConnectPairAsync("splitvpn-badjson-", deadline.Token);
        await using (server)
        await using (pipe)
        {
            await using var client = new IpcClient(pipe);
            var first = client.SendAsync(new GetStatusRequest(), deadline.Token);
            Assert.NotNull(await FrameCodec.ReadAsync(server, deadline.Token));
            await FrameCodec.WriteAsync(server, "{не json"u8.ToArray(), deadline.Token);
            await Assert.ThrowsAnyAsync<System.Text.Json.JsonException>(() => first.WaitAsync(TimeSpan.FromSeconds(5), deadline.Token));

            // Кадр прочитан целиком: граница не потеряна, и следующий обмен идёт по тому же каналу.
            var second = client.SendAsync(new GetStatusRequest(), deadline.Token);
            Assert.NotNull(await FrameCodec.ReadAsync(server, deadline.Token));
            await FrameCodec.WriteAsync(server, IpcSerializer.SerializeResponse(IpcResponse.Success("ok")), deadline.Token);
            Assert.Equal("ok", (await second.WaitAsync(TimeSpan.FromSeconds(5), deadline.Token)).ResultAs<string>());
        }
    }

    [Fact]
    public async Task DisposeDuringSend_WakesHolderAndWaiter_WithServiceUnavailable()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var (server, pipe) = await ConnectPairAsync("splitvpn-dispose-", deadline.Token);
        await using (server)
        await using (pipe)
        {
            var client = new IpcClient(pipe);
            var holder = client.SendAsync(new GetStatusRequest(), deadline.Token);
            Assert.NotNull(await FrameCodec.ReadAsync(server, deadline.Token));
            var waiter = client.SendAsync(new GetStatusRequest(), deadline.Token);

            await client.DisposeAsync();

            // Без зависания, без ObjectDisposedException и без подмены ошибки исключением из Release.
            await Assert.ThrowsAsync<ServiceUnavailableException>(() => holder.WaitAsync(TimeSpan.FromSeconds(5), deadline.Token));
            var queued = await Assert.ThrowsAsync<ServiceUnavailableException>(() => waiter.WaitAsync(TimeSpan.FromSeconds(5), deadline.Token));
            Assert.True(queued.RequestNotSent);

            var late = await Assert.ThrowsAsync<ServiceUnavailableException>(
                () => client.SendAsync(new GetStatusRequest(), deadline.Token).WaitAsync(TimeSpan.FromSeconds(5), deadline.Token));
            Assert.True(late.RequestNotSent);
            await client.DisposeAsync();
        }
    }

    private static async Task<(NamedPipeServerStream Server, NamedPipeClientStream Pipe)> ConnectPairAsync(string prefix, CancellationToken cancellationToken)
    {
        var name = prefix + Guid.NewGuid().ToString("N");
        var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        var accept = server.WaitForConnectionAsync(cancellationToken);
        await pipe.ConnectAsync(cancellationToken);
        await accept;
        return (server, pipe);
    }
}
