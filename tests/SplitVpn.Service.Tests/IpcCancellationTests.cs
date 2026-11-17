using System.IO.Pipes;
using SplitVpn.Core.Ipc;

namespace SplitVpn.Service.Tests;

public sealed class IpcCancellationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InterruptedResponse_ClosesTheDesynchronizedPipe(bool timeout)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var name = "splitvpn-cancel-" + Guid.NewGuid().ToString("N");
        await using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        await using var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        var accept = server.WaitForConnectionAsync(deadline.Token);
        await pipe.ConnectAsync(deadline.Token);
        await accept;
        var handle = pipe.SafePipeHandle;
        await using var client = new IpcClient(pipe);
        using var cancelled = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
        var response = client.SendAsync(new GetStatusRequest(), timeout ? TimeSpan.FromMilliseconds(150) : Timeout.InfiniteTimeSpan, cancelled.Token);
        Assert.NotNull(await FrameCodec.ReadAsync(server, deadline.Token));
        if (timeout)
        {
            var error = await Assert.ThrowsAsync<ServiceUnavailableException>(() => response);
            Assert.Equal(ServiceUnavailableReason.Timeout, error.Reason);
        }
        else
        {
            await cancelled.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => response);
        }

        // Поздний ответ не должен достаться следующему запросу на том же соединении.
        Assert.True(handle.IsClosed);
    }

    [Fact]
    public async Task CancelWhileWaitingForAnotherRequest_DoesNotCloseItsPipe()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var name = "splitvpn-queue-" + Guid.NewGuid().ToString("N");
        await using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        await using var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        var accept = server.WaitForConnectionAsync(deadline.Token);
        await pipe.ConnectAsync(deadline.Token);
        await accept;
        await using var client = new IpcClient(pipe);
        var first = client.SendAsync(new GetStatusRequest(), deadline.Token);
        Assert.NotNull(await FrameCodec.ReadAsync(server, deadline.Token));
        using var cancelled = new CancellationTokenSource();
        var second = client.SendAsync(new GetStatusRequest(), cancelled.Token);
        await cancelled.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => second);

        await FrameCodec.WriteAsync(server, IpcSerializer.SerializeResponse(IpcResponse.Success("first")), deadline.Token);
        Assert.Equal("first", (await first).ResultAs<string>());
        Assert.False(pipe.SafePipeHandle.IsClosed);
    }

    [Fact]
    public async Task WriteFailure_IsMarkedAsNotSent_ButLostResponseIsNot()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        // Служба закрыла канал до запроса: запись не проходит, запрос не доставлен — повтор безопасен.
        var (server, pipe) = await ConnectPairAsync("splitvpn-write-", deadline.Token);
        await using (pipe)
        {
            await server.DisposeAsync();
            await using var client = new IpcClient(pipe);
            var error = await Assert.ThrowsAsync<ServiceUnavailableException>(() => client.SendAsync(new GetStatusRequest(), deadline.Token));
            Assert.True(error.RequestNotSent);
        }

        // Служба приняла запрос и закрыла канал без ответа: команда могла выполниться — повторять нельзя.
        (server, pipe) = await ConnectPairAsync("splitvpn-read-", deadline.Token);
        await using (pipe)
        {
            await using var client = new IpcClient(pipe);
            var response = client.SendAsync(new GetStatusRequest(), deadline.Token);
            Assert.NotNull(await FrameCodec.ReadAsync(server, deadline.Token));
            await server.DisposeAsync();
            var error = await Assert.ThrowsAsync<ServiceUnavailableException>(() => response);
            Assert.False(error.RequestNotSent);
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
