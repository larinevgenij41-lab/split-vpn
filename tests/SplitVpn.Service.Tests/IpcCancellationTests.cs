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
}
