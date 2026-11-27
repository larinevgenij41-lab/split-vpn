using System.IO.Pipes;
using Microsoft.Extensions.Logging.Abstractions;
using SplitVpn.Core.Ipc;
using SplitVpn.Service.Coordination;
using SplitVpn.Service.Ipc;

namespace SplitVpn.Service.Tests;

/// <summary>Клиент, который шлёт запросы, но не читает ответы, не держит экземпляр канала бесконечно.</summary>
public sealed class IpcWriteTimeoutTests
{
    [Fact]
    public async Task ClientNotReadingResponses_IsDisconnectedAfterWriteTimeout()
    {
        using var world = new FakeWorld();
        var name = "SplitVpn.Test." + Guid.NewGuid().ToString("N");
        var server = new IpcServer(new Coordinator(world.Dependencies()), NullLogger<IpcServer>.Instance)
        {
            PipeName = name,
            Security = () => null,
            Precheck = _ => true,
            WriteTimeout = TimeSpan.FromMilliseconds(300),
        };
        await server.StartAsync(TestContext.Current.CancellationToken);
        try
        {
            await using var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(5000, TestContext.Current.CancellationToken);

            // Настройки служба отдаёт без очереди координатора. Ответы не читаются: буферы канала заполняются, запись
            // ответа встаёт, а за ней и чтение запросов — пока служба не закроет соединение.
            var request = IpcSerializer.SerializeRequest(new GetSettingsRequest());
            using var limit = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
            limit.CancelAfter(TimeSpan.FromSeconds(20));
            var closed = false;
            try
            {
                while (!limit.IsCancellationRequested)
                {
                    await FrameCodec.WriteAsync(pipe, request, limit.Token);
                }
            }
            catch (IOException)
            {
                closed = true;
            }
            catch (OperationCanceledException) when (!TestContext.Current.CancellationToken.IsCancellationRequested)
            {
            }

            Assert.True(closed, "служба не закрыла соединение клиента, не читающего ответы");
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
        }
    }
}
