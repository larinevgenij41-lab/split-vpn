using System.IO.Pipes;
using Microsoft.Extensions.Logging.Abstractions;
using SplitVpn.Core.Ipc;
using SplitVpn.Service.Coordination;
using SplitVpn.Service.Ipc;
using Xunit.Sdk;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Экземпляры канала не заканчиваются у нескольких сеансов с пультом: их больше, а соединение без запросов дольше срока
/// простоя закрывается. Клиент после такого закрытия видит «запрос не отправлен» и переподключается без повтора команды.
/// </summary>
public sealed class IpcIdleTimeoutTests
{
    private static IpcServer Server(FakeWorld world, string name, TimeSpan idle) =>
        new(new Coordinator(world.Dependencies()), NullLogger<IpcServer>.Instance)
        {
            PipeName = name,
            Security = () => null,
            Precheck = _ => true,
            IdleTimeout = idle,
        };

    private static async Task<IpcClient> ConnectAsync(string name)
    {
        var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(5000, TestContext.Current.CancellationToken);
        return new IpcClient(pipe);
    }

    private static async Task<IpcResponse> SendAsync(IpcClient client)
    {
        // Настройки служба отдаёт без очереди координатора.
        var response = await client.SendAsync(new GetSettingsRequest(), TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        if (response.ErrorCode == IpcErrorCodes.Denied)
        {
            throw SkipException.ForSkip("Тест запускается под учётной записью администратора интерактивного сеанса.");
        }

        return response;
    }

    [Fact]
    public void InstancesSuffice_ForSeveralConsoleSessions() =>
        Assert.True(IpcServer.MaxInstances >= 64, "экземпляров канала меньше, чем у десятка сеансов с пультом");

    [Fact]
    public async Task IdleConnection_IsClosedAndClientSeesRequestNotSent()
    {
        using var world = new FakeWorld();
        var name = "SplitVpn.Test." + Guid.NewGuid().ToString("N");
        var server = Server(world, name, TimeSpan.FromMilliseconds(300));
        await server.StartAsync(TestContext.Current.CancellationToken);
        try
        {
            await using var client = await ConnectAsync(name);
            Assert.True((await SendAsync(client)).Ok);

            await Task.Delay(1500, TestContext.Current.CancellationToken);

            var closed = await Assert.ThrowsAsync<ServiceUnavailableException>(() => SendAsync(client));
            Assert.True(closed.RequestNotSent, "после закрытия по простою запрос должен считаться не отправленным: " + closed.Message);
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
        }
    }

    /// <summary>
    /// Клиент сам закрывает соединение, простоявшее дольше своего порога (он меньше серверного): запрос, записанный в
    /// момент закрытия службой, иначе мог потеряться без признака «не отправлен». Вызывающий получает «не отправлен» и
    /// переподключается.
    /// </summary>
    [Fact]
    public async Task ClientIdleLimit_ClosesBeforeServerAndReportsRequestNotSent()
    {
        Assert.True(IpcClient.DefaultIdleLimit <= IpcServer.ClientIdleTimeout - TimeSpan.FromMinutes(1),
            "порог простоя клиента должен быть заметно меньше серверного");

        using var world = new FakeWorld();
        var name = "SplitVpn.Test." + Guid.NewGuid().ToString("N");
        var server = Server(world, name, TimeSpan.FromMinutes(1));
        await server.StartAsync(TestContext.Current.CancellationToken);
        try
        {
            var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(5000, TestContext.Current.CancellationToken);
            await using var client = new IpcClient(pipe) { IdleLimit = TimeSpan.FromMilliseconds(300) };
            Assert.True((await SendAsync(client)).Ok);
            Assert.True((await SendAsync(client)).Ok);

            await Task.Delay(600, TestContext.Current.CancellationToken);

            var closed = await Assert.ThrowsAsync<ServiceUnavailableException>(() => SendAsync(client));
            Assert.True(closed.RequestNotSent, closed.Message);
            Assert.Equal(ServiceUnavailableReason.NotRunning, closed.Reason);

            // Новое соединение работает как обычно.
            await using var fresh = await ConnectAsync(name);
            Assert.True((await SendAsync(fresh)).Ok);
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
        }
    }

    /// <summary>Срок простоя — между запросами: клиент, который шлёт запросы чаще срока, остаётся на своём соединении.</summary>
    [Fact]
    public async Task ActiveConnection_IsKept()
    {
        using var world = new FakeWorld();
        var name = "SplitVpn.Test." + Guid.NewGuid().ToString("N");
        var server = Server(world, name, TimeSpan.FromMilliseconds(600));
        await server.StartAsync(TestContext.Current.CancellationToken);
        try
        {
            await using var client = await ConnectAsync(name);
            for (var i = 0; i < 8; i++)
            {
                Assert.True((await SendAsync(client)).Ok);
                await Task.Delay(150, TestContext.Current.CancellationToken);
            }
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
        }
    }

    /// <summary>Подробный журнал канала не пишет адреса с токеном из текста отказа.</summary>
    [Fact]
    public void Trace_StripsUrlsFromErrorText()
    {
        var trace = new IpcConnectionTrace("PID 1, сеанс 1");
        var response = IpcResponse.Failure(IpcErrorCodes.InvalidSettings,
            "Адрес источника обновлений программы должен быть HTTPS-ссылкой: «http://mirror.example/feed?token=SECRET»\r\nвторая строка");

        var line = trace.Record(new SaveSettingsRequest(new Core.Settings.AppSettings()), response, TimeSpan.FromMilliseconds(5));

        Assert.NotNull(line);
        Assert.DoesNotContain("SECRET", line, StringComparison.Ordinal);
        Assert.DoesNotContain("\n", line, StringComparison.Ordinal);
        Assert.Contains("http://mirror.example/feed", line, StringComparison.Ordinal);
    }
}
