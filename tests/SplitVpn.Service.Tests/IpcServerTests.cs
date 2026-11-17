using System.IO.Pipes;
using System.Security.Claims;
using System.Security.Principal;
using Microsoft.Extensions.Logging.Abstractions;
using SplitVpn.Core.Ipc;
using SplitVpn.Service.Coordination;
using SplitVpn.Service.Ipc;
using Xunit.Sdk;

namespace SplitVpn.Service.Tests;

public sealed class IpcServerTests
{
    [Fact]
    public void CurrentInteractiveAdministrator_IsAllowed()
    {
        using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value;
        var inAdministrators = identity.Claims.Any(c => c.Value == administrators);
        if (!inAdministrators)
        {
            throw SkipException.ForSkip("Тест запускается под учётной записью администратора.");
        }

        var dump = string.Join(Environment.NewLine, identity.Claims.Where(c => c.Value is "S-1-5-32-544" or "S-1-5-4").Select(c => $"{c.Type} = {c.Value}"))
            + Environment.NewLine + "Groups: " + string.Join(", ", identity.Groups!.Select(g => g.Value));
        Assert.True(IpcServer.IsAllowedCaller(identity), dump);
        Assert.Contains(identity.Claims, c => c.Type == ClaimTypes.DenyOnlySid || c.Type == ClaimTypes.GroupSid);
    }

    [Fact]
    public async Task ExhaustedInstances_DoNotStopServer()
    {
        using var world = new FakeWorld();
        var name = "SplitVpn.Test." + Guid.NewGuid().ToString("N");
        var server = new IpcServer(new Coordinator(world.Dependencies()), NullLogger<IpcServer>.Instance) { PipeName = name, Security = () => null };
        await server.StartAsync(TestContext.Current.CancellationToken);

        // Подключения без единого кадра занимают экземпляры до FirstFrameTimeout — как посторонний процесс.
        var blockers = new List<NamedPipeClientStream>();
        for (var i = 0; i < IpcServer.MaxInstances + 2; i++)
        {
            var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            try
            {
                await client.ConnectAsync(1000, TestContext.Current.CancellationToken);
                blockers.Add(client);
            }
            catch (TimeoutException)
            {
                client.Dispose();
            }
        }

        await Task.Delay(1500, TestContext.Current.CancellationToken);
        Assert.False(server.ExecuteTask!.IsCompleted, "сервер IPC остановился при переполнении экземпляров");

        foreach (var blocker in blockers)
        {
            blocker.Dispose();
        }

        using var fresh = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        await fresh.ConnectAsync((int)IpcServer.FirstFrameTimeout.TotalMilliseconds + 5000, TestContext.Current.CancellationToken);
        Assert.True(fresh.IsConnected);

        await server.StopAsync(CancellationToken.None);
    }

    /// <summary>
    /// Клиент без прав отсекается сразу после подключения: экземпляр канала не ждёт первого кадра, а
    /// клиент, успевший или не успевший отправить запрос, всё равно читает ответ «отказано».
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(300)]
    public async Task DeniedByPrecheck_IsClosedAtOnceAndClientReadsDenial(int delayBeforeRequestMs)
    {
        using var world = new FakeWorld();
        var name = "SplitVpn.Test." + Guid.NewGuid().ToString("N");
        var server = new IpcServer(new Coordinator(world.Dependencies()), NullLogger<IpcServer>.Instance)
        {
            PipeName = name,
            Security = () => null,
            Precheck = _ => false,
        };
        await server.StartAsync(TestContext.Current.CancellationToken);

        var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(5000, TestContext.Current.CancellationToken);
        await Task.Delay(delayBeforeRequestMs, TestContext.Current.CancellationToken);
        await using (var client = new IpcClient(pipe))
        {
            var response = await client.SendAsync(new GetStatusRequest(), TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
            Assert.False(response.Ok);
            Assert.Equal(IpcErrorCodes.Denied, response.ErrorCode);
        }

        await server.StopAsync(CancellationToken.None);
    }

    /// <summary>Проверка до первого кадра видит учётную запись процесса-клиента.</summary>
    [Fact]
    public async Task PipeClientIdentity_IsClientProcessUser()
    {
        var name = "SplitVpn.Test." + Guid.NewGuid().ToString("N");
        await using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        await using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        var accept = server.WaitForConnectionAsync(TestContext.Current.CancellationToken);
        await client.ConnectAsync(5000, TestContext.Current.CancellationToken);
        await accept;

        using var identity = PipeClientIdentity.TryOpen(server.SafePipeHandle);
        using var self = WindowsIdentity.GetCurrent();
        Assert.NotNull(identity);
        Assert.Equal(self.User, identity.User);
    }

    /// <summary>Без имени из тестов служба берёт случайное имя с постоянной основой.</summary>
    [Fact]
    public void NewPipeName_IsRandomWithCommonPrefix()
    {
        var first = IpcNames.NewPipeName();
        var second = IpcNames.NewPipeName();

        Assert.StartsWith(IpcNames.PipeName + ".", first, StringComparison.Ordinal);
        Assert.NotEqual(first, second);
    }

    /// <summary>
    /// Имя публикуется только после создания первого экземпляра: занятое случайное имя не публикуется,
    /// а следующее пробуется сразу, без паузы между попытками.
    /// </summary>
    [Fact]
    public async Task OccupiedRandomName_IsNotPublishedAndReplacedAtOnce()
    {
        using var world = new FakeWorld();
        var occupied = "SplitVpn.Test." + Guid.NewGuid().ToString("N");
        var free = "SplitVpn.Test." + Guid.NewGuid().ToString("N");
        await using var foreign = new NamedPipeServerStream(occupied, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        var names = new Queue<string>([occupied, free]);
        var published = new List<string>();
        var server = new IpcServer(new Coordinator(world.Dependencies()), NullLogger<IpcServer>.Instance)
        {
            Security = () => null,
            NewPipeName = () => names.Count > 0 ? names.Dequeue() : "SplitVpn.Test." + Guid.NewGuid().ToString("N"),
            PublishPipeName = n =>
            {
                lock (published)
                {
                    published.Add(n);
                }
            },
        };
        await server.StartAsync(TestContext.Current.CancellationToken);

        using var client = new NamedPipeClientStream(".", free, PipeDirection.InOut, PipeOptions.Asynchronous);
        await client.ConnectAsync(5000, TestContext.Current.CancellationToken);
        Assert.True(client.IsConnected);

        // Имя публикуется сразу после создания экземпляра — клиент может подключиться чуть раньше записи.
        for (var i = 0; i < 100; i++)
        {
            lock (published)
            {
                if (published.Count > 0)
                {
                    break;
                }
            }

            await Task.Delay(10, TestContext.Current.CancellationToken);
        }

        lock (published)
        {
            Assert.Equal([free], published);
        }

        await server.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task OccupiedPipeName_IsRetriedNotFatal()
    {
        using var world = new FakeWorld();
        var name = "SplitVpn.Test." + Guid.NewGuid().ToString("N");
        var foreign = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        var server = new IpcServer(new Coordinator(world.Dependencies()), NullLogger<IpcServer>.Instance) { PipeName = name, Security = () => null };
        await server.StartAsync(TestContext.Current.CancellationToken);

        await Task.Delay(1500, TestContext.Current.CancellationToken);
        Assert.False(server.ExecuteTask!.IsCompleted, "сервер IPC остановился из-за занятого имени канала");

        foreign.Dispose();
        using var fresh = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        await fresh.ConnectAsync(5000, TestContext.Current.CancellationToken);
        Assert.True(fresh.IsConnected);

        await server.StopAsync(CancellationToken.None);
    }
}
