using System.IO.Pipes;
using System.Security.Claims;
using System.Security.Principal;
using Microsoft.Extensions.Logging.Abstractions;
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
