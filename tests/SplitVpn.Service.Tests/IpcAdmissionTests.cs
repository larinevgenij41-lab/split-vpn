using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Claims;
using System.Security.Principal;
using Microsoft.Extensions.Logging.Abstractions;
using SplitVpn.Core.Ipc;
using SplitVpn.Service.Coordination;
using SplitVpn.Service.Ipc;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Допуск к каналу управления: решение по SID токена (таблица) и то, что сервер действительно отказывает по нему —
/// до первого кадра и по олицетворению, не передавая кадр координатору.
/// </summary>
public sealed class IpcAdmissionTests
{
    private const string System = "S-1-5-18";
    private const string LocalService = "S-1-5-19";
    private const string NetworkService = "S-1-5-20";
    private const string Administrators = "S-1-5-32-544";
    private const string Users = "S-1-5-32-545";
    private const string Interactive = "S-1-5-4";
    private const string Service = "S-1-5-6";
    private const string Network = "S-1-5-2";
    private const string Batch = "S-1-5-3";
    private const string AuthenticatedUsers = "S-1-5-11";
    private const string Person = "S-1-5-21-1111111111-2222222222-3333333333-1001";
    private const string BuiltinAdministrator = "S-1-5-21-1111111111-2222222222-3333333333-500";

    /// <summary>
    /// Таблица выведена из текущего кода: SYSTEM — всегда; иначе Administrators (включённая или deny-only)
    /// и обязательно включённая INTERACTIVE. NETWORK рядом с INTERACTIVE не мешает: сетевой доступ режет ACL канала.
    /// </summary>
    public static TheoryData<string, string?, string[], string[], bool> Callers() => new()
    {
        { "SYSTEM без групп", System, [], [], true },
        { "SYSTEM с группами", System, [Administrators, Service], [], true },
        { "администратор с повышением, интерактивный", Person, [Administrators, Interactive, Users, AuthenticatedUsers], [], true },
        { "администратор без повышения (UAC, deny-only), интерактивный", Person, [Interactive, Users, AuthenticatedUsers], [Administrators], true },
        { "встроенный Administrator, интерактивный", BuiltinAdministrator, [Administrators, Interactive], [], true },
        { "администратор интерактивный, в токене и NETWORK", Person, [Administrators, Interactive, Network], [], true },
        { "SID учётной записи не определён, администратор интерактивный", null, [Administrators, Interactive], [], true },
        { "администратор, вход службы", Person, [Administrators, Service, AuthenticatedUsers], [], false },
        { "администратор, сетевой вход", Person, [Administrators, Network, AuthenticatedUsers], [], false },
        { "администратор, пакетное задание", Person, [Administrators, Batch, AuthenticatedUsers], [], false },
        { "администратор deny-only, вход службы", Person, [Service], [Administrators], false },
        { "администратор, INTERACTIVE только deny-only", Person, [Administrators], [Interactive], false },
        { "обычный пользователь, интерактивный", Person, [Interactive, Users, AuthenticatedUsers], [], false },
        { "встроенный Administrator вне группы Administrators", BuiltinAdministrator, [Interactive, Users], [], false },
        { "LOCAL SERVICE", LocalService, [Service, AuthenticatedUsers], [], false },
        { "NETWORK SERVICE администратором", NetworkService, [Administrators, Service], [], false },
        { "пустой токен", null, [], [], false },
    };

    [Theory]
    [MemberData(nameof(Callers))]
    public void AdmissionTable(string because, string? user, string[] enabled, string[] denyOnly, bool expected) =>
        Assert.True(expected == IpcServer.IsAllowedCaller(user, enabled, denyOnly), because);

    /// <summary>Обёртка над токеном передаёт решению ровно его SID: для текущего процесса ответы совпадают.</summary>
    [Fact]
    public void IdentityWrapper_MatchesTableDecision()
    {
        using var self = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        var enabled = self.Claims.Where(c => c.Type == ClaimTypes.GroupSid).Select(c => c.Value).ToArray();
        var denyOnly = self.Claims.Where(c => c.Type == ClaimTypes.DenyOnlySid).Select(c => c.Value).ToArray();

        Assert.Equal(IpcServer.IsAllowedCaller(self.User?.Value, enabled, denyOnly), IpcServer.IsAllowedCaller(self));
        if (TestIdentity.IsInteractiveAdministrator())
        {
            Assert.True(IpcServer.IsAllowedCaller(self));
        }
    }

    /// <summary>
    /// Олицетворение отказывает (допуск подменён на «нет»): клиент получает «отказано», а его кадр не доходит
    /// до координатора — команда не встаёт в очередь.
    /// </summary>
    [Fact]
    public async Task AuthorizeDenies_ClientGetsDenied_AndFrameIsNotProcessed()
    {
        using var world = new FakeWorld();
        var coordinator = new Coordinator(world.Dependencies());
        var name = "SplitVpn.Test." + Guid.NewGuid().ToString("N");
        var checks = 0;
        var server = new IpcServer(coordinator, NullLogger<IpcServer>.Instance)
        {
            PipeName = name,
            Security = () => null,
            Precheck = _ => true,
            AllowCaller = _ =>
            {
                Interlocked.Increment(ref checks);
                return false;
            },
        };
        await server.StartAsync(TestContext.Current.CancellationToken);
        try
        {
            var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(5000, TestContext.Current.CancellationToken);
            await using (var client = new IpcClient(pipe))
            {
                // Команда, меняющая состояние, идёт через очередь координатора (он не запущен): пропущенный кадр встал бы в неё.
                var response = await client.SendAsync(new ConnectRequest(null, null), TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
                Assert.False(response.Ok);
                Assert.Equal(IpcErrorCodes.Denied, response.ErrorCode);
            }

            Assert.Equal(1, Volatile.Read(ref checks));
            Assert.Equal(0, coordinator.QueuedCount);
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
        }
    }

    /// <summary>Настоящая проверка до первого кадра: процесс клиента не открылся — отказ сразу, кадр не ждётся.</summary>
    [Fact]
    public async Task UnidentifiedClientProcess_IsRejectedBeforeFirstFrame()
    {
        var checks = 0;
        var answer = await PrecheckAnswerAsync(_ => null, _ =>
        {
            Interlocked.Increment(ref checks);
            return true;
        });

        Assert.NotNull(answer);
        Assert.Equal(IpcErrorCodes.Denied, answer.ErrorCode);
        // Отказ - именно из-за того, что процесс не открылся: решение о допуске даже не спрашивалось.
        Assert.Equal(0, Volatile.Read(ref checks));
    }

    /// <summary>Настоящая проверка до первого кадра: процесс клиента открылся, но допуска нет — отказ сразу.</summary>
    [Fact]
    public async Task NotAllowedClientProcess_IsRejectedBeforeFirstFrame()
    {
        var answer = await PrecheckAnswerAsync(_ => WindowsIdentity.GetCurrent(TokenAccessLevels.Query), _ => false);

        Assert.NotNull(answer);
        Assert.Equal(IpcErrorCodes.Denied, answer.ErrorCode);
    }

    /// <summary>Допущенный клиент проходит проверку до первого кадра: служба ждёт его запроса и ничего не пишет первой.</summary>
    [Fact]
    public async Task AllowedClientProcess_IsNotAnsweredBeforeFirstFrame()
    {
        var answer = await PrecheckAnswerAsync(_ => WindowsIdentity.GetCurrent(TokenAccessLevels.Query), _ => true, listenFor: TimeSpan.FromMilliseconds(500));

        Assert.Null(answer);
    }

    /// <summary>
    /// Подключается без запроса и ждёт, что служба напишет первой (отказ до первого кадра). null — за
    /// <paramref name="listenFor"/> ничего не пришло (служба ждёт первого кадра).
    /// </summary>
    private static async Task<IpcResponse?> PrecheckAnswerAsync(Func<NamedPipeServerStream, WindowsIdentity?> open, Func<WindowsIdentity, bool> allow,
        TimeSpan? listenFor = null)
    {
        using var world = new FakeWorld();
        var name = "SplitVpn.Test." + Guid.NewGuid().ToString("N");
        var server = new IpcServer(new Coordinator(world.Dependencies()), NullLogger<IpcServer>.Instance)
        {
            PipeName = name,
            Security = () => null,
            OpenClientProcess = open,
            AllowCaller = allow,
        };
        await server.StartAsync(TestContext.Current.CancellationToken);
        try
        {
            await using var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(5000, TestContext.Current.CancellationToken);
            using var limit = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
            // Отказ до первого кадра приходит сразу; срок с запасом, но меньше ожидания первого кадра службой.
            limit.CancelAfter(listenFor ?? IpcServer.FirstFrameTimeout - TimeSpan.FromMilliseconds(500));
            var watch = Stopwatch.StartNew();
            try
            {
                var frame = await FrameCodec.ReadAsync(pipe, limit.Token);
                Assert.True(watch.Elapsed < IpcServer.FirstFrameTimeout, $"ответ занял {watch.ElapsedMilliseconds} мс");
                return frame is null ? null : IpcSerializer.DeserializeResponse(frame);
            }
            catch (OperationCanceledException) when (limit.IsCancellationRequested && !TestContext.Current.CancellationToken.IsCancellationRequested)
            {
                return null;
            }
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
        }
    }
}

/// <summary>Факты о токене тестового процесса, не зависящие от проверяемого кода допуска.</summary>
internal static class TestIdentity
{
    /// <summary>
    /// В токене есть группа Administrators (включённая или deny-only при UAC без повышения) и включённая INTERACTIVE:
    /// по ним тесты канала решают, пропускать ли себя, а не по ответу сервера или <see cref="IpcServer.IsAllowedCaller(WindowsIdentity)"/>.
    /// </summary>
    public static bool IsInteractiveAdministrator()
    {
        using var self = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value;
        var interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null).Value;
        return self.Claims.Any(c => c.Value == administrators && c.Type is ClaimTypes.GroupSid or ClaimTypes.DenyOnlySid)
            && self.Claims.Any(c => c.Value == interactive && c.Type == ClaimTypes.GroupSid);
    }
}
