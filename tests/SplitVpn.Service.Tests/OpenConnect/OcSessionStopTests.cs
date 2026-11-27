using SplitVpn.Core.OpenConnect;
using SplitVpn.OpenConnect;

namespace SplitVpn.Service.Tests.OpenConnect;

/// <summary>
/// Команда отмены не дошла до цикла libopenconnect (сбой сокета команд): помощник не сообщает о конце сеанса, которого
/// нет, а завершается сам или сразу сообщает об обрыве. И признак HostScan берётся только из сообщений об ошибках.
/// </summary>
public sealed class OcSessionStopTests
{
    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(10);

    private static StartCommand Start() =>
        new("https://avpn.example.org/", "", "AnyConnect Windows 4.10.06090", true, null, "SplitVpn AC 1", null, null);

    private static void FailCancel(FakeOcLib lib) => lib.OnSendCommand = command =>
    {
        if (command == (byte)'x')
        {
            throw new IOException("Не удалось передать команду в libopenconnect.");
        }
    };

    private static Task<TerminationKind> RunAsync(OcSession session) =>
        Task.Factory.StartNew(() => session.Run(Start()), TaskCreationOptions.LongRunning);

    [Fact]
    public async Task Stop_CancelNotDelivered_ExitsProcessInsteadOfReportingFalseEnd()
    {
        var lib = new FakeOcLib();
        var output = new RecordingOutput();
        using var mainloop = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var exit = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        FailCancel(lib);
        lib.OnMainloop = () =>
        {
            entered.TrySetResult();
            mainloop.Wait(Wait);
            return -4;
        };
        var session = new OcSession(lib, output, new FakeSystem())
        {
            ExitProcess = code =>
            {
                // Как настоящий выход процесса: службе больше ничего не приходит.
                Assert.DoesNotContain(output.All, e => e is TerminatedEvent);
                exit.TrySetResult(code);
                mainloop.Set();
            },
        };

        var run = RunAsync(session);
        await entered.Task.WaitAsync(Wait, TestContext.Current.CancellationToken);
        await Task.Run(() => session.Post(new StopCommand()), TestContext.Current.CancellationToken);

        Assert.Equal(1, await exit.Task.WaitAsync(Wait, TestContext.Current.CancellationToken));
        await run.WaitAsync(Wait, TestContext.Current.CancellationToken);
        Assert.DoesNotContain(output.All, e => e is TerminatedEvent { Kind: TerminationKind.Internal });
        session.Dispose();
    }

    /// <summary>Отмена не дошла, но сеанс ждал ответа пользователя: ожидание отменяется само, процесс не завершается.</summary>
    [Fact]
    public async Task Stop_CancelNotDelivered_DuringSignIn_EndsWithoutExit()
    {
        var lib = new FakeOcLib();
        var output = new RecordingOutput();
        var exits = 0;
        FailCancel(lib);
        lib.OnObtain = callbacks => callbacks.OpenWebview("https://sso.example.org/");
        var session = new OcSession(lib, output, new FakeSystem()) { ExitProcess = _ => Interlocked.Increment(ref exits) };

        var run = RunAsync(session);
        output.Next<SsoOpenEvent>(Wait);
        await Task.Run(() => session.Post(new StopCommand()), TestContext.Current.CancellationToken);

        Assert.Equal(TerminationKind.Cancelled, await run.WaitAsync(Wait, TestContext.Current.CancellationToken));
        Assert.Equal(0, exits);
        Assert.Equal(TerminationKind.Cancelled, Assert.Single(output.All.OfType<TerminatedEvent>()).Kind);
        session.Dispose();
    }

    /// <summary>
    /// Адаптер не перенастроен после переподключения, а отмена не дошла до цикла: служба сразу получает обрыв связи,
    /// а не ждёт, пока цикл на прежнем адресе когда-нибудь завершится. Второго Terminated потом нет.
    /// </summary>
    [Fact]
    public async Task ReconnectInterfaceFailure_CancelNotDelivered_ReportsNetworkErrorAtOnce()
    {
        var lib = new FakeOcLib();
        var output = new RecordingOutput();
        var system = new FakeSystem();
        using var mainloop = new ManualResetEventSlim();
        FailCancel(lib);
        lib.OnMainloop = () =>
        {
            system.ConfigureFailure = new InvalidOperationException("Адаптер не найден");
            try
            {
                lib.Callbacks!.Reconnected();
            }
            catch (IOException)
            {
                // Как Guard в NativeOcLib: исключение колбэка не пересекает границу библиотеки.
            }

            mainloop.Wait(Wait);
            return -5;
        };
        var session = new OcSession(lib, output, system) { ExitProcess = _ => { } };

        var run = RunAsync(session);
        try
        {
            var terminated = output.Next<TerminatedEvent>(Wait);
            Assert.Equal(TerminationKind.NetworkError, terminated.Kind);
            Assert.Contains("перенастроить адаптер", terminated.Text, StringComparison.Ordinal);
            Assert.False(run.IsCompleted);
        }
        finally
        {
            mainloop.Set();
        }

        await run.WaitAsync(Wait, TestContext.Current.CancellationToken);
        Assert.Single(output.All.OfType<TerminatedEvent>());
        session.Dispose();
    }

    /// <summary>Подробный журнал: отладочный дамп XML шлюза упоминает csd, а вход просто отклонён - это не HostScan.</summary>
    [Fact]
    public async Task VerboseDebugDumpMentioningCsd_AuthFailureIsNotHostScan()
    {
        var lib = new FakeOcLib();
        lib.OnObtain = callbacks =>
        {
            callbacks.ProcessForm(FakeField.Form(null, 0));
            callbacks.Log(OcCodes.PrgDebug, "< <config-auth client=\"vpn\" type=\"complete\"><csd token=\"\"/></config-auth>");
            return -OcCodes.Eperm;
        };
        var session = new OcSession(lib, new RecordingOutput(), new FakeSystem()) { Verbose = true };

        Assert.Equal(TerminationKind.AuthRejected, await RunAsync(session).WaitAsync(Wait, TestContext.Current.CancellationToken));
        session.Dispose();
    }

    /// <summary>Сообщение библиотеки об ошибке «шлюз просит HostScan» по-прежнему даёт HostScanRequired - в любом режиме журнала.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HostScanError_IsHostScanRequired(bool verbose)
    {
        var lib = new FakeOcLib();
        lib.OnObtain = callbacks =>
        {
            callbacks.ProcessForm(FakeField.Form(null, 0));
            callbacks.Log(OcCodes.PrgErr, "Error: Server asked us to run CSD hostscan.");
            return -OcCodes.Eperm;
        };
        var session = new OcSession(lib, new RecordingOutput(), new FakeSystem()) { Verbose = verbose };

        Assert.Equal(TerminationKind.HostScanRequired, await RunAsync(session).WaitAsync(Wait, TestContext.Current.CancellationToken));
        session.Dispose();
    }
}
