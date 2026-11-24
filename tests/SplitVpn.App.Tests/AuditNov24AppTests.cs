using System.IO;
using System.Windows.Threading;
using SplitVpn.App.Services;
using SplitVpn.App.ViewModels;
using SplitVpn.Core.Diagnostics;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.State;

namespace SplitVpn.App.Tests;

/// <summary>Аудит 24.11: срок команды со службой и блокировки, которые может занять другой пользователь.</summary>
public sealed class AuditNov24AppTests
{
    [Fact]
    public async Task ElevatedWaitGivesUpAfterTimeout()
    {
        Assert.False(await WindowsServiceHost.ExitsWithinAsync(token => Task.Delay(Timeout.Infinite, token), TimeSpan.FromMilliseconds(50)));
        Assert.True(await WindowsServiceHost.ExitsWithinAsync(_ => Task.CompletedTask, TimeSpan.FromSeconds(5)));
        Assert.Contains("не остановилась за отведённое время", WindowsServiceHost.Overdue(ServiceHostAction.Restart), StringComparison.Ordinal);
    }

    [Fact]
    public Task HungStopReleasesServiceBlock() => RunStaAsync(async () =>
    {
        using var service = new ServiceConnection((_, _) => Task.FromResult(IpcResponse.Success(new StatusDto { State = ConnectionState.Disconnected })));
        using var main = new MainViewModel(service, new UiPreferences());
        main.Confirm = (_, _, _) => Task.FromResult(true);
        var overdue = WindowsServiceHost.Overdue(ServiceHostAction.Stop);
        var lossExpectedDuringStop = false;
        using var host = new ServiceHostViewModel(main)
        {
            QueryState = () => ServiceHostState.Running,
            ReadVersion = () => "1.0.0",
            RunElevated = async _ =>
            {
                lossExpectedDuringStop = main.ServiceLossExpected;
                await Task.Yield();
                return overdue;
            },
        };
        host.Show(ServiceHostState.Running, "1.0.0");

        await host.StopCommand.ExecuteAsync(null);

        Assert.True(lossExpectedDuringStop);
        Assert.False(main.ServiceLossExpected);
        Assert.True(host.View.CanStop && host.View.CanRestart);
        Assert.True(main.CurrentPage.MessageIsError);
        Assert.Equal(overdue, main.CurrentPage.Message);
    });

    [Fact]
    public async Task ProxyIsRemovedWhenMutexIsHeldElsewhere()
    {
        var directory = Path.Combine(Path.GetTempPath(), "splitvpn-test-" + Guid.NewGuid().ToString("N"));
        var mutexName = @"Local\SplitVpn.Test.Proxy." + Guid.NewGuid().ToString("N");
        var settings = new MemoryProxy(new ProxyState(1, null));
        try
        {
            using var proxy = new ProxyService(settings, directory) { MutexName = mutexName };
            var connected = new StatusDto
            {
                Tunnels =
                [
                    new TunnelStatusDto { State = ConnectionState.Connected, ServerNetworks = new ServerNetworksDto { ApplyProxy = true, ProxyPac = "http://gateway.test/proxy.pac" } },
                ],
            };
            Assert.Null(await proxy.UpdateAsync(connected, stopped: false));
            Assert.Equal("http://gateway.test/proxy.pac", settings.State.AutoConfigUrl);

            using (HoldMutex(mutexName))
            {
                Assert.Null(await proxy.UpdateAsync(null, stopped: true));
            }

            Assert.Equal(new ProxyState(1, null), settings.State);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void GateTakesBothLocks_FallsBackToFileLockAndThenRunsWithout()
    {
        var directory = Path.Combine(Path.GetTempPath(), "splitvpn-test-" + Guid.NewGuid().ToString("N"));
        var mutexName = @"Local\SplitVpn.Test.Gate." + Guid.NewGuid().ToString("N");
        var lockFile = Path.Combine(directory, "gate.lock");
        try
        {
            using (var both = UserGate.Enter(mutexName, lockFile, TimeSpan.FromMilliseconds(50), "Test"))
            {
                Assert.Equal((true, true), UserGate.Parts(both));
            }

            using (HoldMutex(mutexName))
            {
                using var first = UserGate.Enter(mutexName, lockFile, TimeSpan.FromMilliseconds(50), "Test");
                Assert.Equal((true, false), UserGate.Parts(first));
                // Заняты и мьютекс, и файл: действие всё равно выполняется, без блокировки.
                Assert.Null(UserGate.Enter(mutexName, lockFile, TimeSpan.FromMilliseconds(50), "Test"));
            }

            // Мьютекс и файл освобождены (в том числе при Dispose занятой только файловой).
            using var free = UserGate.Enter(mutexName, lockFile, TimeSpan.FromMilliseconds(50), "Test");
            Assert.Equal((true, true), UserGate.Parts(free));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Имя мьютекса занял посторонний: две копии интерфейса одного пользователя всё равно исключают друг друга по
    /// файловой блокировке. Прежде при таймауте мьютекса каждая брала файл, а законная копия с мьютексом файл не держала.
    /// </summary>
    [Fact]
    public async Task GateWithSquattedMutex_StillExcludesSecondCopyByFile()
    {
        var directory = Path.Combine(Path.GetTempPath(), "splitvpn-test-" + Guid.NewGuid().ToString("N"));
        var mutexName = @"Local\SplitVpn.Test.Gate." + Guid.NewGuid().ToString("N");
        var lockFile = Path.Combine(directory, "gate.lock");
        try
        {
            using (HoldMutex(mutexName))
            {
                var first = UserGate.Enter(mutexName, lockFile, TimeSpan.FromMilliseconds(50), "Test");
                Assert.Equal((true, false), UserGate.Parts(first));
                var second = Task.Run(() => UserGate.Enter(mutexName, lockFile, TimeSpan.FromSeconds(2), "Test"), TestContext.Current.CancellationToken);
                await Task.Delay(300, TestContext.Current.CancellationToken);
                Assert.False(second.IsCompleted);

                first!.Dispose();
                using var next = await second.WaitAsync(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken);
                Assert.True(UserGate.Parts(next).File);
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>Мьютекс, который держит другой поток (как другой процесс): освобождается при Dispose.</summary>
    private static Release HoldMutex(string name)
    {
        var held = new ManualResetEventSlim();
        var release = new ManualResetEventSlim();
        var thread = new Thread(() =>
        {
            using var mutex = new Mutex(true, name);
            held.Set();
            release.Wait();
            mutex.ReleaseMutex();
        });
        thread.Start();
        held.Wait(TestContext.Current.CancellationToken);
        return new Release(() =>
        {
            release.Set();
            thread.Join();
            held.Dispose();
            release.Dispose();
        });
    }

    private sealed class Release(Action action) : IDisposable
    {
        public void Dispose() => action();
    }

    private sealed class MemoryProxy(ProxyState state) : IProxySettings
    {
        public ProxyState State { get; private set; } = state;

        public ProxyState Read() => State;

        public void Write(ProxyState state) => State = state;
    }

    private static Task RunStaAsync(Func<Task> action)
    {
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            var dispatcher = Dispatcher.CurrentDispatcher;
            SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(dispatcher));
            dispatcher.BeginInvoke(new Action(async () =>
            {
                try { await action(); completion.TrySetResult(); }
                catch (Exception ex) { completion.TrySetException(ex); }
                finally { dispatcher.BeginInvokeShutdown(DispatcherPriority.Background); }
            }));
            Dispatcher.Run();
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        return completion.Task.WaitAsync(TimeSpan.FromSeconds(15), TestContext.Current.CancellationToken);
    }
}
