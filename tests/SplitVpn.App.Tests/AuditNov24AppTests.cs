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

    /// <summary>
    /// Обе блокировки; мьютекс занят посторонним — под одной файловой. Файловую держит живая копия того же
    /// пользователя — «занято»: действие не выполняется (прежде оно шло без блокировки параллельно с ней).
    /// </summary>
    [Fact]
    public void GateTakesBothLocks_FallsBackToFileLock_AndReportsBusyFile()
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
                // Файл держит первая копия: вторая не выполняет действие без блокировки, а получает «занято».
                Assert.Throws<UserGateBusyException>(() => UserGate.Enter(mutexName, lockFile, TimeSpan.FromMilliseconds(50), "Test"));
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
    /// Автозапуск после обновления из другого каталога: запись на удалённый SplitVpn.exe переписывается на текущий путь
    /// с теми же аргументами; существующий файл, чужое имя и уже верный путь не трогаются.
    /// </summary>
    [Theory]
    [InlineData("\"C:\\Program Files\\Old\\SplitVpn.exe\" --tray", "\"C:\\Program Files\\SplitVpn\\SplitVpn.exe\" --tray")]
    [InlineData("C:\\Old\\SplitVpn.exe --tray --x", "\"C:\\Program Files\\SplitVpn\\SplitVpn.exe\" --tray --x")]
    [InlineData("\"C:\\Old\\splitvpn.EXE\"", "\"C:\\Program Files\\SplitVpn\\SplitVpn.exe\"")]
    [InlineData("\"C:\\Old\\Other.exe\" --tray", null)]
    [InlineData("\"C:\\Program Files\\SplitVpn\\SplitVpn.exe\" --tray", null)]
    [InlineData("\"C:\\Old\\SplitVpn.exe --tray", null)]
    [InlineData("C:\\Old\\SplitVpn.exefile --tray", null)]
    public void AutostartRepair_RewritesOnlyMissingOwnExecutable(string command, string? expected)
    {
        const string current = "C:\\Program Files\\SplitVpn\\SplitVpn.exe";

        Assert.Equal(expected, Autostart.RepairedCommand(command, current, _ => false));
    }

    [Fact]
    public void AutostartRepair_KeepsExistingFile()
    {
        Assert.Null(Autostart.RepairedCommand("\"D:\\Dev\\SplitVpn.exe\" --tray", "C:\\Program Files\\SplitVpn\\SplitVpn.exe", _ => true));
    }

    /// <summary>Файловая блокировка недоступна (ошибка создания), а не занята: действие выполняется под одним мьютексом.</summary>
    [Fact]
    public void GateWithUnavailableLockFile_RunsUnderMutexOrWithout()
    {
        var directory = Path.Combine(Path.GetTempPath(), "splitvpn-test-" + Guid.NewGuid().ToString("N"));
        var mutexName = @"Local\SplitVpn.Test.Gate." + Guid.NewGuid().ToString("N");
        Directory.CreateDirectory(directory);
        // Каталог блокировки — на месте обычного файла: создать его нельзя.
        var blocker = Path.Combine(directory, "blocker");
        File.WriteAllText(blocker, "");
        var lockFile = Path.Combine(blocker, "gate.lock");
        try
        {
            using (var mutexOnly = UserGate.Enter(mutexName, lockFile, TimeSpan.FromMilliseconds(50), "Test"))
            {
                Assert.Equal((false, true), UserGate.Parts(mutexOnly));
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>Пока файловую блокировку держит другая копия, прокси не трогается и ошибки нет; после её освобождения — применяется.</summary>
    [Fact]
    public async Task ProxyWaitsWhileAnotherCopyHoldsFileLock()
    {
        var directory = Path.Combine(Path.GetTempPath(), "splitvpn-test-" + Guid.NewGuid().ToString("N"));
        var mutexName = @"Local\SplitVpn.Test.Proxy." + Guid.NewGuid().ToString("N");
        var settings = new MemoryProxy(new ProxyState(1, null));
        Directory.CreateDirectory(directory);
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
            using (new FileStream(Path.Combine(directory, "proxy-sync.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
            {
                Assert.Null(await proxy.UpdateAsync(connected, stopped: false));
                Assert.Null(settings.State.AutoConfigUrl);
            }

            Assert.Null(await proxy.UpdateAsync(connected, stopped: false));
            Assert.Equal("http://gateway.test/proxy.pac", settings.State.AutoConfigUrl);
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
                // Срок второй копии с запасом: первая освобождает файл только через 300 мс, а на загруженной машине позже.
                // Тот же срок вторая копия потом ждёт занятый посторонним мьютекс, поэтому он не 30 с: проверка шла бы
                // полминуты. Внешний предел — с запасом сверх обоих ожиданий.
                var second = Task.Run(() => UserGate.Enter(mutexName, lockFile, TimeSpan.FromSeconds(10), "Test"), TestContext.Current.CancellationToken);
                await Task.Delay(300, TestContext.Current.CancellationToken);
                Assert.False(second.IsCompleted);

                first!.Dispose();
                using var next = await second.WaitAsync(TimeSpan.FromSeconds(60), TestContext.Current.CancellationToken);
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
