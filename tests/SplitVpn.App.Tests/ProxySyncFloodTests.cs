using System.Diagnostics;
using System.IO;
using SplitVpn.App.Services;
using SplitVpn.Core.Diagnostics;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.State;

namespace SplitVpn.App.Tests;

/// <summary>
/// Ревью стабильности 25.11 (L-4): синхронизация прокси на каждом обновлении статуса не берёт межпроцессные
/// блокировки, когда делать нечего, а недоступная блокировка даёт одну строку журнала на смену состояния.
/// </summary>
[Collection(nameof(VerboseSinkGroup))]
public sealed class ProxySyncFloodTests
{
    private const string Pac = "http://gateway.test/proxy.pac";

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnchangedStatus_WithHeldMutex_DoesNotWaitOrWarnEveryTime(bool withPac)
    {
        var directory = Path.Combine(Path.GetTempPath(), "splitvpn-test-" + Guid.NewGuid().ToString("N"));
        var mutexName = @"Local\SplitVpn.Test.ProxyFlood." + Guid.NewGuid().ToString("N");
        var settings = new MemoryProxy(new ProxyState(1, null));
        var warnings = new List<string>();
        var sink = Verbose.Sink;
        Verbose.Sink = (area, text) =>
        {
            if (text.Contains(mutexName, StringComparison.Ordinal))
            {
                lock (warnings) { warnings.Add(text); }
            }
        };
        try
        {
            using var proxy = new ProxyService(settings, directory) { MutexName = mutexName };
            var status = withPac ? Connected() : new StatusDto();
            using (HoldMutex(mutexName))
            {
                var watch = Stopwatch.StartNew();
                for (var i = 0; i < 100; i++)
                {
                    Assert.Null(await proxy.UpdateAsync(status, stopped: false));
                }

                watch.Stop();
                // Ожидание мьютекса (2 с) - только у первой синхронизации, остальным делать нечего.
                Assert.True(watch.Elapsed < TimeSpan.FromSeconds(10), $"100 синхронизаций заняли {watch.Elapsed}");
                lock (warnings) { Assert.Single(warnings); }
                Assert.Equal(withPac ? Pac : null, settings.State.AutoConfigUrl);

                // Отключение по-прежнему снимает прокси, даже пока мьютекс занят.
                Assert.Null(await proxy.UpdateAsync(new StatusDto(), stopped: false));
                Assert.Equal(new ProxyState(1, null), settings.State);
            }
        }
        finally
        {
            Verbose.Sink = sink;
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>Сохранённая копия после аварийного выхода: первая синхронизация её снимает, а не пропускается.</summary>
    [Fact]
    public async Task BackupLeftByCrash_IsRestoredOnFirstSync()
    {
        var directory = Path.Combine(Path.GetTempPath(), "splitvpn-test-" + Guid.NewGuid().ToString("N"));
        var mutexName = @"Local\SplitVpn.Test.ProxyCrash." + Guid.NewGuid().ToString("N");
        var settings = new MemoryProxy(new ProxyState(1, null));
        try
        {
            // Прежняя копия интерфейса применила PAC и завершилась аварийно: копия осталась.
            var crashed = new ProxyService(settings, directory) { MutexName = mutexName };
            Assert.Null(await crashed.UpdateAsync(Connected(), stopped: false));
            Assert.Equal(Pac, settings.State.AutoConfigUrl);

            using var proxy = new ProxyService(settings, directory) { MutexName = mutexName };
            Assert.Null(await proxy.UpdateAsync(new StatusDto(), stopped: false));
            Assert.Equal(new ProxyState(1, null), settings.State);
            Assert.Null(await proxy.UpdateAsync(new StatusDto(), stopped: false));
            crashed.Dispose();
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>Предупреждение о недоступной блокировке - одно на смену состояния, и одна запись о её возвращении.</summary>
    [Fact]
    public void GateWarnsOncePerStateChange()
    {
        var directory = Path.Combine(Path.GetTempPath(), "splitvpn-test-" + Guid.NewGuid().ToString("N"));
        var mutexName = @"Local\SplitVpn.Test.GateFlood." + Guid.NewGuid().ToString("N");
        var lockFile = Path.Combine(directory, "gate.lock");
        var lines = new List<string>();
        var sink = Verbose.Sink;
        Verbose.Sink = (_, text) =>
        {
            if (text.Contains(mutexName, StringComparison.Ordinal))
            {
                lock (lines) { lines.Add(text); }
            }
        };
        try
        {
            using (HoldMutex(mutexName))
            {
                for (var i = 0; i < 5; i++)
                {
                    using var gate = UserGate.Enter(mutexName, lockFile, TimeSpan.FromMilliseconds(20), "Test");
                    Assert.Equal((true, false), UserGate.Parts(gate));
                }
            }

            for (var i = 0; i < 5; i++)
            {
                using var gate = UserGate.Enter(mutexName, lockFile, TimeSpan.FromMilliseconds(20), "Test");
                Assert.Equal((true, true), UserGate.Parts(gate));
            }

            using (HoldMutex(mutexName))
            {
                using var gate = UserGate.Enter(mutexName, lockFile, TimeSpan.FromMilliseconds(20), "Test");
            }

            lock (lines)
            {
                Assert.Equal(3, lines.Count);
                Assert.Contains("недоступна", lines[0], StringComparison.Ordinal);
                Assert.Contains("снова доступны", lines[1], StringComparison.Ordinal);
                Assert.Contains("недоступна", lines[2], StringComparison.Ordinal);
            }
        }
        finally
        {
            Verbose.Sink = sink;
            Directory.Delete(directory, recursive: true);
        }
    }

    private static StatusDto Connected() => new()
    {
        Tunnels =
        [
            new TunnelStatusDto { State = ConnectionState.Connected, ServerNetworks = new ServerNetworksDto { ApplyProxy = true, ProxyPac = Pac } },
        ],
    };

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
}

/// <summary>Проверки, подменяющие общий для процесса Verbose.Sink, идут не параллельно друг другу.</summary>
[CollectionDefinition(nameof(VerboseSinkGroup), DisableParallelization = true)]
public sealed class VerboseSinkGroup;
