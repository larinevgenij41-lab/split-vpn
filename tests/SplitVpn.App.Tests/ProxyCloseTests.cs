using System.Diagnostics;
using System.IO;
using SplitVpn.App.Services;
using SplitVpn.Core.Diagnostics;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.State;

namespace SplitVpn.App.Tests;

/// <summary>
/// Выход интерфейса не висит за зависшей фоновой синхронизацией прокси: ожидание ограничено, а после выхода
/// синхронизации, ждавшие очереди, прокси шлюза уже не ставят.
/// </summary>
public sealed class ProxyCloseTests
{
    private const string Pac = "http://gateway.test/proxy.pac";

    [Fact]
    public async Task Close_WhileSyncHangs_ReturnsWithinWait_AndRetryReverts()
    {
        var directory = Path.Combine(Path.GetTempPath(), "splitvpn-test-" + Guid.NewGuid().ToString("N"));
        var original = new ProxyState(1, null);
        using var settings = new BlockingProxy(original);
        try
        {
            using var proxy = new ProxyService(settings, directory) { MutexName = @"Local\SplitVpn.Test.ProxyClose." + Guid.NewGuid().ToString("N") };
            // Первая синхронизация доходит до записи PAC и зависает в ней, держа блокировку.
            settings.Block = true;
            var update = proxy.UpdateAsync(Connected(), stopped: false);
            Assert.True(settings.Entered.Wait(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken));

            var watch = Stopwatch.StartNew();
            Assert.False(proxy.Close(TimeSpan.FromMilliseconds(200)));
            watch.Stop();
            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), $"Close ждал {watch.Elapsed}");

            // Новая синхронизация после начала выхода прокси шлюза не ставит.
            var late = proxy.UpdateAsync(Connected(), stopped: false);
            settings.Block = false;
            settings.Release.Set();
            Assert.Null(await update);
            Assert.Null(await late);
            Assert.Equal(Pac, settings.State.AutoConfigUrl);

            // Повторный выход дожидается и снимает прокси.
            Assert.True(proxy.Close(TimeSpan.FromSeconds(30)));
            Assert.Equal(original, settings.State);
        }
        finally
        {
            settings.Release.Set();
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

    /// <summary>Прокси в памяти; пока <see cref="Block"/>, запись ждёт <see cref="Release"/>.</summary>
    private sealed class BlockingProxy(ProxyState state) : IProxySettings, IDisposable
    {
        public ProxyState State { get; private set; } = state;

        public bool Block { get; set; }

        public ManualResetEventSlim Entered { get; } = new();

        public ManualResetEventSlim Release { get; } = new();

        public ProxyState Read() => State;

        public void Write(ProxyState state)
        {
            if (Block)
            {
                Entered.Set();
                Release.Wait();
            }

            State = state;
        }

        public void Dispose()
        {
            Entered.Dispose();
            Release.Dispose();
        }
    }
}
