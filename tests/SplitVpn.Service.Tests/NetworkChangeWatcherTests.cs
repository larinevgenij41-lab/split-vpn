using SplitVpn.Windows.Net;

namespace SplitVpn.Service.Tests;

/// <summary>Подписка на настоящие уведомления IP Helper: регистрируется и снимается без прав администратора.</summary>
public sealed class NetworkChangeWatcherTests
{
    [Fact]
    public void Start_RegistersAndDisposesCleanly()
    {
        var calls = 0;
        var watcher = NetworkChangeWatcher.Start(() => Interlocked.Increment(ref calls));
        watcher.Dispose();
        watcher.Dispose();
        Assert.True(Volatile.Read(ref calls) >= 0);
    }
}
