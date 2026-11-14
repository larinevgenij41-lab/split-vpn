using SplitVpn.Windows.Net;
using Windows.Win32.NetworkManagement.IpHelper;

namespace SplitVpn.Service.Tests;

/// <summary>Подписка на уведомления IP Helper и отбор маршрутов, по которым служба сверяется.</summary>
public sealed class NetworkChangeWatcherTests
{
    /// <summary>Настоящая регистрация без прав администратора; повторное снятие подписки безопасно.</summary>
    [Fact]
    public void Start_RegistersAndDisposesTwiceWithoutError()
    {
        var watcher = NetworkChangeWatcher.Start(() => { });

        watcher.Dispose();
        var second = Record.Exception(watcher.Dispose);

        Assert.Null(second);
    }

    [Fact]
    public void Start_NullHandler_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => NetworkChangeWatcher.Start(null!));
    }

    /// <summary>
    /// Сверку вызывает только маршрут по умолчанию: служба сама ставит тысячи маршрутов, и уведомление о
    /// каждом из них запускало бы сверку по кругу.
    /// </summary>
    [Theory]
    [InlineData(0, true)]
    [InlineData(1, false)]
    [InlineData(24, false)]
    [InlineData(32, false)]
    public void IsRelevantRoute_OnlyDefaultRoute(byte prefixLength, bool expected)
    {
        var row = new MIB_IPFORWARD_ROW2();
        row.DestinationPrefix.PrefixLength = prefixLength;

        Assert.Equal(expected, NetworkChangeWatcher.IsRelevantRoute(in row));
    }
}
