using System.Net;
using SplitVpn.Windows.Recovery;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Восстановление сети не сбрасывает 127.0.0.1 пользователя, пока на порту 53 есть его резолвер — в том
/// числе слушающий [::] сокетом двойного стека.
/// </summary>
public sealed class NetworkRecoveryListenerTests
{
    [Theory]
    [InlineData("127.0.0.1", 53, true)]
    [InlineData("0.0.0.0", 53, true)]
    [InlineData("::", 53, true)]
    [InlineData("::ffff:127.0.0.1", 53, true)]
    [InlineData("::1", 53, false)]
    [InlineData("192.168.1.10", 53, false)]
    [InlineData("127.0.0.1", 5353, false)]
    [InlineData("::", 5353, false)]
    public void ServesLoopbackResolver_SeesDualStackListener(string address, int port, bool expected)
    {
        Assert.Equal(expected, NetworkRecovery.ServesLoopbackResolver(new IPEndPoint(IPAddress.Parse(address), port)));
    }
}
