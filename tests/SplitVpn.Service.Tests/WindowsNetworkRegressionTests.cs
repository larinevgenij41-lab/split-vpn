using System.Buffers.Binary;
using System.Net;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Net;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.SshTunnel;

namespace SplitVpn.Service.Tests;

public sealed class WindowsNetworkRegressionTests
{
    [Fact]
    public void SshHealthRequiresEstablishedFlowOfTheOwnedProcessToTheConfiguredPort()
    {
        var table = new byte[28];
        BinaryPrimitives.WriteInt32LittleEndian(table, 1);
        BinaryPrimitives.WriteInt32LittleEndian(table.AsSpan(4), 5);
        var address = Ipv4.Parse("203.0.113.11");
        BinaryPrimitives.WriteUInt32BigEndian(table.AsSpan(16), address);
        BinaryPrimitives.WriteUInt16BigEndian(table.AsSpan(20), 2222);
        BinaryPrimitives.WriteInt32LittleEndian(table.AsSpan(24), 343);
        Assert.True(SshTcpConnections.Find(table, 343, address, 2222));
        Assert.False(SshTcpConnections.Find(table, 344, address, 2222));
        Assert.False(SshTcpConnections.Find(table, 343, address, 22));
        Assert.Null(SshTcpConnections.Find(table.AsSpan(0, 18), 343, address, 2222));
    }

    [Fact]
    public void TruncatedAnswerRequiresOurTcpListenerEvenForSmallResponses()
    {
        var query = DnsMessage.BuildQuery(42, "vpn.example", DnsMessage.TypeA);
        var response = DnsMessage.BuildEmptyResponse(query);
        response[2] |= 2;
        Assert.Equal(2, DnsMessage.GetRcode(DnsProxyServer.FitUdp(query, response, tcpOurs: false)));
        Assert.True(DnsMessage.IsTruncated(DnsProxyServer.FitUdp(query, response)));
    }

    [Fact]
    public async Task UnsupportedOpcodeCannotReuseAStandardAnswer()
    {
        await using var server = new DnsProxyServer(IPAddress.Loopback, new DnsCache(TimeProvider.System));
        var query = DnsMessage.BuildQuery(41, "vpn.example", DnsMessage.TypeA);
        query[2] |= 0x10;
        var response = await server.HandleAsync(query, TestContext.Current.CancellationToken);
        Assert.NotNull(response);
        Assert.Equal(4, DnsMessage.GetRcode(response));
        Assert.Equal(0x10, response[2] & 0x78);
    }

    [Fact]
    public void FailedRouteSwitchPreservesOnlyPathsStillPermittedByThePlan()
    {
        var old = new RouteKey(Ipv4Cidr.Parse("198.51.100.11/32"), 0, 105);
        var subnet = old with { Destination = Ipv4Cidr.Parse("198.51.100.0/24") };
        Assert.True(RouteOps.StillPermitted(old, [subnet]));
        Assert.False(RouteOps.StillPermitted(old, [subnet with { InterfaceLuid = 301 }]));
    }

    [Fact]
    public void HostsLoopbackIsAuthoritativeForBootstrap()
    {
        Assert.Equal([Ipv4.Parse("127.0.0.1")], HostsFile.Parse(["127.0.0.1 gateway.example"], "gateway.example"));
    }
}
