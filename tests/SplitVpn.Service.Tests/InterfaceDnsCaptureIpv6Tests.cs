using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Native;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Снимок DNS адаптера, у которого IPv6-настройки не читаются: какой бы код ни вернула система, снимок создаётся,
/// а IPv6-часть берётся из прежней копии (или пустая). Иначе адаптер не переводился бы на посредник.
/// </summary>
public sealed class InterfaceDnsCaptureIpv6Tests
{
    private static readonly Guid Adapter = new("eeeeeeee-0000-0000-0000-000000000006");

    private static Func<Guid, bool, InterfaceDnsState> FailingIpv6(uint code) => (_, ipv6) => ipv6
        ? throw new NativeCallException("GetInterfaceDnsSettings", code)
        : new InterfaceDnsState("192.0.2.53", "", 0, "home.test");

    [Theory]
    [InlineData(87u)]
    [InlineData(2u)]
    [InlineData(1168u)]
    [InlineData(5u)]
    public void Capture_Ipv6ReadFailure_KeepsPreviousIpv6(uint code)
    {
        var previous = new InterfaceDnsBackup(Adapter, "192.0.2.1", "2001:db8::53", "", 0, default, "home.test");

        var backup = InterfaceDnsOps.Capture(Adapter, previous, DateTimeOffset.UnixEpoch, ownsIpv6Loopback: false, FailingIpv6(code));

        Assert.Equal("2001:db8::53", backup.NameServerV6);
        Assert.Equal("192.0.2.53", backup.NameServerV4);
    }

    [Fact]
    public void Capture_Ipv6ReadFailure_WithoutPreviousBackup_LeavesIpv6Empty()
    {
        var backup = InterfaceDnsOps.Capture(Adapter, null, DateTimeOffset.UnixEpoch, ownsIpv6Loopback: true, FailingIpv6(87));

        Assert.Equal("", backup.NameServerV6);
        Assert.Equal("192.0.2.53", backup.NameServerV4);
        Assert.Equal("home.test", backup.AppliedSearchList);
    }

    [Fact]
    public void Capture_Ipv4ReadFailure_StillThrows()
    {
        Func<Guid, bool, InterfaceDnsState> read = (_, _) => throw new NativeCallException("GetInterfaceDnsSettings", 87);

        Assert.Throws<NativeCallException>(() => InterfaceDnsOps.Capture(Adapter, null, DateTimeOffset.UnixEpoch, ownsIpv6Loopback: false, read));
    }

    [Fact]
    public void Capture_ReadsIpv6WhenAvailable()
    {
        Func<Guid, bool, InterfaceDnsState> read = (_, ipv6) => new InterfaceDnsState(ipv6 ? "2001:db8::1" : "192.0.2.53", "", 0, "");

        var backup = InterfaceDnsOps.Capture(Adapter, null, DateTimeOffset.UnixEpoch, ownsIpv6Loopback: false, read);

        Assert.Equal("2001:db8::1", backup.NameServerV6);
    }
}
