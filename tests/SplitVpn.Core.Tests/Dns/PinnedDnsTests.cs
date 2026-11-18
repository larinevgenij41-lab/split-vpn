using Microsoft.Extensions.Time.Testing;
using SplitVpn.Core.Dns;

namespace SplitVpn.Core.Tests.Dns;

public sealed class PinnedDnsTests
{
    [Fact]
    public void Clear_AfterRoutingChangeDropsTemporaryAnswersButKeepsVpnBootstrap()
    {
        var cache = new DnsCache(new FakeTimeProvider());
        cache.Pin("vpn.example", [1u]);
        cache.Pin("crl.example", [2u], TimeSpan.FromHours(1));

        cache.Clear();

        Assert.True(cache.TryGetPinned("vpn.example", out _));
        Assert.False(cache.TryGetPinned("crl.example", out _));
    }

    [Fact]
    public void TemporaryPin_ExpiresAndCanBeRefreshed()
    {
        var time = new FakeTimeProvider();
        var cache = new DnsCache(time);
        cache.Pin("crl.example", [1u], TimeSpan.FromMinutes(5));
        time.Advance(TimeSpan.FromMinutes(4));
        cache.Pin("crl.example", [2u], TimeSpan.FromMinutes(5));
        time.Advance(TimeSpan.FromMinutes(4));
        Assert.True(cache.TryGetPinned("CRL.Example.", out var addresses));
        Assert.Equal([2u], addresses);
        time.Advance(TimeSpan.FromMinutes(1));
        Assert.False(cache.TryGetPinned("crl.example", out _));
    }

    [Fact]
    public void RetainPins_RemovesRetiredProfilesButPreservesLiveTemporaryNames()
    {
        var time = new FakeTimeProvider();
        var cache = new DnsCache(time);
        cache.Pin("old.example", [1u]);
        cache.Pin("vpn.example", [2u]);
        cache.Pin("crl.example", [3u], TimeSpan.FromMinutes(5));
        cache.RetainPins(["VPN.Example."]);
        Assert.False(cache.TryGetPinned("old.example", out _));
        Assert.True(cache.TryGetPinned("vpn.example", out _));
        Assert.True(cache.TryGetPinned("crl.example", out _));
        time.Advance(TimeSpan.FromDays(2));
        cache.RetainPins(["vpn.example"]);
        Assert.True(cache.TryGetPinned("vpn.example", out _));
        Assert.False(cache.TryGetPinned("crl.example", out _));
    }

    [Fact]
    public void TemporaryLookup_DoesNotExpirePinnedVpnServer()
    {
        var time = new FakeTimeProvider();
        var cache = new DnsCache(time);
        cache.Pin("vpn.example", [1u]);
        cache.Pin("vpn.example", [1u], TimeSpan.FromMinutes(1));
        time.Advance(TimeSpan.FromDays(1));
        Assert.True(cache.TryGetPinned("vpn.example", out _));
    }
}
