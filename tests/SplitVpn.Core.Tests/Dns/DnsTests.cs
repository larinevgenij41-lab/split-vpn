using System.Buffers.Binary;
using Microsoft.Extensions.Time.Testing;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Net;

namespace SplitVpn.Core.Tests.Dns;

public class DnsTests
{
    [Fact]
    public void Query_RoundTripsQuestion()
    {
        var query = DnsMessage.BuildQuery(0x1234, "SSTP.Example.COM.", DnsMessage.TypeA);

        Assert.True(DnsMessage.TryReadQuestion(query, out var question));
        Assert.Equal("sstp.example.com", question.Name);
        Assert.Equal(DnsMessage.TypeA, question.Type);
        Assert.Equal(0x1234, DnsMessage.GetId(query));
        Assert.False(DnsMessage.IsResponse(query));
    }

    [Fact]
    public void AddressResponse_IsReadableWithCompressedNames()
    {
        var query = DnsMessage.BuildQuery(7, "vpn.example.com", DnsMessage.TypeA);
        var addresses = new[] { Ipv4.Parse("203.0.113.20"), Ipv4.Parse("203.0.113.10") };

        var response = DnsMessage.BuildAddressResponse(query, addresses, 300);

        Assert.True(DnsMessage.IsResponse(response));
        Assert.Equal(addresses, DnsMessage.ReadAddresses(response));
        Assert.Equal(300u, DnsMessage.GetMinTtl(response));
        Assert.True(DnsMessage.TryReadQuestion(response, out var question));
        Assert.Equal("vpn.example.com", question.Name);
    }

    [Fact]
    public void RewriteTtls_SkipsOptRecord()
    {
        var response = WithOpt(DnsMessage.BuildAddressResponse(DnsMessage.BuildQuery(1, "a.b", DnsMessage.TypeA), [1u], 600));

        Assert.True(DnsMessage.RewriteTtls(response, 30));

        Assert.Equal(30u, DnsMessage.GetMinTtl(response));
        // TTL-поле OPT содержит расширенный RCODE и флаги — оно не должно измениться.
        Assert.Equal(0x00008000u, BinaryPrimitives.ReadUInt32BigEndian(response.AsSpan(response.Length - 6)));
    }

    [Fact]
    public void ServerFailure_KeepsIdAndQuestion()
    {
        var query = DnsMessage.BuildQuery(0xBEEF, "example.org", DnsMessage.TypeAaaa);

        var failure = DnsMessage.BuildServerFailure(query);

        Assert.Equal(0xBEEF, DnsMessage.GetId(failure));
        Assert.Equal(2, DnsMessage.GetRcode(failure));
        Assert.True(DnsMessage.TryReadQuestion(failure, out var q));
        Assert.Equal(DnsMessage.TypeAaaa, q.Type);
    }

    [Theory]
    [InlineData(new byte[] { })]
    [InlineData(new byte[] { 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 })]
    [InlineData(new byte[] { 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C })]
    [InlineData(new byte[] { 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 5, (byte)'a' })]
    public void MalformedMessages_AreRejected(byte[] message)
    {
        Assert.False(DnsMessage.TryReadQuestion(message, out _));
        Assert.Null(DnsMessage.GetMinTtl(message.Length >= 12 ? AsResponseWithAnswer(message) : message));
    }

    [Fact]
    public void Cache_ExpiresOnline_ButServesShortStaleOffline()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UnixEpoch);
        var cache = new DnsCache(time);
        var query = DnsMessage.BuildQuery(1, "ya.ru", DnsMessage.TypeA);
        DnsMessage.TryReadQuestion(query, out var question);
        cache.Put(question, DnsMessage.BuildAddressResponse(query, [Ipv4.Parse("5.255.255.242")], 120));

        var fresh = cache.TryGet(question, 99, offline: false);
        Assert.NotNull(fresh);
        Assert.Equal(99, DnsMessage.GetId(fresh));
        Assert.Equal(120u, DnsMessage.GetMinTtl(fresh));

        time.Advance(TimeSpan.FromSeconds(200));
        Assert.Null(cache.TryGet(question, 1, offline: false));
        var stale = cache.TryGet(question, 1, offline: true);
        Assert.NotNull(stale);
        Assert.Equal(30u, DnsMessage.GetMinTtl(stale));
    }

    [Fact]
    public void Cache_IgnoresZeroTtlAndTruncated_AndPinsServerRecords()
    {
        var cache = new DnsCache(new FakeTimeProvider());
        var query = DnsMessage.BuildQuery(1, "x.example", DnsMessage.TypeA);
        DnsMessage.TryReadQuestion(query, out var question);
        cache.Put(question, DnsMessage.BuildAddressResponse(query, [1u], 0));
        var truncated = DnsMessage.BuildAddressResponse(query, [1u], 60);
        truncated[2] |= 0x02;
        cache.Put(question, truncated);

        Assert.Equal(0, cache.Count);

        cache.Pin("VPN.Example.", [Ipv4.Parse("203.0.113.20")]);
        Assert.True(cache.TryGetPinned("vpn.example", out var pinned));
        Assert.Single(pinned);
    }

    [Fact]
    public void Cache_EvictsOldestWhenFull()
    {
        var time = new FakeTimeProvider();
        var cache = new DnsCache(time, capacity: 10);
        for (var i = 0; i < 25; i++)
        {
            var query = DnsMessage.BuildQuery(1, $"n{i}.example", DnsMessage.TypeA);
            DnsMessage.TryReadQuestion(query, out var question);
            cache.Put(question, DnsMessage.BuildAddressResponse(query, [1u], 60));
            time.Advance(TimeSpan.FromMilliseconds(1));
        }

        Assert.True(cache.Count <= 10);
    }

    private static byte[] WithOpt(byte[] response)
    {
        // Добавить OPT-запись: корневое имя, тип 41, UDP 1232, TTL 0x00008000 (DO), RDLEN 0.
        var opt = new byte[] { 0, 0, 41, 0x04, 0xD0, 0x00, 0x00, 0x80, 0x00, 0, 0 };
        var result = response.Concat(opt).ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(10), 1);
        return result;
    }

    private static byte[] AsResponseWithAnswer(byte[] message)
    {
        var copy = message.ToArray();
        copy[7] = 1; // ANCOUNT = 1 без данных записи
        return copy;
    }
}
