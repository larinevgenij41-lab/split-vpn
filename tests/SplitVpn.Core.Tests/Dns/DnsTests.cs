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

    /// <summary>Путь разрешения в ключе кеша: в тестах один и тот же, если не сказано иное.</summary>
    private const string Upstream = "5:1.1.1.1:53";

    [Fact]
    public void Cache_ExpiresOnline_ButServesShortStaleOffline()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UnixEpoch);
        var cache = new DnsCache(time);
        var query = DnsMessage.BuildQuery(1, "ya.ru", DnsMessage.TypeA);
        DnsMessage.TryReadQuestion(query, out var question);
        cache.Put(question, Upstream, DnsMessage.BuildAddressResponse(query, [Ipv4.Parse("5.255.255.242")], 120));

        var fresh = cache.TryGet(question, Upstream, 99, offline: false);
        Assert.NotNull(fresh);
        Assert.Equal(99, DnsMessage.GetId(fresh));
        Assert.Equal(120u, DnsMessage.GetMinTtl(fresh));

        time.Advance(TimeSpan.FromSeconds(200));
        Assert.Null(cache.TryGet(question, Upstream, 1, offline: false));
        var stale = cache.TryGet(question, Upstream, 1, offline: true);
        Assert.NotNull(stale);
        Assert.Equal(30u, DnsMessage.GetMinTtl(stale));
    }

    [Fact]
    public void Cache_IgnoresZeroTtlAndTruncated_AndPinsServerRecords()
    {
        var cache = new DnsCache(new FakeTimeProvider());
        var query = DnsMessage.BuildQuery(1, "x.example", DnsMessage.TypeA);
        DnsMessage.TryReadQuestion(query, out var question);
        cache.Put(question, Upstream, DnsMessage.BuildAddressResponse(query, [1u], 0));
        var truncated = DnsMessage.BuildAddressResponse(query, [1u], 60);
        truncated[2] |= 0x02;
        cache.Put(question, Upstream, truncated);

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
            cache.Put(question, Upstream, DnsMessage.BuildAddressResponse(query, [1u], 60));
            time.Advance(TimeSpan.FromMilliseconds(1));
        }

        Assert.True(cache.Count <= 10);
    }

    [Fact]
    public void Cache_SeparatesAnswersOfDifferentResolutionPaths()
    {
        var cache = new DnsCache(new FakeTimeProvider(DateTimeOffset.UnixEpoch));
        var query = DnsMessage.BuildQuery(1, "intranet.example", DnsMessage.TypeA);
        DnsMessage.TryReadQuestion(query, out var question);
        cache.Put(question, Upstream, DnsMessage.BuildAddressResponse(query, [Ipv4.Parse("10.0.0.5")], 300));

        // Тот же вопрос через другой DNS — другой ответ: смешивать их нельзя (split-DNS).
        Assert.NotNull(cache.TryGet(question, Upstream, 1, offline: false));
        Assert.Null(cache.TryGet(question, "7:203.0.113.53:53", 1, offline: false));
    }

    [Fact]
    public void Cache_StopsServingStaleAnswersAfterTheLimit()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UnixEpoch);
        var cache = new DnsCache(time);
        var query = DnsMessage.BuildQuery(1, "old.example", DnsMessage.TypeA);
        DnsMessage.TryReadQuestion(query, out var question);
        cache.Put(question, Upstream, DnsMessage.BuildAddressResponse(query, [Ipv4.Parse("203.0.113.7")], 60));

        time.Advance(TimeSpan.FromHours(2));
        Assert.NotNull(cache.TryGet(question, Upstream, 1, offline: true));

        time.Advance(DnsCache.MaxStaleAge);
        Assert.Null(cache.TryGet(question, Upstream, 1, offline: true));
    }

    [Fact]
    public void Answers_RequiresTheSameQuestion()
    {
        var query = DnsMessage.BuildQuery(0x2211, "private.example", DnsMessage.TypeA);
        var right = DnsMessage.BuildAddressResponse(query, [1u], 60);
        var wrong = DnsMessage.BuildAddressResponse(DnsMessage.BuildQuery(0x2211, "wrong.example", DnsMessage.TypeA), [2u], 60);
        var otherType = DnsMessage.BuildEmptyResponse(DnsMessage.BuildQuery(0x2211, "private.example", DnsMessage.TypeAaaa));

        Assert.True(DnsMessage.Answers(right, query));
        Assert.False(DnsMessage.Answers(wrong, query));
        Assert.False(DnsMessage.Answers(otherType, query));
        Assert.False(DnsMessage.Answers(query, query));
    }

    [Fact]
    public void ReadAddresses_TakesOnlyTheChainOfTheQuestion()
    {
        var query = DnsMessage.BuildQuery(5, "www.example.org", DnsMessage.TypeA);
        var response = Response(
            query,
            Record("www.example.org", DnsMessage.TypeCname, Name("cdn.example.net")),
            Record("cdn.example.net", DnsMessage.TypeA, Address("203.0.113.9")),
            Record("evil.example", DnsMessage.TypeA, Address("198.51.100.1")));

        Assert.Equal([Ipv4.Parse("203.0.113.9")], DnsMessage.ReadAddresses(response, "www.example.org"));
        Assert.Equal(2, DnsMessage.ReadAddresses(response).Count);
    }

    /// <summary>Ответ с произвольными записями: имена пишутся без сжатия, этого достаточно для разбора.</summary>
    private static byte[] Response(byte[] query, params byte[][] records)
    {
        var header = query.ToArray();
        header[2] = 0x80;
        header[3] = 0x80;
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(6), (ushort)records.Length);
        return records.Aggregate(header.AsEnumerable(), (all, r) => all.Concat(r)).ToArray();
    }

    private static byte[] Record(string owner, ushort type, byte[] data)
    {
        var head = new List<byte>(Name(owner));
        head.AddRange([(byte)(type >> 8), (byte)type, 0, (byte)DnsMessage.ClassIn, 0, 0, 0, 60, (byte)(data.Length >> 8), (byte)data.Length]);
        return [.. head, .. data];
    }

    private static byte[] Name(string name)
    {
        var bytes = new List<byte>();
        foreach (var label in name.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            bytes.Add((byte)label.Length);
            bytes.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }

        bytes.Add(0);
        return [.. bytes];
    }

    private static byte[] Address(string text)
    {
        var value = Ipv4.Parse(text);
        return [(byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value];
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
