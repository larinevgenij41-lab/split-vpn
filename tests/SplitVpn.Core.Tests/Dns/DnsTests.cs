using System.Buffers.Binary;
using Microsoft.Extensions.Time.Testing;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Net;

namespace SplitVpn.Core.Tests.Dns;

public class DnsTests
{
    [Theory]
    [InlineData(0u)]
    [InlineData(30u)]
    public void CapTtls_PreservesShortTtlAndOpt(uint shortTtl)
    {
        var query = DnsMessage.BuildQuery(1, "example.com", DnsMessage.TypeA);
        var response = WithOpt(DnsMessage.BuildAddressResponse(query, [1u, 2u], 86400));
        BinaryPrimitives.WriteUInt32BigEndian(response.AsSpan(query.Length + 6), shortTtl);
        var opt = response[^11..].ToArray();

        DnsMessage.CapTtls(response, 3600);

        Assert.Equal(shortTtl, BinaryPrimitives.ReadUInt32BigEndian(response.AsSpan(query.Length + 6)));
        Assert.Equal(3600u, BinaryPrimitives.ReadUInt32BigEndian(response.AsSpan(query.Length + 22)));
        Assert.Equal(opt, response[^11..]);
    }

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

    [Fact]
    public void Names_EscapeDotsAndNonAsciiInsideLabels()
    {
        // Одна метка «evil.example» и метка «org» — не то же имя, что evil.example.org.
        byte[] owner = [12, .. System.Text.Encoding.ASCII.GetBytes("evil.example"), 3, (byte)'o', (byte)'r', (byte)'g', 0];
        var query = DnsMessage.BuildQuery(9, "evil.example.org", DnsMessage.TypeA);
        var response = Response(query, [.. owner, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, .. Address("198.51.100.1")]);
        byte[] rawQuery = [.. query[..12], 3, (byte)'a', 0xC3, (byte)'_', 2, (byte)'r', (byte)'u', 0, 0, 1, 0, 1];

        Assert.Empty(DnsMessage.ReadAddresses(response, "evil.example.org"));
        Assert.Single(DnsMessage.ReadAddresses(response));
        Assert.True(DnsMessage.TryReadQuestion(rawQuery, out var question));
        Assert.Equal("a\\195_.ru", question.Name);
    }

    [Theory]
    [InlineData(3600u, 60u, 60u)]
    [InlineData(30u, 900u, 30u)]
    public void NegativeResponse_IsCachedForMinOfSoaTtlAndMinimum(uint ttl, uint minimum, uint expected)
    {
        var query = DnsMessage.BuildQuery(3, "missing.example.org", DnsMessage.TypeA);
        var soa = new List<byte>(Name("example.org"));
        soa.AddRange([0, 6, 0, 1, (byte)(ttl >> 24), (byte)(ttl >> 16), (byte)(ttl >> 8), (byte)ttl]);
        var data = new List<byte>(Name("ns.example.org"));
        data.AddRange(Name("admin.example.org"));
        foreach (var value in new uint[] { 1, 7200, 900, 1209600, minimum })
        {
            data.AddRange([(byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value]);
        }

        soa.AddRange([(byte)(data.Count >> 8), (byte)data.Count, .. data]);
        var response = Response(query, [.. soa]);
        response[3] = 0x83; // NXDOMAIN
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(6), 0);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(8), 1);

        Assert.Equal(expected, DnsMessage.GetMinTtl(response));
    }

    [Theory]
    [InlineData(true, 60u)]
    [InlineData(false, 600u)]
    public void NxDomainAfterCname_UsesSoaMinimum_ButSoaAnswerKeepsItsTtl(bool authority, uint expected)
    {
        // CNAME TTL 600 и SOA TTL 600 с MINIMUM 60. SOA в полномочиях — отрицательный ответ: срок 60 (RFC 2308).
        // SOA в секции ответа (запрос типа SOA) — обычная запись: MINIMUM к ней не применяется.
        var query = DnsMessage.BuildQuery(3, "www.example.org", DnsMessage.TypeA);
        var data = new List<byte>(Name("ns.example.org"));
        data.AddRange(Name("admin.example.org"));
        foreach (var value in new uint[] { 1, 7200, 900, 1209600, 60 })
        {
            data.AddRange([(byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value]);
        }

        var soa = WithTtl(Record("example.org", DnsMessage.TypeSoa, [.. data]), 600);
        var cname = WithTtl(Record("www.example.org", DnsMessage.TypeCname, Name("gone.example.org")), 600);
        var response = authority ? Response(query, cname, soa) : Response(query, soa);
        if (authority)
        {
            response[3] = 0x83; // NXDOMAIN
            BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(6), 1);
            BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(8), 1);
        }

        Assert.Equal(expected, DnsMessage.GetMinTtl(response));
    }

    [Fact]
    public void QueryFlags_DistinguishRecursionAndEdnsOptions()
    {
        var plain = DnsMessage.BuildQuery(1, "site.example", DnsMessage.TypeA);
        var noRecursion = plain.ToArray();
        noRecursion[2] &= 0xFE;
        byte[] cookie = [0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        byte[] otherCookie = [0, 10, 0, 8, 8, 7, 6, 5, 4, 3, 2, 1];

        var flags = new[] { plain, noRecursion, WithOptData(plain, cookie), WithOptData(plain, otherCookie), WithOptData(plain, []) }
            .Select(q => DnsMessage.ReadQueryFlags(q)).ToList();

        Assert.Equal(default, flags[0]);
        Assert.True(flags[1].NoRecursion);
        Assert.Equal("000A00080102030405060708", flags[2].EdnsOptions);
        Assert.Equal(5, flags.Distinct().Count());

        // Обычный запрос с OPT без опций — тот же ключ, что и раньше: попадания в кеш не теряются.
        Assert.Equal(new DnsQueryFlags(false, true, false), flags[4]);
    }

    private static byte[] WithTtl(byte[] record, uint ttl)
    {
        var nameLength = Array.IndexOf(record, (byte)0) + 1;
        BinaryPrimitives.WriteUInt32BigEndian(record.AsSpan(nameLength + 4), ttl);
        return record;
    }

    private static byte[] WithOptData(byte[] query, byte[] options)
    {
        var result = new byte[query.Length + 11 + options.Length];
        query.CopyTo(result, 0);
        result[11] = 1; // ARCOUNT
        var offset = query.Length;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset + 1), DnsMessage.TypeOpt);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset + 3), 1232);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset + 9), (ushort)options.Length);
        options.CopyTo(result, offset + 11);
        return result;
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

    /// <summary>Ответ, собранный самим прокси, на запрос с OPT несёт свою запись OPT (RFC 6891 §7).</summary>
    [Fact]
    public void SynthesizedReplies_CarryOptWhenQueryHasIt()
    {
        var query = WithOptData(DnsMessage.BuildQuery(1, "example.com", DnsMessage.TypeA), []);
        var plain = DnsMessage.BuildQuery(1, "example.com", DnsMessage.TypeA);

        Assert.True(DnsMessage.ReadEdns(DnsMessage.BuildEmptyResponse(query)).Present);
        Assert.True(DnsMessage.ReadEdns(DnsMessage.BuildServerFailure(query)).Present);
        Assert.True(DnsMessage.ReadEdns(DnsMessage.BuildAddressResponse(query, [1u], 60)).Present);
        Assert.Equal([1u], DnsMessage.ReadAddresses(DnsMessage.BuildAddressResponse(query, [1u], 60)));
        Assert.False(DnsMessage.ReadEdns(DnsMessage.BuildEmptyResponse(plain)).Present);
    }

    /// <summary>Выравнивание EDNS не меняет ключ кэша, а cookie клиента меняет.</summary>
    [Fact]
    public void QueryFlags_IgnorePaddingButKeepCookie()
    {
        var query = DnsMessage.BuildQuery(1, "example.com", DnsMessage.TypeA);
        byte[] padding4 = [0, 12, 0, 4, 0, 0, 0, 0];
        byte[] padding8 = [0, 12, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0];
        byte[] cookieA = [0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        byte[] cookieB = [0, 10, 0, 8, 8, 7, 6, 5, 4, 3, 2, 1];

        Assert.Equal(DnsMessage.ReadQueryFlags(WithOptData(query, padding4)), DnsMessage.ReadQueryFlags(WithOptData(query, padding8)));
        Assert.Equal(DnsMessage.ReadQueryFlags(WithOptData(query, [])), DnsMessage.ReadQueryFlags(WithOptData(query, padding8)));
        Assert.NotEqual(DnsMessage.ReadQueryFlags(WithOptData(query, cookieA)), DnsMessage.ReadQueryFlags(WithOptData(query, cookieB)));
        Assert.Equal("!", DnsMessage.ReadQueryFlags(WithOptData(query, [0, 10, 0, 9, 1])).EdnsOptions);
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
