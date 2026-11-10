using Microsoft.Extensions.Time.Testing;
using SplitVpn.Core.Dns;

namespace SplitVpn.Core.Tests.Dns;

public sealed class DnsCacheIndexTests
{
    [Fact]
    public void AnyPath_SelectsNewestPathAndReplacement()
    {
        var time = new FakeTimeProvider();
        var cache = new DnsCache(time);
        var question = Put(cache, "host.example", "first", 1);
        time.Advance(TimeSpan.FromSeconds(1));
        Put(cache, "host.example", "second", 2);
        Assert.Equal([2u], DnsMessage.ReadAddresses(cache.TryGetAnyPath(question, 7)!));
        time.Advance(TimeSpan.FromSeconds(1));
        Put(cache, "HOST.EXAMPLE.", "first", 3);
        var response = cache.TryGetAnyPath(question, 9)!;
        Assert.Equal([3u], DnsMessage.ReadAddresses(response));
        Assert.Equal(9, DnsMessage.GetId(response));
        Assert.Equal([2u], DnsMessage.ReadAddresses(cache.TryGet(question, "second", 1, false)!));
    }

    [Fact]
    public void Eviction_RemovesOnlyExpiredIndexPathThenWholeQuestion()
    {
        var time = new FakeTimeProvider();
        var cache = new DnsCache(time, capacity: 2);
        var question = Put(cache, "host.example", "old", 1);
        time.Advance(TimeSpan.FromSeconds(1));
        Put(cache, "host.example", "new", 2);
        time.Advance(TimeSpan.FromSeconds(1));
        Put(cache, "other.example", "new", 3);
        Assert.Null(cache.TryGet(question, "old", 1, false));
        Assert.Equal([2u], DnsMessage.ReadAddresses(cache.TryGetAnyPath(question, 1)!));
        time.Advance(TimeSpan.FromSeconds(1));
        Put(cache, "last.example", "new", 4);
        Assert.Null(cache.TryGetAnyPath(question, 1));
        Assert.Equal(2, cache.Count);
    }

    [Fact]
    public void UpdatingFullCache_DoesNotEvictUnrelatedQuestion()
    {
        var time = new FakeTimeProvider();
        var cache = new DnsCache(time, capacity: 2);
        var first = Put(cache, "first.example", "path", 1);
        time.Advance(TimeSpan.FromSeconds(1));
        Put(cache, "second.example", "path", 2);
        Put(cache, "second.example", "path", 3);
        Assert.NotNull(cache.TryGetAnyPath(first, 1));
        Assert.Equal(2, cache.Count);
    }

    [Fact]
    public void ClearAndStaleAge_ApplyToAnyPathIndex()
    {
        var time = new FakeTimeProvider();
        var cache = new DnsCache(time);
        var question = Put(cache, "host.example", "path", 1);
        time.Advance(DnsCache.MaxStaleAge + TimeSpan.FromHours(2));
        Assert.Null(cache.TryGetAnyPath(question, 1));
        Put(cache, "host.example", "path", 2);
        Assert.NotNull(cache.TryGetAnyPath(question, 1));
        cache.Clear();
        Assert.Null(cache.TryGetAnyPath(question, 1));
        Assert.Equal(0, cache.Count);
    }

    [Fact]
    public void AnyPath_DoesNotMixQuestionTypes()
    {
        var cache = new DnsCache(new FakeTimeProvider());
        Put(cache, "host.example", "path", 1);
        DnsMessage.TryReadQuestion(DnsMessage.BuildQuery(1, "host.example", DnsMessage.TypeAaaa), out var question);
        Assert.Null(cache.TryGetAnyPath(question, 1));
    }

    private static DnsQuestion Put(DnsCache cache, string name, string context, uint address)
    {
        var query = DnsMessage.BuildQuery(1, name, DnsMessage.TypeA);
        DnsMessage.TryReadQuestion(query, out var question);
        cache.Put(question, context, DnsMessage.BuildAddressResponse(query, [address], 300));
        return question;
    }
}
