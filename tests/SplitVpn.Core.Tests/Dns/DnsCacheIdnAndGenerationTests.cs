using Microsoft.Extensions.Time.Testing;
using SplitVpn.Core.Dns;

namespace SplitVpn.Core.Tests.Dns;

/// <summary>
/// Ревью 0.15.19: имя VPN-сервера, записанное по-русски, закрепляется под ASCII-ключом (запросы приходят
/// в Punycode), а ответ, записываемый после очистки кеша при смене сети, в кеш не попадает.
/// </summary>
public sealed class DnsCacheIdnAndGenerationTests
{
    private const string UnicodeServer = "vpn.пример.рф";

    [Fact]
    public void PinnedUnicodeServerName_IsFoundByPunycodeQuery()
    {
        var cache = new DnsCache(new FakeTimeProvider());
        cache.Pin(UnicodeServer, [0x0A000001]);
        Assert.True(DnsMessage.TryReadQuestion(DnsMessage.BuildQuery(1, UnicodeServer, DnsMessage.TypeA), out var question));
        Assert.StartsWith("vpn.xn--", question.Name, StringComparison.Ordinal);

        Assert.True(cache.TryGetPinned(question.Name, out var addresses));
        Assert.Equal([0x0A000001u], addresses);

        // Сохранение закреплений по имени из настроек тоже совпадает с ASCII-ключом.
        cache.RetainPins([UnicodeServer]);
        Assert.True(cache.TryGetPinned(question.Name + ".", out _));

        cache.Unpin(question.Name);
        Assert.False(cache.TryGetPinned(UnicodeServer, out _));
    }

    [Fact]
    public void PutAfterClear_WithGenerationCapturedBefore_IsDropped()
    {
        var cache = new DnsCache(new FakeTimeProvider());
        var query = DnsMessage.BuildQuery(1, "site.example", DnsMessage.TypeA);
        Assert.True(DnsMessage.TryReadQuestion(query, out var question));
        var response = DnsMessage.BuildAddressResponse(query, [0xCB007109], 300);

        // Запрос ушёл в прежней сети, затем служба очистила кеш, и только потом ответ пришёл.
        var before = cache.Generation;
        cache.Clear();
        cache.Put(question, "ctx", response, default, before);

        Assert.Equal(0, cache.Count);
        Assert.Null(cache.TryGet(question, "ctx", 1, offline: false));

        // Ответ текущего поколения кешируется как обычно.
        cache.Put(question, "ctx", response, default, cache.Generation);
        Assert.NotNull(cache.TryGet(question, "ctx", 1, offline: false));
    }
}
