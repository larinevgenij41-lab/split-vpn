using SplitVpn.Core.Dns;

namespace SplitVpn.Core.Tests.Dns;

/// <summary>
/// Имя сервера на национальном алфавите (vpn.пример.рф): запрос уходит в Punycode, владелец A-записи в ответе тоже
/// в Punycode, а вопрос вызывающий может передать по-русски. Адрес должен находиться при любом написании.
/// </summary>
public class DnsMessageIdnTests
{
    private const string Unicode = "vpn.пример.рф";
    private const string Punycode = "vpn.xn--e1afmkfd.xn--p1ai";

    [Theory]
    [InlineData(Unicode)]
    [InlineData(Punycode)]
    [InlineData("VPN.Пример.РФ.")]
    public void ReadAddresses_FindsAnswerForUnicodeAndPunycodeQuestion(string question)
    {
        var query = DnsMessage.BuildQuery(7, Unicode, DnsMessage.TypeA);
        var response = DnsMessage.BuildAddressResponse(query, [0xC0000207], 60);

        // Владелец записи — указатель сжатия на имя вопроса (0xC00C), имя вопроса в запросе — Punycode.
        Assert.Equal(0xC0, response[query.Length]);
        Assert.Equal(0x0C, response[query.Length + 1]);
        Assert.True(DnsMessage.TryReadQuestion(response, out var asked));
        Assert.Equal(Punycode, asked.Name);

        Assert.Equal([0xC0000207u], DnsMessage.ReadAddresses(response, question));
    }

    [Fact]
    public void ReadAddresses_StillFiltersForeignNames()
    {
        var query = DnsMessage.BuildQuery(7, Unicode, DnsMessage.TypeA);
        var response = DnsMessage.BuildAddressResponse(query, [0xC0000207], 60);

        Assert.Empty(DnsMessage.ReadAddresses(response, "vpn.другой.рф"));
        Assert.Empty(DnsMessage.ReadAddresses(response, "vpn..рф"));
    }

    [Fact]
    public void ReadCanonicalNames_ExcludesUnicodeQuestionItself()
    {
        var query = DnsMessage.BuildQuery(7, Unicode, DnsMessage.TypeA);
        var response = DnsMessage.BuildAddressResponse(query, [0xC0000207], 60);

        Assert.Empty(DnsMessage.ReadCanonicalNames(response, Unicode));
    }

    [Theory]
    [InlineData(Unicode, Punycode)]
    [InlineData("Example.ORG.", "example.org")]
    [InlineData("xn--e1afmkfd.xn--p1ai", "xn--e1afmkfd.xn--p1ai")]
    public void TryGetAsciiName_ConvertsToLowercaseIdnaAscii(string name, string expected)
    {
        Assert.True(DnsMessage.TryGetAsciiName(name, out var ascii));
        Assert.Equal(expected, ascii);
    }

    [Fact]
    public void TryGetAsciiName_RejectsInvalidIdnWithoutThrowing()
    {
        Assert.False(DnsMessage.TryGetAsciiName("vpn..рф", out var ascii));
        Assert.Equal("", ascii);
    }
}
