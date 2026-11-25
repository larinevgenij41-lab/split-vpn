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

    /// <summary>Итерация 12: CNAME-связь создаёт только ответ из одних CNAME (и подписей), без адресов.</summary>
    [Fact]
    public void IsCnameOnly_OnlyForAnswersWithoutAddresses()
    {
        var query = DnsMessage.BuildQuery(7, "x.evil.ru", DnsMessage.TypeA);
        var cname = Record("x.evil.ru", DnsMessage.TypeCname, Name("mail.google.com"));
        var address = Record("mail.google.com", DnsMessage.TypeA, [142, 250, 1, 17]);
        var signature = Record("x.evil.ru", DnsMessage.TypeRrsig, [1, 2, 3]);

        Assert.True(DnsMessage.IsCnameOnly(Response(query, cname)));
        Assert.True(DnsMessage.IsCnameOnly(Response(query, cname, signature)));
        Assert.False(DnsMessage.IsCnameOnly(Response(query, cname, address)));
        Assert.False(DnsMessage.IsCnameOnly(Response(query)));
        Assert.False(DnsMessage.IsCnameOnly(Response(query, signature)));
        Assert.False(DnsMessage.IsCnameOnly(Response(query, cname, Record("x.evil.ru", 16, [1, (byte)'a']))));
        Assert.False(DnsMessage.IsCnameOnly(DnsMessage.BuildAddressResponse(query, [0xC0000207], 60)));
    }

    private static byte[] Response(byte[] query, params byte[][] answers)
    {
        var head = DnsMessage.BuildEmptyResponse(query);
        head[6] = (byte)(answers.Length >> 8);
        head[7] = (byte)answers.Length;
        return [.. head, .. answers.SelectMany(a => a)];
    }

    private static byte[] Name(string name) =>
        [.. name.Split('.').SelectMany(l => new[] { (byte)l.Length }.Concat(System.Text.Encoding.ASCII.GetBytes(l))), 0];

    private static byte[] Record(string owner, ushort type, byte[] data) =>
        [.. Name(owner), (byte)(type >> 8), (byte)type, 0, 1, 0, 0, 0, 60, (byte)(data.Length >> 8), (byte)data.Length, .. data];

    [Fact]
    public void TryGetAsciiName_RejectsInvalidIdnWithoutThrowing()
    {
        Assert.False(DnsMessage.TryGetAsciiName("vpn..рф", out var ascii));
        Assert.Equal("", ascii);
    }
}
