using System.Buffers.Binary;
using System.Text;
using SplitVpn.Core.Dns;

namespace SplitVpn.Core.Tests.Dns;

/// <summary>
/// Посредник разбирает недоверенные данные: обрезанный ответ (TCP-добор с длиной 0–3 байта) и имя,
/// собранное сжатием из повторяющихся меток, не должны ронять чтение заголовка и разбор.
/// </summary>
public class DnsMessageBoundsTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(11)]
    public void HeaderReads_DoNotThrowOnShortMessages(int length)
    {
        var message = new byte[length];

        Assert.Equal(0, DnsMessage.GetId(message));
        Assert.False(DnsMessage.IsResponse(message));
        Assert.False(DnsMessage.IsTruncated(message));
        Assert.Equal(length > 3 ? 0 : DnsMessage.RcodeUnknown, DnsMessage.GetRcode(message));
        Assert.False(DnsMessage.TryReadQuestion(message, out _));
        Assert.Null(DnsMessage.GetMinTtl(message));
        DnsMessage.SetId(message, 0x1234);
    }

    [Fact]
    public void HeaderReads_StillWorkOnWholeMessage()
    {
        var query = DnsMessage.BuildQuery(0x1234, "example.org", DnsMessage.TypeA);
        var failure = DnsMessage.BuildServerFailure(query);

        Assert.Equal(0x1234, DnsMessage.GetId(failure));
        Assert.True(DnsMessage.IsResponse(failure));
        Assert.Equal(2, DnsMessage.GetRcode(failure));
    }

    [Fact]
    public void TryReadQuestion_RejectsNameLongerThanLimit()
    {
        // Пять меток по 63 знака — 319 знаков, больше предела 255.
        Assert.False(DnsMessage.TryReadQuestion(QueryWithLabels(5), out _));
    }

    [Fact]
    public void TryReadQuestion_AcceptsNameAtLimit()
    {
        Assert.True(DnsMessage.TryReadQuestion(QueryWithLabels(4), out var question));
        Assert.Equal(DnsMessage.MaxNameLength, question.Name.Length);
    }

    [Fact]
    public void TryReadQuestion_RejectsNameGrownByCompressionLoop()
    {
        // Имя из одной метки, указатель которой ведёт на самого себя: без предела длины сборка
        // остановилась бы только на пределе переходов, собрав килобайты.
        var message = new byte[DnsMessage.HeaderLength + 66];
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(4), 1);
        message[DnsMessage.HeaderLength] = 63;
        Encoding.ASCII.GetBytes(new string('a', 63), message.AsSpan(DnsMessage.HeaderLength + 1));
        message[DnsMessage.HeaderLength + 64] = 0xC0;
        message[DnsMessage.HeaderLength + 65] = DnsMessage.HeaderLength;

        Assert.False(DnsMessage.TryReadQuestion(message, out _));
    }

    /// <summary>Запрос из указанного числа меток по 63 знака: длина имени — 64 × меток − 1.</summary>
    private static byte[] QueryWithLabels(int labels) =>
        DnsMessage.BuildQuery(1, string.Join('.', Enumerable.Repeat(new string('a', 63), labels)), DnsMessage.TypeA);
}
