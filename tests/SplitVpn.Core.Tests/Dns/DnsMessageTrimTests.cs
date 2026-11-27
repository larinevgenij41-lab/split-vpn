using System.Buffers.Binary;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Net;

namespace SplitVpn.Core.Tests.Dns;

/// <summary>
/// Вырезание записей из ответа DNS: счётчики секций пересчитываются, указатели сжатых имён после вырезанного
/// сдвигаются, указатель внутрь вырезанного делает ответ неисправимым (null).
/// </summary>
public class DnsMessageTrimTests
{
    private static readonly uint First = Ipv4.Parse("203.0.113.1");
    private static readonly uint Second = Ipv4.Parse("203.0.113.2");

    private static byte[] Name(string name)
    {
        var bytes = new List<byte>();
        foreach (var label in name.Split('.'))
        {
            bytes.Add((byte)label.Length);
            bytes.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }

        bytes.Add(0);
        return [.. bytes];
    }

    private static byte[] Pointer(int offset) => [(byte)(0xC0 | (offset >> 8)), (byte)offset];

    private static byte[] Record(byte[] owner, ushort type, byte[] data)
    {
        var record = new byte[owner.Length + 10 + data.Length];
        owner.CopyTo(record, 0);
        BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(owner.Length), type);
        BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(owner.Length + 2), DnsMessage.ClassIn);
        BinaryPrimitives.WriteUInt32BigEndian(record.AsSpan(owner.Length + 4), 300);
        BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(owner.Length + 8), (ushort)data.Length);
        data.CopyTo(record, owner.Length + 10);
        return record;
    }

    private static byte[] A(byte[] owner, uint address)
    {
        var data = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(data, address);
        return Record(owner, DnsMessage.TypeA, data);
    }

    private static byte[] Response(byte[] query, int answers, int additional, params byte[][] records)
    {
        byte[] message = [.. DnsMessage.BuildEmptyResponse(query), .. records.SelectMany(r => r)];
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(6), (ushort)answers);
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(10), (ushort)additional);
        return message;
    }

    private static ushort Count(byte[] message, int section) => BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(6 + (2 * section)));

    [Fact]
    public void KeepAnswerAddresses_ShiftsPointersThatFollowTheCut()
    {
        // a.example A First; a.example CNAME b.example (имя целиком в RDATA); b.example (указатель в RDATA) A Second.
        var query = DnsMessage.BuildQuery(1, "a.example", DnsMessage.TypeA);
        var removed = A(Pointer(12), First);
        var cname = Record(Pointer(12), DnsMessage.TypeCname, Name("b.example"));
        var target = query.Length + removed.Length + 12;
        var response = Response(query, 3, 0, removed, cname, A(Pointer(target), Second));

        var trimmed = DnsMessage.KeepAnswerAddresses(response, new HashSet<uint> { Second });

        Assert.NotNull(trimmed);
        Assert.Equal(2, Count(trimmed, 0));
        Assert.Equal(response.Length - removed.Length, trimmed.Length);
        Assert.Equal(new[] { Second }, DnsMessage.ReadAddresses(trimmed, "a.example"));
        Assert.Equal(new[] { "b.example" }, DnsMessage.ReadCanonicalNames(trimmed, "a.example"));
    }

    [Fact]
    public void KeepAnswerAddresses_PointerIntoRemovedRecord_IsNotRepairable()
    {
        var query = DnsMessage.BuildQuery(1, "a.example", DnsMessage.TypeA);
        var owner = query.Length;
        var response = Response(query, 2, 0, A(Name("a.example"), First), A(Pointer(owner), Second));

        Assert.Null(DnsMessage.KeepAnswerAddresses(response, new HashSet<uint> { Second }));
    }

    [Fact]
    public void KeepAnswerAddresses_NothingToRemove_ReturnsSameMessage()
    {
        var query = DnsMessage.BuildQuery(1, "a.example", DnsMessage.TypeA);
        var response = DnsMessage.BuildAddressResponse(query, [First, Second], 300);

        Assert.Same(response, DnsMessage.KeepAnswerAddresses(response, new HashSet<uint> { First, Second }));
    }

    [Fact]
    public void KeepAnswerAddresses_RemovesAddressesOutsideTheChainToo()
    {
        var query = DnsMessage.BuildQuery(1, "a.example", DnsMessage.TypeA);
        var response = Response(query, 2, 0, A(Pointer(12), First), A(Name("other.example"), Second));

        var trimmed = DnsMessage.KeepAnswerAddresses(response, new HashSet<uint> { First });

        Assert.NotNull(trimmed);
        Assert.Equal(1, Count(trimmed, 0));
        Assert.Equal(new[] { First }, DnsMessage.ReadAddresses(trimmed));
    }

    [Fact]
    public void RemoveAdditionalRecords_KeepsOptAndOtherSections()
    {
        var plain = DnsMessage.BuildQuery(1, "_sip._tcp.a.example", 33);
        byte[] srv = [0, 10, 0, 5, 0x13, 0xC4, .. Name("sip.a.example")];
        var srvRecord = Record(Pointer(12), 33, srv);
        var glueOwner = plain.Length + srvRecord.Length - Name("sip.a.example").Length;
        var opt = DnsMessage.AppendOpt(DnsMessage.BuildEmptyResponse(plain), 1232, false)[^11..];
        var response = Response(plain, 1, 3, srvRecord, A(Pointer(glueOwner), First),
            Record(Pointer(glueOwner), DnsMessage.TypeAaaa, new byte[16]), opt);

        var stripped = DnsMessage.RemoveAdditionalRecords(response);

        Assert.NotNull(stripped);
        Assert.Equal(1, Count(stripped, 0));
        Assert.Equal(1, Count(stripped, 2));
        Assert.True(DnsMessage.ReadEdns(stripped).Present);
        Assert.Equal(plain.Length + srvRecord.Length + 11, stripped.Length);
        Assert.Equal(response[..(plain.Length + srvRecord.Length)].Skip(12), stripped[..(plain.Length + srvRecord.Length)].Skip(12));
    }

    [Fact]
    public void RemoveRecords_DamagedMessage_IsNull()
    {
        var query = DnsMessage.BuildQuery(1, "a.example", DnsMessage.TypeA);
        var response = DnsMessage.BuildAddressResponse(query, [First], 300);

        Assert.Null(DnsMessage.RemoveAdditionalRecords(response[..^2]));
    }
}
