using System.Buffers.Binary;
using System.Text;

namespace SplitVpn.Core.Dns;

public readonly record struct DnsQuestion(string Name, ushort Type, ushort Class);

/// <summary>Минимальная работа с DNS-сообщениями в сырых байтах: посредник пересылает их как есть.</summary>
public static class DnsMessage
{
    public const int HeaderLength = 12;
    public const ushort TypeA = 1;
    public const ushort TypeCname = 5;
    public const ushort TypeAaaa = 28;
    public const ushort TypeOpt = 41;
    public const ushort ClassIn = 1;

    private const int MaxPointerJumps = 32;

    /// <summary>Предел длины имени в текстовом виде (RFC 1035: 255 октетов на всё имя).</summary>
    public const int MaxNameLength = 255;

    /// <summary>
    /// Чтения заголовка получают сырые байты из сети (в том числе обрезанный ответ по TCP), поэтому
    /// сообщение короче заголовка не исключение, а обычный случай: заголовка нет — считаем сообщение
    /// негодным (не ответ, не усечено, идентификатор 0, код ответа <see cref="RcodeUnknown"/>).
    /// </summary>
    public const int RcodeUnknown = -1;

    public static ushort GetId(ReadOnlySpan<byte> message) => message.Length >= 2 ? BinaryPrimitives.ReadUInt16BigEndian(message) : (ushort)0;

    public static void SetId(Span<byte> message, ushort id)
    {
        if (message.Length >= 2)
        {
            BinaryPrimitives.WriteUInt16BigEndian(message, id);
        }
    }

    public static bool IsResponse(ReadOnlySpan<byte> message) => message.Length > 2 && (message[2] & 0x80) != 0;

    public static bool IsTruncated(ReadOnlySpan<byte> message) => message.Length > 2 && (message[2] & 0x02) != 0;

    public static int GetRcode(ReadOnlySpan<byte> message) => message.Length > 3 ? message[3] & 0x0F : RcodeUnknown;

    /// <summary>Разбирает первый вопрос сообщения. Имя приводится к нижнему регистру.</summary>
    public static bool TryReadQuestion(ReadOnlySpan<byte> message, out DnsQuestion question)
    {
        question = default;
        if (message.Length < HeaderLength || BinaryPrimitives.ReadUInt16BigEndian(message[4..]) == 0)
        {
            return false;
        }

        var offset = HeaderLength;
        if (!TryReadName(message, ref offset, out var name) || offset + 4 > message.Length)
        {
            return false;
        }

        question = new DnsQuestion(
            name,
            BinaryPrimitives.ReadUInt16BigEndian(message[offset..]),
            BinaryPrimitives.ReadUInt16BigEndian(message[(offset + 2)..]));
        return true;
    }

    /// <summary>Минимальный TTL среди записей ответа и полномочий; null — записей нет или сообщение повреждено.</summary>
    public static uint? GetMinTtl(ReadOnlySpan<byte> message)
    {
        uint? min = null;
        var ok = VisitRecords(message, includeAdditional: false, (type, ttlOffset, bytes) =>
        {
            var ttl = BinaryPrimitives.ReadUInt32BigEndian(bytes[ttlOffset..]);
            min = min is null ? ttl : Math.Min(min.Value, ttl);
        });
        return ok ? min : null;
    }

    /// <summary>Подменяет TTL всех записей, кроме OPT.</summary>
    public static bool RewriteTtls(Span<byte> message, uint ttl)
    {
        var offsets = new List<int>();
        var ok = VisitRecords(message, includeAdditional: true, (type, ttlOffset, _) =>
        {
            if (type != TypeOpt)
            {
                offsets.Add(ttlOffset);
            }
        });
        foreach (var offset in offsets)
        {
            BinaryPrimitives.WriteUInt32BigEndian(message[offset..], ttl);
        }

        return ok;
    }

    public static byte[] BuildServerFailure(ReadOnlySpan<byte> query) => BuildEmptyResponse(query, rcode: 2);

    /// <summary>Ответ на A-запрос заданными адресами (закреплённые записи сервера).</summary>
    public static byte[] BuildAddressResponse(ReadOnlySpan<byte> query, IReadOnlyList<uint> addresses, uint ttl)
    {
        ArgumentNullException.ThrowIfNull(addresses);
        var questionEnd = QuestionEnd(query);
        var buffer = new byte[questionEnd + (addresses.Count * 16)];
        query[..questionEnd].CopyTo(buffer);
        WriteResponseHeader(buffer, rcode: 0, answerCount: (ushort)addresses.Count);
        var offset = questionEnd;
        foreach (var address in addresses)
        {
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(offset), 0xC00C);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(offset + 2), TypeA);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(offset + 4), ClassIn);
            BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(offset + 6), ttl);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(offset + 10), 4);
            BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(offset + 12), address);
            offset += 16;
        }

        return buffer;
    }

    /// <summary>Пустой успешный ответ (например, AAAA для сервера в IPv4-only режиме).</summary>
    public static byte[] BuildEmptyResponse(ReadOnlySpan<byte> query, int rcode = 0)
    {
        var questionEnd = QuestionEnd(query);
        var buffer = query[..questionEnd].ToArray();
        WriteResponseHeader(buffer, rcode, answerCount: 0);
        return buffer;
    }

    /// <summary>Строит A-запрос (для начального разрешения и тестов).</summary>
    public static byte[] BuildQuery(ushort id, string name, ushort type)
    {
        ArgumentNullException.ThrowIfNull(name);
        var labels = name.TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries);
        var nameLength = labels.Sum(l => Encoding.ASCII.GetByteCount(l) + 1) + 1;
        var buffer = new byte[HeaderLength + nameLength + 4];
        BinaryPrimitives.WriteUInt16BigEndian(buffer, id);
        buffer[2] = 0x01; // RD
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(4), 1);
        var offset = HeaderLength;
        foreach (var label in labels)
        {
            var written = Encoding.ASCII.GetBytes(label, buffer.AsSpan(offset + 1));
            buffer[offset] = (byte)written;
            offset += written + 1;
        }

        buffer[offset] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(offset + 1), type);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(offset + 3), ClassIn);
        return buffer;
    }

    /// <summary>
    /// Ответ относится к заданному запросу: это ответ с тем же кодом операции и ровно тем же единственным
    /// вопросом. Без такой проверки в кеш и в маршруты попал бы ответ на чужое имя.
    /// </summary>
    public static bool Answers(ReadOnlySpan<byte> response, ReadOnlySpan<byte> query)
    {
        if (response.Length < HeaderLength || query.Length < HeaderLength
            || !IsResponse(response) || (response[2] & 0x78) != (query[2] & 0x78)
            || BinaryPrimitives.ReadUInt16BigEndian(response[4..]) != 1)
        {
            return false;
        }

        return TryReadQuestion(response, out var asked) && TryReadQuestion(query, out var expected) && asked == expected;
    }

    /// <summary>
    /// A-записи ответа. Если задано имя вопроса — только адреса его цепочки «имя → CNAME → …»: посторонние
    /// записи, приложенные к ответу, не должны попадать в закрепления и маршруты.
    /// </summary>
    public static IReadOnlyList<uint> ReadAddresses(ReadOnlySpan<byte> message, string? question = null)
    {
        var answers = ReadAnswers(message);
        if (answers is null)
        {
            return [];
        }

        HashSet<string>? chain = null;
        if (question is not null)
        {
            chain = new HashSet<string>(StringComparer.Ordinal) { question.TrimEnd('.').ToLowerInvariant() };

            // Цепочка может лежать в ответе не по порядку: проходы повторяются, пока она растёт.
            bool grown;
            do
            {
                grown = false;
                foreach (var record in answers)
                {
                    var offset = record.DataOffset;
                    if (record.Type == TypeCname && chain.Contains(record.Owner)
                        && TryReadName(message, ref offset, out var target) && chain.Add(target))
                    {
                        grown = true;
                    }
                }
            }
            while (grown);
        }

        var result = new List<uint>();
        foreach (var record in answers)
        {
            if (record.Type == TypeA && record.DataLength == 4 && (chain is null || chain.Contains(record.Owner)))
            {
                result.Add(BinaryPrimitives.ReadUInt32BigEndian(message[record.DataOffset..]));
            }
        }

        return result;
    }

    private readonly record struct AnswerRecord(string Owner, ushort Type, int DataOffset, int DataLength);

    /// <summary>Записи секции ответа с именами владельцев; null — сообщение повреждено.</summary>
    private static List<AnswerRecord>? ReadAnswers(ReadOnlySpan<byte> message)
    {
        if (message.Length < HeaderLength)
        {
            return null;
        }

        var offset = HeaderLength;
        var questions = BinaryPrimitives.ReadUInt16BigEndian(message[4..]);
        for (var i = 0; i < questions; i++)
        {
            if (!TrySkipName(message, ref offset) || (offset += 4) > message.Length)
            {
                return null;
            }
        }

        var count = BinaryPrimitives.ReadUInt16BigEndian(message[6..]);
        var result = new List<AnswerRecord>(count);
        for (var i = 0; i < count; i++)
        {
            if (!TryReadName(message, ref offset, out var owner) || offset + 10 > message.Length)
            {
                return null;
            }

            var type = BinaryPrimitives.ReadUInt16BigEndian(message[offset..]);
            var length = BinaryPrimitives.ReadUInt16BigEndian(message[(offset + 8)..]);
            if (offset + 10 + length > message.Length)
            {
                return null;
            }

            result.Add(new AnswerRecord(owner, type, offset + 10, length));
            offset += 10 + length;
        }

        return result;
    }

    private delegate void RecordVisitor(ushort type, int ttlOffset, ReadOnlySpan<byte> message);

    private static bool VisitRecords(ReadOnlySpan<byte> message, bool includeAdditional, RecordVisitor visitor)
    {
        if (message.Length < HeaderLength)
        {
            return false;
        }

        var offset = HeaderLength;
        var questions = BinaryPrimitives.ReadUInt16BigEndian(message[4..]);
        for (var i = 0; i < questions; i++)
        {
            if (!TrySkipName(message, ref offset) || (offset += 4) > message.Length)
            {
                return false;
            }
        }

        var records = BinaryPrimitives.ReadUInt16BigEndian(message[6..]) + BinaryPrimitives.ReadUInt16BigEndian(message[8..]);
        if (includeAdditional)
        {
            records += BinaryPrimitives.ReadUInt16BigEndian(message[10..]);
        }

        for (var i = 0; i < records; i++)
        {
            if (!TryVisitRecord(message, ref offset, visitor))
            {
                return false;
            }
        }

        return true;
    }

    private static bool TryVisitRecord(ReadOnlySpan<byte> message, ref int offset, RecordVisitor visitor)
    {
        if (!TrySkipName(message, ref offset) || offset + 10 > message.Length)
        {
            return false;
        }

        var type = BinaryPrimitives.ReadUInt16BigEndian(message[offset..]);
        var length = BinaryPrimitives.ReadUInt16BigEndian(message[(offset + 8)..]);
        if (offset + 10 + length > message.Length)
        {
            return false;
        }

        visitor(type, offset + 4, message);
        offset += 10 + length;
        return true;
    }

    private static bool TrySkipName(ReadOnlySpan<byte> message, ref int offset)
    {
        while (offset < message.Length)
        {
            var length = message[offset];
            if ((length & 0xC0) == 0xC0)
            {
                offset += 2;
                return offset <= message.Length;
            }

            offset += length + 1;
            if (length == 0)
            {
                return offset <= message.Length;
            }
        }

        return false;
    }

    private static bool TryReadName(ReadOnlySpan<byte> message, ref int offset, out string name)
    {
        name = "";
        var builder = new StringBuilder();
        var position = offset;
        var jumps = 0;
        var endOffset = -1;
        while (position < message.Length)
        {
            var length = message[position];
            if (length == 0)
            {
                offset = endOffset >= 0 ? endOffset : position + 1;
                name = builder.ToString().ToLowerInvariant();
                return true;
            }

            if ((length & 0xC0) == 0xC0)
            {
                if (position + 1 >= message.Length || ++jumps > MaxPointerJumps)
                {
                    return false;
                }

                endOffset = endOffset >= 0 ? endOffset : position + 2;
                position = ((length & 0x3F) << 8) | message[position + 1];
                continue;
            }

            if (position + 1 + length > message.Length)
            {
                return false;
            }

            // Имя длиннее предела протокола: сжатие может собрать его из повторяющихся меток.
            if (builder.Length + (builder.Length > 0 ? length + 1 : length) > MaxNameLength)
            {
                return false;
            }

            if (builder.Length > 0)
            {
                builder.Append('.');
            }

            builder.Append(Encoding.ASCII.GetString(message.Slice(position + 1, length)));
            position += length + 1;
        }

        return false;
    }

    private static int QuestionEnd(ReadOnlySpan<byte> query)
    {
        var offset = HeaderLength;
        if (query.Length < HeaderLength || !TrySkipName(query, ref offset) || offset + 4 > query.Length)
        {
            throw new FormatException("Повреждённый DNS-запрос.");
        }

        return offset + 4;
    }

    private static void WriteResponseHeader(Span<byte> buffer, int rcode, ushort answerCount)
    {
        buffer[2] = (byte)(0x80 | (buffer[2] & 0x79)); // QR, сохранить opcode и RD
        buffer[3] = (byte)(0x80 | rcode); // RA
        BinaryPrimitives.WriteUInt16BigEndian(buffer[4..], 1);
        BinaryPrimitives.WriteUInt16BigEndian(buffer[6..], answerCount);
        BinaryPrimitives.WriteUInt16BigEndian(buffer[8..], 0);
        BinaryPrimitives.WriteUInt16BigEndian(buffer[10..], 0);
    }
}
