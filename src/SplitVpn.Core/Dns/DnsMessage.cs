using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace SplitVpn.Core.Dns;

public readonly record struct DnsQuestion(string Name, ushort Type, ushort Class);

/// <summary>EDNS запроса: есть ли запись OPT, заявленный размер UDP-буфера клиента и бит DO.</summary>
public readonly record struct EdnsInfo(bool Present, ushort UdpSize, bool DnssecOk);

/// <summary>
/// Признаки запроса, от которых зависит ответ upstream: бит CD (проверка DNSSEC), наличие OPT (EDNS), бит DO
/// (записи RRSIG), снятый бит RD (запрос без рекурсии получает отсылку, а не ответ) и опции EDNS в
/// шестнадцатеричном виде (Client Subnet, Cookie, NSID меняют ответ). Ответы на запросы, различающиеся ими,
/// взаимозаменяемыми не считаются. Значение по умолчанию — обычный запрос с RD без OPT.
/// </summary>
public readonly record struct DnsQueryFlags(bool CheckingDisabled, bool Edns, bool DnssecOk, bool NoRecursion = false, string? EdnsOptions = null);

/// <summary>Минимальная работа с DNS-сообщениями в сырых байтах: посредник пересылает их как есть.</summary>
public static class DnsMessage
{
    public const int HeaderLength = 12;
    public const ushort TypeA = 1;
    public const ushort TypeCname = 5;
    public const ushort TypeSoa = 6;
    public const ushort TypeAaaa = 28;
    public const ushort TypeOpt = 41;
    public const ushort TypeSvcb = 64;
    public const ushort TypeHttps = 65;
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

    /// <summary>EDNS сообщения по первой записи OPT; сообщение без OPT или повреждённое — значение по умолчанию.</summary>
    public static EdnsInfo ReadEdns(ReadOnlySpan<byte> message)
    {
        var offset = FindOpt(message);

        // CLASS записи OPT — размер буфера, в поле TTL старший бит третьего байта — DO (RFC 6891).
        return offset < 0 ? default
            : new EdnsInfo(true, BinaryPrimitives.ReadUInt16BigEndian(message[(offset + 2)..]), (message[offset + 6] & 0x80) != 0);
    }

    /// <summary>Смещение поля TYPE первой записи OPT; -1 — записи нет или сообщение повреждено.</summary>
    private static int FindOpt(ReadOnlySpan<byte> message)
    {
        if (message.Length < HeaderLength)
        {
            return -1;
        }

        var offset = HeaderLength;
        var questions = BinaryPrimitives.ReadUInt16BigEndian(message[4..]);
        for (var i = 0; i < questions; i++)
        {
            if (!TrySkipName(message, ref offset) || (offset += 4) > message.Length)
            {
                return -1;
            }
        }

        var records = BinaryPrimitives.ReadUInt16BigEndian(message[6..]) + BinaryPrimitives.ReadUInt16BigEndian(message[8..])
            + BinaryPrimitives.ReadUInt16BigEndian(message[10..]);
        for (var i = 0; i < records; i++)
        {
            if (!TrySkipName(message, ref offset) || offset + 10 > message.Length)
            {
                return -1;
            }

            if (BinaryPrimitives.ReadUInt16BigEndian(message[offset..]) == TypeOpt)
            {
                return offset;
            }

            offset += 10 + BinaryPrimitives.ReadUInt16BigEndian(message[(offset + 8)..]);
        }

        return -1;
    }

    /// <summary>Признаки запроса, меняющие ответ upstream: CD, OPT, DO, RD и опции EDNS.</summary>
    public static DnsQueryFlags ReadQueryFlags(ReadOnlySpan<byte> query)
    {
        var edns = ReadEdns(query);
        var noRecursion = query.Length > 2 && (query[2] & 0x01) == 0;
        string? options = null;
        var opt = FindOpt(query);
        if (opt >= 0)
        {
            // RDATA записи OPT — сами опции. Обрезанная запись получает особую метку и ни с чем не совпадает по содержимому.
            var length = BinaryPrimitives.ReadUInt16BigEndian(query[(opt + 8)..]);
            var data = query[(opt + 10)..];
            options = length == 0 ? null : length <= data.Length ? CacheRelevantOptions(data[..length]) : "!";
        }

        return new DnsQueryFlags(query.Length > 3 && (query[3] & 0x10) != 0, edns.Present, edns.DnssecOk, noRecursion, options);
    }

    /// <summary>
    /// Опции EDNS, от которых зависит ответ. Выравнивание (12) меняет лишь длину запроса, и клиент, который
    /// дополняет запросы до кратной длины, иначе получал бы разные ключи для одного вопроса. Cookie (10) остаётся
    /// в ключе: ответ несёт cookie клиента, и чужой ответ из кэша клиент обязан отбросить (RFC 7873 §5.3).
    /// Повреждённый список получает особую метку.
    /// </summary>
    private static string? CacheRelevantOptions(ReadOnlySpan<byte> data)
    {
        const ushort Padding = 12;
        var kept = new StringBuilder();
        var offset = 0;
        while (offset < data.Length)
        {
            if (offset + 4 > data.Length)
            {
                return "!";
            }

            var code = BinaryPrimitives.ReadUInt16BigEndian(data[offset..]);
            var size = BinaryPrimitives.ReadUInt16BigEndian(data[(offset + 2)..]);
            if (offset + 4 + size > data.Length)
            {
                return "!";
            }

            if (code != Padding)
            {
                kept.Append(Convert.ToHexString(data.Slice(offset, 4 + size)));
            }

            offset += 4 + size;
        }

        return kept.Length == 0 ? null : kept.ToString();
    }

    /// <summary>
    /// Минимальный TTL среди записей ответа и полномочий; null — записей нет или сообщение повреждено.
    /// SOA в секции полномочий бывает в отрицательном ответе (NXDOMAIN, NODATA — в том числе после цепочки
    /// CNAME в секции ответа): его срок — меньшее из TTL и поля MINIMUM (RFC 2308 §5). SOA в секции ответа
    /// (запрос типа SOA) — обычная запись.
    /// </summary>
    public static uint? GetMinTtl(ReadOnlySpan<byte> message)
    {
        uint? min = null;
        var answers = message.Length >= HeaderLength ? BinaryPrimitives.ReadUInt16BigEndian(message[6..]) : 0;
        var index = 0;
        var ok = VisitRecords(message, includeAdditional: false, (type, ttlOffset, bytes) =>
        {
            var ttl = BinaryPrimitives.ReadUInt32BigEndian(bytes[ttlOffset..]);
            var authority = index++ >= answers;
            if (authority && type == TypeSoa && TryReadSoaMinimum(bytes, ttlOffset, out var minimum))
            {
                ttl = Math.Min(ttl, minimum);
            }

            min = min is null ? ttl : Math.Min(min.Value, ttl);
        });
        return ok ? min : null;
    }

    /// <summary>
    /// Поле MINIMUM — последние четыре байта RDATA записи SOA: имена MNAME и RNAME (минимум по байту)
    /// и пять 32-битных чисел. Короче — запись повреждена, срок берётся по её TTL.
    /// </summary>
    private static bool TryReadSoaMinimum(ReadOnlySpan<byte> message, int ttlOffset, out uint minimum)
    {
        const int MinSoaLength = 2 + (5 * 4);
        minimum = 0;
        var length = BinaryPrimitives.ReadUInt16BigEndian(message[(ttlOffset + 4)..]);
        if (length < MinSoaLength)
        {
            return false;
        }

        minimum = BinaryPrimitives.ReadUInt32BigEndian(message[(ttlOffset + 6 + length - 4)..]);
        return true;
    }

    /// <summary>Подменяет TTL всех записей, кроме OPT.</summary>
    public static bool RewriteTtls(Span<byte> message, uint ttl)
        => WriteTtls(message, ttl, onlyReduce: false);

    /// <summary>Ограничивает срок кеширования, не продлевая короткие записи и не меняя OPT.</summary>
    public static bool CapTtls(Span<byte> message, uint ttl)
        => WriteTtls(message, ttl, onlyReduce: true);

    private static bool WriteTtls(Span<byte> message, uint ttl, bool onlyReduce)
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
            var value = onlyReduce ? Math.Min(ttl, BinaryPrimitives.ReadUInt32BigEndian(message[offset..])) : ttl;
            BinaryPrimitives.WriteUInt32BigEndian(message[offset..], value);
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

        return WithOpt(query, buffer);
    }

    /// <summary>Пустой успешный ответ (например, AAAA для сервера в IPv4-only режиме).</summary>
    public static byte[] BuildEmptyResponse(ReadOnlySpan<byte> query, int rcode = 0)
    {
        var questionEnd = QuestionEnd(query);
        var buffer = query[..questionEnd].ToArray();
        WriteResponseHeader(buffer, rcode, answerCount: 0);
        return WithOpt(query, buffer);
    }

    /// <summary>Размер буфера UDP, который прокси объявляет в своих ответах.</summary>
    public const ushort ResponseUdpSize = 4096;

    /// <summary>
    /// Ответ, собранный самим прокси, на запрос с OPT несёт свою запись OPT (RFC 6891 §7): без неё клиент
    /// решит, что сервер EDNS не понимает, и перестанет его использовать.
    /// </summary>
    private static byte[] WithOpt(ReadOnlySpan<byte> query, byte[] reply)
    {
        var edns = ReadEdns(query);
        return edns.Present ? AppendOpt(reply, ResponseUdpSize, edns.DnssecOk) : reply;
    }

    /// <summary>
    /// Копия сообщения с минимальной записью OPT в конце дополнительной секции (RFC 6891 §6.1.2): корневое имя,
    /// размер буфера в CLASS, бит DO, без опций. Ответ на запрос с OPT обязан нести OPT (§7).
    /// </summary>
    public static byte[] AppendOpt(ReadOnlySpan<byte> message, ushort udpSize, bool dnssecOk)
    {
        if (message.Length < HeaderLength)
        {
            throw new ArgumentException("Сообщение короче заголовка DNS.", nameof(message));
        }

        var buffer = new byte[message.Length + 11];
        message.CopyTo(buffer);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(10), (ushort)(BinaryPrimitives.ReadUInt16BigEndian(message[10..]) + 1));
        var offset = message.Length;
        buffer[offset] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(offset + 1), TypeOpt);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(offset + 3), udpSize);
        buffer[offset + 7] = dnssecOk ? (byte)0x80 : (byte)0;
        return buffer;
    }

    /// <summary>Строит A-запрос (для начального разрешения и тестов).</summary>
    public static byte[] BuildQuery(ushort id, string name, ushort type)
    {
        ArgumentNullException.ThrowIfNull(name);
        // Имя на национальном алфавите (vpn.пример.рф) проходит проверку настроек; в запрос DNS оно идёт в
        // записи Punycode, иначе ASCII заменил бы каждую букву знаком «?», и имя не разрешилось бы.
        var ascii = name.TrimEnd('.');
        if (!System.Text.Ascii.IsValid(ascii))
        {
            ascii = new System.Globalization.IdnMapping().GetAscii(ascii);
        }

        var labels = ascii.Split('.', StringSplitOptions.RemoveEmptyEntries);
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

        var chain = question is null ? null : Chain(message, answers, question);
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

    /// <summary>
    /// Имена, в которые вопрос переходит по CNAME в секции ответа (без самого вопроса). По ним каноническое
    /// имя наследует правило исходного: иначе отдельный запрос канонического имени ушёл бы общим путём.
    /// </summary>
    public static IReadOnlyList<string> ReadCanonicalNames(ReadOnlySpan<byte> message, string question)
    {
        ArgumentNullException.ThrowIfNull(question);
        var answers = ReadAnswers(message);
        if (answers is null)
        {
            return [];
        }

        var asked = question.TrimEnd('.').ToLowerInvariant();
        return Chain(message, answers, question).Where(n => n != asked).ToList();
    }

    /// <summary>Цепочка «имя → CNAME → …» вопроса по записям ответа, включая сам вопрос.</summary>
    private static HashSet<string> Chain(ReadOnlySpan<byte> message, List<AnswerRecord> answers, string question)
    {
        var chain = new HashSet<string>(StringComparer.Ordinal) { question.TrimEnd('.').ToLowerInvariant() };

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

        return chain;
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
        var nameLength = 0;
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
            if (nameLength + (nameLength > 0 ? length + 1 : length) > MaxNameLength)
            {
                return false;
            }

            if (nameLength > 0)
            {
                builder.Append('.');
                nameLength++;
            }

            AppendLabel(builder, message.Slice(position + 1, length));
            nameLength += length;
            position += length + 1;
        }

        return false;
    }

    /// <summary>
    /// Метка в текстовом виде. Точка, обратная косая черта и байты вне печатного ASCII экранируются как «\DDD»
    /// (RFC 4343): иначе метка «a.b» и две метки «a», «b» дали бы одно имя «a.b», а разные не-ASCII байты —
    /// одинаковые «?», и чужое имя совпало бы с правилом домена. Обычные имена (буквы, цифры, «-», «_»,
    /// IDN в punycode) не меняются.
    /// </summary>
    private static void AppendLabel(StringBuilder builder, ReadOnlySpan<byte> label)
    {
        foreach (var value in label)
        {
            if (value is > 0x20 and < 0x7F and not (byte)'.' and not (byte)'\\')
            {
                builder.Append((char)value);
            }
            else
            {
                builder.Append('\\').Append(value.ToString("D3", CultureInfo.InvariantCulture));
            }
        }
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
