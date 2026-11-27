using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace SplitVpn.Windows.SshTunnel;

/// <summary>
/// Снимок системной таблицы соединений TCP (IPv4): удалённые адреса установленных соединений. По нему служба
/// продлевает закрепление адреса за целью правила для домена, пока к адресу есть живые соединения. Один вызов -
/// одна таблица на все закрепления, а не вызов на адрес.
/// </summary>
public static partial class TcpConnectionTable
{
    private const int RowBytes = 20; // MIB_TCPROW: состояние, локальные адрес и порт, удалённые адрес и порт
    private const uint Established = 5; // MIB_TCP_STATE_ESTAB
    private const int BasicConnections = 1; // TCP_TABLE_BASIC_CONNECTIONS
    private const uint InetFamily = 2; // AF_INET

    /// <summary>Удалённые адреса установленных соединений TCP; null - таблицу прочитать не удалось.</summary>
    public static unsafe IReadOnlySet<uint>? EstablishedRemoteAddresses()
    {
        const uint insufficientBuffer = 122;
        uint size = 0;
        var result = GetExtendedTcpTable(null, ref size, 0, InetFamily, BasicConnections, 0);
        for (var attempt = 0; result == insufficientBuffer && attempt < 3; attempt++)
        {
            // Таблица может вырасти между вызовами: запас, чтобы не повторять вызов по кругу.
            size += 64 * RowBytes;
            var buffer = new byte[size];
            fixed (byte* data = buffer)
            {
                result = GetExtendedTcpTable(data, ref size, 0, InetFamily, BasicConnections, 0);
            }

            if (result == 0) { return ParseEstablishedRemotes(buffer.AsSpan(0, (int)Math.Min(size, (uint)buffer.Length))); }
        }

        return result == 0 ? new HashSet<uint>() : null;
    }

    /// <summary>Разбор MIB_TCPTABLE: число строк и строки MIB_TCPROW. Повреждённая таблица - null.</summary>
    internal static HashSet<uint>? ParseEstablishedRemotes(ReadOnlySpan<byte> table)
    {
        if (table.Length < 4) { return null; }
        var count = BinaryPrimitives.ReadUInt32LittleEndian(table);
        table = table[4..];
        if (count > table.Length / RowBytes) { return null; }
        var remotes = new HashSet<uint>();
        for (var i = 0; i < count; i++, table = table[RowBytes..])
        {
            // Адрес в строке - в сетевом порядке байтов, как и закреплённые адреса службы после чтения big-endian.
            if (BinaryPrimitives.ReadUInt32LittleEndian(table) == Established)
            {
                remotes.Add(BinaryPrimitives.ReadUInt32BigEndian(table[12..]));
            }
        }

        return remotes;
    }

    [LibraryImport("iphlpapi.dll")]
    private static unsafe partial uint GetExtendedTcpTable(byte* table, ref uint size, int order, uint family, int tableClass, uint reserved);
}
