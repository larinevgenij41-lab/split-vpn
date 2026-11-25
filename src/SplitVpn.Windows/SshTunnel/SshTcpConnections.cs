using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace SplitVpn.Windows.SshTunnel;

internal static partial class SshTcpConnections
{
    private const int RowBytes = 24; // MIB_TCPROW_OWNER_PID

    internal static unsafe bool? HasEstablished(int pid, uint server, ushort port)
    {
        const uint insufficientBuffer = 122;
        uint size = 0;
        var result = GetExtendedTcpTable(null, ref size, 0, 2, 5, 0);
        for (var attempt = 0; result == insufficientBuffer && attempt < 3; attempt++)
        {
            var buffer = new byte[size];
            fixed (byte* data = buffer)
            {
                result = GetExtendedTcpTable(data, ref size, 0, 2, 5, 0);
            }

            if (result == 0) { return Find(buffer.AsSpan(0, (int)size), pid, server, port); }
        }

        return null;
    }

    internal static bool? Find(ReadOnlySpan<byte> table, int pid, uint server, ushort port)
    {
        if (table.Length < 4) { return null; }
        var count = BinaryPrimitives.ReadUInt32LittleEndian(table);
        table = table[4..];
        if (count > table.Length / RowBytes) { return null; }
        for (var i = 0; i < count; i++, table = table[RowBytes..])
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(table) == 5
                && BinaryPrimitives.ReadUInt32BigEndian(table[12..]) == server
                && BinaryPrimitives.ReadUInt16BigEndian(table[16..]) == port
                && BinaryPrimitives.ReadInt32LittleEndian(table[20..]) == pid)
            {
                return true;
            }
        }

        return false;
    }

    [LibraryImport("iphlpapi.dll")]
    private static unsafe partial uint GetExtendedTcpTable(byte* table, ref uint size, int order, uint family, int tableClass, uint reserved);
}
