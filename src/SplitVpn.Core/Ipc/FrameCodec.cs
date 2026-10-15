using System.Buffers.Binary;

namespace SplitVpn.Core.Ipc;

public sealed class IpcProtocolException(string message) : Exception(message);

/// <summary>Кадр IPC: 4 байта длины (little-endian) и UTF-8 JSON.</summary>
public static class FrameCodec
{
    public const int MaxFrameBytes = 2 * 1024 * 1024;

    public static async Task WriteAsync(Stream stream, byte[] payload, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(payload);
        if (payload.Length > MaxFrameBytes)
        {
            throw new IpcProtocolException("Сообщение превышает допустимый размер.");
        }

        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
        await stream.WriteAsync(header, cancellationToken);
        await stream.WriteAsync(payload, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    /// <summary>Читает кадр; null — поток закрыт до начала кадра.</summary>
    public static async Task<byte[]?> ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var header = new byte[4];
        if (!await ReadExactAsync(stream, header, allowEof: true, cancellationToken))
        {
            return null;
        }

        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length is < 0 or > MaxFrameBytes)
        {
            throw new IpcProtocolException("Недопустимая длина сообщения.");
        }

        var payload = new byte[length];
        await ReadExactAsync(stream, payload, allowEof: false, cancellationToken);
        return payload;
    }

    private static async Task<bool> ReadExactAsync(Stream stream, byte[] buffer, bool allowEof, CancellationToken cancellationToken)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(read), cancellationToken);
            if (n == 0)
            {
                return read == 0 && allowEof ? false : throw new IpcProtocolException("Соединение закрыто посреди сообщения.");
            }

            read += n;
        }

        return true;
    }
}
