namespace SplitVpn.Service.Diagnostics;

/// <summary>Предел проверяется до записи, включая финальный каталог ZIP.</summary>
internal sealed class QuotaWriteStream(Stream inner, long limit) : Stream
{
    private long _written;
    public bool Exceeded { get; private set; }
    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => _written;
    public override long Position { get => _written; set => throw new NotSupportedException(); }
    public override void Flush() => inner.Flush();
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
    public override void Write(ReadOnlySpan<byte> buffer)
    {
        if (Exceeded || buffer.Length > limit - _written)
        {
            Exceeded = true;
            throw new IOException("Архив превышает предел хранения диагностики.");
        }

        inner.Write(buffer);
        _written += buffer.Length;
    }
}
