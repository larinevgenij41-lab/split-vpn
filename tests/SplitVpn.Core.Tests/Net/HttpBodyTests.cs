using System.Net;
using System.Net.Http.Headers;
using SplitVpn.Core.Net;

namespace SplitVpn.Core.Tests.Net;

/// <summary>
/// Чтение тела с пределом: ровно предел - принимается, на байт больше - null, независимо от того, честен ли
/// Content-Length и какими кусками приходят данные.
/// </summary>
public sealed class HttpBodyTests
{
    /// <summary>Поток без длины, отдающий данные кусками заданного размера.</summary>
    private sealed class ChunkedStream(byte[] data, int chunk) : MemoryStream(data)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            base.ReadAsync(buffer[..Math.Min(buffer.Length, chunk)], cancellationToken);
    }

    private sealed class NoLengthContent(Stream stream) : StreamContent(stream)
    {
        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }

    private static byte[] Data(int length) => [.. Enumerable.Range(0, length).Select(i => (byte)i)];

    private static Task<byte[]?> Read(HttpContent content, long max) => HttpBody.ReadLimitedAsync(content, max, CancellationToken.None);

    [Theory]
    [InlineData(0, 0)]
    [InlineData(0, 10)]
    [InlineData(1, 1)]
    [InlineData(81920, 81920)]
    [InlineData(81921, 81921)]
    [InlineData(81920 * 3, 81920 * 3)]
    public async Task BodyAtOrBelowLimit_IsReturnedExactly(int length, long max)
    {
        var data = Data(length);

        Assert.Equal(data, await Read(new ByteArrayContent(data), max));
        Assert.Equal(data, await Read(new NoLengthContent(new ChunkedStream(data, 7)), max));
    }

    [Theory]
    [InlineData(1, 0)]
    [InlineData(81921, 81920)]
    [InlineData(81920 * 3 + 1, 81920 * 3)]
    public async Task BodyOneByteOverLimit_IsNull_WithAndWithoutContentLength(int length, long max)
    {
        var data = Data(length);

        Assert.Null(await Read(new ByteArrayContent(data), max));
        Assert.Null(await Read(new NoLengthContent(new MemoryStream(data)), max));
        Assert.Null(await Read(new NoLengthContent(new ChunkedStream(data, 1000)), max));
    }

    /// <summary>Сервер занизил Content-Length: решает фактическое число байтов, а не заголовок.</summary>
    [Fact]
    public async Task UnderstatedContentLength_IsNotTrusted()
    {
        var content = new NoLengthContent(new MemoryStream(Data(200)));
        content.Headers.ContentLength = 10;

        Assert.Null(await Read(content, 100));
    }

    /// <summary>Завышенный Content-Length сверх предела отвергается до чтения тела.</summary>
    [Fact]
    public async Task OverstatedContentLength_IsRejectedWithoutReading()
    {
        var stream = new ChunkedStream(Data(10), 10);
        var content = new NoLengthContent(stream);
        content.Headers.ContentLength = long.MaxValue;

        Assert.Null(await Read(content, 1000));
        Assert.Equal(0, stream.Position);
    }

    [Fact]
    public async Task Cancellation_Propagates()
    {
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            HttpBody.ReadLimitedAsync(new NoLengthContent(new ChunkedStream(Data(100), 10)), 1000, cancelled.Token));
    }

    [Fact]
    public async Task BrokenConnection_Propagates() =>
        await Assert.ThrowsAsync<IOException>(() => Read(new NoLengthContent(new BrokenStream(Data(1000))), 10000));

    [Fact]
    public async Task NullContent_Throws() =>
        await Assert.ThrowsAsync<ArgumentNullException>(() => Read(null!, 1));

    /// <summary>Предел long.MaxValue не переполняет сравнение.</summary>
    [Fact]
    public async Task HugeLimit_DoesNotOverflow() =>
        Assert.Equal(Data(5), await Read(new ByteArrayContent(Data(5)), long.MaxValue));

    [Fact]
    public async Task ContentLengthHeaderZero_WithEmptyBody_IsEmptyArrayNotNull()
    {
        var content = new ByteArrayContent([]);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

        var body = await Read(content, 0);

        Assert.NotNull(body);
        Assert.Empty(body);
    }

    [Fact]
    public async Task EmptyResponseFromHandler_Works()
    {
        using var client = new HttpClient(new ScriptedHandler(_ => new HttpResponseMessage(HttpStatusCode.NoContent)));
        using var response = await client.GetAsync(new Uri("https://example.invalid/"), TestContext.Current.CancellationToken);

        var body = await Read(response.Content, 0);
        Assert.NotNull(body);
        Assert.Empty(body);
    }
}
