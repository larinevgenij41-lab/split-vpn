using System.Net;
using System.Net.Http.Headers;
using System.Text;
using SplitVpn.Core.Geo;

namespace SplitVpn.Core.Tests.Geo;

public class GeoDownloaderTests
{
    private static readonly byte[] Body = Encoding.UTF8.GetBytes("5.8.0.0/16\n");

    [Fact]
    public async Task Success_ReturnsContentAndETag()
    {
        var handler = new ScriptedHandler(_ => Ok(Body, "\"abc\""));
        var result = await Downloader(handler).FetchAsync(new LoyalsoldierSource(), null, CancellationToken.None);

        Assert.Equal(GeoFetchStatus.Downloaded, result.Status);
        Assert.Equal(Body, result.Content);
        Assert.Equal("\"abc\"", result.ETag);
    }

    [Fact]
    public async Task NotModified_SendsIfNoneMatch()
    {
        string? sentTag = null;
        var handler = new ScriptedHandler(request =>
        {
            sentTag = request.Headers.IfNoneMatch.ToString();
            return new HttpResponseMessage(HttpStatusCode.NotModified);
        });

        var result = await Downloader(handler).FetchAsync(new LoyalsoldierSource(), "\"abc\"", CancellationToken.None);

        Assert.Equal(GeoFetchStatus.NotModified, result.Status);
        Assert.Equal("\"abc\"", sentTag);
    }

    [Fact]
    public async Task NotFound_FallsBackToMirror()
    {
        var handler = new ScriptedHandler(request => request.RequestUri == LoyalsoldierSource.Primary
            ? new HttpResponseMessage(HttpStatusCode.NotFound)
            : Ok(Body, null));

        var result = await Downloader(handler).FetchAsync(new LoyalsoldierSource(), null, CancellationToken.None);

        Assert.Equal(GeoFetchStatus.Downloaded, result.Status);
        Assert.Equal(LoyalsoldierSource.JsDelivrMirror, result.Url);
    }

    [Theory]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.Forbidden)]
    public async Task RateLimited_StopsAndReportsRetryAfter(HttpStatusCode code)
    {
        var calls = 0;
        var handler = new ScriptedHandler(_ =>
        {
            calls++;
            var response = new HttpResponseMessage(code);
            response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromMinutes(30));
            return response;
        });

        var result = await Downloader(handler).FetchAsync(new LoyalsoldierSource(), null, CancellationToken.None);

        Assert.Equal(GeoFetchFailure.RateLimited, result.Failure);
        Assert.Equal(TimeSpan.FromMinutes(30), result.RetryAfter);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task Timeout_IsReportedPerMirror()
    {
        var handler = new ScriptedHandler(async (_, token) =>
        {
            await Task.Delay(TimeSpan.FromSeconds(10), token);
            return Ok(Body, null);
        });

        var result = await new GeoDownloader(new HttpClient(handler), TimeSpan.FromMilliseconds(50))
            .FetchAsync(new LoyalsoldierSource(), null, CancellationToken.None);

        Assert.Equal(GeoFetchFailure.Timeout, result.Failure);
    }

    [Fact]
    public async Task TlsOrNetworkError_IsReported()
    {
        var handler = new ScriptedHandler(_ => throw new HttpRequestException("The SSL connection could not be established"));

        var result = await Downloader(handler).FetchAsync(new LoyalsoldierSource(), null, CancellationToken.None);

        Assert.Equal(GeoFetchStatus.Failed, result.Status);
        Assert.Equal(GeoFetchFailure.Network, result.Failure);
    }

    [Fact]
    public async Task InterruptedStream_IsReported()
    {
        var handler = new ScriptedHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new BrokenStream(Body)) });

        var result = await Downloader(handler).FetchAsync(new LoyalsoldierSource(), null, CancellationToken.None);

        Assert.Equal(GeoFetchFailure.Network, result.Failure);
    }

    [Fact]
    public async Task OversizedResponse_IsRejected()
    {
        var handler = new ScriptedHandler(_ => Ok(new byte[5000], null));

        var result = await new GeoDownloader(new HttpClient(handler), maxBytes: 1000).FetchAsync(new LoyalsoldierSource(), null, CancellationToken.None);

        Assert.Equal(GeoFetchFailure.TooLarge, result.Failure);
    }

    private static GeoDownloader Downloader(HttpMessageHandler handler) => new(new HttpClient(handler));

    private static HttpResponseMessage Ok(byte[] body, string? etag)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) };
        if (etag is not null)
        {
            response.Headers.ETag = EntityTagHeaderValue.Parse(etag);
        }

        return response;
    }

    private sealed class ScriptedHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _respond;

        public ScriptedHandler(Func<HttpRequestMessage, HttpResponseMessage> respond)
        {
            _respond = (request, _) => Task.FromResult(respond(request));
        }

        public ScriptedHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond)
        {
            _respond = respond;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            _respond(request, cancellationToken);
    }

    /// <summary>Отдаёт половину данных и падает, как оборванное соединение.</summary>
    private sealed class BrokenStream(byte[] data) : MemoryStream(data)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (Position >= Length / 2)
            {
                throw new IOException("Соединение разорвано");
            }

            var count = (int)Math.Min(buffer.Length, (Length / 2) - Position);
            return base.ReadAsync(buffer[..count], cancellationToken);
        }
    }
}
