using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using SplitVpn.Core.Geo;
using SplitVpn.Core.Net;
using SplitVpn.Core.Update;

namespace SplitVpn.Core.Tests.Update;

/// <summary>
/// Ограничение частоты (429) у основного адреса не закрывает зеркала: загрузчики идут к следующему источнику,
/// а «лимит» со сроком повтора возвращают, только если отказали все.
/// </summary>
public sealed class RateLimitMirrorTests : IDisposable
{
    private static readonly Uri Primary = new("https://github.com/o/r/releases/download/v1/file");
    private static readonly Uri Mirror = new("https://mirror.example.org/file");

    private readonly string _root = Path.Combine(Path.GetTempPath(), "splitvpn-ratelimit-" + Guid.NewGuid().ToString("N"));

    public RateLimitMirrorTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Временный каталог уберёт система.
        }
    }

    private static HttpResponseMessage TooManyRequests()
    {
        var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
        response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromMinutes(30));
        return response;
    }

    [Fact]
    public async Task Manifest_PrimaryRateLimited_MirrorAnswers()
    {
        var handler = new ScriptedHandler(request => request.RequestUri!.Host == Primary.Host
            ? TooManyRequests()
            : ScriptedHandler.Ok(Encoding.UTF8.GetBytes(request.RequestUri!.AbsoluteUri.EndsWith(".sig", StringComparison.Ordinal)
                ? Convert.ToBase64String(new byte[64])
                : "{\"schema\":1}")));

        var result = await new ManifestDownloader(new HttpClient(handler)).FetchAsync([Primary, Mirror], null, CancellationToken.None);

        Assert.True(result.Ok);
        Assert.Equal(Mirror, result.Url);
    }

    [Fact]
    public async Task Manifest_AllRateLimited_ReportsRetryAfter()
    {
        var result = await new ManifestDownloader(new HttpClient(new ScriptedHandler(_ => TooManyRequests())))
            .FetchAsync([Primary, Mirror], null, CancellationToken.None);

        Assert.Equal(FetchFailure.RateLimited, result.Failure);
        Assert.Equal(TimeSpan.FromMinutes(30), result.RetryAfter);
    }

    [Fact]
    public async Task Manifest_RateLimitedThenNotFound_StillReportsRateLimit()
    {
        var handler = new ScriptedHandler(request => request.RequestUri!.Host == Primary.Host
            ? TooManyRequests()
            : new HttpResponseMessage(HttpStatusCode.NotFound));

        var result = await new ManifestDownloader(new HttpClient(handler)).FetchAsync([Primary, Mirror], null, CancellationToken.None);

        Assert.Equal(FetchFailure.RateLimited, result.Failure);
        Assert.Equal(TimeSpan.FromMinutes(30), result.RetryAfter);
    }

    [Fact]
    public async Task Package_PrimaryRateLimited_MirrorAnswers()
    {
        var body = Encoding.UTF8.GetBytes(new string('п', 4096));
        var handler = new ScriptedHandler(request => request.RequestUri!.Host == Primary.Host ? TooManyRequests() : ScriptedHandler.Ok(body));
        var partial = Path.Combine(_root, "file.part");
        var package = Path.Combine(_root, "file");

        var result = await new PackageDownloader(new HttpClient(handler), spareDiskBytes: 0).DownloadAsync(
            [Primary, Mirror], partial, package, body.Length, Convert.ToHexStringLower(SHA256.HashData(body)), null, CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal(Mirror, result.Url);
        Assert.True(File.Exists(package));
    }

    [Fact]
    public async Task Geo_PrimaryRateLimited_MirrorAnswers()
    {
        var body = Encoding.UTF8.GetBytes("5.8.0.0/16\n");
        var handler = new ScriptedHandler(request => request.RequestUri == LoyalsoldierSource.Primary ? TooManyRequests() : ScriptedHandler.Ok(body));

        var result = await new GeoDownloader(new HttpClient(handler)).FetchAsync(new LoyalsoldierSource(), null, CancellationToken.None);

        Assert.Equal(GeoFetchStatus.Downloaded, result.Status);
        Assert.Equal(LoyalsoldierSource.JsDelivrMirror, result.Url);
    }
}
