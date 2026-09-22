using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using SplitVpn.Core.Net;
using SplitVpn.Core.Update;

namespace SplitVpn.Core.Tests.Update;

public sealed class PackageDownloaderTests : IDisposable
{
    private static readonly Uri Primary = new("https://github.com/o/r/releases/download/v1/SplitVpn.msi");
    private static readonly Uri Mirror = new("https://mirror.example.org/SplitVpn.msi");

    private readonly string _root = Path.Combine(Path.GetTempPath(), "splitvpn-package-" + Guid.NewGuid().ToString("N"));
    private readonly byte[] _body = Encoding.UTF8.GetBytes(new string('п', 4096));

    public PackageDownloaderTests() => Directory.CreateDirectory(_root);

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

    private string Partial => Path.Combine(_root, "SplitVpn.msi.part");

    private string Package => Path.Combine(_root, "SplitVpn.msi");

    private string Hash => Convert.ToHexStringLower(SHA256.HashData(_body));

    [Fact]
    public async Task Success_WritesPackageAndRemovesPartial()
    {
        var reported = new List<long>();
        var result = await Download(new ScriptedHandler(_ => ScriptedHandler.Ok(_body)), new Progress(reported));

        Assert.True(result.Success);
        Assert.Equal(_body.Length, result.Bytes);
        Assert.True(File.Exists(Package));
        Assert.False(File.Exists(Partial));
        Assert.Equal(_body, await File.ReadAllBytesAsync(Package, TestContext.Current.CancellationToken));
        Assert.NotEmpty(reported);
    }

    [Fact]
    public async Task ChecksumMismatch_DiscardsEverything()
    {
        var other = Encoding.UTF8.GetBytes(new string('ч', 4096));
        var result = await Download(new ScriptedHandler(_ => ScriptedHandler.Ok(other)));

        Assert.False(result.Success);
        Assert.True(result.PartialDiscarded);
        Assert.False(File.Exists(Package));
        Assert.False(File.Exists(Partial));
    }

    [Fact]
    public async Task LongerThanPromised_IsRejected()
    {
        var result = await Download(new ScriptedHandler(_ => ScriptedHandler.Ok(new byte[_body.Length + 100])));

        Assert.Equal(FetchFailure.TooLarge, result.Failure);
        Assert.False(File.Exists(Partial));
    }

    /// <summary>Обрыв связи сохраняет недокачанное: следующая попытка продолжит с того же места.</summary>
    [Fact]
    public async Task BrokenStream_KeepsPartial()
    {
        var handler = new ScriptedHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new BrokenStream(_body)) });

        var result = await Download(handler);

        Assert.Equal(FetchFailure.Network, result.Failure);
        Assert.True(File.Exists(Partial));
        Assert.True(new FileInfo(Partial).Length > 0);
    }

    [Fact]
    public async Task Resume_ContinuesFromRange()
    {
        var half = _body.Length / 2;
        await File.WriteAllBytesAsync(Partial, _body[..half], TestContext.Current.CancellationToken);
        RangeHeaderValue? requested = null;
        var handler = new ScriptedHandler(request =>
        {
            requested = request.Headers.Range;
            var from = (int)(request.Headers.Range?.Ranges.First().From ?? 0);
            var response = new HttpResponseMessage(HttpStatusCode.PartialContent) { Content = new ByteArrayContent(_body[from..]) };
            return response;
        });

        var result = await Download(handler);

        Assert.True(result.Success);
        Assert.Equal(half, requested?.Ranges.First().From);
        Assert.Equal(_body, await File.ReadAllBytesAsync(Package, TestContext.Current.CancellationToken));
    }

    /// <summary>Источник не понял докачку и отдал файл целиком: запись начинается с нуля, а не дописывается.</summary>
    [Fact]
    public async Task ResumeIgnoredByServer_RewritesFromStart()
    {
        await File.WriteAllBytesAsync(Partial, _body[..100], TestContext.Current.CancellationToken);

        var result = await Download(new ScriptedHandler(_ => ScriptedHandler.Ok(_body)));

        Assert.True(result.Success);
        Assert.Equal(_body, await File.ReadAllBytesAsync(Package, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RangeNotSatisfiable_StartsOver()
    {
        await File.WriteAllBytesAsync(Partial, _body[..100], TestContext.Current.CancellationToken);
        var calls = 0;
        var handler = new ScriptedHandler(request =>
        {
            calls++;
            return request.Headers.Range is not null
                ? new HttpResponseMessage(HttpStatusCode.RequestedRangeNotSatisfiable)
                : ScriptedHandler.Ok(_body);
        });

        var result = await Download(handler);

        Assert.True(result.Success);
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task NotFound_FallsBackToMirror()
    {
        var handler = new ScriptedHandler(request => request.RequestUri == Primary
            ? new HttpResponseMessage(HttpStatusCode.NotFound)
            : ScriptedHandler.Ok(_body));

        var result = await Download(handler);

        Assert.True(result.Success);
        Assert.Equal(Mirror, result.Url);
    }

    /// <summary>Ограничение частоты: зеркала не перебираются, а срок повтора берётся из ответа.</summary>
    [Fact]
    public async Task RateLimited_StopsAndReportsRetryAfter()
    {
        var calls = 0;
        var handler = new ScriptedHandler(_ =>
        {
            calls++;
            var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
            response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromMinutes(30));
            return response;
        });

        var result = await Download(handler);

        Assert.Equal(FetchFailure.RateLimited, result.Failure);
        Assert.Equal(1, calls);
        Assert.Equal(TimeSpan.FromMinutes(30), result.RetryAfter);
    }

    [Fact]
    public async Task ContentLengthOverPromise_IsRejectedBeforeReading()
    {
        var handler = new ScriptedHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(_body) };
            response.Content.Headers.ContentLength = _body.Length + 1000;
            return response;
        });

        var result = await Download(handler);

        Assert.Equal(FetchFailure.TooLarge, result.Failure);
    }

    [Fact]
    public async Task IdleSource_TimesOut()
    {
        var handler = new ScriptedHandler(async (_, token) =>
        {
            await Task.Delay(TimeSpan.FromSeconds(5), token);
            return ScriptedHandler.Ok(_body);
        });

        var result = await Download(handler, idleTimeout: TimeSpan.FromMilliseconds(50));

        Assert.Equal(FetchFailure.Timeout, result.Failure);
    }

    [Fact]
    public async Task NoUrls_IsReported()
    {
        var downloader = new PackageDownloader(new HttpClient(new ScriptedHandler(_ => ScriptedHandler.Ok(_body))), spareDiskBytes: 0);

        var result = await downloader.DownloadAsync([], Partial, Package, _body.Length, Hash, null, CancellationToken.None);

        Assert.False(result.Success);
        Assert.NotNull(result.Message);
    }

    private Task<PackageDownloadResult> Download(HttpMessageHandler handler, IProgress<long>? progress = null, TimeSpan? idleTimeout = null)
    {
        var downloader = new PackageDownloader(new HttpClient(handler), idleTimeout, spareDiskBytes: 0);
        return downloader.DownloadAsync([Primary, Mirror], Partial, Package, _body.Length, Hash, progress, CancellationToken.None);
    }

    private sealed class Progress(List<long> reported) : IProgress<long>
    {
        public void Report(long value) => reported.Add(value);
    }
}
