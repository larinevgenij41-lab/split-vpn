using System.Net;
using System.Text;
using SplitVpn.Core.Net;
using SplitVpn.Core.Update;

namespace SplitVpn.Core.Tests.Update;

public class ManifestDownloaderTests
{
    private static readonly Uri Primary = new("https://github.com/o/r/releases/latest/download/update.json");
    private static readonly Uri Mirror = new("https://cdn.example.org/update.json");

    [Fact]
    public async Task ManifestAndSignature_AreFetchedFromSameSource()
    {
        var manifest = Encoding.UTF8.GetBytes("{\"schema\":1}");
        var signature = Convert.ToBase64String(new byte[64]);
        var asked = new List<Uri>();
        var handler = new ScriptedHandler(request =>
        {
            asked.Add(request.RequestUri!);
            return ScriptedHandler.Ok(request.RequestUri!.AbsoluteUri.EndsWith(".sig", StringComparison.Ordinal)
                ? Encoding.UTF8.GetBytes(signature)
                : manifest, "\"v1\"");
        });

        var result = await new ManifestDownloader(new HttpClient(handler)).FetchAsync([Primary], null, CancellationToken.None);

        Assert.True(result.Ok);
        Assert.Equal(manifest, result.Manifest);
        Assert.Equal(new byte[64], result.Signature);
        Assert.Equal("\"v1\"", result.ETag);
        Assert.Equal([Primary, new Uri(Primary.AbsoluteUri + ".sig")], asked);
    }

    [Fact]
    public async Task NotModified_IsReportedWithoutSignature()
    {
        var handler = new ScriptedHandler(_ => new HttpResponseMessage(HttpStatusCode.NotModified));

        var result = await new ManifestDownloader(new HttpClient(handler)).FetchAsync([Primary], "\"v1\"", CancellationToken.None);

        Assert.True(result.NotModified);
        Assert.False(result.Ok);
    }

    [Fact]
    public async Task FailedPrimary_FallsBackToMirror()
    {
        var handler = new ScriptedHandler(request => request.RequestUri!.Host == Primary.Host
            ? new HttpResponseMessage(HttpStatusCode.NotFound)
            : ScriptedHandler.Ok(Encoding.UTF8.GetBytes(request.RequestUri!.AbsoluteUri.EndsWith(".sig", StringComparison.Ordinal)
                ? Convert.ToBase64String(new byte[64])
                : "{\"schema\":1}")));

        var result = await new ManifestDownloader(new HttpClient(handler)).FetchAsync([Primary, Mirror], null, CancellationToken.None);

        Assert.True(result.Ok);
        Assert.Equal(Mirror, result.Url);
    }

    /// <summary>Подпись не читается — манифест не принимается: проверять его будет нечем.</summary>
    [Fact]
    public async Task MissingSignature_IsFailure()
    {
        var handler = new ScriptedHandler(request => request.RequestUri!.AbsoluteUri.EndsWith(".sig", StringComparison.Ordinal)
            ? new HttpResponseMessage(HttpStatusCode.NotFound)
            : ScriptedHandler.Ok(Encoding.UTF8.GetBytes("{\"schema\":1}")));

        var result = await new ManifestDownloader(new HttpClient(handler)).FetchAsync([Primary], null, CancellationToken.None);

        Assert.False(result.Ok);
        Assert.Equal(FetchFailure.HttpError, result.Failure);
    }

    /// <summary>Подпись из мусора разбирается в пустую: проверка затем её отклонит, исключения не будет.</summary>
    [Fact]
    public async Task GarbageSignature_BecomesEmpty()
    {
        var handler = new ScriptedHandler(request => ScriptedHandler.Ok(Encoding.UTF8.GetBytes(
            request.RequestUri!.AbsoluteUri.EndsWith(".sig", StringComparison.Ordinal) ? "не base64!!" : "{\"schema\":1}")));

        var result = await new ManifestDownloader(new HttpClient(handler)).FetchAsync([Primary], null, CancellationToken.None);

        Assert.True(result.Ok);
        Assert.Empty(result.Signature!);
    }

    [Fact]
    public async Task OversizedManifest_IsRejected()
    {
        var handler = new ScriptedHandler(_ => ScriptedHandler.Ok(new byte[UpdateManifestParser.MaxManifestBytes + 1]));

        var result = await new ManifestDownloader(new HttpClient(handler)).FetchAsync([Primary], null, CancellationToken.None);

        Assert.Equal(FetchFailure.TooLarge, result.Failure);
    }

    [Fact]
    public async Task NoUrls_IsReported()
    {
        var result = await new ManifestDownloader(new HttpClient()).FetchAsync([], null, CancellationToken.None);

        Assert.False(result.Ok);
        Assert.NotNull(result.Message);
    }

    /// <summary>Адреса манифеста по умолчанию: основной выпуск и два зеркала дерева репозитория.</summary>
    [Fact]
    public void DefaultSources_AreHttpsAndOrdered()
    {
        var urls = UpdateSources.ManifestUrls(["https://my.example.org/update.json", "не адрес"]);

        Assert.Equal(UpdateSources.LatestRelease, urls[0]);
        Assert.Contains(UpdateSources.JsDelivrMirror, urls);
        Assert.Contains(UpdateSources.RawMirror, urls);
        Assert.Equal(4, urls.Count);
        Assert.All(urls, u => Assert.Equal(Uri.UriSchemeHttps, u.Scheme));
    }
}
