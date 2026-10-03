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

    /// <summary>Подпись из мусора — отказ источника, а не пустая подпись: перебор идёт к зеркалу.</summary>
    [Fact]
    public async Task GarbageSignature_IsFailureAndMirrorIsTried()
    {
        var handler = new ScriptedHandler(request => ScriptedHandler.Ok(Encoding.UTF8.GetBytes(
            !request.RequestUri!.AbsoluteUri.EndsWith(".sig", StringComparison.Ordinal) ? "{\"schema\":1}"
            : request.RequestUri.Host == Primary.Host ? "не base64!!" : Convert.ToBase64String(new byte[64]))));

        var single = await new ManifestDownloader(new HttpClient(handler)).FetchAsync([Primary], null, CancellationToken.None);
        var both = await new ManifestDownloader(new HttpClient(handler)).FetchAsync([Primary, Mirror], null, CancellationToken.None);

        Assert.False(single.Ok);
        Assert.Equal(FetchFailure.HttpError, single.Failure);
        Assert.True(both.Ok);
        Assert.Equal(Mirror, both.Url);
    }

    /// <summary>
    /// Ответ, отвергнутый проверкой (подпись, срок годности), не останавливает перебор; если не прошёл
    /// ни один источник — возвращается первый отвергнутый ответ, чтобы вызывающий назвал точную причину.
    /// </summary>
    [Fact]
    public async Task RejectedManifest_FallsBackToMirror_OrIsReturnedWhenNothingPasses()
    {
        var handler = new ScriptedHandler(request => ScriptedHandler.Ok(Encoding.UTF8.GetBytes(
            request.RequestUri!.AbsoluteUri.EndsWith(".sig", StringComparison.Ordinal) ? Convert.ToBase64String(new byte[64])
            : request.RequestUri.Host == Primary.Host ? "{\"old\":1}" : "{\"fresh\":1}")));
        var downloader = new ManifestDownloader(new HttpClient(handler));

        var fallback = await downloader.FetchAsync([Primary, Mirror], null,
            f => Encoding.UTF8.GetString(f.Manifest!).Contains("old", StringComparison.Ordinal) ? "старый" : null, CancellationToken.None);
        var none = await downloader.FetchAsync([Primary, Mirror], null, _ => "отвергнут", CancellationToken.None);

        Assert.True(fallback.Ok);
        Assert.Equal(Mirror, fallback.Url);
        Assert.True(none.Ok);
        Assert.Equal(Primary, none.Url);
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
