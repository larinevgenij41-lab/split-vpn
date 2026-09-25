using System.Net;
using System.Net.Http.Headers;
using SplitVpn.Core.Net;

namespace SplitVpn.Core.Update;

/// <summary>Результат обращения к источнику манифеста: сам манифест с подписью либо причина отказа.</summary>
public sealed record ManifestFetch
{
    /// <summary>Источник ответил «не изменилось»: проверять нечего, срок следующей проверки продлевается.</summary>
    public bool NotModified { get; init; }

    public byte[]? Manifest { get; init; }

    public byte[]? Signature { get; init; }

    public string? ETag { get; init; }

    public Uri? Url { get; init; }

    public FetchFailure Failure { get; init; }

    public string? Message { get; init; }

    public TimeSpan? RetryAfter { get; init; }

    public bool Ok => Manifest is not null && Signature is not null;
}

/// <summary>
/// Манифест релиза и отсоединённая подпись к нему. Подпись лежит рядом с манифестом под тем же именем
/// с «.sig» на конце и берётся с того же адреса: иначе зеркало могло бы отдать свежий манифест со
/// старой подписью.
/// </summary>
public sealed class ManifestDownloader(HttpClient client, TimeSpan? timeout = null)
{
    /// <summary>Подпись P-256 — 64 байта; предел с запасом на перевод строки в конце файла.</summary>
    public const long MaxSignatureBytes = 1024;

    public const string SignatureSuffix = ".sig";

    private readonly TimeSpan _timeout = timeout ?? TimeSpan.FromSeconds(30);

    /// <summary>Перебирает адреса по порядку; при ограничении частоты к следующему не переходит.</summary>
    public async Task<ManifestFetch> FetchAsync(IReadOnlyList<Uri> urls, string? etag, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(urls);
        ManifestFetch? last = null;
        foreach (var url in urls)
        {
            // ETag относится к основному адресу: у зеркал свои значения.
            last = await FetchOneAsync(url, url == urls[0] ? etag : null, cancellationToken);
            if (last.Ok || last.NotModified || last.Failure == FetchFailure.RateLimited)
            {
                return last;
            }
        }

        return last ?? Failed(null, new FetchProblem(FetchFailure.Network, "Не задан адрес проверки обновлений."));
    }

    private async Task<ManifestFetch> FetchOneAsync(Uri url, string? etag, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_timeout);
        try
        {
            var (manifest, notModified, tag, problem) = await GetAsync(url, etag, UpdateManifestParser.MaxManifestBytes, timeout.Token);
            if (problem is { } manifestProblem)
            {
                return Failed(url, manifestProblem);
            }

            if (notModified)
            {
                return new ManifestFetch { NotModified = true, Url = url, ETag = tag };
            }

            var signatureUrl = new Uri(url.AbsoluteUri + SignatureSuffix);
            var (signature, _, _, signatureProblem) = await GetAsync(signatureUrl, null, MaxSignatureBytes, timeout.Token);
            if (signatureProblem is { } failure)
            {
                return Failed(signatureUrl, failure);
            }

            return new ManifestFetch { Manifest = manifest, Signature = Decode(signature), Url = url, ETag = tag };
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Failed(url, new FetchProblem(FetchFailure.Timeout, HttpFailureClassifier.TimeoutMessage));
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException)
        {
            return Failed(url, HttpFailureClassifier.FromException(ex, url));
        }
    }

    private async Task<(byte[]? Content, bool NotModified, string? ETag, FetchProblem? Problem)> GetAsync(
        Uri url, string? etag, long maxBytes, CancellationToken token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        if (!string.IsNullOrEmpty(etag) && EntityTagHeaderValue.TryParse(etag, out var tag))
        {
            request.Headers.IfNoneMatch.Add(tag);
        }

        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token);
        if (HttpFailureClassifier.Classify(response) is { } problem)
        {
            return (null, false, null, problem);
        }

        if (response.StatusCode == HttpStatusCode.NotModified)
        {
            return (null, true, response.Headers.ETag?.ToString(), null);
        }

        var content = await HttpBody.ReadLimitedAsync(response.Content, maxBytes, token);
        return content is null
            ? (null, false, null, new FetchProblem(FetchFailure.TooLarge, HttpFailureClassifier.TooLargeMessage))
            : (content, false, response.Headers.ETag?.ToString(), null);
    }

    /// <summary>Подпись выкладывается в base64 текстом; посторонние пробелы и переводы строк отбрасываются.</summary>
    private static byte[] Decode(byte[]? content)
    {
        if (content is null)
        {
            return [];
        }

        try
        {
            return Convert.FromBase64String(System.Text.Encoding.UTF8.GetString(content).Trim());
        }
        catch (FormatException)
        {
            return [];
        }
    }

    private static ManifestFetch Failed(Uri? url, FetchProblem problem) => new()
    {
        Url = url,
        Failure = problem.Failure,
        Message = problem.Message,
        RetryAfter = problem.RetryAfter,
    };
}
