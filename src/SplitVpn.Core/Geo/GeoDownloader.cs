using System.Net;
using System.Net.Http.Headers;
using SplitVpn.Core.Net;

namespace SplitVpn.Core.Geo;

public enum GeoFetchStatus
{
    Downloaded,
    NotModified,
    Failed,
}

public sealed record GeoFetchResult
{
    public GeoFetchStatus Status { get; init; }

    public byte[]? Content { get; init; }

    public string? ETag { get; init; }

    public DateTimeOffset? LastModified { get; init; }

    public Uri? Url { get; init; }

    public FetchFailure Failure { get; init; }

    public string? Message { get; init; }

    public TimeSpan? RetryAfter { get; init; }
}

/// <summary>Загрузка списка по HTTPS с ETag, таймаутом и ограничением размера; скачанное не исполняется.</summary>
public sealed class GeoDownloader
{
    public const long DefaultMaxBytes = 16 * 1024 * 1024;

    private readonly HttpClient _client;
    private readonly TimeSpan _timeout;
    private readonly long _maxBytes;

    public GeoDownloader(HttpClient client, TimeSpan? timeout = null, long maxBytes = DefaultMaxBytes)
    {
        _client = client;
        _timeout = timeout ?? TimeSpan.FromSeconds(60);
        _maxBytes = maxBytes;
    }

    /// <summary>Перебирает основной адрес и зеркала; при ограничении частоты не переходит к зеркалам.</summary>
    public async Task<GeoFetchResult> FetchAsync(IGeoSource source, string? etag, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(source);
        GeoFetchResult? last = null;
        foreach (var url in source.Urls)
        {
            // ETag относится к основному адресу: у зеркал свои значения.
            last = await FetchOneAsync(url, url == source.Urls[0] ? etag : null, cancellationToken);
            if (last.Status != GeoFetchStatus.Failed || last.Failure == FetchFailure.RateLimited)
            {
                return last;
            }
        }

        return last ?? Failed(null, new FetchProblem(FetchFailure.Network, "Источник не содержит адресов."));
    }

    private async Task<GeoFetchResult> FetchOneAsync(Uri url, string? etag, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_timeout);
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            if (!string.IsNullOrEmpty(etag) && EntityTagHeaderValue.TryParse(etag, out var tag))
            {
                request.Headers.IfNoneMatch.Add(tag);
            }

            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            return await InterpretAsync(url, response, timeout.Token);
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

    private async Task<GeoFetchResult> InterpretAsync(Uri url, HttpResponseMessage response, CancellationToken token)
    {
        if (HttpFailureClassifier.Classify(response) is { } problem)
        {
            return Failed(url, problem);
        }

        if (response.StatusCode == HttpStatusCode.NotModified)
        {
            return new GeoFetchResult { Status = GeoFetchStatus.NotModified, Url = url, ETag = response.Headers.ETag?.ToString() };
        }

        var content = await HttpBody.ReadLimitedAsync(response.Content, _maxBytes, token);
        if (content is null)
        {
            return Failed(url, new FetchProblem(FetchFailure.TooLarge, HttpFailureClassifier.TooLargeMessage));
        }

        return new GeoFetchResult
        {
            Status = GeoFetchStatus.Downloaded,
            Content = content,
            Url = url,
            ETag = response.Headers.ETag?.ToString(),
            LastModified = response.Content.Headers.LastModified,
        };
    }

    private static GeoFetchResult Failed(Uri? url, FetchProblem problem) => new()
    {
        Status = GeoFetchStatus.Failed,
        Url = url,
        Failure = problem.Failure,
        Message = problem.Message,
        RetryAfter = problem.RetryAfter,
    };
}
