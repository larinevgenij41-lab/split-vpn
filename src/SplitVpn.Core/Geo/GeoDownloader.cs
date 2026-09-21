using System.Globalization;
using System.Net;
using System.Net.Http.Headers;

namespace SplitVpn.Core.Geo;

public enum GeoFetchStatus
{
    Downloaded,
    NotModified,
    Failed,
}

public enum GeoFetchFailure
{
    None,
    Network,
    Timeout,
    HttpError,
    RateLimited,
    TooLarge,
}

public sealed record GeoFetchResult
{
    public GeoFetchStatus Status { get; init; }

    public byte[]? Content { get; init; }

    public string? ETag { get; init; }

    public DateTimeOffset? LastModified { get; init; }

    public Uri? Url { get; init; }

    public GeoFetchFailure Failure { get; init; }

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
            if (last.Status != GeoFetchStatus.Failed || last.Failure == GeoFetchFailure.RateLimited)
            {
                return last;
            }
        }

        return last ?? Failed(null, GeoFetchFailure.Network, "Источник не содержит адресов.");
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
            return Failed(url, GeoFetchFailure.Timeout, "Превышено время ожидания ответа источника.");
        }
        catch (HttpRequestException ex)
        {
            return Failed(url, GeoFetchFailure.Network, "Ошибка сети или TLS: " + (ex.InnerException is { } inner ? $"{ex.Message} {inner.Message}" : ex.Message) + $" ({url.Host})");
        }
        catch (IOException ex)
        {
            return Failed(url, GeoFetchFailure.Network, "Загрузка прервана: " + ex.Message);
        }
    }

    private async Task<GeoFetchResult> InterpretAsync(Uri url, HttpResponseMessage response, CancellationToken token)
    {
        if (response.StatusCode == HttpStatusCode.NotModified)
        {
            return new GeoFetchResult { Status = GeoFetchStatus.NotModified, Url = url, ETag = response.Headers.ETag?.ToString() };
        }

        if (response.StatusCode is HttpStatusCode.TooManyRequests or HttpStatusCode.Forbidden)
        {
            return Failed(url, GeoFetchFailure.RateLimited, Status(response), RetryAfterOf(response));
        }

        if (!response.IsSuccessStatusCode)
        {
            return Failed(url, GeoFetchFailure.HttpError, Status(response));
        }

        if (response.Content.Headers.ContentLength > _maxBytes)
        {
            return Failed(url, GeoFetchFailure.TooLarge, "Ответ источника превышает допустимый размер.");
        }

        var content = await ReadLimitedAsync(response.Content, token);
        if (content is null)
        {
            return Failed(url, GeoFetchFailure.TooLarge, "Ответ источника превышает допустимый размер.");
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

    private async Task<byte[]?> ReadLimitedAsync(HttpContent content, CancellationToken token)
    {
        await using var stream = await content.ReadAsStreamAsync(token);
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = await stream.ReadAsync(chunk, token)) > 0)
        {
            if (buffer.Length + read > _maxBytes)
            {
                return null;
            }

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    private static TimeSpan? RetryAfterOf(HttpResponseMessage response)
    {
        var retry = response.Headers.RetryAfter;
        if (retry?.Delta is { } delta)
        {
            return delta;
        }

        return retry?.Date is { } date ? date - DateTimeOffset.UtcNow : null;
    }

    private static string Status(HttpResponseMessage response) =>
        string.Create(CultureInfo.InvariantCulture, $"Источник ответил HTTP {(int)response.StatusCode} {response.ReasonPhrase}.");

    private static GeoFetchResult Failed(Uri? url, GeoFetchFailure failure, string message, TimeSpan? retryAfter = null) =>
        new() { Status = GeoFetchStatus.Failed, Url = url, Failure = failure, Message = message, RetryAfter = retryAfter };
}
