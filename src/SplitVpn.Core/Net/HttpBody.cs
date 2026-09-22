namespace SplitVpn.Core.Net;

/// <summary>Чтение тела ответа с пределом размера: чужой ответ не должен занимать память без границ.</summary>
public static class HttpBody
{
    /// <summary>Читает тело целиком; null — предел превышен. Скачанное не исполняется.</summary>
    public static async Task<byte[]?> ReadLimitedAsync(HttpContent content, long maxBytes, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);
        if (content.Headers.ContentLength > maxBytes)
        {
            return null;
        }

        await using var stream = await content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken)) > 0)
        {
            if (buffer.Length + read > maxBytes)
            {
                return null;
            }

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }
}
