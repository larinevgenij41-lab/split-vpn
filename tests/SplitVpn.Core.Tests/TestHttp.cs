using System.Net;
using System.Net.Http.Headers;

namespace SplitVpn.Core.Tests;

/// <summary>Подставной обработчик HTTP: ответы задаются по запросу. Общий для тестов загрузчиков.</summary>
internal sealed class ScriptedHandler : HttpMessageHandler
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

    public static HttpResponseMessage Ok(byte[] body, string? etag = null)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) };
        if (etag is not null)
        {
            response.Headers.ETag = EntityTagHeaderValue.Parse(etag);
        }

        return response;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
        _respond(request, cancellationToken);
}

/// <summary>Отдаёт половину данных и падает, как оборванное соединение.</summary>
internal sealed class BrokenStream(byte[] data) : MemoryStream(data)
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
