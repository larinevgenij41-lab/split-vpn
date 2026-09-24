using System.Globalization;
using System.Net;

namespace SplitVpn.Core.Net;

/// <summary>Почему загрузка не удалась. Общее для списков адресов и установщика программы.</summary>
public enum FetchFailure
{
    None,
    Network,
    Timeout,
    HttpError,
    RateLimited,
    TooLarge,
}

/// <summary>Отказ загрузки: причина, текст для журнала и срок, раньше которого повторять бессмысленно.</summary>
public readonly record struct FetchProblem(FetchFailure Failure, string Message, TimeSpan? RetryAfter = null);

/// <summary>
/// Разбор ответа сервера на «что случилось»: один разбор на оба загрузчика — списка адресов
/// и установщика программы. Тексты идут в журнал службы и на страницу «О программе».
/// </summary>
public static class HttpFailureClassifier
{
    public const string TooLargeMessage = "Ответ источника превышает допустимый размер.";

    public const string TimeoutMessage = "Превышено время ожидания ответа источника.";

    /// <summary>Отказ по коду ответа; null — ответ пригоден (успех или 304 «не изменилось»).</summary>
    public static FetchProblem? Classify(HttpResponseMessage response)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.StatusCode == HttpStatusCode.NotModified)
        {
            return null;
        }

        // 403 от раздачи файлов означает исчерпанный лимит частоты, а не запрет: зеркала перебирать не нужно.
        if (response.StatusCode is HttpStatusCode.TooManyRequests or HttpStatusCode.Forbidden)
        {
            return new FetchProblem(FetchFailure.RateLimited, Describe(response), RetryAfterOf(response));
        }

        return response.IsSuccessStatusCode ? null : new FetchProblem(FetchFailure.HttpError, Describe(response));
    }

    /// <summary>Ошибка сети или чтения в текст для пользователя; имя узла помогает понять, какое зеркало отказало.</summary>
    public static FetchProblem FromException(Exception exception, Uri? url)
    {
        ArgumentNullException.ThrowIfNull(exception);
        if (exception is HttpRequestException)
        {
            var detail = exception.InnerException is { } inner ? $"{exception.Message} {inner.Message}" : exception.Message;
            return new FetchProblem(FetchFailure.Network, "Ошибка сети или TLS: " + detail + (url is null ? "" : $" ({url.Host})"));
        }

        return new FetchProblem(FetchFailure.Network, "Загрузка прервана: " + exception.Message);
    }

    public static TimeSpan? RetryAfterOf(HttpResponseMessage response)
    {
        ArgumentNullException.ThrowIfNull(response);
        var retry = response.Headers.RetryAfter;
        if (retry?.Delta is { } delta)
        {
            return delta;
        }

        return retry?.Date is { } date ? date - DateTimeOffset.UtcNow : null;
    }

    public static string Describe(HttpResponseMessage response)
    {
        ArgumentNullException.ThrowIfNull(response);
        return string.Create(CultureInfo.InvariantCulture, $"Источник ответил HTTP {(int)response.StatusCode} {response.ReasonPhrase}.");
    }
}
