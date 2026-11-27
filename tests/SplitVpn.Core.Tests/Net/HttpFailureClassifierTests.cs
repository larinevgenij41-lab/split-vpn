using System.Net;
using System.Net.Http.Headers;
using SplitVpn.Core.Net;

namespace SplitVpn.Core.Tests.Net;

/// <summary>
/// Разбор отказа загрузки. Контракт: 2xx и 304 - не отказ; 429 и 403 с явным признаком лимита - RateLimited
/// с паузой не дольше суток; прочее - HttpError. Текст - инвариантный, с кодом ответа.
/// </summary>
public sealed class HttpFailureClassifierTests
{
    private static HttpResponseMessage Response(int code) => new((HttpStatusCode)code);

    [Theory]
    [InlineData(200)]
    [InlineData(204)]
    [InlineData(206)]
    [InlineData(299)]
    [InlineData(304)]
    public void SuccessAndNotModified_AreNotFailures(int code) => Assert.Null(HttpFailureClassifier.Classify(Response(code)));

    [Theory]
    [InlineData(100)]
    [InlineData(199)]
    [InlineData(300)]
    [InlineData(301)]
    [InlineData(302)]
    [InlineData(400)]
    [InlineData(403)]
    [InlineData(404)]
    [InlineData(500)]
    [InlineData(503)]
    [InlineData(599)]
    [InlineData(999)]
    public void OtherCodes_AreHttpErrors(int code)
    {
        var problem = HttpFailureClassifier.Classify(Response(code));

        Assert.Equal(FetchFailure.HttpError, problem?.Failure);
        Assert.Null(problem?.RetryAfter);
        Assert.Contains($"HTTP {code}", problem!.Value.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TooManyRequests_IsRateLimited_EvenWithoutRetryAfter()
    {
        var problem = HttpFailureClassifier.Classify(Response(429));

        Assert.Equal(FetchFailure.RateLimited, problem?.Failure);
        Assert.Null(problem?.RetryAfter);
    }

    [Theory]
    [InlineData("0", true)]
    [InlineData("1", false)]
    [InlineData("00", false)]
    [InlineData("", false)]
    public void Forbidden_IsRateLimitedOnlyWhenRemainingIsZero(string remaining, bool limited)
    {
        var response = Response(403);
        response.Headers.TryAddWithoutValidation("X-RateLimit-Remaining", remaining);

        Assert.Equal(limited ? FetchFailure.RateLimited : FetchFailure.HttpError, HttpFailureClassifier.Classify(response)?.Failure);
    }

    [Fact]
    public void Forbidden_WithRetryAfter_IsRateLimited_WithThatPause()
    {
        var response = Response(403);
        response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(90));

        var problem = HttpFailureClassifier.Classify(response);

        Assert.Equal(FetchFailure.RateLimited, problem?.Failure);
        Assert.Equal(TimeSpan.FromSeconds(90), problem?.RetryAfter);
    }

    [Theory]
    [InlineData(0, null)]
    [InlineData(1, 1)]
    [InlineData(86400, 86400)]
    [InlineData(86401, 86400)]
    [InlineData(int.MaxValue, 86400)]
    public void RetryAfterDelta_IsClampedToOneDay_AndZeroIsNoPause(int seconds, int? expected)
    {
        var response = Response(429);
        response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(seconds));

        Assert.Equal(expected is { } e ? TimeSpan.FromSeconds(e) : null, HttpFailureClassifier.RetryAfterOf(response));
    }

    /// <summary>Неразборчивый Retry-After («скоро», отрицательное число) - без паузы, а не исключение.</summary>
    [Theory]
    [InlineData("soon")]
    [InlineData("-5")]
    [InlineData("1.5")]
    [InlineData("99999999999999999999")]
    public void MalformedRetryAfter_IsIgnored(string value)
    {
        var response = Response(429);
        response.Headers.TryAddWithoutValidation("Retry-After", value);

        Assert.Null(HttpFailureClassifier.RetryAfterOf(response));
        Assert.Equal(FetchFailure.RateLimited, HttpFailureClassifier.Classify(response)?.Failure);
    }

    [Fact]
    public void RetryAfterDate_FarFutureAndPast_DoNotDependOnExactClock()
    {
        var future = Response(429);
        future.Headers.RetryAfter = new RetryConditionHeaderValue(DateTimeOffset.UtcNow.AddYears(5));
        var past = Response(429);
        past.Headers.RetryAfter = new RetryConditionHeaderValue(new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero));

        Assert.Equal(HttpFailureClassifier.MaxRetryAfter, HttpFailureClassifier.RetryAfterOf(future));
        Assert.Null(HttpFailureClassifier.RetryAfterOf(past));
    }

    [Fact]
    public void Describe_IsInvariant_AndIncludesReasonPhrase()
    {
        var response = Response(503);
        response.ReasonPhrase = "Service Unavailable";

        TestCulture.AssertSameUnderAll(() => HttpFailureClassifier.Describe(response));
        Assert.Contains("HTTP 503 Service Unavailable.", HttpFailureClassifier.Describe(response), StringComparison.Ordinal);
    }

    /// <summary>Код без стандартной фразы: «HTTP 599.» без пробела перед точкой.</summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void Describe_WithoutReasonPhrase_HasNoDanglingSpace(string? reason)
    {
        var response = Response(599);
        response.ReasonPhrase = reason;

        Assert.EndsWith("HTTP 599.", HttpFailureClassifier.Describe(response), StringComparison.Ordinal);
    }

    [Fact]
    public void FromException_HttpRequest_IncludesInnerMessageAndHost()
    {
        var problem = HttpFailureClassifier.FromException(
            new HttpRequestException("outer", new IOException("inner")), new Uri("https://mirror.example.org/list.txt"));

        Assert.Equal(FetchFailure.Network, problem.Failure);
        Assert.Contains("outer inner", problem.Message, StringComparison.Ordinal);
        Assert.EndsWith("(mirror.example.org)", problem.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void FromException_WithoutUrlOrInner_HasNoEmptyParentheses()
    {
        var problem = HttpFailureClassifier.FromException(new HttpRequestException("outer"), null);

        Assert.DoesNotContain("()", problem.Message, StringComparison.Ordinal);
        Assert.EndsWith("outer", problem.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void FromException_OtherException_IsNetworkInterrupted()
    {
        var problem = HttpFailureClassifier.FromException(new IOException("reset"), new Uri("https://a.example/"));

        Assert.Equal(FetchFailure.Network, problem.Failure);
        Assert.EndsWith("reset", problem.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void NullArguments_Throw()
    {
        Assert.Throws<ArgumentNullException>(() => HttpFailureClassifier.Classify(null!));
        Assert.Throws<ArgumentNullException>(() => HttpFailureClassifier.RetryAfterOf(null!));
        Assert.Throws<ArgumentNullException>(() => HttpFailureClassifier.Describe(null!));
        Assert.Throws<ArgumentNullException>(() => HttpFailureClassifier.FromException(null!, null));
    }
}
