using SplitVpn.Core.OpenConnect;

namespace SplitVpn.Core.Tests.OpenConnect;

/// <summary>Окно входа повторяет загрузку после сетевой ошибки, пока опорный VPN поднимается (разбор старта 09.11.2026).</summary>
public sealed class SignInRetryPolicyTests
{
    [Fact]
    public void NetworkError_IsRetriedUpToLimit()
    {
        var policy = new SignInRetryPolicy();

        for (var attempt = 1; attempt <= SignInRetryPolicy.MaxAttempts; attempt++)
        {
            Assert.Equal(attempt, policy.NextAttempt("HostNameNotResolved"));
        }

        Assert.Null(policy.NextAttempt("HostNameNotResolved"));
    }

    [Theory]
    [InlineData("CertificateIsInvalid")]
    [InlineData("OperationCanceled")]
    [InlineData("ValidAuthenticationCredentialsRequired")]
    public void NonNetworkError_IsNotRetried(string status) =>
        Assert.Null(new SignInRetryPolicy().NextAttempt(status));

    [Fact]
    public void SuccessfulLoad_RestoresAttempts()
    {
        var policy = new SignInRetryPolicy();
        for (var i = 0; i < SignInRetryPolicy.MaxAttempts; i++)
        {
            policy.NextAttempt("Timeout");
        }

        policy.Succeeded();

        Assert.Equal(1, policy.NextAttempt("CannotConnect"));
    }
}
