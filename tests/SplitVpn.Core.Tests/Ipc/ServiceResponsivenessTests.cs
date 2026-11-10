using SplitVpn.Core.Ipc;

namespace SplitVpn.Core.Tests.Ipc;

public sealed class ServiceResponsivenessTests
{
    private static readonly DateTimeOffset Start = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void SingleTimeout_IsNotReported()
    {
        var health = new ServiceResponsiveness();
        health.OnSuccess(Start);

        Assert.False(health.OnFailure(ServiceUnavailableReason.Timeout, Start.AddSeconds(6.5)));
    }

    [Fact]
    public void SecondTimeoutAfterSilence_IsReported()
    {
        var health = new ServiceResponsiveness();
        health.OnSuccess(Start);

        Assert.False(health.OnFailure(ServiceUnavailableReason.Timeout, Start.AddSeconds(6.5)));
        Assert.True(health.OnFailure(ServiceUnavailableReason.Timeout, Start.AddSeconds(12)));
    }

    [Fact]
    public void SuccessBetweenTimeouts_ResetsCounter()
    {
        var health = new ServiceResponsiveness();
        health.OnSuccess(Start);

        Assert.False(health.OnFailure(ServiceUnavailableReason.Timeout, Start.AddSeconds(6)));
        health.OnSuccess(Start.AddSeconds(8));
        Assert.False(health.OnFailure(ServiceUnavailableReason.Timeout, Start.AddSeconds(14)));
    }

    [Fact]
    public void TwoQuickTimeouts_WaitForSilenceThreshold()
    {
        var health = new ServiceResponsiveness();
        health.OnSuccess(Start);

        Assert.False(health.OnFailure(ServiceUnavailableReason.Timeout, Start.AddSeconds(2)));
        Assert.False(health.OnFailure(ServiceUnavailableReason.Timeout, Start.AddSeconds(4)));
        Assert.True(health.OnFailure(ServiceUnavailableReason.Timeout, Start.AddSeconds(8)));
    }

    [Fact]
    public void StoppedService_IsReportedImmediately()
    {
        var health = new ServiceResponsiveness();
        health.OnSuccess(Start);

        Assert.True(health.OnFailure(ServiceUnavailableReason.NotRunning, Start.AddSeconds(1)));
        Assert.True(health.OnFailure(ServiceUnavailableReason.VersionMismatch, Start.AddSeconds(2)));
    }

    [Fact]
    public void NoSuccessYet_ReportedAfterTwoTimeouts()
    {
        var health = new ServiceResponsiveness();

        Assert.False(health.OnFailure(ServiceUnavailableReason.Timeout, Start));
        Assert.True(health.OnFailure(ServiceUnavailableReason.Timeout, Start.AddSeconds(5)));
    }
}
