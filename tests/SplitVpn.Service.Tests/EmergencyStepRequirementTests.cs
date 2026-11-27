using SplitVpn.Core.Recovery;
using SplitVpn.Service.Emergency;

namespace SplitVpn.Service.Tests;

/// <summary>Обязательность шагов экстренного отключения и включения задаётся одним списком необязательных шагов.</summary>
public sealed class EmergencyStepRequirementTests : IDisposable
{
    private readonly FakeEmergencySystem _system = new();

    /// <summary>Шаги-предупреждения: их сбой в отчёте есть, но на код завершения не влияет.</summary>
    private static readonly HashSet<string> Optional =
        [EmergencySteps.FailureActions, EmergencySteps.RestoreFailureActions, EmergencySteps.SuspendState, EmergencySteps.FlushDns];

    public void Dispose() => _system.Dispose();

    private EmergencyOrchestrator Orchestrator() => new(_system, new EmergencyOptions
    {
        LockWait = TimeSpan.FromMilliseconds(10),
        StopWaitBeforeKill = TimeSpan.FromMilliseconds(60),
        KillWait = TimeSpan.FromMilliseconds(60),
        StartWait = TimeSpan.FromMilliseconds(200),
        ScmCallTimeout = TimeSpan.FromMilliseconds(300),
        PollInterval = TimeSpan.FromMilliseconds(5),
        AbandonedStepGrace = TimeSpan.FromMilliseconds(100),
        StepTimeout = _ => TimeSpan.FromSeconds(10),
    });

    [Fact]
    public async Task Off_OnlyWarningStepsAreOptional()
    {
        var report = await Orchestrator().OffAsync(CancellationToken.None);

        Assert.All(report.Steps, s => Assert.Equal(!Optional.Contains(s.Step), s.Required));
        Assert.Equal(4, report.Steps.Count(s => !s.Required));
    }

    [Fact]
    public async Task On_OnlyWarningStepsAreOptional()
    {
        await Orchestrator().OffAsync(CancellationToken.None);
        var report = await Orchestrator().OnAsync(CancellationToken.None);

        Assert.All(report.Steps, s => Assert.Equal(!Optional.Contains(s.Step), s.Required));
        Assert.Contains(report.Steps, s => !s.Required);
    }
}
