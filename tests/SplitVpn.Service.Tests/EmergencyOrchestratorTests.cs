using System.Text.Json;
using SplitVpn.Core.Recovery;
using SplitVpn.Core.Settings;
using SplitVpn.Service.Emergency;

namespace SplitVpn.Service.Tests;

/// <summary>Экстренное отключение и включение по шагам — на фейковой системе, без прав администратора.</summary>
public sealed class EmergencyOrchestratorTests : IDisposable
{
    private readonly FakeEmergencySystem _system = new();

    private static readonly string[] OffOrder =
    [
        EmergencySteps.Flag, EmergencySteps.StartType, EmergencySteps.FailureActions, EmergencySteps.Service, EmergencySteps.Helpers,
        EmergencySteps.SuspendState, EmergencySteps.Wfp, EmergencySteps.Ras, EmergencySteps.Routes,
        EmergencySteps.Dns, EmergencySteps.Wcm, EmergencySteps.FlushDns, EmergencySteps.RestoreFailureActions,
    ];

    public void Dispose() => _system.Dispose();

    private static EmergencyOptions Options(Func<string, TimeSpan>? timeout = null) => new()
    {
        LockWait = TimeSpan.FromMilliseconds(10),
        StopWaitBeforeKill = TimeSpan.FromMilliseconds(60),
        KillWait = TimeSpan.FromMilliseconds(60),
        StartWait = TimeSpan.FromMilliseconds(200),
        ScmCallTimeout = TimeSpan.FromMilliseconds(300),
        PollInterval = TimeSpan.FromMilliseconds(5),
        StepTimeout = timeout ?? (_ => TimeSpan.FromSeconds(10)),
    };

    private EmergencyOrchestrator Orchestrator(Func<string, TimeSpan>? timeout = null) => new(_system, Options(timeout));

    [Fact]
    public async Task Off_RunsStepsInOrder_AndTurnsEverythingOff()
    {
        var report = await Orchestrator().OffAsync(CancellationToken.None);

        Assert.Equal(OffOrder, report.Steps.Select(s => s.Step));
        Assert.All(report.Steps, s => Assert.Equal(EmergencyStepOutcome.Done, s.Outcome));
        Assert.Equal(EmergencyExitCodes.Success, report.ExitCode);
        Assert.True(report.NetworkClean);
        Assert.True(report.ServiceConfirmed);
        // Флаг — первым, затем ручной запуск, остановка и сеть: WFP раньше RAS, маршрутов, DNS, Wi-Fi и кеша.
        var calls = _system.Calls;
        Assert.True(IsSubsequence(calls, ["WriteFlag", "SetManualStart", "RequestStop", "RemoveFilters", "HangUp", "RemoveRoutes", "RestoreDns:True", "RestoreWcm", "FlushDns"]),
            string.Join(", ", calls));
        Assert.True(_system.Flag);
        Assert.Equal(EmergencyRegistry.StartDemand, _system.StartType);
        Assert.Equal(EmergencyRegistry.StartAuto, _system.SavedStart);
        Assert.Equal(ServiceRunState.Stopped, _system.State);
        Assert.False(_system.FailureActionsSuspended);
        Assert.All(report.Steps, s => Assert.Equal(EmergencySteps.Title(s.Step), s.Title));
    }

    [Fact]
    public async Task Off_SecondRun_ReportsAlready()
    {
        await Orchestrator().OffAsync(CancellationToken.None);

        var second = await Orchestrator().OffAsync(CancellationToken.None);

        Assert.Equal(EmergencyExitCodes.Success, second.ExitCode);
        foreach (var step in new[] { EmergencySteps.Flag, EmergencySteps.StartType, EmergencySteps.Service, EmergencySteps.Helpers, EmergencySteps.SuspendState,
            EmergencySteps.Wfp, EmergencySteps.Ras, EmergencySteps.Routes, EmergencySteps.Dns, EmergencySteps.Wcm })
        {
            Assert.Equal(EmergencyStepOutcome.Already, second.Steps.Single(s => s.Step == step).Outcome);
        }

        Assert.Equal("auto", _system.SavedStart);
    }

    [Fact]
    public async Task HangingStep_TimesOut_AndLaterStepsStillRun()
    {
        _system.Hang.Add("RemoveFilters");

        var report = await Orchestrator(step => step == EmergencySteps.Wfp ? TimeSpan.FromMilliseconds(200) : TimeSpan.FromSeconds(10))
            .OffAsync(CancellationToken.None);

        var wfp = report.Steps.Single(s => s.Step == EmergencySteps.Wfp);
        Assert.Equal(EmergencyStepOutcome.Timeout, wfp.Outcome);
        Assert.Contains("не завершился", wfp.Detail, StringComparison.Ordinal);
        foreach (var step in new[] { EmergencySteps.Ras, EmergencySteps.Routes, EmergencySteps.Dns, EmergencySteps.Wcm, EmergencySteps.FlushDns })
        {
            Assert.Equal(EmergencyStepOutcome.Done, report.Steps.Single(s => s.Step == step).Outcome);
        }

        Assert.Equal(EmergencyExitCodes.Incomplete, report.ExitCode);
        Assert.False(report.NetworkClean);
    }

    [Fact]
    public async Task ExceptionInServiceStop_DoesNotSkipNetworkSteps()
    {
        _system.QueryThrows = true;
        _system.KillOwnThrows = true;
        _system.OwnProcesses = 1;

        var report = await Orchestrator().OffAsync(CancellationToken.None);

        Assert.Equal(EmergencyStepOutcome.Failed, report.Steps.Single(s => s.Step == EmergencySteps.Service).Outcome);
        foreach (var step in new[] { EmergencySteps.Wfp, EmergencySteps.Ras, EmergencySteps.Routes, EmergencySteps.Dns, EmergencySteps.Wcm })
        {
            Assert.Equal(EmergencyStepOutcome.Done, report.Steps.Single(s => s.Step == step).Outcome);
        }

        Assert.Equal(EmergencyExitCodes.ServiceNotConfirmed, report.ExitCode);
        Assert.True(report.NetworkClean);
        Assert.False(report.ServiceConfirmed);
        // Остановка не подтверждена: DNS сбрасывается по правилам работающей службы.
        Assert.Contains("RestoreDns:False", _system.Calls);
    }

    [Fact]
    public async Task ScmDoesNotAnswer_FallsBackToKillByPath()
    {
        _system.QueryThrows = true;
        _system.OwnProcesses = 2;

        var report = await Orchestrator().OffAsync(CancellationToken.None);

        var service = report.Steps.Single(s => s.Step == EmergencySteps.Service);
        Assert.Equal(EmergencyStepOutcome.Done, service.Outcome);
        Assert.Contains("диспетчер служб не ответил", service.Detail, StringComparison.Ordinal);
        Assert.Contains("KillOwn", _system.Calls);
        Assert.DoesNotContain("RequestStop", _system.Calls);
        Assert.Equal(0, _system.OwnProcesses);
        Assert.Equal(EmergencyExitCodes.Success, report.ExitCode);
    }

    [Fact]
    public async Task HungScmCall_FallsBackToKillByPath()
    {
        _system.Hang.Add("QueryService");
        _system.OwnProcesses = 1;

        var report = await Orchestrator().OffAsync(CancellationToken.None);

        Assert.Equal(EmergencyStepOutcome.Done, report.Steps.Single(s => s.Step == EmergencySteps.Service).Outcome);
        Assert.Contains("KillOwn", _system.Calls);
    }

    [Fact]
    public async Task StopIgnored_KillsRegisteredPid_RetriesWhenPidChanges()
    {
        _system.StopIgnored = true;
        _system.Pid = 100;
        _system.PidAfterFailedKill = 200;
        _system.KillRefused.Add(100);

        var report = await Orchestrator().OffAsync(CancellationToken.None);

        var service = report.Steps.Single(s => s.Step == EmergencySteps.Service);
        Assert.Equal(EmergencyStepOutcome.Done, service.Outcome);
        Assert.Contains("200", service.Detail, StringComparison.Ordinal);
        Assert.Equal(["Kill:100", "Kill:200"], _system.Calls.Where(c => c.StartsWith("Kill:", StringComparison.Ordinal)));
        // Автоперезапуск снят на всю остановку и возвращён после неё.
        Assert.True(IsSubsequence(_system.Calls, ["SuspendFailureActions", "Kill:200", "RestoreFailureActions"]));
    }

    [Fact]
    public async Task NotElevated_DoesNothing()
    {
        _system.Elevated = false;

        var report = await Orchestrator().OffAsync(CancellationToken.None);

        Assert.Equal(EmergencyExitCodes.NotElevated, report.ExitCode);
        Assert.Empty(report.Steps);
        Assert.DoesNotContain("Lock", _system.Calls);
        Assert.False(_system.Flag);
    }

    [Fact]
    public async Task BusyLock_DoesNothing()
    {
        _system.LockBusy = true;

        var off = await Orchestrator().OffAsync(CancellationToken.None);
        var on = await Orchestrator().OnAsync(CancellationToken.None);

        Assert.Equal(EmergencyExitCodes.Busy, off.ExitCode);
        Assert.Equal(EmergencyExitCodes.Busy, on.ExitCode);
        Assert.Empty(off.Steps);
        Assert.Equal(["Lock", "Lock"], _system.Calls);
    }

    [Fact]
    public async Task Uninstall_SkipsFlagAndStartType_ProceedsWhenBusy()
    {
        _system.LockBusy = true;

        var report = await new EmergencyOrchestrator(_system, Options() with { ProceedWhenBusy = true }).UninstallNetworkAsync(CancellationToken.None);

        Assert.Equal(OffOrder.Skip(2), report.Steps.Select(s => s.Step));
        Assert.False(_system.Flag);
        Assert.Equal(EmergencyRegistry.StartAuto, _system.StartType);
        Assert.True(report.NetworkClean);
        Assert.True(report.ServiceConfirmed);
    }

    [Fact]
    public async Task On_ClearsFlag_RestoresStartType_RestartsInertService()
    {
        await Orchestrator().OffAsync(CancellationToken.None);
        _system.SavedStart = EmergencyRegistry.StartDelayedAuto;
        _system.State = ServiceRunState.Running; // установщик запустил «пустую» службу
        _system.Calls.Clear();

        var report = await Orchestrator().OnAsync(CancellationToken.None);

        Assert.Equal([EmergencySteps.FailureActions, EmergencySteps.Service, EmergencySteps.RestoreFailureActions, EmergencySteps.SuspendState,
            EmergencySteps.ClearFlag, EmergencySteps.RestoreStartType, EmergencySteps.StartService], report.Steps.Select(s => s.Step));
        Assert.Equal(EmergencyExitCodes.Success, report.ExitCode);
        Assert.True(report.ServiceConfirmed);
        Assert.False(_system.Flag);
        Assert.Equal(EmergencyRegistry.StartDelayedAuto, _system.StartType);
        Assert.Null(_system.SavedStart);
        Assert.Equal(ServiceRunState.Running, _system.State);
        Assert.True(IsSubsequence(_system.Calls, ["RequestStop", "SuspendProtection", "ClearFlag", "RestoreStartType", "RequestStart"]));
        // Ничего сетевого включение не делает.
        Assert.DoesNotContain("RemoveFilters", _system.Calls);
    }

    [Fact]
    public async Task On_StartFails_IsCode2_FlagNotCleared_IsCode3()
    {
        _system.Flag = true;
        _system.State = ServiceRunState.Stopped;
        _system.StartIgnored = true;
        var report = await Orchestrator().OnAsync(CancellationToken.None);
        Assert.Equal(EmergencyExitCodes.ServiceNotConfirmed, report.ExitCode);

        _system.StartIgnored = false;
        _system.Flag = true;
        _system.ClearFlagThrows = true;
        report = await Orchestrator().OnAsync(CancellationToken.None);
        Assert.Equal(EmergencyExitCodes.Incomplete, report.ExitCode);
        Assert.Equal(EmergencyStepOutcome.Failed, report.Steps.Single(s => s.Step == EmergencySteps.ClearFlag).Outcome);
    }

    [Theory]
    [InlineData(EmergencySteps.Wfp, EmergencyStepOutcome.Failed, EmergencyExitCodes.Incomplete)]
    [InlineData(EmergencySteps.Ras, EmergencyStepOutcome.Timeout, EmergencyExitCodes.Incomplete)]
    [InlineData(EmergencySteps.Dns, EmergencyStepOutcome.Failed, EmergencyExitCodes.Incomplete)]
    [InlineData(EmergencySteps.Helpers, EmergencyStepOutcome.Failed, EmergencyExitCodes.Incomplete)]
    [InlineData(EmergencySteps.Wcm, EmergencyStepOutcome.Failed, EmergencyExitCodes.Incomplete)]
    [InlineData(EmergencySteps.Service, EmergencyStepOutcome.Timeout, EmergencyExitCodes.ServiceNotConfirmed)]
    [InlineData(EmergencySteps.Flag, EmergencyStepOutcome.Failed, EmergencyExitCodes.ServiceNotConfirmed)]
    [InlineData(EmergencySteps.StartType, EmergencyStepOutcome.Failed, EmergencyExitCodes.ServiceNotConfirmed)]
    [InlineData(EmergencySteps.FlushDns, EmergencyStepOutcome.Failed, EmergencyExitCodes.Success)]
    [InlineData(EmergencySteps.SuspendState, EmergencyStepOutcome.Failed, EmergencyExitCodes.Success)]
    [InlineData(EmergencySteps.Service, EmergencyStepOutcome.Skipped, EmergencyExitCodes.Success)]
    public void OffExitCode_Mapping(string failedStep, EmergencyStepOutcome outcome, int expected)
    {
        var steps = OffOrder.Select(step => new EmergencyStepReport(step, EmergencySteps.Title(step),
            step == failedStep ? outcome : EmergencyStepOutcome.Done, null, 1,
            Required: step is not (EmergencySteps.FlushDns or EmergencySteps.SuspendState or EmergencySteps.FailureActions or EmergencySteps.RestoreFailureActions))).ToList();

        Assert.Equal(expected, EmergencyOrchestrator.OffExitCode(steps));
    }

    [Fact]
    public void OffExitCode_NetworkWinsOverService()
    {
        var steps = new[]
        {
            new EmergencyStepReport(EmergencySteps.Service, "", EmergencyStepOutcome.Failed, null, 1),
            new EmergencyStepReport(EmergencySteps.Dns, "", EmergencyStepOutcome.Failed, null, 1),
        };

        Assert.Equal(EmergencyExitCodes.Incomplete, EmergencyOrchestrator.OffExitCode(steps));
    }

    [Fact]
    public async Task Report_IsCamelCaseJson_WithLowercaseOutcomes_AndLastCopy()
    {
        _system.Hang.Add("RemoveRoutes");
        var report = await Orchestrator(step => step == EmergencySteps.Routes ? TimeSpan.FromMilliseconds(100) : TimeSpan.FromSeconds(10))
            .OffAsync(CancellationToken.None);
        var json = JsonSerializer.Serialize(report, JsonDefaults.Options);
        var root = Path.Combine(Path.GetTempPath(), "SplitVpn.Test." + Guid.NewGuid().ToString("N"));
        var directory = Path.Combine(root, EmergencyReportFiles.DirectoryName);
        try
        {
            var secured = 0;
            var first = EmergencyReportWriter.Write(directory, json, d => { secured++; Directory.CreateDirectory(d); return []; }, _ => true, _ => { });
            var second = EmergencyReportWriter.Write(directory, json.Replace("\"version\"", "\"version\" ", StringComparison.Ordinal), _ => [], _ => true, _ => { });

            Assert.NotNull(first);
            Assert.NotNull(second);
            Assert.NotEqual(first, second);
            Assert.Equal(1, secured);
            Assert.StartsWith("emergency-", Path.GetFileName(first), StringComparison.Ordinal);
            var last = File.ReadAllBytes(Path.Combine(directory, EmergencyReportFiles.LastFileName));
            Assert.Equal(File.ReadAllBytes(second), last);
            Assert.False(last.Length >= 3 && last[0] == 0xEF && last[1] == 0xBB && last[2] == 0xBF, "без BOM");
            Assert.Empty(Directory.GetFiles(directory, "*.tmp"));

            using var document = JsonDocument.Parse(last);
            var top = document.RootElement;
            Assert.Equal(1, top.GetProperty("version").GetInt32());
            Assert.Equal(EmergencyCommands.Off, top.GetProperty("command").GetString());
            Assert.Equal(EmergencyExitCodes.Incomplete, top.GetProperty("exitCode").GetInt32());
            Assert.False(top.GetProperty("networkClean").GetBoolean());
            Assert.True(top.GetProperty("serviceConfirmed").GetBoolean());
            Assert.False(string.IsNullOrEmpty(top.GetProperty("summary").GetString()));
            var routes = top.GetProperty("steps").EnumerateArray().Single(s => s.GetProperty("step").GetString() == EmergencySteps.Routes);
            Assert.Equal("timeout", routes.GetProperty("outcome").GetString());
            Assert.Equal("Маршруты программы", routes.GetProperty("title").GetString());
            Assert.True(routes.GetProperty("ms").GetInt64() >= 0);
            Assert.True(routes.GetProperty("required").GetBoolean());
            Assert.Equal("done", top.GetProperty("steps")[0].GetProperty("outcome").GetString());
            Assert.Equal(report.Steps.Count, EmergencyReportFiles.Parse(File.ReadAllText(Path.Combine(directory, EmergencyReportFiles.LastFileName)))!.Steps.Count);
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public void Report_ForeignDirectory_IsNotUsed()
    {
        var root = Path.Combine(Path.GetTempPath(), "SplitVpn.Test." + Guid.NewGuid().ToString("N"));
        var directory = Path.Combine(root, EmergencyReportFiles.DirectoryName);
        Directory.CreateDirectory(directory);
        try
        {
            var warnings = new List<string>();
            Assert.Null(EmergencyReportWriter.Write(directory, "{}", _ => [], _ => false, warnings.Add));
            Assert.Empty(Directory.EnumerateFileSystemEntries(directory));
            Assert.Contains(warnings, w => w.Contains("посторонней", StringComparison.Ordinal));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData(new[] { "recover" }, RecoveryMode.Recover)]
    [InlineData(new[] { "emergency-off" }, RecoveryMode.EmergencyOff)]
    [InlineData(new[] { "EMERGENCY-ON" }, RecoveryMode.EmergencyOn)]
    [InlineData(new[] { "recover", "--uninstall-network" }, RecoveryMode.UninstallNetwork)]
    public void Commands_AreParsed(string[] args, RecoveryMode expected)
    {
        Assert.True(ServiceRecovery.IsRecoveryCommand(args[0]));
        Assert.Equal(expected, ServiceRecovery.ParseMode(args));
    }

    [Fact]
    public void Flag_ParsedFromRegistryValues()
    {
        Assert.Null(EmergencyRegistry.Parse(null, null));
        Assert.Null(EmergencyRegistry.Parse(0, "2026-11-25T08:00:00.0000000+00:00"));
        Assert.Equal(new DateTimeOffset(2026, 11, 25, 8, 0, 0, TimeSpan.Zero), EmergencyRegistry.Parse(1, "2026-11-25T08:00:00.0000000+00:00")!.SinceUtc);
        Assert.Null(EmergencyRegistry.Parse(1, "мусор")!.SinceUtc);
    }

    private static bool IsSubsequence(IReadOnlyList<string> calls, IReadOnlyList<string> expected)
    {
        var index = 0;
        foreach (var call in calls)
        {
            if (index < expected.Count && call == expected[index])
            {
                index++;
            }
        }

        return index == expected.Count;
    }
}

/// <summary>Система для оркестратора: состояние в памяти, вызовы записываются, любой вызов можно «подвесить».</summary>
internal sealed class FakeEmergencySystem : IEmergencySystem, IDisposable
{
    private readonly Lock _lock = new();
    private readonly List<string> _calls = [];
    private readonly ManualResetEventSlim _release = new();

    public List<string> Calls
    {
        get
        {
            lock (_lock)
            {
                return _calls;
            }
        }
    }

    /// <summary>Вызовы, которые висят до конца теста.</summary>
    public HashSet<string> Hang { get; } = [];

    public bool Elevated { get; set; } = true;
    public bool LockBusy { get; set; }
    public bool Flag { get; set; }
    public bool ClearFlagThrows { get; set; }
    public string StartType { get; set; } = EmergencyRegistry.StartAuto;
    public string? SavedStart { get; set; }
    public bool FailureActionsSuspended { get; private set; }
    public ServiceRunState State { get; set; } = ServiceRunState.Running;
    public uint Pid { get; set; } = 100;
    public uint? PidAfterFailedKill { get; set; }
    public HashSet<uint> KillRefused { get; } = [];
    public bool QueryThrows { get; set; }
    public bool StopIgnored { get; set; }
    public bool StartIgnored { get; set; }
    public bool KillOwnThrows { get; set; }
    public int OwnProcesses { get; set; }
    public int Helpers { get; set; } = 1;
    public bool Suspended { get; set; }
    public int Filters { get; set; } = 10;
    public int Connections { get; set; } = 1;
    public int Routes { get; set; } = 5;
    public bool DnsOurs { get; set; } = true;
    public bool WcmChanged { get; set; } = true;

    private void Call(string name)
    {
        lock (_lock)
        {
            _calls.Add(name);
        }

        if (Hang.Contains(name))
        {
            _release.Wait();
            throw new OperationCanceledException("отпущен в конце теста");
        }
    }

    public void Dispose()
    {
        _release.Set();
    }

    public bool IsElevated() => Elevated;

    public IDisposable? TryAcquireLock(TimeSpan wait)
    {
        Call("Lock");
        return LockBusy ? null : new Held();
    }

    private sealed class Held : IDisposable
    {
        public void Dispose()
        {
        }
    }

    public StepResult WriteFlag(DateTimeOffset now)
    {
        Call("WriteFlag");
        if (Flag) return StepResult.Already();
        Flag = true;
        return StepResult.Done();
    }

    public StepResult ClearFlag()
    {
        Call("ClearFlag");
        if (ClearFlagThrows) throw new UnauthorizedAccessException("реестр недоступен");
        if (!Flag) return StepResult.Already();
        Flag = false;
        return StepResult.Done();
    }

    public StepResult SetManualStart()
    {
        Call("SetManualStart");
        if (StartType == EmergencyRegistry.StartDemand) return StepResult.Already();
        SavedStart ??= StartType;
        StartType = EmergencyRegistry.StartDemand;
        return StepResult.Done();
    }

    public StepResult RestoreStartType()
    {
        Call("RestoreStartType");
        var target = SavedStart ?? EmergencyRegistry.StartAuto;
        SavedStart = null;
        if (StartType == target) return StepResult.Already();
        StartType = target;
        return StepResult.Done();
    }

    public StepResult SuspendFailureActions()
    {
        Call("SuspendFailureActions");
        FailureActionsSuspended = true;
        return StepResult.Done();
    }

    public StepResult RestoreFailureActions()
    {
        Call("RestoreFailureActions");
        FailureActionsSuspended = false;
        return StepResult.Done();
    }

    public ServiceSnapshot? QueryService()
    {
        Call("QueryService");
        if (QueryThrows) throw new InvalidOperationException("диспетчер служб недоступен");
        return new ServiceSnapshot(State, State == ServiceRunState.Stopped ? 0 : Pid);
    }

    public void RequestStop()
    {
        Call("RequestStop");
        if (!StopIgnored) State = ServiceRunState.Stopped;
    }

    public void RequestStart()
    {
        Call("RequestStart");
        if (!StartIgnored) State = ServiceRunState.Running;
    }

    public bool KillServiceProcess(uint processId, TimeSpan wait)
    {
        Call("Kill:" + processId);
        if (KillRefused.Contains(processId))
        {
            Pid = PidAfterFailedKill ?? Pid;
            throw new InvalidOperationException($"процесс {processId} — уже не служба");
        }

        State = ServiceRunState.Stopped;
        return true;
    }

    public int KillOwnServiceProcesses()
    {
        Call("KillOwn");
        if (KillOwnThrows) throw new IOException("отказано в доступе");
        var killed = OwnProcesses;
        OwnProcesses = 0;
        if (!QueryThrows) State = ServiceRunState.Stopped;
        return killed;
    }

    public int CountOwnServiceProcesses() => OwnProcesses;

    public StepResult StopHelpers()
    {
        Call("StopHelpers");
        if (Helpers == 0) return StepResult.Already();
        Helpers = 0;
        return StepResult.Done();
    }

    public StepResult SuspendProtection()
    {
        Call("SuspendProtection");
        if (Suspended) return StepResult.Already();
        Suspended = true;
        return StepResult.Done();
    }

    public StepResult RemoveFilters()
    {
        Call("RemoveFilters");
        if (Filters == 0) return StepResult.Already();
        Filters = 0;
        return StepResult.Done();
    }

    public Task<StepResult> HangUpConnectionsAsync(CancellationToken cancellationToken)
    {
        Call("HangUp");
        if (Connections == 0) return Task.FromResult(StepResult.Already());
        Connections = 0;
        return Task.FromResult(StepResult.Done());
    }

    public StepResult RemoveRoutes()
    {
        Call("RemoveRoutes");
        if (Routes == 0) return StepResult.Already();
        Routes = 0;
        return StepResult.Done();
    }

    public StepResult RestoreDns(bool serviceStopped)
    {
        Call("RestoreDns:" + serviceStopped);
        if (!DnsOurs) return StepResult.Already();
        DnsOurs = false;
        return StepResult.Done();
    }

    public StepResult RestoreWcm()
    {
        Call("RestoreWcm");
        if (!WcmChanged) return StepResult.Already();
        WcmChanged = false;
        return StepResult.Done();
    }

    public StepResult FlushDns()
    {
        Call("FlushDns");
        return StepResult.Done();
    }
}
