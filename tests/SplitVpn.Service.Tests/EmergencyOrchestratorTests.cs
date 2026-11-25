using System.Text.Json;
using SplitVpn.Core.Recovery;
using SplitVpn.Core.Settings;
using SplitVpn.Service.Emergency;

namespace SplitVpn.Service.Tests;

/// <summary>Экстренное отключение и включение по шагам — на фейковой системе, без прав администратора.</summary>
public sealed class EmergencyOrchestratorTests : IDisposable
{
    private readonly FakeEmergencySystem _system = new();

    /// <summary>Порядок при подтверждённой остановке: автоперезапуск возвращается сразу после неё.</summary>
    private static readonly string[] OffOrder =
    [
        EmergencySteps.Flag, EmergencySteps.StartType, EmergencySteps.FailureActions, EmergencySteps.Service, EmergencySteps.RestoreFailureActions,
        EmergencySteps.Helpers, EmergencySteps.Wfp, EmergencySteps.Ras, EmergencySteps.Routes, EmergencySteps.Dns, EmergencySteps.Wcm,
        EmergencySteps.ServiceRecheck, EmergencySteps.SuspendState, EmergencySteps.FlushDns,
    ];

    private static readonly HashSet<string> OptionalSteps =
        [EmergencySteps.FlushDns, EmergencySteps.SuspendState, EmergencySteps.FailureActions, EmergencySteps.RestoreFailureActions];

    public void Dispose() => _system.Dispose();

    private static EmergencyOptions Options(Func<string, TimeSpan>? timeout = null) => new()
    {
        LockWait = TimeSpan.FromMilliseconds(10),
        StopWaitBeforeKill = TimeSpan.FromMilliseconds(60),
        KillWait = TimeSpan.FromMilliseconds(60),
        StartWait = TimeSpan.FromMilliseconds(200),
        ScmCallTimeout = TimeSpan.FromMilliseconds(300),
        PollInterval = TimeSpan.FromMilliseconds(5),
        AbandonedStepGrace = TimeSpan.FromMilliseconds(100),
        StepTimeout = timeout ?? (_ => TimeSpan.FromSeconds(10)),
    };

    private EmergencyOrchestrator Orchestrator(Func<string, TimeSpan>? timeout = null) => new(_system, Options(timeout));

    [Fact]
    public async Task Off_RunsStepsInOrder_AndTurnsEverythingOff()
    {
        var report = await Orchestrator().OffAsync(CancellationToken.None);

        Assert.Equal(OffOrder, report.Steps.Select(s => s.Step));
        Assert.All(report.Steps.Where(s => s.Step != EmergencySteps.ServiceRecheck), s => Assert.Equal(EmergencyStepOutcome.Done, s.Outcome));
        Assert.Equal(EmergencyStepOutcome.Already, report.Steps.Single(s => s.Step == EmergencySteps.ServiceRecheck).Outcome);
        Assert.Equal(EmergencyExitCodes.Success, report.ExitCode);
        Assert.True(report.NetworkClean);
        Assert.True(report.ServiceConfirmed);
        // Флаг — первым, затем ручной запуск, остановка, сразу возврат автоперезапуска и сеть: WFP раньше RAS, маршрутов,
        // DNS, Wi-Fi и кеша; флаг приостановки — после сети.
        var calls = _system.Calls;
        Assert.True(IsSubsequence(calls, ["WriteFlag", "SetManualStart", "SuspendFailureActions", "RequestStop", "RestoreFailureActions", "RemoveFilters", "HangUp",
            "RemoveRoutes", "RestoreDns:True", "RestoreWcm", "SuspendProtection", "FlushDns"]), string.Join(", ", calls));
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

    /// <summary>
    /// Остановка не удалась, и процесс службы жив: сетевые шаги всё равно выполнены, но живая служба вернёт своё — сеть не
    /// считается возвращённой (код 3, а не 2), итог говорит, что служба работает, автоперезапуск возвращается в конце.
    /// </summary>
    [Fact]
    public async Task ServiceStepFailed_WhileServiceAlive_IsIncomplete()
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

        var recheck = report.Steps.Single(s => s.Step == EmergencySteps.ServiceRecheck);
        Assert.Equal(EmergencyStepOutcome.Failed, recheck.Outcome);
        Assert.StartsWith("служба всё ещё работает", recheck.Detail, StringComparison.Ordinal);
        Assert.Equal(EmergencyExitCodes.Incomplete, report.ExitCode);
        Assert.False(report.NetworkClean);
        Assert.False(report.ServiceConfirmed);
        Assert.Contains("Служба всё ещё работает", report.Summary, StringComparison.Ordinal);
        Assert.Equal(EmergencySteps.RestoreFailureActions, report.Steps[^1].Step);
        // Остановка не подтверждена: DNS сбрасывается по правилам работающей службы.
        Assert.Contains("RestoreDns:False", _system.Calls);
        Assert.False(ServiceRecovery.MayPurgeData(report with { Command = "uninstall-network" }, trusted: true, staleMarkCleared: true));
    }

    /// <summary>
    /// Остановка не подтверждена, но повторная проверка завершила процесс службы: фильтры, маршруты и DNS снимаются ещё раз
    /// (DNS — уже по правилам остановленной службы), сеть возвращена, код 2.
    /// </summary>
    [Fact]
    public async Task ServiceStepFailed_RecheckKillsService_AndCleansAgain()
    {
        _system.QueryThrows = true;
        _system.KillOwnFailuresLeft = 1;
        _system.OwnProcesses = 1;

        var report = await Orchestrator().OffAsync(CancellationToken.None);

        Assert.Equal(EmergencyStepOutcome.Failed, report.Steps.Single(s => s.Step == EmergencySteps.Service).Outcome);
        var recheck = report.Steps.Single(s => s.Step == EmergencySteps.ServiceRecheck);
        Assert.Equal(EmergencyStepOutcome.Done, recheck.Outcome);
        Assert.Contains("завершено: 1", recheck.Detail, StringComparison.Ordinal);
        Assert.True(IsSubsequence(_system.Calls, ["RestoreDns:False", "RestoreWcm", "KillOwn", "RemoveFilters", "RemoveRoutes", "RestoreDns:True"]),
            string.Join(", ", _system.Calls));
        Assert.Equal(EmergencyExitCodes.ServiceNotConfirmed, report.ExitCode);
        Assert.True(report.NetworkClean);
        Assert.DoesNotContain("Служба всё ещё работает", report.Summary, StringComparison.Ordinal);
    }

    /// <summary>Служба уже остановлена и лишних процессов нет — завершать нечего (команды восстановления не трогаются).</summary>
    [Fact]
    public async Task AlreadyStopped_NoStrays_KillsNothing()
    {
        _system.State = ServiceRunState.Stopped;

        var report = await Orchestrator().OffAsync(CancellationToken.None);

        Assert.Equal(EmergencyStepOutcome.Already, report.Steps.Single(s => s.Step == EmergencySteps.Service).Outcome);
        Assert.DoesNotContain("KillOwn", _system.Calls);
        Assert.Equal(EmergencyExitCodes.Success, report.ExitCode);
    }

    /// <summary>
    /// Истёк общий срок команды (сторож удаления программы): не запущенные шаги — «timeout» с понятной причиной, а не
    /// «skipped»; сеть не возвращена, и удаление данных (с копией DNS) не разрешается.
    /// </summary>
    [Fact]
    public async Task OverallDeadline_StepsNotRun_AreTimeouts_AndBlockPurge()
    {
        _system.Hang.Add("RemoveFilters");
        using var overall = new CancellationTokenSource();
        overall.CancelAfter(TimeSpan.FromMilliseconds(300));

        var report = await new EmergencyOrchestrator(_system, Options()).UninstallNetworkAsync(overall.Token);

        Assert.Equal(EmergencyStepOutcome.Timeout, report.Steps.Single(s => s.Step == EmergencySteps.Wfp).Outcome);
        foreach (var step in new[] { EmergencySteps.Ras, EmergencySteps.Routes, EmergencySteps.Dns, EmergencySteps.Wcm, EmergencySteps.ServiceRecheck })
        {
            var skipped = report.Steps.Single(s => s.Step == step);
            Assert.Equal(EmergencyStepOutcome.Timeout, skipped.Outcome);
            Assert.Equal("не запущен: истёк общий срок команды", skipped.Detail);
        }

        Assert.DoesNotContain(report.Steps, s => s.Outcome == EmergencyStepOutcome.Skipped);
        Assert.DoesNotContain("HangUp", _system.Calls);
        Assert.Equal(EmergencyExitCodes.Incomplete, report.ExitCode);
        Assert.False(report.NetworkClean);
        Assert.False(ServiceRecovery.MayPurgeData(report, trusted: true, staleMarkCleared: true));
    }

    [Fact]
    public async Task PurgeData_OnlyForCleanUninstall()
    {
        var clean = await new EmergencyOrchestrator(_system, Options()).UninstallNetworkAsync(CancellationToken.None);

        Assert.True(ServiceRecovery.MayPurgeData(clean, trusted: true, staleMarkCleared: true));
        Assert.False(ServiceRecovery.MayPurgeData(clean, trusted: false, staleMarkCleared: true));
        Assert.False(ServiceRecovery.MayPurgeData(clean, trusted: true, staleMarkCleared: false));
        Assert.False(ServiceRecovery.MayPurgeData(clean with { ServiceConfirmed = false }, trusted: true, staleMarkCleared: true));

        // Сетевой шаг пропал из отчёта — сеть не считается возвращённой, даже если флаг в отчёте выставлен.
        var missing = clean with { Steps = clean.Steps.Where(s => s.Step != EmergencySteps.Dns).ToList() };
        Assert.False(EmergencyOrchestrator.IsNetworkClean(missing.Steps));
        Assert.False(ServiceRecovery.MayPurgeData(missing, trusted: true, staleMarkCleared: true));
    }

    /// <summary>Шаг не уложился в свой срок: его токен отменён к возврату итога (явно, а не таймером), шаг узнаёт об этом сразу.</summary>
    [Fact]
    public async Task StepTimeout_CancelsStepTokenExplicitly()
    {
        var runner = new EmergencyOrchestrator.StepRunner(Options(_ => TimeSpan.FromMilliseconds(100)));
        CancellationToken seen = default;
        using var started = new ManualResetEventSlim();
        using var observed = new ManualResetEventSlim();
        using var stepReturned = new ManualResetEventSlim();

        var report = await runner.StepAsync(EmergencySteps.Wfp, token =>
        {
            seen = token;
            started.Set();
            stepReturned.Wait(TimeSpan.FromSeconds(10), CancellationToken.None);
            if (token.IsCancellationRequested) observed.Set();
            return StepResult.Done();
        }, CancellationToken.None);

        Assert.Equal(EmergencyStepOutcome.Timeout, report.Outcome);
        Assert.True(started.Wait(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken));
        Assert.True(seen.IsCancellationRequested);
        stepReturned.Set();
        Assert.True(observed.Wait(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken));
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

    /// <summary>
    /// Блокировку держит кто-то другой (обычный пользователь мог создать мьютекс в Global\ заранее) или её не открыть:
    /// команда всё равно выполняется, код 5 не возвращается, а итог говорит, что без блокировки.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LockUnavailable_ProceedsWithNote(bool throws)
    {
        _system.LockBusy = !throws;
        _system.LockThrows = throws;

        var off = await Orchestrator().OffAsync(CancellationToken.None);
        var on = await Orchestrator().OnAsync(CancellationToken.None);

        foreach (var report in new[] { off, on })
        {
            Assert.Equal(EmergencyExitCodes.Success, report.ExitCode);
            Assert.NotEmpty(report.Steps);
            Assert.Contains("команда выполнена без неё", report.Summary, StringComparison.Ordinal);
        }

        Assert.True(off.NetworkClean);
        Assert.False(_system.Flag);
        Assert.Contains("RemoveFilters", _system.Calls);
    }

    [Fact]
    public async Task Uninstall_SkipsFlagAndStartType_ProceedsWhenBusy()
    {
        _system.LockBusy = true;

        var report = await new EmergencyOrchestrator(_system, Options()).UninstallNetworkAsync(CancellationToken.None);

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
    [InlineData(EmergencySteps.ServiceRecheck, EmergencyStepOutcome.Failed, EmergencyExitCodes.Incomplete)]
    [InlineData(EmergencySteps.RestoreFailureActions, EmergencyStepOutcome.Timeout, EmergencyExitCodes.Success)]
    public void OffExitCode_Mapping(string failedStep, EmergencyStepOutcome outcome, int expected)
    {
        var steps = OffOrder.Select(step => new EmergencyStepReport(step, EmergencySteps.Title(step),
            step == failedStep ? outcome : EmergencyStepOutcome.Done, null, 1, Required: !OptionalSteps.Contains(step))).ToList();

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

    /// <summary>
    /// Каталог отчётов заранее создал кто-то другой: в него ничего не пишется, он переносится в сторону (.untrusted-…), а
    /// отчёт ложится в заново созданный защищённый каталог.
    /// </summary>
    [Fact]
    public void Report_ForeignDirectory_IsSetAside_AndRecreated()
    {
        var root = Path.Combine(Path.GetTempPath(), "SplitVpn.Test." + Guid.NewGuid().ToString("N"));
        var directory = Path.Combine(root, EmergencyReportFiles.DirectoryName);
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "planted.txt"), "чужое");
        try
        {
            var warnings = new List<string>();
            var path = EmergencyReportWriter.Write(directory, "{}", d => { Directory.CreateDirectory(d); return []; },
                d => !File.Exists(Path.Combine(d.FullName, "planted.txt")), warnings.Add);

            Assert.NotNull(path);
            Assert.Equal(directory, Path.GetDirectoryName(path));
            Assert.False(File.Exists(Path.Combine(directory, "planted.txt")));
            var aside = Assert.Single(Directory.GetDirectories(root, EmergencyReportFiles.DirectoryName + ".untrusted-*"));
            Assert.True(File.Exists(Path.Combine(aside, "planted.txt")));
            Assert.Single(Directory.GetFiles(aside));
            Assert.Contains(warnings, w => w.Contains("посторонней", StringComparison.Ordinal) && w.Contains("перенесён", StringComparison.Ordinal));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>Каталог так и не стал своим за три попытки: отчёт не записан (только вывод команды).</summary>
    [Fact]
    public void Report_DirectoryStaysForeign_GivesUpAfterThreeAttempts()
    {
        var root = Path.Combine(Path.GetTempPath(), "SplitVpn.Test." + Guid.NewGuid().ToString("N"));
        var directory = Path.Combine(root, EmergencyReportFiles.DirectoryName);
        Directory.CreateDirectory(directory);
        try
        {
            var warnings = new List<string>();
            Assert.Null(EmergencyReportWriter.Write(directory, "{}", d => { Directory.CreateDirectory(d); return []; }, _ => false, warnings.Add));
            Assert.Equal(3, Directory.GetDirectories(root, EmergencyReportFiles.DirectoryName + ".untrusted-*").Length);
            Assert.Empty(Directory.GetFiles(directory));
            Assert.Contains(warnings, w => w.Contains("перенести его в сторону не удалось", StringComparison.Ordinal));
            Assert.Contains("только в выводе команды", EmergencyReportWriter.NotWrittenNote, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void FailureActions_RoundTripAndLeftoverRestore()
    {
        var snapshot = new FailureActionsSnapshot(86400, [(1, 5000), (1, 5000), (1, 5000)]);
        var text = snapshot.Serialize();

        Assert.Equal("v1;reset=86400;actions=1:5000,1:5000,1:5000", text);
        Assert.Equal(snapshot, FailureActionsSnapshot.Parse(text));
        Assert.Equal(new FailureActionsSnapshot(0, []), FailureActionsSnapshot.Parse("v1;reset=0;actions="));
        Assert.Null(FailureActionsSnapshot.Parse("v1;reset=x;actions="));
        Assert.Null(FailureActionsSnapshot.Parse("v1;reset=1;actions=9:1"));
        Assert.Null(FailureActionsSnapshot.Parse(null));

        // Запуск службы: запись от прерванной команды возвращается и удаляется; без записи — ничего.
        FailureActionsSnapshot? applied = null;
        var deleted = 0;
        var warnings = new List<string>();
        Assert.True(ServiceFailurePolicy.RestoreLeftover(() => text, s => applied = s, () => deleted++, warnings.Add));
        Assert.Equal(snapshot, applied);
        Assert.Equal(1, deleted);
        Assert.False(ServiceFailurePolicy.RestoreLeftover(() => null, _ => throw new InvalidOperationException(), () => deleted++, warnings.Add));
        Assert.Equal(1, deleted);

        // Не разобрать — запись удаляется, действия не трогаются; сбой возврата — запись остаётся до следующего раза.
        Assert.False(ServiceFailurePolicy.RestoreLeftover(() => "мусор", _ => throw new InvalidOperationException(), () => deleted++, warnings.Add));
        Assert.Equal(2, deleted);
        Assert.False(ServiceFailurePolicy.RestoreLeftover(() => text, _ => throw new InvalidOperationException("нет доступа"), () => deleted++, warnings.Add));
        Assert.Equal(2, deleted);
        Assert.Contains(warnings, w => w.Contains("нет доступа", StringComparison.Ordinal));
    }

    /// <summary>
    /// Завершаются только процессы службы: другая команда восстановления из того же SplitVpn.Service.exe (первый аргумент —
    /// emergency-off, emergency-on или recover) не трогается; командную строку не прочитать — процесс считается службой.
    /// </summary>
    [Theory]
    [InlineData("\"C:\\Program Files\\SplitVpn\\SplitVpn.Service.exe\"", true)]
    [InlineData("\"C:\\Program Files\\SplitVpn\\SplitVpn.Service.exe\" emergency-off", false)]
    [InlineData("\"C:\\Program Files\\SplitVpn\\SplitVpn.Service.exe\" EMERGENCY-ON", false)]
    [InlineData("SplitVpn.Service.exe recover --uninstall-network", false)]
    [InlineData("SplitVpn.Service.exe --contentRoot x", true)]
    [InlineData("SplitVpn.Service.exe \"emergency-off\"", false)]
    public void KillSelection_SkipsRecoveryCommands(string commandLine, bool serviceHost)
    {
        Assert.Equal(serviceHost, SystemEmergency.IsServiceHost(SplitVpn.Windows.Native.ProcessImage.SplitCommandLine(commandLine)));
    }

    [Fact]
    public void KillSelection_UnreadableCommandLine_CountsAsService()
    {
        Assert.True(SystemEmergency.IsServiceHost(null));
        Assert.True(SystemEmergency.IsServiceHost([]));

        // Командная строка своего процесса читается без особых прав.
        var own = SplitVpn.Windows.Native.ProcessImage.TryGetArguments(Environment.ProcessId);
        Assert.NotNull(own);
        Assert.NotEmpty(own);
    }

    [Fact]
    public void DataRootTrust_RequiresTrustedOwnerAndNoForeignWrite()
    {
        var system = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
        var admins = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
        var users = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null);
        var creatorOwner = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.CreatorOwnerSid, null);
        const System.Security.AccessControl.InheritanceFlags inherit =
            System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit;

        System.Security.AccessControl.DirectorySecurity Secure(System.Security.Principal.SecurityIdentifier owner)
        {
            var security = new System.Security.AccessControl.DirectorySecurity();
            security.SetOwner(owner);
            security.SetAccessRuleProtection(true, false);
            foreach (var sid in new[] { system, admins })
            {
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(sid, System.Security.AccessControl.FileSystemRights.FullControl,
                    inherit, System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
            }

            return security;
        }

        Assert.Null(DataRootTrust.Problem(FileAttributes.Directory, Secure(system)));

        var readable = Secure(admins);
        readable.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(users, System.Security.AccessControl.FileSystemRights.ReadAndExecute,
            inherit, System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
        readable.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(creatorOwner, System.Security.AccessControl.FileSystemRights.FullControl,
            inherit, System.Security.AccessControl.PropagationFlags.InheritOnly, System.Security.AccessControl.AccessControlType.Allow));
        Assert.Null(DataRootTrust.Problem(FileAttributes.Directory, readable));

        Assert.Contains("посторонней", DataRootTrust.Problem(FileAttributes.Directory, Secure(users)), StringComparison.Ordinal);
        Assert.Contains("ссылкой", DataRootTrust.Problem(FileAttributes.Directory | FileAttributes.ReparsePoint, Secure(system)), StringComparison.Ordinal);

        var writable = Secure(system);
        writable.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(users, System.Security.AccessControl.FileSystemRights.CreateFiles,
            inherit, System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
        Assert.Contains(users.Value, DataRootTrust.Problem(FileAttributes.Directory, writable), StringComparison.Ordinal);

        // Каталог, созданный обычным пользователем (временный каталог теста), недоверенный; каталога нет — нечего читать.
        var temp = Path.Combine(Path.GetTempPath(), "SplitVpn.Test." + Guid.NewGuid().ToString("N"));
        Assert.Equal(new DataRootTrustResult(false, null), DataRootTrust.Check(temp, Path.Combine(temp, "dns-backup.json")));
        Directory.CreateDirectory(temp);
        try
        {
            Assert.NotNull(DataRootTrust.Check(temp, Path.Combine(temp, "dns-backup.json")).Problem);
        }
        finally
        {
            Directory.Delete(temp);
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

    // ---------- Итерация 11: сроки, повторные снятия, итог, метка запуска, другая команда ----------

    /// <summary>
    /// Худший случай в договоре — это ожидание блокировки, проверка другой команды, запас для зависших шагов и сумма сроков
    /// всех шагов, которые команда может выполнить; общий срок команды по умолчанию равен ему, а сроки шагов по умолчанию
    /// берутся из того же договора.
    /// </summary>
    [Fact]
    public void WorstCase_IsSumOfStepBudgets_AndIsTheDefaultDeadline()
    {
        static TimeSpan Sum(IEnumerable<string> steps) => steps.Aggregate(
            EmergencyTimeouts.LockWait + EmergencyTimeouts.OtherCommandCheck + EmergencyTimeouts.AbandonedStepGrace, (t, s) => t + EmergencyTimeouts.Step(s));

        Assert.Equal(Sum(EmergencyTimeouts.OffSteps), EmergencyTimeouts.OffWorstCase);
        Assert.Equal(Sum(EmergencyTimeouts.OnSteps), EmergencyTimeouts.OnWorstCase);
        Assert.Equal(TimeSpan.FromMinutes(17), EmergencyTimeouts.OffWorstCase);
        Assert.Distinct(EmergencyTimeouts.OffSteps);

        var defaults = new EmergencyOptions();
        Assert.Equal(EmergencyTimeouts.OffWorstCase, defaults.OffDeadline);
        Assert.Equal(EmergencyTimeouts.OnWorstCase, defaults.OnDeadline);
        Assert.Equal(EmergencyTimeouts.LockWait, defaults.LockWait);
        Assert.All(EmergencyTimeouts.OffSteps.Concat(EmergencyTimeouts.OnSteps), s => Assert.Equal(EmergencyTimeouts.Step(s), defaults.TimeoutFor(s)));
        // Срок штатной остановки — тот же, что у службы (срок остановки хоста и 2 с на выход процесса).
        Assert.Equal(ServiceRecovery.StopWaitBeforeKill, EmergencyTimeouts.StopWaitBeforeKill);
        // Повторная проверка больше не включает повторные снятия: её срок покрывает два завершения и два вызова диспетчера.
        Assert.True(EmergencyTimeouts.Step(EmergencySteps.ServiceRecheck) >= 2 * (EmergencyTimeouts.KillWait + EmergencyTimeouts.ScmCallTimeout));
    }

    /// <summary>Самый длинный путь отключения (служба жива до конца) не выходит за шаги договора и не повторяет шаг.</summary>
    [Fact]
    public async Task LongestOffPath_UsesOnlyContractSteps()
    {
        _system.QueryThrows = true;
        _system.KillOwnThrows = true;
        _system.OwnProcesses = 1;

        var report = await Orchestrator().OffAsync(CancellationToken.None);

        Assert.All(report.Steps, s => Assert.Contains(s.Step, EmergencyTimeouts.OffSteps));
        Assert.Distinct(report.Steps.Select(s => s.Step));
        Assert.Contains(report.Steps, s => s.Step == EmergencySteps.WfpAgain);
        Assert.All(report.Steps, s => Assert.Equal(EmergencySteps.Title(s.Step), s.Title));
        Assert.DoesNotContain(report.Steps, s => s.Title == s.Step);
    }

    /// <summary>Общий срок команды истёк посреди шагов: оставшиеся не запускаются и честно помечены.</summary>
    [Fact]
    public async Task OwnDeadline_StopsRemainingSteps()
    {
        _system.Hang.Add("RemoveFilters");
        var options = Options() with { OffDeadline = TimeSpan.FromMilliseconds(300) };

        var report = await new EmergencyOrchestrator(_system, options).OffAsync(CancellationToken.None);

        Assert.Equal(EmergencyStepOutcome.Timeout, report.Steps.Single(s => s.Step == EmergencySteps.Wfp).Outcome);
        Assert.Equal(EmergencyOrchestrator.DeadlineSkipDetail, report.Steps.Single(s => s.Step == EmergencySteps.Dns).Detail);
        Assert.Equal(EmergencyExitCodes.Incomplete, report.ExitCode);
    }

    /// <summary>
    /// Шаг не уложился в срок, но ещё дописывает своё: перед выходом команда даёт ему короткий запас, а зависший навсегда
    /// шаг её не держит.
    /// </summary>
    [Fact]
    public async Task AbandonedStep_GetsShortGrace_ButNeverHangsTheCommand()
    {
        var runner = new EmergencyOrchestrator.StepRunner(Options(_ => TimeSpan.FromMilliseconds(50)));
        var finished = 0;
        await runner.StepAsync(EmergencySteps.Dns, _ =>
        {
            Thread.Sleep(300);
            Interlocked.Exchange(ref finished, 1);
            return StepResult.Done();
        }, CancellationToken.None);
        Assert.Equal(0, Volatile.Read(ref finished));

        await runner.DrainAbandonedAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, Volatile.Read(ref finished));

        using var never = new ManualResetEventSlim();
        await runner.StepAsync(EmergencySteps.Wfp, _ => { never.Wait(TimeSpan.FromSeconds(30), CancellationToken.None); return StepResult.Done(); }, CancellationToken.None);
        var watch = System.Diagnostics.Stopwatch.StartNew();
        await runner.DrainAbandonedAsync(TimeSpan.FromMilliseconds(200));
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5));
        never.Set();
    }

    /// <summary>
    /// Шаг остановки не подтвердил её (не уложился в срок), а процессов службы уже нет: DNS шёл по правилам работающей
    /// службы, поэтому выполняется ещё раз — по правилам остановленной (иначе остался бы loopback без посредника).
    /// </summary>
    [Fact]
    public async Task ServiceStepTimedOut_NoProcessesLeft_DnsRerunWithStoppedRules()
    {
        _system.Hang.Add("RequestStop");

        var report = await Orchestrator(step => step == EmergencySteps.Service ? TimeSpan.FromMilliseconds(200) : TimeSpan.FromSeconds(10))
            .OffAsync(CancellationToken.None);

        Assert.Equal(EmergencyStepOutcome.Timeout, report.Steps.Single(s => s.Step == EmergencySteps.Service).Outcome);
        Assert.Equal(EmergencyStepOutcome.Already, report.Steps.Single(s => s.Step == EmergencySteps.ServiceRecheck).Outcome);
        Assert.True(IsSubsequence(_system.Calls, ["RestoreDns:False", "RestoreWcm", "RestoreDns:True"]), string.Join(", ", _system.Calls));
        Assert.Contains(report.Steps, s => s.Step == EmergencySteps.DnsAgain && s.Succeeded);
        Assert.DoesNotContain(report.Steps, s => s.Step == EmergencySteps.WfpAgain);
        Assert.Equal(EmergencyExitCodes.ServiceNotConfirmed, report.ExitCode);
        Assert.True(report.NetworkClean);
    }

    /// <summary>Повторное снятие не удалось — сеть не возвращена (код 3), даже если основной шаг прошёл.</summary>
    [Fact]
    public void FailedAgainStep_IsIncomplete()
    {
        var steps = OffOrder.Select(step => new EmergencyStepReport(step, EmergencySteps.Title(step), EmergencyStepOutcome.Done, null, 1,
            Required: !OptionalSteps.Contains(step))).ToList();
        Assert.True(EmergencyOrchestrator.IsNetworkClean(steps));
        steps.Add(new EmergencyStepReport(EmergencySteps.DnsAgain, EmergencySteps.Title(EmergencySteps.DnsAgain), EmergencyStepOutcome.Timeout, null, 1));

        Assert.Equal(EmergencyExitCodes.Incomplete, EmergencyOrchestrator.OffExitCode(steps));
        Assert.False(EmergencyOrchestrator.IsNetworkClean(steps));
    }

    /// <summary>Код 0 с неудавшимся необязательным шагом: итог не говорит «Не выполнено», а называет это замечанием.</summary>
    [Fact]
    public void Summary_SeparatesRequiredFailures_FromRemarks()
    {
        var steps = OffOrder.Select(step => new EmergencyStepReport(step, EmergencySteps.Title(step),
            step == EmergencySteps.FlushDns ? EmergencyStepOutcome.Failed : EmergencyStepOutcome.Done, null, 1,
            Required: !OptionalSteps.Contains(step))).ToList();
        Assert.Equal(EmergencyExitCodes.Success, EmergencyOrchestrator.OffExitCode(steps));

        var ok = EmergencyOrchestrator.Summary(EmergencyCommands.Off, EmergencyExitCodes.Success, steps, null);
        Assert.DoesNotContain("Не выполнено", ok, StringComparison.Ordinal);
        Assert.Contains("Замечания (на итог не влияют): не удалось — Кеш DNS.", ok, StringComparison.Ordinal);

        steps[steps.FindIndex(s => s.Step == EmergencySteps.Wfp)] = steps.Single(s => s.Step == EmergencySteps.Wfp) with { Outcome = EmergencyStepOutcome.Failed };
        var bad = EmergencyOrchestrator.Summary(EmergencyCommands.Off, EmergencyExitCodes.Incomplete, steps, null);
        Assert.Contains("Не выполнено: Фильтры защиты (WFP).", bad, StringComparison.Ordinal);
        Assert.DoesNotContain("Не выполнено: Фильтры защиты (WFP), Кеш DNS", bad, StringComparison.Ordinal);
        Assert.True(bad.IndexOf("Не выполнено", StringComparison.Ordinal) < bad.IndexOf("Замечания", StringComparison.Ordinal));
    }

    /// <summary>Метка запуска: только GUID сразу за ключом; попадает в отчёт.</summary>
    [Theory]
    [InlineData(new[] { "emergency-off", "--report-id", "6f9619ff-8b86-d011-b42d-00c04fc964ff" }, "6f9619ff-8b86-d011-b42d-00c04fc964ff")]
    [InlineData(new[] { "emergency-on", "--REPORT-ID", "6F9619FF-8B86-D011-B42D-00C04FC964FF" }, "6f9619ff-8b86-d011-b42d-00c04fc964ff")]
    [InlineData(new[] { "emergency-off", "--report-id", "{6f9619ff-8b86-d011-b42d-00c04fc964ff}" }, null)]
    [InlineData(new[] { "emergency-off", "--report-id", "6f9619ff8b86d011b42d00c04fc964ff" }, null)]
    [InlineData(new[] { "emergency-off", "--report-id", "00000000-0000-0000-0000-000000000000" }, null)]
    [InlineData(new[] { "emergency-off", "--report-id", "x" }, null)]
    [InlineData(new[] { "emergency-off", "--report-id" }, null)]
    [InlineData(new[] { "emergency-off" }, null)]
    public void ReportId_IsStrictGuid(string[] args, string? expected)
    {
        Assert.Equal(expected is null ? null : Guid.Parse(expected), EmergencyCommands.ParseReportId(args));
        // Ключ не меняет саму команду.
        Assert.True(ServiceRecovery.IsRecoveryCommand(args[0]));
        Assert.NotEqual(RecoveryMode.Recover, ServiceRecovery.ParseMode(args));
    }

    [Fact]
    public async Task ReportId_IsEchoedInReport()
    {
        var id = Guid.NewGuid();

        var off = await Orchestrator().OffAsync(CancellationToken.None, id);
        var json = JsonSerializer.Serialize(off, JsonDefaults.Options);

        Assert.Equal(id, off.ReportId);
        Assert.Equal(id.ToString("D"), JsonDocument.Parse(json).RootElement.GetProperty("reportId").GetString());
        Assert.Equal(id, EmergencyReportFiles.Parse(json)!.ReportId);
        Assert.Null((await Orchestrator().OnAsync(CancellationToken.None)).ReportId);
    }

    /// <summary>
    /// Рядом выполняется другая команда этой программы: включение отказывается (код 5, ничего не делалось), а отключение
    /// выполняется (оно идемпотентно).
    /// </summary>
    [Fact]
    public async Task OtherCommandRunning_OnRefusesWithBusy_OffProceeds()
    {
        _system.OtherCommand = true;
        _system.Flag = true;

        var on = await Orchestrator().OnAsync(CancellationToken.None);

        Assert.Equal(EmergencyExitCodes.Busy, on.ExitCode);
        Assert.Empty(on.Steps);
        Assert.True(_system.Flag);
        Assert.DoesNotContain("RequestStop", _system.Calls);
        Assert.Contains("уже выполняется другая экстренная команда", on.Summary, StringComparison.Ordinal);

        var off = await Orchestrator().OffAsync(CancellationToken.None);
        Assert.Equal(EmergencyExitCodes.Success, off.ExitCode);
        Assert.NotEmpty(off.Steps);
    }

    /// <summary>Другой командой считается процесс того же файла с командой восстановления; служба и пустая строка — нет.</summary>
    [Theory]
    [InlineData("\"C:\\Program Files\\SplitVpn\\SplitVpn.Service.exe\" emergency-off --report-id 6f9619ff-8b86-d011-b42d-00c04fc964ff", true)]
    [InlineData("SplitVpn.Service.exe recover --uninstall-network", true)]
    [InlineData("SplitVpn.Service.exe EMERGENCY-ON", true)]
    [InlineData("\"C:\\Program Files\\SplitVpn\\SplitVpn.Service.exe\"", false)]
    [InlineData("SplitVpn.Service.exe --contentRoot x", false)]
    public void OtherCommandDetection_ByCommandLine(string commandLine, bool recovery)
    {
        Assert.Equal(recovery, SystemEmergency.IsRecoveryCommand(SplitVpn.Windows.Native.ProcessImage.SplitCommandLine(commandLine)));
        Assert.False(SystemEmergency.IsRecoveryCommand(null));
    }

    /// <summary>
    /// Владелец каталога данных — те же правила, что у хранилища секретов: прямой член локальной группы Administrators
    /// тоже свой (каталог создан повышенным администратором); посторонний пользователь — нет.
    /// </summary>
    [Fact]
    public void DataRootTrust_AcceptsSameOwnersAsSecretStore()
    {
        var admin = new System.Security.Principal.SecurityIdentifier("S-1-5-21-1-2-3-1001");
        var stranger = new System.Security.Principal.SecurityIdentifier("S-1-5-21-1-2-3-1002");
        var system = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
        System.Security.AccessControl.DirectorySecurity Owned(System.Security.Principal.SecurityIdentifier owner)
        {
            var security = new System.Security.AccessControl.DirectorySecurity();
            security.SetOwner(owner);
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(system, System.Security.AccessControl.FileSystemRights.FullControl,
                System.Security.AccessControl.AccessControlType.Allow));
            return security;
        }

        bool IsAdmin(System.Security.Principal.SecurityIdentifier sid) => sid.Equals(admin);
        Assert.Null(DataRootTrust.Problem(FileAttributes.Directory, Owned(admin), IsAdmin));
        Assert.Null(DataRootTrust.Problem(FileAttributes.Directory, Owned(Core.Recovery.AdminOnlyAccess.TrustedInstaller), IsAdmin));
        Assert.Contains("посторонней", DataRootTrust.Problem(FileAttributes.Directory, Owned(stranger), IsAdmin), StringComparison.Ordinal);
        Assert.Equal(SplitVpn.Windows.Security.SecretStore.IsAcceptedOwner(admin, IsAdmin), DataRootTrust.Problem(FileAttributes.Directory, Owned(admin), IsAdmin) is null);
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

    /// <summary>Рядом выполняется другая команда восстановления этой программы.</summary>
    public bool OtherCommand { get; set; }
    public bool LockBusy { get; set; }
    public bool LockThrows { get; set; }

    /// <summary>Сколько ближайших вызовов KillOwnServiceProcesses завершатся ошибкой.</summary>
    public int KillOwnFailuresLeft { get; set; }
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

    public bool OtherRecoveryCommandRunning()
    {
        Call("OtherCommand");
        return OtherCommand;
    }

    public IDisposable? TryAcquireLock(TimeSpan wait)
    {
        Call("Lock");
        if (LockThrows) throw new IOException("Блокировка команд недоступна: отказано в доступе");
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
        SavedStart ??= StartType;
        if (StartType == EmergencyRegistry.StartDemand) return StepResult.Already();
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
        if (KillOwnThrows || KillOwnFailuresLeft-- > 0) throw new IOException("отказано в доступе");
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
