using System.Diagnostics;
using System.IO;
using System.Windows.Threading;
using SplitVpn.App.Services;
using SplitVpn.App.ViewModels;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Recovery;
using SplitVpn.Core.State;

namespace SplitVpn.App.Tests;

/// <summary>
/// Экстренное выключение в приложении: запуск команды с правами администратора мимо канала службы, разбор итога и
/// отчёта, состояние «экстренно выключен» по статусу или реестру, защита от двойного запуска, снятие прокси и ключ
/// командной строки. Настоящая команда и окно UAC здесь не запускаются: процесс и реестр подменены.
/// </summary>
public sealed class EmergencyAppTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 25, 12, 0, 0, TimeSpan.Zero);
    private const string Exe = @"C:\Program Files\SplitVpn\SplitVpn.Service.exe";
    private const string ReportPath = @"C:\ProgramData\SplitVpn.Recovery\last.json";

    // ---------- Запуск команды ----------

    [Theory]
    [InlineData(false, "emergency-off")]
    [InlineData(true, "emergency-on")]
    public void StartInfo_IsElevatedHiddenFromSystem32(bool on, string argument)
    {
        var info = EmergencyLauncher.BuildStartInfo(Exe, on);

        Assert.Equal(Exe, info.FileName);
        Assert.Equal(argument, info.Arguments);
        Assert.Equal("runas", info.Verb);
        Assert.True(info.UseShellExecute);
        Assert.Equal(ProcessWindowStyle.Hidden, info.WindowStyle);
        Assert.Equal(Environment.SystemDirectory, info.WorkingDirectory);
    }

    [Fact]
    public async Task Launcher_RunsFoundExecutable_WithBoundedWait_AndReadsFreshReport()
    {
        var runner = new FakeRunner { Outcome = ElevatedProcessOutcome.Exited(0) };
        var report = Report(EmergencyCommands.Off, 0, Now.AddSeconds(1));
        var launcher = Launcher(runner, report);

        var result = await launcher.RunAsync(on: false, TestContext.Current.CancellationToken);

        Assert.Equal(Exe, runner.Started!.FileName);
        Assert.Equal("emergency-off", runner.Started.Arguments);
        Assert.Equal(EmergencyLauncher.OffTimeout, runner.Timeout);
        Assert.True(EmergencyLauncher.OffTimeout > TimeSpan.FromMinutes(11));
        Assert.Equal(EmergencyRunKind.Succeeded, result.Kind);
        Assert.Equal(0, result.ExitCode);
        Assert.Equal(ReportPath, result.ReportPath);
        Assert.Equal(report.Steps.Count, result.Steps.Count);
        Assert.Contains("«Включить программу»", result.Advice, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Launcher_UacCancelled_IsQuietCancel()
    {
        var launcher = Launcher(new FakeRunner { Outcome = ElevatedProcessOutcome.NotStarted(1223) }, report: null);

        var result = await launcher.RunAsync(on: false, TestContext.Current.CancellationToken);

        Assert.Equal(EmergencyRunKind.Cancelled, result.Kind);
        Assert.False(result.IsError);
        Assert.Contains("отменено", result.Summary, StringComparison.Ordinal);
        Assert.Equal(1223, result.ProcessExitCode);
    }

    [Fact]
    public async Task Launcher_OtherStartError_SaysWhatToDo()
    {
        var launcher = Launcher(new FakeRunner { Outcome = ElevatedProcessOutcome.NotStarted(2) }, report: null);

        var result = await launcher.RunAsync(on: false, TestContext.Current.CancellationToken);

        Assert.Equal(EmergencyRunKind.Failed, result.Kind);
        Assert.Contains("код 2", result.Summary, StringComparison.Ordinal);
        Assert.Contains("recover-network.cmd", result.Advice, StringComparison.Ordinal);
        Assert.Equal(EmergencyExitCodes.Unexpected, result.ProcessExitCode);
    }

    [Fact]
    public async Task Launcher_NoServiceFile_NothingStarted()
    {
        var runner = new FakeRunner();
        var launcher = new EmergencyLauncher(runner, () => null, _ => null, ReportPath, new FixedTime(Now));

        var result = await launcher.RunAsync(on: false, TestContext.Current.CancellationToken);

        Assert.Null(runner.Started);
        Assert.Equal(EmergencyRunKind.Failed, result.Kind);
        Assert.Contains("не найден", result.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Launcher_Overdue_SaysSo_AndStillShowsFreshReport()
    {
        var launcher = Launcher(new FakeRunner { Outcome = ElevatedProcessOutcome.Overdue }, Report(EmergencyCommands.Off, 3, Now.AddSeconds(2)));

        var result = await launcher.RunAsync(on: false, TestContext.Current.CancellationToken);

        Assert.Equal(EmergencyRunKind.Overdue, result.Kind);
        Assert.Contains("не завершилась за 12 мин", result.Summary, StringComparison.Ordinal);
        Assert.NotEmpty(result.Steps);
        Assert.Equal(ReportPath, result.ReportPath);
    }

    [Theory]
    [InlineData(false, 0, EmergencyRunKind.Succeeded)]
    [InlineData(false, 1, EmergencyRunKind.Failed)]
    [InlineData(false, 2, EmergencyRunKind.Failed)]
    [InlineData(false, 3, EmergencyRunKind.Failed)]
    [InlineData(false, 4, EmergencyRunKind.Failed)]
    [InlineData(false, 5, EmergencyRunKind.Busy)]
    [InlineData(true, 0, EmergencyRunKind.Succeeded)]
    [InlineData(true, 2, EmergencyRunKind.Failed)]
    [InlineData(true, 3, EmergencyRunKind.Failed)]
    [InlineData(true, 5, EmergencyRunKind.Busy)]
    public async Task ExitCodes_MapToDescribeAndAdvice_WithoutReport(bool on, int code, EmergencyRunKind kind)
    {
        var launcher = Launcher(new FakeRunner { Outcome = ElevatedProcessOutcome.Exited(code) }, report: null);

        var result = await launcher.RunAsync(on, TestContext.Current.CancellationToken);

        Assert.Equal(kind, result.Kind);
        Assert.Equal(code, result.ExitCode);
        Assert.Equal(code, result.ProcessExitCode);
        Assert.Equal(EmergencyExitCodes.Describe(code, on), result.Summary);
        Assert.NotEmpty(result.Advice);
        Assert.DoesNotContain("код " + code, result.Summary, StringComparison.Ordinal);
        Assert.Null(result.ReportPath);
        if (code == EmergencyExitCodes.Busy)
        {
            Assert.Contains("Уже выполняется", result.Advice, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void StaleReport_IsIgnored_FreshIsUsed()
    {
        Assert.False(EmergencyLauncher.IsFresh(Report(EmergencyCommands.Off, 0, Now.AddMinutes(-10)), on: false, Now));
        Assert.False(EmergencyLauncher.IsFresh(Report(EmergencyCommands.On, 0, Now.AddSeconds(1)), on: false, Now));
        Assert.False(EmergencyLauncher.IsFresh(Report("uninstall-network", 0, Now.AddSeconds(1)), on: false, Now));
        Assert.False(EmergencyLauncher.IsFresh(null, on: false, Now));
        Assert.True(EmergencyLauncher.IsFresh(Report(EmergencyCommands.Off, 0, Now.AddSeconds(1)), on: false, Now));
        Assert.True(EmergencyLauncher.IsFresh(Report(EmergencyCommands.On, 0, Now.AddSeconds(-2)), on: true, Now));
    }

    [Fact]
    public async Task StaleLastJson_DoesNotBecomeThisRunsSteps()
    {
        // Код 5: команда ничего не делала и отчёт не писала; в last.json — отчёт прошлого запуска.
        var launcher = Launcher(new FakeRunner { Outcome = ElevatedProcessOutcome.Exited(5) }, Report(EmergencyCommands.Off, 0, Now.AddHours(-2)));

        var result = await launcher.RunAsync(on: false, TestContext.Current.CancellationToken);

        Assert.Empty(result.Steps);
        Assert.Null(result.ReportPath);
        Assert.Equal(EmergencyRunKind.Busy, result.Kind);
    }

    [Fact]
    public async Task UnreadableOrBrokenReport_IsIgnored()
    {
        var runner = new FakeRunner { Outcome = ElevatedProcessOutcome.Exited(0) };
        var broken = new EmergencyLauncher(runner, () => Exe, _ => "{ не json", ReportPath, new FixedTime(Now));
        var locked = new EmergencyLauncher(runner, () => Exe, _ => throw new UnauthorizedAccessException("нет доступа"), ReportPath, new FixedTime(Now));

        Assert.Empty((await broken.RunAsync(false, TestContext.Current.CancellationToken)).Steps);
        Assert.Empty((await locked.RunAsync(false, TestContext.Current.CancellationToken)).Steps);
    }

    [Fact]
    public void Report_BecomesStepList_WithRussianOutcomes_AndSeverities()
    {
        var report = Report(EmergencyCommands.Off, 3, Now) with
        {
            Summary = "Сеть возвращена не полностью.",
            Steps =
            [
                new(EmergencySteps.Flag, "Отметка отключения", EmergencyStepOutcome.Done, "записано", 5),
                new(EmergencySteps.Routes, "", EmergencyStepOutcome.Already, null, 5),
                new(EmergencySteps.Helpers, "Помощники VPN (AnyConnect, SSH)", EmergencyStepOutcome.Skipped, null, 5),
                new(EmergencySteps.Wfp, "Фильтры защиты (WFP)", EmergencyStepOutcome.Failed, "ошибка 5", 5),
                new(EmergencySteps.Dns, "DNS адаптеров", EmergencyStepOutcome.Timeout, "не завершился за 90 с", 5),
                new(EmergencySteps.FlushDns, "Кеш DNS", EmergencyStepOutcome.Failed, "код 1", 5, Required: false),
            ],
        };

        var result = EmergencyRunResult.FromExitCode(on: false, 3, report, ReportPath);

        Assert.Equal("Сеть возвращена не полностью.", result.Summary);
        Assert.Equal(["сделано", "уже было так", "не требовалось", "не удалось", "не уложился в срок", "не удалось"], result.Steps.Select(s => s.OutcomeText));
        Assert.Equal("Маршруты программы", result.Steps[1].Title);
        Assert.Equal(
            [EmergencyStepSeverity.Ok, EmergencyStepSeverity.Ok, EmergencyStepSeverity.Ok, EmergencyStepSeverity.Error, EmergencyStepSeverity.Error, EmergencyStepSeverity.Warning],
            result.Steps.Select(s => s.Severity));
        Assert.True(result.HasProblems);
        // Код 3: что не вернулось (без предупреждений) и совет перезагрузиться.
        Assert.Contains("Не возвращено: Фильтры защиты (WFP), DNS адаптеров.", result.Advice, StringComparison.Ordinal);
        Assert.DoesNotContain("Кеш DNS", result.Advice, StringComparison.Ordinal);
        Assert.Contains("Перезагрузите компьютер", result.Advice, StringComparison.Ordinal);

        var message = result.ToMessageText();
        Assert.Contains("Фильтры защиты (WFP): не удалось (ошибка 5)", message, StringComparison.Ordinal);
        Assert.Contains("Кеш DNS: не удалось (код 1) — не влияет на итог", message, StringComparison.Ordinal);
        Assert.DoesNotContain("Отметка отключения", message, StringComparison.Ordinal);
        Assert.Contains("Отчёт: " + ReportPath, message, StringComparison.Ordinal);

        var copied = result.ToReportText();
        Assert.Contains("Отметка отключения: сделано (записано)", copied, StringComparison.Ordinal);
        Assert.Contains("Код завершения: 3", copied, StringComparison.Ordinal);
    }

    [Fact]
    public void ServiceFile_RegisteredFirst_ThenNextToApp()
    {
        var app = Path.Combine(Path.GetTempPath(), "splitvpn-app");
        Assert.Equal(Exe, NetworkRecovery.FindServiceExecutable(Exe, app, _ => true));
        Assert.Equal(Path.Combine(app, "SplitVpn.Service.exe"), NetworkRecovery.FindServiceExecutable(null, app, _ => true));
        Assert.Equal(Path.Combine(app, "service", "SplitVpn.Service.exe"),
            NetworkRecovery.FindServiceExecutable(null, app, p => p.Contains(Path.Combine(app, "service"), StringComparison.Ordinal)));
        Assert.Null(NetworkRecovery.FindServiceExecutable(null, app, _ => false));
    }

    // ---------- Кнопка в приложении ----------

    [Theory]
    [InlineData(null)]
    [InlineData(ServiceUnavailableReason.Untrusted)]
    [InlineData(ServiceUnavailableReason.Timeout)]
    [InlineData(ServiceUnavailableReason.NotRunning)]
    [InlineData(ServiceUnavailableReason.Denied)]
    [InlineData(ServiceUnavailableReason.VersionMismatch)]
    public Task TurnOff_GoesStraightToLauncher_WhateverThePipe(ServiceUnavailableReason? reason) => RunStaAsync(async () =>
    {
        var requests = new List<IpcRequest>();
        using var service = new ServiceConnection((request, _) =>
        {
            requests.Add(request);
            return Task.FromResult(IpcResponse.Success(new StatusDto()));
        });
        using var main = NewMain(service, out var launcher, out _);
        main.ServiceAvailable = reason is null;
        main.UnavailableReason = reason;
        var prompts = new List<string>();
        main.Confirm = (title, text, _) => { prompts.Add(text); return Task.FromResult(true); };

        await main.Diagnostics.Emergency.TurnOffCommand.ExecuteAsync(null);

        Assert.Equal([false], launcher.Runs);
        var prompt = Assert.Single(prompts);
        Assert.Contains("VPN будет отключён", prompt, StringComparison.Ordinal);
        Assert.Contains("защита от утечек снята", prompt, StringComparison.Ordinal);
        Assert.Contains("не запустится сама, даже после перезагрузки", prompt, StringComparison.Ordinal);
        Assert.Contains("«Включить программу»", prompt, StringComparison.Ordinal);
        // Команд службе нет: только опрос состояния после команды и чтения страниц по нему.
        Assert.Contains(requests, r => r is GetStatusRequest);
        Assert.All(requests, r => Assert.True(r is GetStatusRequest or GetSettingsRequest or GetAdaptersRequest or GetEventsRequest, r.GetType().Name));
        Assert.NotNull(main.Emergency.Result);
    });

    [Fact]
    public Task TurnOff_Declined_RunsNothing() => RunStaAsync(async () =>
    {
        using var service = new ServiceConnection((_, _) => Task.FromResult(IpcResponse.Success(new StatusDto())));
        using var main = NewMain(service, out var launcher, out _);
        main.Confirm = (_, _, _) => Task.FromResult(false);

        await main.Emergency.TurnOffCommand.ExecuteAsync(null);

        Assert.Empty(launcher.Runs);
        Assert.Null(main.Emergency.Result);
    });

    [Fact]
    public Task TurnOff_RevertsOwnProxy_BeforeElevating() => RunStaAsync(async () =>
    {
        using var service = new ServiceConnection((_, _) => Task.FromResult(IpcResponse.Success(new StatusDto())));
        using var main = NewMain(service, out var launcher, out _);
        var order = new List<string>();
        main.Emergency.RevertProxy = () => { order.Add("proxy"); return Task.CompletedTask; };
        launcher.OnRun = on => order.Add(on ? "on" : "off");
        main.Confirm = (_, _, _) => Task.FromResult(true);

        await main.Emergency.TurnOffCommand.ExecuteAsync(null);
        await main.Emergency.TurnOnCommand.ExecuteAsync(null);

        // Включение прокси не трогает: его поставит подключение туннеля.
        Assert.Equal(["proxy", "off"], order.Take(2));
    });

    [Fact]
    public Task FailingProxyRevert_DoesNotBlockEmergencyOff() => RunStaAsync(async () =>
    {
        using var service = new ServiceConnection((_, _) => Task.FromResult(IpcResponse.Success(new StatusDto())));
        using var main = NewMain(service, out var launcher, out _);
        main.Emergency.RevertProxy = () => throw new IOException("файл занят");

        await main.Emergency.RunAsync(on: false);

        Assert.Equal([false], launcher.Runs);
    });

    [Fact]
    public Task SecondStart_WhileRunning_IsIgnored() => RunStaAsync(async () =>
    {
        using var service = new ServiceConnection((_, _) => Task.FromResult(IpcResponse.Success(new StatusDto())));
        using var main = NewMain(service, out var launcher, out _);
        var gate = new TaskCompletionSource<EmergencyRunResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        launcher.Pending = gate.Task;
        main.Confirm = (_, _, _) => Task.FromResult(true);

        var first = main.Emergency.TurnOffCommand.ExecuteAsync(null);
        Assert.True(main.Emergency.IsRunning);
        Assert.False(main.Emergency.TurnOffCommand.CanExecute(null));
        Assert.False(main.Emergency.TurnOnCommand.CanExecute(null));
        await main.Emergency.RunAsync(on: false);
        await main.Emergency.RunAsync(on: true);
        Assert.Single(launcher.Runs);

        gate.SetResult(EmergencyRunResult.FromExitCode(false, 0, null, null));
        await first;
        Assert.False(main.Emergency.IsRunning);
        Assert.True(main.Emergency.TurnOffCommand.CanExecute(null));
    });

    [Fact]
    public Task UacCancel_ShowsQuietMessage_NoResultPanel() => RunStaAsync(async () =>
    {
        using var service = new ServiceConnection((_, _) => Task.FromResult(IpcResponse.Success(new StatusDto())));
        using var main = NewMain(service, out var launcher, out _);
        launcher.Result = EmergencyRunResult.Cancelled(on: false);

        await main.Emergency.RunAsync(on: false);

        Assert.Null(main.Emergency.Result);
        Assert.Equal("Экстренное выключение отменено.", main.CurrentPage.Message);
        Assert.False(main.CurrentPage.MessageIsError);
    });

    // ---------- Состояние «экстренно выключен» ----------

    [Fact]
    public Task SilentService_FlagFromRegistry_ShowsCalmBanner_HidesConnectAndServiceStart() => RunStaAsync(async () =>
    {
        using var service = new ServiceConnection((_, _) => Task.FromException<IpcResponse>(
            new ServiceUnavailableException("Служба не запущена.", null, ServiceUnavailableReason.NotRunning)));
        using var main = NewMain(service, out _, out var flags);
        flags.Flag = new EmergencyFlag(Now);
        main.ServiceHost.Show(ServiceHostState.Stopped, "1.0.0");
        var notifications = new List<AppNotification>();
        main.Notify += notifications.Add;

        await main.RefreshAsync();

        Assert.True(main.Emergency.IsOff);
        Assert.Equal(Now, main.Emergency.Since);
        Assert.False(main.ShowServiceError);
        Assert.False(main.ShowServiceRecovery);
        Assert.False(main.ConnectCommand.CanExecute(null));
        Assert.False(main.ToggleConnectionCommand.CanExecute(null));
        Assert.False(main.ServiceHost.StartCommand.CanExecute(null));
        Assert.False(main.ServiceHost.RestartCommand.CanExecute(null));
        Assert.False(main.Diagnostics.CanStartService);
        Assert.True(main.Emergency.TurnOnCommand.CanExecute(null));
        Assert.Equal(UiText.EmergencyStateText, main.StateText);
        Assert.Equal(Views.StateTone.Caution, main.Home.Tone);
        Assert.Null(main.Home.ErrorText);
        Assert.Contains("Включить программу", main.Emergency.BannerText, StringComparison.Ordinal);
        Assert.Equal(UiText.EmergencyOnAction, main.Emergency.TrayActionText);
        Assert.Empty(notifications);

        // Флаг снят (программу включили другим способом): обычная ошибка «служба недоступна» и её запуск.
        flags.Flag = null;
        await main.RefreshAsync();
        Assert.False(main.Emergency.IsOff);
        Assert.True(main.ShowServiceError);
        Assert.True(main.ServiceHost.StartCommand.CanExecute(null));
        Assert.Equal(UiText.EmergencyOffAction + "…", main.Emergency.TrayActionText);
    });

    [Fact]
    public Task AnsweringService_FlagFromStatus() => RunStaAsync(async () =>
    {
        var off = true;
        using var service = new ServiceConnection((_, _) => Task.FromResult(IpcResponse.Success(new StatusDto
        {
            State = ConnectionState.Disconnected,
            EmergencyOff = off,
            EmergencyOffSinceUtc = off ? Now : null,
        })));
        using var main = NewMain(service, out _, out var flags);
        flags.Flag = null;

        await main.RefreshAsync();

        Assert.True(main.ServiceAvailable);
        Assert.True(main.Emergency.IsOff);
        Assert.Equal(Now, main.Emergency.Since);
        Assert.False(main.ConnectCommand.CanExecute(null));
        Assert.Equal(UiText.EmergencyStateText, main.StateText);
        Assert.Equal(0, flags.Reads);

        off = false;
        await main.RefreshAsync();
        Assert.False(main.Emergency.IsOff);
        Assert.True(main.ConnectCommand.CanExecute(null));
        Assert.NotEqual(UiText.EmergencyStateText, main.StateText);
    });

    [Fact]
    public Task EmergencyOffRefusal_ShowsBanner_NotRawError() => RunStaAsync(async () =>
    {
        using var service = new ServiceConnection((request, _) => Task.FromResult(request is GetStatusRequest
            ? IpcResponse.Success(new StatusDto { EmergencyOff = true })
            : IpcResponse.Failure(IpcErrorCodes.EmergencyOff, IpcErrorCodes.EmergencyOffMessage)));
        using var main = NewMain(service, out _, out var flags);
        flags.Flag = null;

        // Отказ сам по себе (статус ещё не пришёл) включает баннер.
        await service.SendAsync(new GeoUpdateNowRequest(), TestContext.Current.CancellationToken);
        Assert.True(main.Emergency.IsOff);

        await main.RunCommandAsync(new ConnectRequest(null, null));
        Assert.True(main.Emergency.IsOff);
        Assert.Null(main.Home.Message);
    });

    [Fact]
    public Task TurnOn_ClearsState_AndDoesNotConnect() => RunStaAsync(async () =>
    {
        var requests = new List<IpcRequest>();
        var off = true;
        using var service = new ServiceConnection((request, _) =>
        {
            requests.Add(request);
            return Task.FromResult(IpcResponse.Success(new StatusDto { EmergencyOff = off }));
        });
        using var main = NewMain(service, out var launcher, out var flags);
        await main.RefreshAsync();
        Assert.True(main.Emergency.IsOff);
        launcher.OnRun = _ => { off = false; flags.Flag = null; };
        launcher.Result = EmergencyRunResult.FromExitCode(true, 0, null, null);

        await main.Emergency.TurnOnCommand.ExecuteAsync(null);

        Assert.Equal([true], launcher.Runs);
        Assert.False(main.Emergency.IsOff);
        Assert.Contains("«Подключить»", main.Emergency.Result!.Advice, StringComparison.Ordinal);
        Assert.DoesNotContain(requests, r => r is ConnectRequest);
        Assert.True(main.ConnectCommand.CanExecute(null));
    });

    [Fact]
    public void TrayTooltip_SaysEmergencyOff()
    {
        Assert.Equal("Раздельный VPN: экстренно выключен", TrayIcon.Tooltip(UiText.EmergencyStateText, null, emergencyOff: true));
    }

    // ---------- Командная строка ----------

    [Theory]
    [InlineData(new[] { "--emergency-off" }, true)]
    [InlineData(new[] { "--EMERGENCY-OFF" }, true)]
    [InlineData(new[] { "--tray", "--emergency-off" }, true)]
    [InlineData(new[] { "--tray" }, false)]
    [InlineData(new[] { "--emergency-on" }, false)]
    [InlineData(new[] { "emergency-off" }, false)]
    [InlineData(new string[0], false)]
    public void CommandLine_EmergencyOffArgument(string[] args, bool expected) =>
        Assert.Equal(expected, EmergencyCommandLine.IsEmergencyOff(args));

    [Fact]
    public async Task CommandLine_RevertsProxyFirst_ThenRunsOff()
    {
        var launcher = new FakeLauncher();
        var order = new List<string>();
        launcher.OnRun = on => order.Add(on ? "on" : "off");

        var result = await EmergencyCommandLine.RunAsync(launcher, () => { order.Add("proxy"); return Task.CompletedTask; });

        Assert.Equal(["proxy", "off"], order);
        Assert.Equal(0, result.ProcessExitCode);
    }

    // ---------- Подмены ----------

    private static MainViewModel NewMain(ServiceConnection service, out FakeLauncher launcher, out FakeFlags flags)
    {
        var main = new MainViewModel(service, new UiPreferences());
        launcher = new FakeLauncher();
        flags = new FakeFlags();
        main.Emergency.Launcher = launcher;
        main.Emergency.FlagSource = flags;
        return main;
    }

    private static EmergencyLauncher Launcher(FakeRunner runner, EmergencyReport? report) =>
        new(runner, () => Exe, path => path == ReportPath && report is not null ? System.Text.Json.JsonSerializer.Serialize(report, Core.Settings.JsonDefaults.Options) : null,
            ReportPath, new FixedTime(Now));

    private static EmergencyReport Report(string command, int code, DateTimeOffset started) => new()
    {
        Command = command,
        StartedUtc = started,
        FinishedUtc = started.AddSeconds(30),
        ExitCode = code,
        Summary = EmergencyExitCodes.Describe(code, command == EmergencyCommands.On),
        NetworkClean = code is 0 or 2,
        ServiceConfirmed = code == 0,
        Steps =
        [
            new(EmergencySteps.Flag, EmergencySteps.Title(EmergencySteps.Flag), EmergencyStepOutcome.Done, null, 10),
            new(EmergencySteps.Wfp, EmergencySteps.Title(EmergencySteps.Wfp), code == 3 ? EmergencyStepOutcome.Failed : EmergencyStepOutcome.Done, null, 10),
        ],
    };

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class FakeRunner : IElevatedProcessRunner
    {
        public ElevatedProcessOutcome Outcome { get; init; } = ElevatedProcessOutcome.Exited(0);

        public ProcessStartInfo? Started { get; private set; }

        public TimeSpan Timeout { get; private set; }

        public Task<ElevatedProcessOutcome> RunAsync(ProcessStartInfo startInfo, TimeSpan timeout, CancellationToken cancellationToken)
        {
            Started = startInfo;
            Timeout = timeout;
            return Task.FromResult(Outcome);
        }
    }

    private sealed class FakeFlags : IEmergencyFlagSource
    {
        public EmergencyFlag? Flag { get; set; }

        public int Reads { get; private set; }

        public EmergencyFlag? Read()
        {
            Reads++;
            return Flag;
        }
    }

    private sealed class FakeLauncher : IEmergencyLauncher
    {
        public List<bool> Runs { get; } = [];

        public Action<bool>? OnRun { get; set; }

        public Task<EmergencyRunResult>? Pending { get; set; }

        public EmergencyRunResult? Result { get; set; }

        public Task<EmergencyRunResult> RunAsync(bool on, CancellationToken cancellationToken = default)
        {
            Runs.Add(on);
            OnRun?.Invoke(on);
            return Pending ?? Task.FromResult(Result ?? EmergencyRunResult.FromExitCode(on, 0, null, null));
        }
    }

    private static Task RunStaAsync(Func<Task> action)
    {
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            var dispatcher = Dispatcher.CurrentDispatcher;
            SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(dispatcher));
            dispatcher.BeginInvoke(new Action(async () =>
            {
                try { await action(); completion.TrySetResult(); }
                catch (Exception ex) { completion.TrySetException(ex); }
                finally { dispatcher.BeginInvokeShutdown(DispatcherPriority.Background); }
            }));
            Dispatcher.Run();
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        return completion.Task.WaitAsync(TimeSpan.FromSeconds(15), TestContext.Current.CancellationToken);
    }
}
