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

    /// <summary>Метка запуска, которую выдаёт подменённый генератор.</summary>
    private static readonly Guid RunId = new("6f9619ff-8b86-d011-b42d-00c04fc964ff");

    // ---------- Запуск команды ----------

    [Theory]
    [InlineData(false, "emergency-off")]
    [InlineData(true, "emergency-on")]
    public void StartInfo_IsElevatedHiddenFromSystem32_WithReportId(bool on, string argument)
    {
        var info = EmergencyLauncher.BuildStartInfo(Exe, on, RunId);

        Assert.Equal(Exe, info.FileName);
        Assert.Equal(argument + " --report-id " + RunId.ToString("D"), info.Arguments);
        Assert.Equal(RunId, EmergencyCommands.ParseReportId(info.Arguments.Split(' ')));
        Assert.Equal("runas", info.Verb);
        Assert.True(info.UseShellExecute);
        Assert.Equal(ProcessWindowStyle.Hidden, info.WindowStyle);
        Assert.Equal(Environment.SystemDirectory, info.WorkingDirectory);
    }

    /// <summary>Ожидание приложения выводится из худшего случая команды в договоре и с запасом его превышает.</summary>
    [Fact]
    public void AppWait_ExceedsContractWorstCase()
    {
        Assert.Equal(EmergencyTimeouts.OffWorstCase + EmergencyLauncher.WaitMargin, EmergencyLauncher.OffTimeout);
        Assert.Equal(EmergencyTimeouts.OnWorstCase + EmergencyLauncher.WaitMargin, EmergencyLauncher.OnTimeout);
        Assert.True(EmergencyLauncher.OffTimeout - EmergencyTimeouts.OffWorstCase >= TimeSpan.FromMinutes(1));
        Assert.True(EmergencyLauncher.OnTimeout - EmergencyTimeouts.OnWorstCase >= TimeSpan.FromMinutes(1));
    }

    [Fact]
    public async Task Launcher_RunsFoundExecutable_WithContractWait_AndReadsThisRunsReport()
    {
        var runner = new FakeRunner { Outcome = ElevatedProcessOutcome.Exited(0) };
        var report = Report(EmergencyCommands.Off, 0, Now.AddSeconds(1));
        var launcher = Launcher(runner, report);

        var result = await launcher.RunAsync(on: false, TestContext.Current.CancellationToken);

        Assert.Equal(Exe, runner.Started!.FileName);
        Assert.Equal("emergency-off --report-id " + RunId.ToString("D"), runner.Started.Arguments);
        Assert.Equal(EmergencyLauncher.OffTimeout, runner.Timeout);
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
        Assert.True(result.OffersLastResort);
    }

    [Fact]
    public async Task Launcher_NoServiceFile_NothingStarted()
    {
        var runner = new FakeRunner();
        var launcher = new EmergencyLauncher(runner, () => null, _ => null, ReportPath, new FixedTime(Now), () => RunId);

        var result = await launcher.RunAsync(on: false, TestContext.Current.CancellationToken);

        Assert.Null(runner.Started);
        Assert.Equal(EmergencyRunKind.Failed, result.Kind);
        Assert.Contains("не найден", result.Summary, StringComparison.Ordinal);
        Assert.Contains("recover-network.cmd", result.Advice, StringComparison.Ordinal);
    }

    /// <summary>
    /// Не дождались: итог — «ещё выполняется» без кода и шагов, процесс не прерывается, а окончательный итог (с отчётом
    /// этого запуска) приходит, когда команда действительно выйдет.
    /// </summary>
    [Fact]
    public async Task Launcher_Overdue_KeepsWaiting_AndDeliversFinalResult()
    {
        var exit = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        var launcher = Launcher(new FakeRunner { Outcome = ElevatedProcessOutcome.Overdue(exit.Task) }, Report(EmergencyCommands.Off, 3, Now.AddSeconds(2)));

        var result = await launcher.RunAsync(on: false, TestContext.Current.CancellationToken);

        Assert.Equal(EmergencyRunKind.Overdue, result.Kind);
        Assert.Contains("ещё выполняется", result.Summary, StringComparison.Ordinal);
        Assert.Contains(((int)EmergencyLauncher.OffTimeout.TotalMinutes).ToString(System.Globalization.CultureInfo.InvariantCulture) + " мин", result.Summary, StringComparison.Ordinal);
        Assert.Null(result.ExitCode);
        Assert.Empty(result.Steps);
        Assert.False(result.IsError);
        Assert.NotNull(result.Completion);
        Assert.False(result.Completion.IsCompleted);

        exit.SetResult(3);
        var final = await result.Completion.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        Assert.Equal(EmergencyRunKind.Failed, final.Kind);
        Assert.Equal(3, final.ExitCode);
        Assert.NotEmpty(final.Steps);
        Assert.Equal(ReportPath, final.ReportPath);
    }

    [Fact]
    public async Task Launcher_Overdue_FailedWait_GivesExitCodeText_NotException()
    {
        var launcher = Launcher(new FakeRunner { Outcome = ElevatedProcessOutcome.Overdue(Task.FromException<int>(new InvalidOperationException("процесс пропал"))) }, report: null);

        var result = await launcher.RunAsync(on: false, TestContext.Current.CancellationToken);
        var final = await result.Completion!;

        Assert.Equal(EmergencyExitCodes.Unexpected, final.ExitCode);
        Assert.Equal(EmergencyExitCodes.Describe(EmergencyExitCodes.Unexpected), final.Summary);
    }

    [Theory]
    [InlineData(false, 0, EmergencyRunKind.Succeeded)]
    [InlineData(false, 1, EmergencyRunKind.Failed)]
    [InlineData(false, 2, EmergencyRunKind.Failed)]
    [InlineData(false, 3, EmergencyRunKind.Failed)]
    [InlineData(false, 4, EmergencyRunKind.Failed)]
    [InlineData(true, 0, EmergencyRunKind.Succeeded)]
    [InlineData(true, 2, EmergencyRunKind.Failed)]
    [InlineData(true, 3, EmergencyRunKind.Failed)]
    [InlineData(true, 4, EmergencyRunKind.Failed)]
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
    }

    /// <summary>Код 5 (включение рядом с другой экстренной командой): ничего не делалось — дождаться и повторить.</summary>
    [Fact]
    public void Busy_On_SaysAnotherCommandRuns_AndToRetry()
    {
        var result = EmergencyRunResult.FromExitCode(on: true, EmergencyExitCodes.Busy, null, null);

        Assert.Equal(EmergencyRunKind.Busy, result.Kind);
        Assert.Contains("другая экстренная команда этой программы", result.Summary, StringComparison.Ordinal);
        Assert.Contains("Дождитесь", result.Advice, StringComparison.Ordinal);
        Assert.Contains("«Включить программу»", result.Advice, StringComparison.Ordinal);
        Assert.Equal(Views.StateTone.Caution, result.Tone);
    }

    /// <summary>Код 2: сеть есть, служба не работает, но её возврат не исключён — повторить выключение.</summary>
    [Fact]
    public void Code2_Off_WarnsProgramMayComeBackAfterReboot()
    {
        var result = EmergencyRunResult.FromExitCode(on: false, EmergencyExitCodes.ServiceNotConfirmed, null, null);

        Assert.Contains("После перезагрузки программа может снова включиться — повторите экстренное выключение.", result.Advice, StringComparison.Ordinal);
        Assert.False(result.OffersLastResort);
    }

    /// <summary>
    /// Код 3: совет «служба запускается только вручную» — только если отметка и ручной запуск подтверждены; служба ещё
    /// работает — сказано прямо; список шагов не повторяется (он в итоге команды).
    /// </summary>
    [Fact]
    public void Code3_Advice_FollowsReport()
    {
        var confirmed = Report(EmergencyCommands.Off, 3, Now) with
        {
            Summary = "Сеть возвращена не полностью. Не выполнено: Фильтры защиты (WFP).",
            Steps =
            [
                new(EmergencySteps.Flag, EmergencySteps.Title(EmergencySteps.Flag), EmergencyStepOutcome.Done, null, 1),
                new(EmergencySteps.StartType, EmergencySteps.Title(EmergencySteps.StartType), EmergencyStepOutcome.Done, null, 1),
                new(EmergencySteps.Wfp, EmergencySteps.Title(EmergencySteps.Wfp), EmergencyStepOutcome.Failed, "ошибка 5", 1),
            ],
        };
        var advice = EmergencyRunResult.FromExitCode(false, 3, confirmed, ReportPath).Advice;
        Assert.Contains("только вручную", advice, StringComparison.Ordinal);
        Assert.DoesNotContain("Фильтры защиты", advice, StringComparison.Ordinal);
        Assert.DoesNotContain("всё ещё работает", advice, StringComparison.Ordinal);

        var startTypeFailed = confirmed with
        {
            Steps =
            [
                .. confirmed.Steps.Where(s => s.Step != EmergencySteps.StartType),
                new(EmergencySteps.StartType, EmergencySteps.Title(EmergencySteps.StartType), EmergencyStepOutcome.Failed, "нет доступа", 1),
                new(EmergencySteps.ServiceRecheck, EmergencySteps.Title(EmergencySteps.ServiceRecheck), EmergencyStepOutcome.Failed, "служба всё ещё работает: процессов 1", 1),
            ],
        };
        advice = EmergencyRunResult.FromExitCode(false, 3, startTypeFailed, ReportPath).Advice;
        Assert.DoesNotContain("только вручную", advice, StringComparison.Ordinal);
        Assert.Contains("может снова включиться", advice, StringComparison.Ordinal);
        Assert.Contains("Служба программы всё ещё работает", advice, StringComparison.Ordinal);
    }

    [Fact]
    public void Code4_SaysAdministratorAccountIsNeeded()
    {
        Assert.Contains("учётная запись администратора", EmergencyRunResult.FromExitCode(false, EmergencyExitCodes.NotElevated, null, null).Advice, StringComparison.Ordinal);
    }

    /// <summary>Адаптер со статическим адресом в подробностях шага DNS — отдельная заметка: DNS указать вручную.</summary>
    [Fact]
    public void StaticAddressNote_IsSurfaced()
    {
        var report = Report(EmergencyCommands.Off, 0, Now) with
        {
            Steps =
            [
                new(EmergencySteps.Dns, EmergencySteps.Title(EmergencySteps.Dns), EmergencyStepOutcome.Done,
                    "DNS адаптера «Wi-Fi» возвращён; адаптер «Ethernet 3» " + EmergencyNotes.StaticAddress + ": DNS «127.0.0.1» программы не сброшен (без DHCP адаптер остался бы без DNS) — DNS укажите вручную", 1),
            ],
        };

        var advice = EmergencyRunResult.FromExitCode(false, 0, report, ReportPath).Advice;

        Assert.Contains("Обратите внимание: адаптер «Ethernet 3» со статическим адресом", advice, StringComparison.Ordinal);
        Assert.DoesNotContain("«Wi-Fi» возвращён", advice, StringComparison.Ordinal);
    }

    /// <summary>
    /// Отчёт принимается, только если он этого запуска: та же метка, команда и код завершения, время в пределах запуска и
    /// «сейчас», цел список шагов. Прежний, чужой, подложенный, из будущего — нет.
    /// </summary>
    [Fact]
    public void ReportOfThisRun_Only()
    {
        var now = Now.AddMinutes(1);
        var good = Report(EmergencyCommands.Off, 3, Now.AddSeconds(1));
        Assert.True(EmergencyLauncher.IsThisRun(good, on: false, RunId, 3, Now, now));

        Assert.False(EmergencyLauncher.IsThisRun(null, false, RunId, 3, Now, now));
        Assert.False(EmergencyLauncher.IsThisRun(good with { ReportId = null }, false, RunId, 3, Now, now), "подложенный без метки");
        Assert.False(EmergencyLauncher.IsThisRun(good with { ReportId = Guid.NewGuid() }, false, RunId, 3, Now, now), "другая метка");
        Assert.False(EmergencyLauncher.IsThisRun(good, true, RunId, 3, Now, now), "другая команда");
        Assert.False(EmergencyLauncher.IsThisRun(good with { Command = "uninstall-network" }, false, RunId, 3, Now, now));
        Assert.False(EmergencyLauncher.IsThisRun(good, false, RunId, 0, Now, now), "код отчёта не совпадает с кодом процесса");
        Assert.False(EmergencyLauncher.IsThisRun(good with { StartedUtc = Now.AddMinutes(-10), FinishedUtc = Now.AddMinutes(-9) }, false, RunId, 3, Now, now), "прежний");
        Assert.False(EmergencyLauncher.IsThisRun(good with { StartedUtc = now.AddHours(1), FinishedUtc = now.AddHours(1) }, false, RunId, 3, Now, now), "из будущего");
        Assert.False(EmergencyLauncher.IsThisRun(good with { FinishedUtc = good.StartedUtc.AddSeconds(-1) }, false, RunId, 3, Now, now));
        Assert.False(EmergencyLauncher.IsThisRun(good with { Steps = null! }, false, RunId, 3, Now, now), "нет списка шагов");
        Assert.False(EmergencyLauncher.IsThisRun(good with { Steps = [good.Steps[0], null!] }, false, RunId, 3, Now, now), "пустой шаг");
    }

    /// <summary>Отчёт с «steps»: null или пустым элементом из файла — как отчёта нет; исключение чтения наружу не выходит.</summary>
    [Theory]
    [InlineData("\"steps\":null")]
    [InlineData("\"steps\":[null]")]
    [InlineData("\"steps\":[{\"step\":null,\"title\":\"x\",\"outcome\":\"done\",\"ms\":1}]")]
    public async Task BrokenStepsInFile_AreNoReport(string steps)
    {
        var json = "{\"version\":1,\"command\":\"emergency-off\",\"reportId\":\"" + RunId.ToString("D") + "\",\"startedUtc\":\"2026-11-25T12:00:01+00:00\","
            + "\"finishedUtc\":\"2026-11-25T12:00:30+00:00\",\"exitCode\":0,\"summary\":\"x\"," + steps + "}";
        var launcher = new EmergencyLauncher(new FakeRunner { Outcome = ElevatedProcessOutcome.Exited(0) }, () => Exe, _ => json, ReportPath, new FixedTime(Now), () => RunId);

        var result = await launcher.RunAsync(false, TestContext.Current.CancellationToken);

        Assert.Empty(result.Steps);
        Assert.Null(result.ReportPath);
        Assert.Equal(EmergencyExitCodes.Describe(0), result.Summary);
    }

    [Fact]
    public async Task StaleLastJson_DoesNotBecomeThisRunsSteps()
    {
        // Включение отказалось (код 5) и отчёта с этой меткой не писало; в last.json — отчёт прошлого запуска.
        var stale = Report(EmergencyCommands.On, 0, Now.AddHours(-2)) with { ReportId = Guid.NewGuid() };
        var launcher = Launcher(new FakeRunner { Outcome = ElevatedProcessOutcome.Exited(5) }, stale);

        var result = await launcher.RunAsync(on: true, TestContext.Current.CancellationToken);

        Assert.Empty(result.Steps);
        Assert.Null(result.ReportPath);
        Assert.Equal(EmergencyRunKind.Busy, result.Kind);
    }

    [Fact]
    public async Task UnreadableOrBrokenReport_IsIgnored_NoExceptionEscapes()
    {
        var runner = new FakeRunner { Outcome = ElevatedProcessOutcome.Exited(0) };
        var broken = new EmergencyLauncher(runner, () => Exe, _ => "{ не json", ReportPath, new FixedTime(Now), () => RunId);
        var locked = new EmergencyLauncher(runner, () => Exe, _ => throw new UnauthorizedAccessException("нет доступа"), ReportPath, new FixedTime(Now), () => RunId);
        var odd = new EmergencyLauncher(runner, () => Exe, _ => throw new InvalidOperationException("что-то иное"), ReportPath, new FixedTime(Now), () => RunId);
        var lookup = new EmergencyLauncher(runner, () => throw new InvalidOperationException("реестр"), _ => null, ReportPath, new FixedTime(Now), () => RunId);

        Assert.Empty((await broken.RunAsync(false, TestContext.Current.CancellationToken)).Steps);
        Assert.Empty((await locked.RunAsync(false, TestContext.Current.CancellationToken)).Steps);
        Assert.Equal(EmergencyRunKind.Succeeded, (await odd.RunAsync(false, TestContext.Current.CancellationToken)).Kind);
        Assert.Equal(EmergencyRunKind.Failed, (await lookup.RunAsync(false, TestContext.Current.CancellationToken)).Kind);
    }

    /// <summary>
    /// Отчёт читается, только если каталог и файл принадлежат SYSTEM или Administrators и не ссылки; больше 1 МБ — не
    /// читается. Временный каталог теста принадлежит обычному пользователю — такой отчёт отвергается.
    /// </summary>
    [Fact]
    public void ReportFile_TrustAndSizeCap()
    {
        var directory = Path.Combine(Path.GetTempPath(), "SplitVpn.Test." + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var path = Path.Combine(directory, "last.json");
            File.WriteAllText(path, "{\"version\":1}");
            var checkedEntries = new List<string>();

            Assert.Equal("{\"version\":1}", EmergencyLauncher.ReadTrustedReport(path, e => { checkedEntries.Add(e.FullName); return null; }));
            Assert.Equal([directory, path], checkedEntries);
            Assert.Null(EmergencyLauncher.ReadTrustedReport(path, e => e is DirectoryInfo ? "чужой каталог" : null));
            Assert.Null(EmergencyLauncher.ReadTrustedReport(path, e => e is FileInfo ? "чужой файл" : null));

            // Настоящая проверка владельца: каталог создан обычным пользователем — не доверяем.
            Assert.NotNull(Core.Recovery.AdminOnlyAccess.OwnedByAdminsProblem(new DirectoryInfo(directory)));
            Assert.Null(EmergencyLauncher.ReadTrustedReport(path));

            File.WriteAllBytes(path, new byte[EmergencyLauncher.MaxReportBytes + 1]);
            Assert.Null(EmergencyLauncher.ReadTrustedReport(path, _ => null));
            File.WriteAllBytes(path, System.Text.Encoding.UTF8.GetBytes("\uFEFF{}"));
            Assert.Equal("{}", EmergencyLauncher.ReadTrustedReport(path, _ => null));
            Assert.Null(EmergencyLauncher.ReadTrustedReport(Path.Combine(directory, "нет.json"), _ => null));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Report_BecomesStepList_WithRussianOutcomes_AndSeverities()
    {
        var report = Report(EmergencyCommands.Off, 3, Now) with
        {
            Summary = "Сеть возвращена не полностью. Не выполнено: Фильтры защиты (WFP), DNS адаптеров.",
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

        Assert.Equal(report.Summary, result.Summary);
        // Не выполненные — первыми (список в шапке ограничен по высоте), затем предупреждения, затем выполненные; внутри — по порядку.
        Assert.Equal(["не удалось", "не уложился в срок", "не удалось", "сделано", "уже было так", "не требовалось"], result.Steps.Select(s => s.OutcomeText));
        Assert.Equal("Фильтры защиты (WFP)", result.Steps[0].Title);
        Assert.Equal("Маршруты программы", result.Steps[4].Title);
        Assert.Equal(
            [EmergencyStepSeverity.Error, EmergencyStepSeverity.Error, EmergencyStepSeverity.Warning, EmergencyStepSeverity.Ok, EmergencyStepSeverity.Ok, EmergencyStepSeverity.Ok],
            result.Steps.Select(s => s.Severity));
        Assert.True(result.HasProblems);
        // Совет не повторяет список шагов (он уже в итоге команды), но говорит, что делать.
        Assert.DoesNotContain("Не возвращено", result.Advice, StringComparison.Ordinal);
        Assert.DoesNotContain("Кеш DNS", result.Advice, StringComparison.Ordinal);
        // Ручной запуск в отчёте не подтверждён: совет не опирается на него.
        Assert.Contains("Повторите экстренное выключение", result.Advice, StringComparison.Ordinal);
        Assert.DoesNotContain("только вручную", result.Advice, StringComparison.Ordinal);
        Assert.True(result.OffersLastResort);

        var message = result.ToMessageText();
        Assert.Contains("Фильтры защиты (WFP): не удалось (ошибка 5)", message, StringComparison.Ordinal);
        Assert.Contains("Кеш DNS: не удалось (код 1) — не влияет на итог", message, StringComparison.Ordinal);
        Assert.DoesNotContain("Отметка отключения:", message, StringComparison.Ordinal);
        Assert.Contains("Отчёт: " + ReportPath, message, StringComparison.Ordinal);

        var copied = result.ToReportText();
        Assert.Contains("Отметка отключения: сделано (записано)", copied, StringComparison.Ordinal);
        Assert.Contains("Код завершения: 3", copied, StringComparison.Ordinal);
    }

    // ---------- Файл службы и скрипт для запуска с правами администратора ----------

    /// <summary>
    /// Кандидаты — только путь из регистрации службы и %ProgramFiles%\SplitVpn; каждый — лишь если он прошёл проверку прав
    /// и ссылок. Файл рядом с приложением и подкаталог service больше не рассматриваются.
    /// </summary>
    [Fact]
    public void ServiceFile_OnlyRegisteredOrProgramFiles_AndOnlyIfAdminOnly()
    {
        const string programFiles = @"C:\Program Files";
        var standard = Path.Combine(programFiles, "SplitVpn", "SplitVpn.Service.exe");
        const string registered = @"C:\Program Files\SplitVpn.Dev\service\SplitVpn.Service.exe";
        var asked = new List<string>();
        string? Ok(string path) { asked.Add(path); return null; }

        Assert.Equal(registered, NetworkRecovery.FindServiceExecutable(registered, programFiles, Ok));
        Assert.Equal(standard, NetworkRecovery.FindServiceExecutable(registered, programFiles, p => p == registered ? "каталог доступен для записи пользователям" : null));
        Assert.Equal(standard, NetworkRecovery.FindServiceExecutable(null, programFiles, Ok));
        Assert.Null(NetworkRecovery.FindServiceExecutable(@"C:\Users\u\AppData\Local\SplitVpn\SplitVpn.Service.exe", programFiles, _ => "чужой каталог"));
        Assert.DoesNotContain(asked, p => p.Contains("AppData", StringComparison.OrdinalIgnoreCase) || p.Contains(AppContext.BaseDirectory, StringComparison.OrdinalIgnoreCase));
        Assert.All(asked, p => Assert.True(p == registered || p == standard, p));
    }

    [Fact]
    public void RecoveryScript_NextToValidatedService_BothScriptsChecked()
    {
        var asked = new List<string>();
        var script = NetworkRecovery.FindRecoveryScript(Exe, p => { asked.Add(p); return null; });

        Assert.Equal(@"C:\Program Files\SplitVpn\scripts\recover-network.cmd", script);
        Assert.Equal([@"C:\Program Files\SplitVpn\scripts\recover-network.cmd", @"C:\Program Files\SplitVpn\scripts\recover-network.ps1"], asked);
        Assert.Null(NetworkRecovery.FindRecoveryScript(Exe, p => p.EndsWith(".ps1", StringComparison.Ordinal) ? "доступен для записи" : null));
        Assert.Null(NetworkRecovery.FindRecoveryScript(null, _ => null));

        var info = NetworkRecovery.RecoveryScriptStartInfo(script!);
        Assert.Equal("runas", info.Verb);
        Assert.True(info.UseShellExecute);
        Assert.Equal(Environment.SystemDirectory, info.WorkingDirectory);
    }

    /// <summary>
    /// Правила пути для запуска с повышением на дескрипторах в памяти: файл и его каталог — без записи посторонним, каталоги
    /// выше — без права подменить путь (создавать новое в корне диска «Прошедшим проверку» можно), никаких ссылок, владелец —
    /// SYSTEM, Administrators или TrustedInstaller.
    /// </summary>
    [Fact]
    public void ElevationTarget_PathRules()
    {
        var system = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
        var users = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null);
        var authenticated = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.AuthenticatedUserSid, null);
        var stranger = new System.Security.Principal.SecurityIdentifier("S-1-5-21-1-2-3-1001");
        const string file = @"C:\Program Files\SplitVpn\SplitVpn.Service.exe";

        System.Security.AccessControl.FileSystemSecurity Acl(System.Security.Principal.SecurityIdentifier owner, params (System.Security.Principal.SecurityIdentifier Who, System.Security.AccessControl.FileSystemRights Rights)[] extra)
        {
            var security = new System.Security.AccessControl.DirectorySecurity();
            security.SetOwner(owner);
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(system, System.Security.AccessControl.FileSystemRights.FullControl, System.Security.AccessControl.AccessControlType.Allow));
            security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(users, System.Security.AccessControl.FileSystemRights.ReadAndExecute, System.Security.AccessControl.AccessControlType.Allow));
            foreach (var (who, rights) in extra)
            {
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(who, rights, System.Security.AccessControl.AccessControlType.Allow));
            }

            return security;
        }

        string? Check(Func<string, System.Security.AccessControl.FileSystemSecurity> acl, Func<string, FileAttributes>? attributes = null) =>
            Core.Recovery.AdminOnlyAccess.ElevationTargetProblem(file, (path, directory) =>
                (attributes?.Invoke(path) ?? (directory ? FileAttributes.Directory : FileAttributes.Archive), acl(path)));

        var root = Acl(system, (authenticated, System.Security.AccessControl.FileSystemRights.AppendData));
        System.Security.AccessControl.FileSystemSecurity Normal(string path) => path == @"C:\" ? root : Acl(Core.Recovery.AdminOnlyAccess.TrustedInstaller);

        Assert.Null(Check(Normal));
        Assert.Contains(@"C:\Program Files\SplitVpn:", Check(p => p == @"C:\Program Files\SplitVpn" ? Acl(system, (users, System.Security.AccessControl.FileSystemRights.CreateFiles)) : Normal(p)), StringComparison.Ordinal);
        Assert.Contains("SplitVpn.Service.exe:", Check(p => p == file ? Acl(system, (users, System.Security.AccessControl.FileSystemRights.Write)) : Normal(p)), StringComparison.Ordinal);
        Assert.Contains(@"C:\Program Files:", Check(p => p == @"C:\Program Files" ? Acl(system, (users, System.Security.AccessControl.FileSystemRights.Delete)) : Normal(p)), StringComparison.Ordinal);
        Assert.Null(Check(p => p == @"C:\Program Files" ? Acl(system, (users, System.Security.AccessControl.FileSystemRights.CreateDirectories)) : Normal(p)));
        Assert.Contains("посторонней", Check(p => p == @"C:\Program Files\SplitVpn" ? Acl(stranger) : Normal(p)), StringComparison.Ordinal);
        Assert.Contains("ссылкой", Check(Normal, p => p == @"C:\Program Files" ? FileAttributes.Directory | FileAttributes.ReparsePoint : p == file ? FileAttributes.Archive : FileAttributes.Directory), StringComparison.Ordinal);
        Assert.Contains("не найден", Core.Recovery.AdminOnlyAccess.ElevationTargetProblem(file, (_, _) => null), StringComparison.Ordinal);
        foreach (var bad in new[] { @"\\server\share\SplitVpn.Service.exe", @"SplitVpn.Service.exe", @"C:\Program Files\..\Users\SplitVpn.Service.exe", "" })
        {
            Assert.Contains("путь не полный", Core.Recovery.AdminOnlyAccess.ElevationTargetProblem(bad, (_, _) => throw new InvalidOperationException()), StringComparison.Ordinal);
        }
    }

    /// <summary>Настоящая файловая система: системный файл Windows проходит, файл во временном каталоге пользователя — нет.</summary>
    [Fact]
    public void ElevationTarget_RealFileSystem()
    {
        Assert.Null(Core.Recovery.AdminOnlyAccess.ElevationTargetProblem(Path.Combine(Environment.SystemDirectory, "cmd.exe")));

        var temp = Path.Combine(Path.GetTempPath(), "SplitVpn.Test." + Guid.NewGuid().ToString("N") + ".exe");
        File.WriteAllText(temp, "x");
        try
        {
            Assert.NotNull(Core.Recovery.AdminOnlyAccess.ElevationTargetProblem(temp));
        }
        finally
        {
            File.Delete(temp);
        }
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
        var off = false;
        using var service = new ServiceConnection((_, _) => Task.FromResult(IpcResponse.Success(new StatusDto { EmergencyOff = off })));
        using var main = NewMain(service, out var launcher, out var flags);
        var order = new List<string>();
        main.Emergency.RevertProxy = () => { order.Add("proxy"); return Task.CompletedTask; };
        launcher.OnRun = on =>
        {
            order.Add(on ? "on" : "off");
            off = !on;
            flags.Flag = on ? null : new EmergencyFlag(Now);
        };
        main.Confirm = (_, _, _) => Task.FromResult(true);

        await main.Emergency.TurnOffCommand.ExecuteAsync(null);
        Assert.True(main.Emergency.IsOff);
        Assert.True(main.Emergency.TurnOnCommand.CanExecute(null));
        await main.Emergency.TurnOnCommand.ExecuteAsync(null);

        // Прокси снимается перед выключением; включение прокси не трогает: его поставит подключение туннеля.
        Assert.Equal(["proxy", "off", "on"], order);
        Assert.False(main.Emergency.IsOff);
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

    /// <summary>
    /// Команда не уложилась в ожидание: «ещё выполняется», состояние «идёт команда» сохраняется, «Включить программу» и
    /// «Экстренно выключить» недоступны (и повторный запуск ничего не делает), пока процесс действительно не выйдет; затем — итог.
    /// </summary>
    [Fact]
    public Task Overdue_KeepsRunningState_AndBlocksTurnOn_UntilProcessExits() => RunStaAsync(async () =>
    {
        using var service = new ServiceConnection((_, _) => Task.FromResult(IpcResponse.Success(new StatusDto { EmergencyOff = true })));
        using var main = NewMain(service, out var launcher, out var flags);
        flags.Flag = new EmergencyFlag(Now);
        await main.RefreshAsync();
        Assert.True(main.Emergency.TurnOnCommand.CanExecute(null));
        var exit = new TaskCompletionSource<EmergencyRunResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        launcher.Result = EmergencyRunResult.Overdue(on: true, EmergencyLauncher.OnTimeout, exit.Task);

        var run = main.Emergency.TurnOnCommand.ExecuteAsync(null);
        await Task.Yield();

        Assert.True(main.Emergency.IsRunning);
        Assert.Equal(EmergencyRunKind.Overdue, main.Emergency.Result?.Kind);
        Assert.Contains("ещё выполняется", main.Emergency.RunningText, StringComparison.Ordinal);
        Assert.False(main.Emergency.TurnOnCommand.CanExecute(null));
        Assert.False(main.Emergency.TurnOffCommand.CanExecute(null));
        await main.Emergency.RunAsync(on: true);
        await main.Emergency.RunAsync(on: false);
        Assert.Equal([true], launcher.Runs);

        exit.SetResult(EmergencyRunResult.FromExitCode(true, 0, null, null));
        await run;
        Assert.False(main.Emergency.IsRunning);
        Assert.Equal(EmergencyRunKind.Succeeded, main.Emergency.Result?.Kind);
        Assert.Equal("", main.Emergency.RunningText);
    });

    /// <summary>
    /// Раскрытие списка шагов — свойство модели: новый итог задаёт его заново (раскрыт при сбоях, свёрнут без них и в
    /// низком окне), а между итогами его меняет человек.
    /// </summary>
    [Fact]
    public Task StepsExpanded_ResetPerResult_AndCollapsedInCompactWindow() => RunStaAsync(async () =>
    {
        using var service = new ServiceConnection((_, _) => Task.FromResult(IpcResponse.Success(new StatusDto())));
        using var main = NewMain(service, out _, out _);
        var failed = EmergencyRunResult.FromExitCode(false, 3, Report(EmergencyCommands.Off, 3, Now), ReportPath);
        var clean = EmergencyRunResult.FromExitCode(false, 0, Report(EmergencyCommands.Off, 0, Now), ReportPath);

        main.Emergency.Result = failed;
        Assert.True(main.Emergency.StepsExpanded);
        main.Emergency.StepsExpanded = false;
        Assert.Same(failed, main.Emergency.Result);
        main.Emergency.Result = clean;
        Assert.False(main.Emergency.StepsExpanded);
        main.Emergency.Result = failed;
        Assert.True(main.Emergency.StepsExpanded);

        main.Emergency.CompactLayout = true;
        main.Emergency.Result = null;
        main.Emergency.Result = failed;
        Assert.False(main.Emergency.StepsExpanded);
        await Task.CompletedTask;
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

    /// <summary>Ярлык: сначала одно подтверждение; «Нет» — ничего не запускается, код как у отказа в UAC.</summary>
    [Fact]
    public void Shortcut_Declined_RunsNothing()
    {
        var host = new FakeHost { ConfirmAnswer = false };

        Assert.Equal(EmergencyLauncher.UacCancelled, EmergencyCommandLine.Run(host));
        Assert.Empty(host.Launcher.Runs);
        Assert.Contains("VPN и защита от утечек будут отключены", host.Confirmed!, StringComparison.Ordinal);
        Assert.Contains("не запустится", host.Confirmed!, StringComparison.Ordinal);
        Assert.Contains("«Включить программу»", host.Confirmed!, StringComparison.Ordinal);
        Assert.Empty(host.Shown);
    }

    [Fact]
    public void Shortcut_Success_ShowsResult_NoLastResortOffer()
    {
        var host = new FakeHost();

        Assert.Equal(0, EmergencyCommandLine.Run(host));
        Assert.Equal([false], host.Launcher.Runs);
        var (text, error) = Assert.Single(host.Shown);
        Assert.False(error);
        Assert.Contains("«Включить программу»", text, StringComparison.Ordinal);
        Assert.Null(host.Asked);
        Assert.Null(host.Started);
    }

    /// <summary>Сделано не всё (не запустилась, код 1 или 3 и выше): в том же окне — предложение последнего средства.</summary>
    [Theory]
    [InlineData(3, true, true)]
    [InlineData(1, true, false)]
    [InlineData(4, false, false)]
    public void Shortcut_Failure_OffersRecoveryScript(int code, bool yes, bool found)
    {
        var host = new FakeHost { AskAnswer = yes, Script = found ? @"C:\Program Files\SplitVpn\scripts\recover-network.cmd" : null };
        host.Launcher.Result = EmergencyRunResult.FromExitCode(false, code, null, null);

        Assert.Equal(code, EmergencyCommandLine.Run(host));

        if (found)
        {
            Assert.Contains(EmergencyCommandLine.LastResortQuestion, host.Asked!, StringComparison.Ordinal);
            Assert.Empty(host.Shown);
            Assert.Equal(yes ? host.Script : null, host.Started);
        }
        else
        {
            Assert.Null(host.Asked);
            Assert.Single(host.Shown);
            Assert.Null(host.Started);
        }
    }

    [Fact]
    public void Shortcut_Code2_DoesNotOfferRecoveryScript()
    {
        var host = new FakeHost { Script = "x.cmd" };
        host.Launcher.Result = EmergencyRunResult.FromExitCode(false, 2, null, null);

        EmergencyCommandLine.Run(host);

        Assert.Null(host.Asked);
        Assert.Single(host.Shown);
    }

    /// <summary>Любая ошибка ярлыка — в журнал ошибок и в окно с советом о recover-network.cmd, а не молчаливое закрытие.</summary>
    [Fact]
    public void Shortcut_Exception_IsRecorded_AndFallbackShown()
    {
        var host = new FakeHost();
        host.Launcher.Throw = new InvalidOperationException("сломалось");

        Assert.Equal(EmergencyExitCodes.Unexpected, EmergencyCommandLine.Run(host));

        Assert.IsType<InvalidOperationException>(Assert.Single(host.Recorded));
        var (text, error) = Assert.Single(host.Shown);
        Assert.True(error);
        Assert.Contains("recover-network.cmd", text, StringComparison.Ordinal);
        Assert.Contains("ui-errors.log", text, StringComparison.Ordinal);
    }

    /// <summary>Ярлык: команда не уложилась в ожидание — дождаться настоящего окончания и показать окончательный итог.</summary>
    [Fact]
    public void Shortcut_Overdue_WaitsForFinalResult()
    {
        var host = new FakeHost();
        host.Launcher.Result = EmergencyRunResult.Overdue(false, EmergencyLauncher.OffTimeout,
            Task.Run(async () => { await Task.Delay(50); return EmergencyRunResult.FromExitCode(false, 0, null, null); }));

        Assert.Equal(0, EmergencyCommandLine.Run(host));
        Assert.DoesNotContain("ещё выполняется", Assert.Single(host.Shown).Text, StringComparison.Ordinal);
    }

    private sealed class FakeHost : IEmergencyCommandLineHost
    {
        public FakeLauncher Launcher { get; } = new();

        IEmergencyLauncher IEmergencyCommandLineHost.Launcher => Launcher;

        public Func<Task>? RevertProxy => null;

        public bool ConfirmAnswer { get; init; } = true;

        public bool AskAnswer { get; init; }

        public string? Script { get; init; }

        public string? Confirmed { get; private set; }

        public string? Asked { get; private set; }

        public string? Started { get; private set; }

        public List<(string Text, bool Error)> Shown { get; } = [];

        public List<Exception> Recorded { get; } = [];

        public bool Confirm(string text)
        {
            Confirmed = text;
            return ConfirmAnswer;
        }

        public void ShowResult(string text, bool error) => Shown.Add((text, error));

        public bool AskResult(string text)
        {
            Asked = text;
            return AskAnswer;
        }

        public string? FindRecoveryScript() => Script;

        public void StartRecoveryScript(string script) => Started = script;

        public void Record(Exception exception) => Recorded.Add(exception);
    }

    // ---------- Подмены ----------

    /// <summary>
    /// Шапка не противоречит блоку «Служба»: до первого ответа службы красной плашки нет (окно показывает
    /// «Подключение к службе…»), а пока служба останавливается, «Подключить» недоступна, хотя канал ещё отвечает.
    /// </summary>
    [Fact]
    public Task ServiceHeader_IsConsistentWithServiceBlock() => RunStaAsync(async () =>
    {
        using var service = new ServiceConnection((_, _) => Task.FromResult(IpcResponse.Success(new StatusDto())));
        using var main = NewMain(service, out _, out _);
        main.ServiceHost.Show(ServiceHostState.Running, "1.0.0");
        Assert.False(main.ServiceAvailable);
        Assert.False(main.ShowServiceError);

        await main.RefreshAsync();
        Assert.True(main.ConnectCommand.CanExecute(null));
        Assert.True(main.CanSendCommands);

        main.ServiceHost.Show(ServiceHostState.StopPending, "1.0.0");
        Assert.True(main.ServiceAvailable);
        Assert.False(main.CanSendCommands);
        Assert.False(main.ConnectCommand.CanExecute(null));
        Assert.False(main.ToggleConnectionCommand.CanExecute(null));

        main.ServiceHost.Show(ServiceHostState.Running, "1.0.0");
        Assert.True(main.ConnectCommand.CanExecute(null));
    });

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
            ReportPath, new FixedTime(Now), () => RunId);

    private static EmergencyReport Report(string command, int code, DateTimeOffset started) => new()
    {
        Command = command,
        ReportId = RunId,
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

        public Exception? Throw { get; set; }

        public Task<EmergencyRunResult> RunAsync(bool on, CancellationToken cancellationToken = default)
        {
            Runs.Add(on);
            OnRun?.Invoke(on);
            if (Throw is not null)
            {
                throw Throw;
            }

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
