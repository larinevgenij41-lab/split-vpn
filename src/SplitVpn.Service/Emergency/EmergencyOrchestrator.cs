using System.Diagnostics;
using System.Globalization;
using SplitVpn.Core.Recovery;

namespace SplitVpn.Service.Emergency;

/// <summary>
/// Сроки команд. Значения по умолчанию — из договора (<see cref="EmergencyTimeouts"/>): по тем же числам приложение
/// считает, сколько ждать команду. Тесты задают малые.
/// </summary>
internal sealed record EmergencyOptions
{
    /// <summary>Сколько ждать занятую блокировку команд.</summary>
    public TimeSpan LockWait { get; init; } = EmergencyTimeouts.LockWait;

    /// <summary>Срок проверки, не выполняется ли другая команда этой программы.</summary>
    public TimeSpan OtherCommandCheck { get; init; } = EmergencyTimeouts.OtherCommandCheck;

    /// <summary>Сколько ждать штатной остановки службы до принудительного завершения (общий срок с прежним recover).</summary>
    public TimeSpan StopWaitBeforeKill { get; init; } = EmergencyTimeouts.StopWaitBeforeKill;

    /// <summary>Сколько ждать выхода завершаемого процесса.</summary>
    public TimeSpan KillWait { get; init; } = EmergencyTimeouts.KillWait;

    /// <summary>Сколько ждать запуска службы.</summary>
    public TimeSpan StartWait { get; init; } = EmergencyTimeouts.StartWait;

    /// <summary>Срок одного вызова диспетчера служб внутри шага остановки: не ответил — завершение процессов по пути.</summary>
    public TimeSpan ScmCallTimeout { get; init; } = EmergencyTimeouts.ScmCallTimeout;

    /// <summary>Сколько перед выходом ждать шаги, не уложившиеся в срок и ещё работающие в фоне.</summary>
    public TimeSpan AbandonedStepGrace { get; init; } = EmergencyTimeouts.AbandonedStepGrace;

    /// <summary>Общий срок emergency-off (и сетевого шага удаления): худший случай из договора.</summary>
    public TimeSpan OffDeadline { get; init; } = EmergencyTimeouts.OffWorstCase;

    /// <summary>Общий срок emergency-on.</summary>
    public TimeSpan OnDeadline { get; init; } = EmergencyTimeouts.OnWorstCase;

    public TimeSpan PollInterval { get; init; } = TimeSpan.FromMilliseconds(500);

    /// <summary>Срок шага; null — из договора (<see cref="EmergencyTimeouts.Step"/>).</summary>
    public Func<string, TimeSpan>? StepTimeout { get; init; }

    public TimeSpan TimeoutFor(string step) => StepTimeout?.Invoke(step) ?? EmergencyTimeouts.Step(step);
}

/// <summary>
/// Экстренное отключение и включение программы по шагам. Каждый шаг изолирован: свой поток, свой срок, своя обработка
/// ошибок; исключение или зависание одного не пропускает следующие. Каждый шаг попадает в отчёт: итог, подробности,
/// длительность.
/// </summary>
internal sealed class EmergencyOrchestrator(IEmergencySystem system, EmergencyOptions options)
{
    /// <summary>
    /// Сетевые шаги: их сбой — «сеть возвращена не полностью» (код 3). Повторная проверка службы — тоже: живая служба
    /// вернёт фильтры, маршруты и DNS, сколько их ни снимай.
    /// </summary>
    private static readonly string[] NetworkSteps =
    [
        EmergencySteps.Helpers, EmergencySteps.Wfp, EmergencySteps.Ras, EmergencySteps.Routes, EmergencySteps.Dns, EmergencySteps.Wcm,
        EmergencySteps.ServiceRecheck,
    ];

    /// <summary>Повторные снятия: выполняются, только когда нужны, но если выполнялись — их сбой тоже «сеть не возвращена».</summary>
    private static readonly string[] AgainSteps = [EmergencySteps.WfpAgain, EmergencySteps.RoutesAgain, EmergencySteps.DnsAgain];

    /// <summary>Подробности шага, не запущенного из-за общего срока команды.</summary>
    internal const string DeadlineSkipDetail = "не запущен: истёк общий срок команды";

    /// <summary>Начало подробностей повторной проверки, после которой процессы службы остались.</summary>
    internal const string StillRunningDetail = "служба всё ещё работает";

    /// <summary>Шаги «служба выключена и сама не вернётся»: их сбой — код 2.</summary>
    private static readonly string[] ServiceSteps = [EmergencySteps.Flag, EmergencySteps.StartType, EmergencySteps.Service];

    /// <summary>Шаги-предупреждения: их сбой в отчёте есть, но на код завершения не влияет.</summary>
    private static readonly HashSet<string> Optional = new(StringComparer.Ordinal)
    {
        EmergencySteps.FailureActions, EmergencySteps.RestoreFailureActions, EmergencySteps.SuspendState, EmergencySteps.FlushDns,
    };

    /// <summary>Подробности повторной проверки: какие повторные снятия нужны (заполняет шаг, читает команда после него).</summary>
    private volatile RecheckFinding? _recheck;

    /// <summary>Шаг DNS выполнялся по правилам работающей службы (остановка не была подтверждена).</summary>
    private bool _dnsUsedRunningRules;

    public Task<EmergencyReport> OffAsync(CancellationToken overall, Guid? reportId = null) =>
        RunAsync(EmergencyCommands.Off, includeServiceGuard: true, OffStepsAsync, options.OffDeadline, reportId, overall);

    /// <summary>Шаг удаления программы: остановка службы и сеть, без флага и без смены типа запуска.</summary>
    public Task<EmergencyReport> UninstallNetworkAsync(CancellationToken overall) =>
        RunAsync("uninstall-network", includeServiceGuard: false, OffStepsAsync, options.OffDeadline, null, overall);

    public Task<EmergencyReport> OnAsync(CancellationToken overall, Guid? reportId = null) =>
        RunAsync(EmergencyCommands.On, includeServiceGuard: true, OnStepsAsync, options.OnDeadline, reportId, overall);

    private async Task<EmergencyReport> RunAsync(string command, bool includeServiceGuard,
        Func<StepRunner, bool, CancellationToken, Task> steps, TimeSpan deadline, Guid? reportId, CancellationToken overall)
    {
        var started = DateTimeOffset.UtcNow;
        if (!SafeIsElevated())
        {
            return Finish(command, started, [], EmergencyExitCodes.NotElevated, reportId);
        }

        // Общий срок команды — худший случай из договора: приложение ждёт его с запасом, и команда не должна пережить это
        // ожидание. Отсчёт — с начала, вместе с ожиданием блокировки.
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(overall);
        limit.CancelAfter(deadline);
        overall = limit.Token;

        // Включение рядом с другой командой этой программы (по живым процессам, а не по мьютексу, который может занять и
        // обычный пользователь) не выполняется: оно перезапускало бы службу, которую та команда как раз останавливает, и
        // вернуло бы автоперезапуск посреди её остановки. Отключение идемпотентно и выполняется всё равно.
        if (command == EmergencyCommands.On && OtherCommandRunning())
        {
            return Finish(command, started, [], EmergencyExitCodes.Busy, reportId);
        }

        // Блокировка — только от двух одновременных команд. Занять её заранее может и обычный пользователь (мьютекс в
        // Global\ создаётся без особых прав), поэтому после ограниченного ожидания команда выполняется без неё: шаги
        // идемпотентны, а аварийная кнопка, которую можно заблокировать без прав, — хуже двух одновременных команд.
        IDisposable? held;
        string? lockNote = null;
        try
        {
            held = system.TryAcquireLock(options.LockWait);
            if (held is null)
            {
                lockNote = string.Create(CultureInfo.InvariantCulture,
                    $"Блокировка команд была занята дольше {options.LockWait.TotalSeconds:0.#} с: команда выполнена без неё.");
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Trace.TraceWarning("Блокировка команд экстренного отключения недоступна: {0}", ex.Message);
            held = null;
            lockNote = "Блокировка команд недоступна (" + ex.Message + "): команда выполнена без неё.";
        }

        using (held)
        {
            var runner = new StepRunner(options);
            await steps(runner, includeServiceGuard, overall);

            // Шаги, не уложившиеся в срок, ещё работают в фоне: перед выходом процесса им дано немного времени, чтобы начатая
            // запись (копия DNS, состояние) не оборвалась на середине. Дольше не ждём: команда должна ответить.
            await runner.DrainAbandonedAsync(options.AbandonedStepGrace);
            var code = command == EmergencyCommands.On ? OnExitCode(runner.Steps) : OffExitCode(runner.Steps);
            return Finish(command, started, runner.Steps, code, reportId, lockNote);
        }
    }

    /// <summary>Выполняется ли другая команда восстановления этой программы; сбой или зависание проверки — «нет».</summary>
    private bool OtherCommandRunning()
    {
        var check = Task.Factory.StartNew(system.OtherRecoveryCommandRunning, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        try
        {
            if (check.Wait(options.OtherCommandCheck))
            {
                return check.Result;
            }
        }
        catch (AggregateException ex)
        {
            Trace.TraceWarning("Проверка другой команды не удалась: {0}", ex.GetBaseException().Message);
            return false;
        }

        _ = check.ContinueWith(t => _ = t.Exception, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        return false;
    }

    private bool SafeIsElevated()
    {
        try
        {
            return system.IsElevated();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return false;
        }
    }

    private async Task OffStepsAsync(StepRunner run, bool full, CancellationToken overall)
    {
        // Флаг первым: что бы ни случилось дальше, служба, запущенная кем угодно, будет «пустой».
        if (full)
        {
            await run.StepAsync(EmergencySteps.Flag, _ => system.WriteFlag(DateTimeOffset.UtcNow), overall);
            await run.StepAsync(EmergencySteps.StartType, _ => system.SetManualStart(), overall);
        }

        // Автоперезапуск снят на время остановки: убитый процесс службы диспетчер служб не поднимет снова. Снятые действия
        // сначала записываются в реестр: прерванная команда не оставит службу без автоперезапуска навсегда.
        await run.StepAsync(EmergencySteps.FailureActions, _ => system.SuspendFailureActions(), overall, required: false);
        var stop = await run.StepAsync(EmergencySteps.Service, StopService, overall);
        var serviceStopped = stop.Succeeded;
        if (serviceStopped)
        {
            // Остановка подтверждена — автоперезапуск возвращается сразу, а не после всех сетевых шагов.
            await run.StepAsync(EmergencySteps.RestoreFailureActions, _ => system.RestoreFailureActions(), overall, required: false);
        }

        await run.StepAsync(EmergencySteps.Helpers, _ => system.StopHelpers(), overall);

        // Сеть: сначала фильтры WFP — без них трафик уже идёт, даже если следующие шаги зависнут.
        await run.StepAsync(EmergencySteps.Wfp, _ => system.RemoveFilters(), overall);
        await run.StepAsync(EmergencySteps.Ras, system.HangUpConnectionsAsync, overall);
        await run.StepAsync(EmergencySteps.Routes, _ => system.RemoveRoutes(), overall);
        _dnsUsedRunningRules = !serviceStopped;
        await run.StepAsync(EmergencySteps.Dns, _ => system.RestoreDns(serviceStopped), overall);
        await run.StepAsync(EmergencySteps.Wcm, _ => system.RestoreWcm(), overall);

        // Повторная проверка — только подсчёт и завершение процессов службы; повторные снятия — отдельными шагами со своими
        // сроками и только когда нужны.
        _recheck = null;
        var recheck = await run.StepAsync(EmergencySteps.ServiceRecheck, RecheckService, overall);
        var finding = _recheck;
        if (finding is null || finding.Alive > 0 || !recheck.Succeeded)
        {
            // Процессы службы были живы (или проверка не дошла до конца): живая служба могла вернуть своё. DNS — по правилам
            // остановленной службы, только если процессов подтверждённо не осталось.
            var stopped = finding is { Left: 0 };
            await run.StepAsync(EmergencySteps.WfpAgain, _ => system.RemoveFilters(), overall);
            await run.StepAsync(EmergencySteps.RoutesAgain, _ => system.RemoveRoutes(), overall);
            await run.StepAsync(EmergencySteps.DnsAgain, _ => system.RestoreDns(stopped), overall);
        }
        else if (_dnsUsedRunningRules)
        {
            // Остановка не была подтверждена, и DNS шёл по правилам работающей службы (наш loopback мог остаться), а процессов
            // службы нет: без посредника такой DNS не отвечает — DNS ещё раз, по правилам остановленной службы.
            await run.StepAsync(EmergencySteps.DnsAgain, _ => system.RestoreDns(true), overall);
        }

        // Флаг приостановки — после сетевых шагов: он не нужен для возврата сети, а работающая служба записала бы своё
        // состояние поверх него. Каталог данных при этом не исправляется (никакого рекурсивного обхода прав): недоверенный
        // каталог — только предупреждение.
        await run.StepAsync(EmergencySteps.SuspendState, _ => system.SuspendProtection(), overall, required: false);
        await run.StepAsync(EmergencySteps.FlushDns, _ => system.FlushDns(), overall, required: false);

        if (!serviceStopped)
        {
            // Остановка не подтверждена: автоперезапуск возвращается в самом конце (шаг остановки, не уложившийся в срок,
            // мог ещё завершать процесс). Сбой возврата — только предупреждение; записанное в реестр вернёт следующая
            // команда или запуск службы.
            await run.StepAsync(EmergencySteps.RestoreFailureActions, _ => system.RestoreFailureActions(), overall, required: false);
        }
    }

    /// <summary>Итог повторной проверки: сколько процессов службы было и сколько осталось.</summary>
    private sealed record RecheckFinding(int Alive, int Left);

    /// <summary>
    /// Повторная проверка после сетевых шагов: остались процессы службы (остановка не удалась, процесс не отдал дескриптор
    /// или служба запустилась снова) — они завершаются; фильтры, маршруты и DNS после этого снимаются ещё раз отдельными
    /// шагами (живая служба успела бы вернуть своё). Процессы остались и после этого — шаг не выполнен (код 3), итог
    /// говорит, что служба работает.
    /// </summary>
    private StepResult RecheckService(CancellationToken cancellationToken)
    {
        int alive;
        try
        {
            alive = system.CountOwnServiceProcesses();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return StepResult.Failed("процессы службы не перечислены: " + ex.Message);
        }

        if (alive == 0)
        {
            _recheck = new RecheckFinding(0, 0);
            return StepResult.Already("процессов службы нет");
        }

        var notes = new List<string> { $"работало процессов службы: {alive}" };
        try
        {
            notes.Add($"завершено: {system.KillOwnServiceProcesses()}");
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            notes.Add("завершение процессов: " + ex.Message);
        }

        int left;
        try
        {
            left = system.CountOwnServiceProcesses();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            notes.Add("повторный подсчёт: " + ex.Message);
            left = alive;
        }

        _recheck = new RecheckFinding(alive, left);
        if (left > 0)
        {
            return StepResult.Failed($"{StillRunningDetail}: процессов {left}; " + string.Join("; ", notes));
        }

        notes.Add("фильтры, маршруты и DNS снимаются ещё раз");
        return StepResult.Done(string.Join("; ", notes));
    }

    private async Task OnStepsAsync(StepRunner run, bool full, CancellationToken overall)
    {
        // Служба могла работать «пустой» (её запустил установщик): флаг она читает при запуске, поэтому перезапуск.
        await run.StepAsync(EmergencySteps.FailureActions, _ => system.SuspendFailureActions(), overall, required: false);
        await run.StepAsync(EmergencySteps.Service, StopService, overall);
        await run.StepAsync(EmergencySteps.RestoreFailureActions, _ => system.RestoreFailureActions(), overall, required: false);

        // Защита остаётся приостановленной до «Подключить»: после включения ничего не применяется само.
        await run.StepAsync(EmergencySteps.SuspendState, _ => system.SuspendProtection(), overall, required: false);
        await run.StepAsync(EmergencySteps.ClearFlag, _ => system.ClearFlag(), overall);
        await run.StepAsync(EmergencySteps.RestoreStartType, _ => system.RestoreStartType(), overall);
        await run.StepAsync(EmergencySteps.StartService, StartService, overall);
    }

    /// <summary>
    /// Остановка службы. Штатная команда и ожидание общего срока; не остановилась — завершение процесса по номеру из
    /// диспетчера служб (сменился номер — повтор, а не отказ); диспетчер не отвечает или не помогло — завершение всех
    /// процессов SplitVpn.Service.exe из каталога программы, кроме себя. Каждый вызов диспетчера — со своим сроком.
    /// </summary>
    private StepResult StopService(CancellationToken cancellationToken)
    {
        var notes = new List<string>();
        ServiceSnapshot? snapshot;
        string? scmProblem = null;
        try
        {
            snapshot = Scm(system.QueryService);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            snapshot = null;
            scmProblem = ex.Message;
        }

        // Служба не установлена или уже остановлена: завершать есть что, только если найдены оставшиеся процессы службы
        // (команды восстановления из того же файла процессами службы не считаются).
        if (scmProblem is null && snapshot is null)
        {
            var strays = system.CountOwnServiceProcesses() > 0 ? system.KillOwnServiceProcesses() : 0;
            return StepResult.Skipped("служба не установлена" + (strays > 0 ? $"; завершено процессов службы: {strays}" : ""));
        }

        if (snapshot is { State: ServiceRunState.Stopped })
        {
            var strays = system.CountOwnServiceProcesses() > 0 ? system.KillOwnServiceProcesses() : 0;
            return strays > 0 ? StepResult.Done($"служба уже остановлена; завершено оставшихся процессов: {strays}") : StepResult.Already("служба уже остановлена");
        }

        if (scmProblem is null)
        {
            try
            {
                Scm(() => { system.RequestStop(); return true; });
                notes.Add("команда остановки отправлена");
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                notes.Add("команда остановки не принята: " + ex.Message);
            }

            if (WaitFor(ServiceRunState.Stopped, options.StopWaitBeforeKill, ref scmProblem, cancellationToken))
            {
                return StepResult.Done("служба остановлена штатно");
            }

            for (var attempt = 0; attempt < 3 && scmProblem is null; attempt++)
            {
                ServiceSnapshot? current;
                try
                {
                    current = Scm(system.QueryService);
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    scmProblem = ex.Message;
                    break;
                }

                if (current is null or { State: ServiceRunState.Stopped })
                {
                    return StepResult.Done(string.Join("; ", notes.Append("служба остановлена")));
                }

                if (current.ProcessId == 0)
                {
                    Sleep(cancellationToken);
                    continue;
                }

                try
                {
                    if (system.KillServiceProcess(current.ProcessId, options.KillWait)
                        && WaitFor(ServiceRunState.Stopped, options.KillWait, ref scmProblem, cancellationToken))
                    {
                        return StepResult.Done(string.Join("; ", notes.Append(
                            string.Create(CultureInfo.InvariantCulture, $"процесс службы {current.ProcessId} завершён принудительно"))));
                    }
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    // Процесс сменился или не отдал дескриптор: следующая попытка берёт номер заново.
                    notes.Add("завершение процесса: " + ex.Message);
                }
            }
        }

        if (scmProblem is not null)
        {
            notes.Add("диспетчер служб не ответил: " + scmProblem);
        }

        try
        {
            var killed = system.KillOwnServiceProcesses();
            notes.Add($"завершено процессов службы по пути: {killed}");
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            notes.Add("завершение процессов по пути: " + ex.Message);
        }

        // Подтверждение: диспетчер служб говорит «остановлена», а если он не отвечает — не осталось ни одного процесса службы.
        string? confirmProblem = null;
        try
        {
            if (Scm(system.QueryService) is null or { State: ServiceRunState.Stopped })
            {
                return StepResult.Done(string.Join("; ", notes.Append("служба остановлена")));
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            confirmProblem = ex.Message;
        }

        var left = system.CountOwnServiceProcesses();
        if (confirmProblem is not null && left == 0)
        {
            return StepResult.Done(string.Join("; ", notes.Append("процессов службы не осталось")));
        }

        notes.Add(left > 0 ? $"работает процессов службы: {left}" : "диспетчер служб не подтвердил остановку");
        return StepResult.Failed(string.Join("; ", notes));
    }

    private StepResult StartService(CancellationToken cancellationToken)
    {
        ServiceSnapshot? snapshot = Scm(system.QueryService);
        if (snapshot is null)
        {
            return StepResult.Failed("служба не установлена");
        }

        if (snapshot.State == ServiceRunState.Running)
        {
            return StepResult.Already("служба уже работает");
        }

        Scm(() => { system.RequestStart(); return true; });
        string? problem = null;
        return WaitFor(ServiceRunState.Running, options.StartWait, ref problem, cancellationToken)
            ? StepResult.Done("служба запущена")
            : StepResult.Failed(problem is null ? "служба не запустилась за отведённое время" : "диспетчер служб не ответил: " + problem);
    }

    private bool WaitFor(ServiceRunState state, TimeSpan limit, ref string? scmProblem, CancellationToken cancellationToken)
    {
        var watch = Stopwatch.StartNew();
        while (true)
        {
            try
            {
                var current = Scm(system.QueryService);
                if (current?.State == state || (state == ServiceRunState.Stopped && current is null))
                {
                    return true;
                }
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                scmProblem = ex.Message;
                return false;
            }

            if (watch.Elapsed >= limit || cancellationToken.IsCancellationRequested)
            {
                return false;
            }

            Sleep(cancellationToken);
        }
    }

    private void Sleep(CancellationToken cancellationToken) => cancellationToken.WaitHandle.WaitOne(options.PollInterval);

    /// <summary>Вызов диспетчера служб в отдельном потоке со своим сроком: зависший вызов не задерживает запасной путь.</summary>
    private T Scm<T>(Func<T> call)
    {
        var task = Task.Factory.StartNew(call, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        try
        {
            if (!task.Wait(options.ScmCallTimeout))
            {
                throw new TimeoutException($"нет ответа за {options.ScmCallTimeout.TotalSeconds:0} с");
            }
        }
        catch (AggregateException ex) when (ex.InnerExceptions.Count == 1)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(ex.InnerExceptions[0]).Throw();
        }

        return task.Result;
    }

    /// <summary>Код завершения отключения: сеть важнее службы.</summary>
    internal static int OffExitCode(IReadOnlyList<EmergencyStepReport> steps)
    {
        if (steps.Any(s => s.Required && (NetworkSteps.Contains(s.Step) || AgainSteps.Contains(s.Step)) && !s.Succeeded))
        {
            return EmergencyExitCodes.Incomplete;
        }

        return steps.Any(s => s.Required && ServiceSteps.Contains(s.Step) && !s.Succeeded)
            ? EmergencyExitCodes.ServiceNotConfirmed
            : EmergencyExitCodes.Success;
    }

    /// <summary>Код завершения включения: флаг не снят — 3, служба не перезапущена или не запустилась — 2.</summary>
    internal static int OnExitCode(IReadOnlyList<EmergencyStepReport> steps)
    {
        if (steps.Any(s => s.Step is EmergencySteps.ClearFlag && !s.Succeeded))
        {
            return EmergencyExitCodes.Incomplete;
        }

        return steps.Any(s => s.Required && s.Step is EmergencySteps.Service or EmergencySteps.RestoreStartType or EmergencySteps.StartService && !s.Succeeded)
            ? EmergencyExitCodes.ServiceNotConfirmed
            : EmergencyExitCodes.Success;
    }

    /// <summary>
    /// Сеть возвращена: каждый сетевой шаг есть в отчёте и выполнен (не запущенный из-за общего срока — не выполнен), как и
    /// каждое повторное снятие, если оно было.
    /// </summary>
    internal static bool IsNetworkClean(IReadOnlyList<EmergencyStepReport> steps) =>
        NetworkSteps.All(id => steps.Any(s => s.Step == id && s.Succeeded))
        && steps.Where(s => AgainSteps.Contains(s.Step)).All(s => s.Succeeded);

    /// <summary>
    /// Итог одним абзацем: что получилось (по коду), что из обязательного не выполнено («Не выполнено»), служба ли ещё
    /// работает, отдельно — необязательные шаги, которые не удались («Замечания»: на код не влияют), и о блокировке.
    /// </summary>
    internal static string Summary(string command, int code, IReadOnlyList<EmergencyStepReport> steps, string? lockNote)
    {
        var on = command == EmergencyCommands.On;
        var failed = steps.Where(s => !s.Succeeded && s.Required).Select(s => s.Title).ToList();
        var remarks = steps.Where(s => !s.Succeeded && !s.Required).Select(s => s.Title).ToList();
        var stillRunning = steps.Any(s => s.Step == EmergencySteps.ServiceRecheck && !s.Succeeded
            && s.Detail?.StartsWith(StillRunningDetail, StringComparison.Ordinal) == true);
        return EmergencyExitCodes.Describe(code, on)
            + (failed.Count > 0 ? " Не выполнено: " + string.Join(", ", failed) + "." : "")
            + (stillRunning ? " Служба всё ещё работает и может снова применить фильтры, маршруты и DNS." : "")
            + (remarks.Count > 0 ? " Замечания (на итог не влияют): не удалось — " + string.Join(", ", remarks) + "." : "")
            + (lockNote is null ? "" : " " + lockNote);
    }

    private static EmergencyReport Finish(string command, DateTimeOffset started, IReadOnlyList<EmergencyStepReport> steps, int code,
        Guid? reportId, string? lockNote = null)
    {
        var on = command == EmergencyCommands.On;
        var serviceConfirmed = steps.FirstOrDefault(s => s.Step == (on ? EmergencySteps.StartService : EmergencySteps.Service)) is { Succeeded: true };
        return new EmergencyReport
        {
            Command = command,
            ReportId = reportId,
            StartedUtc = started,
            FinishedUtc = DateTimeOffset.UtcNow,
            ExitCode = code,
            Summary = Summary(command, code, steps, lockNote),
            NetworkClean = !on && IsNetworkClean(steps),
            ServiceConfirmed = serviceConfirmed,
            Steps = steps,
        };
    }

    /// <summary>Выполняет шаги и записывает их итоги.</summary>
    internal sealed class StepRunner(EmergencyOptions options)
    {
        private readonly List<EmergencyStepReport> _steps = [];
        private readonly List<Task> _abandoned = [];

        public IReadOnlyList<EmergencyStepReport> Steps => _steps;

        /// <summary>
        /// Даёт шагам, не уложившимся в срок, ещё не больше <paramref name="grace"/> на завершение: начатая запись не
        /// обрывается выходом процесса. Не успели — процесс всё равно завершается (команда не висит бесконечно).
        /// </summary>
        public async Task DrainAbandonedAsync(TimeSpan grace)
        {
            var running = _abandoned.Where(t => !t.IsCompleted).ToArray();
            if (running.Length == 0)
            {
                return;
            }

            try
            {
                await Task.WhenAll(running).WaitAsync(grace);
            }
            catch (TimeoutException)
            {
                Trace.TraceWarning("Шаги, не уложившиеся в срок, ещё работают: {0}", running.Count(t => !t.IsCompleted));
            }
        }

        public Task<EmergencyStepReport> StepAsync(string step, Func<CancellationToken, StepResult> body, CancellationToken overall, bool required = true) =>
            StepAsync(step, token => Task.FromResult(body(token)), overall, required);

        /// <summary>
        /// Шаг в своём потоке (LongRunning: синхронная часть не занимает пул) и со своим сроком. Не уложился — «timeout»,
        /// его токен отменяется явно, а поток остаётся доделывать своё в фоне (фоновый поток процесс не держит);
        /// исключение — «failed». Истёк общий срок команды — оставшиеся шаги «timeout» с подробностями
        /// <see cref="DeadlineSkipDetail"/>: не выполненный шаг не может считаться успешным (иначе удаление программы
        /// стёрло бы копию DNS при оставшихся фильтрах и DNS).
        /// </summary>
        public async Task<EmergencyStepReport> StepAsync(string step, Func<CancellationToken, Task<StepResult>> body, CancellationToken overall, bool required = true)
        {
            var watch = Stopwatch.StartNew();
            StepResult result;
            if (overall.IsCancellationRequested)
            {
                result = new StepResult(EmergencyStepOutcome.Timeout, DeadlineSkipDetail);
            }
            else
            {
                var timeout = options.TimeoutFor(step);
                // Источник отмены живёт, пока жив шаг: зависший шаг ещё может ждать на его токене, поэтому он освобождается
                // в продолжении после завершения задачи шага, а не при выходе отсюда.
                var limit = CancellationTokenSource.CreateLinkedTokenSource(overall);
                limit.CancelAfter(timeout);
                var task = Task.Factory.StartNew(() => body(limit.Token), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default).Unwrap();
                try
                {
                    result = await task.WaitAsync(timeout, overall);
                }
                catch (TimeoutException)
                {
                    result = new StepResult(EmergencyStepOutcome.Timeout, string.Create(CultureInfo.InvariantCulture, $"не завершился за {timeout.TotalSeconds:0.#} с"));
                }
                catch (OperationCanceledException) when (overall.IsCancellationRequested)
                {
                    result = new StepResult(EmergencyStepOutcome.Timeout, "прерван: истёк общий срок команды");
                }
                catch (OperationCanceledException) when (limit.IsCancellationRequested)
                {
                    result = new StepResult(EmergencyStepOutcome.Timeout, string.Create(CultureInfo.InvariantCulture, $"не завершился за {timeout.TotalSeconds:0.#} с"));
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    result = StepResult.Failed(ex.Message);
                }

                if (task.IsCompleted)
                {
                    limit.Dispose();
                }
                else
                {
                    // Срок вышел: шаг узнаёт об этом сразу (его ожидания на токене прерываются), а не по таймеру источника.
                    try
                    {
                        limit.Cancel();
                    }
                    catch (AggregateException ex)
                    {
                        Trace.TraceWarning("Отмена шага {0}: {1}", step, ex.GetBaseException().Message);
                    }

                    // Зависший шаг не должен уронить процесс необработанным исключением, когда всё же завершится. Продолжение
                    // само не падает: перед выходом процесса команда ждёт его недолго (DrainAbandonedAsync).
                    _abandoned.Add(task.ContinueWith(t =>
                    {
                        _ = t.Exception;
                        limit.Dispose();
                    }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default));
                }
            }

            var report = new EmergencyStepReport(step, EmergencySteps.Title(step), result.Outcome, result.Detail, watch.ElapsedMilliseconds, required);
            _steps.Add(report);
            return report;
        }
    }
}
