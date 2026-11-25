using System.Diagnostics;
using System.Globalization;
using SplitVpn.Core.Recovery;

namespace SplitVpn.Service.Emergency;

/// <summary>Сроки команд. Значения по умолчанию — для настоящей системы; тесты задают малые.</summary>
internal sealed record EmergencyOptions
{
    /// <summary>Сколько ждать занятую блокировку команд.</summary>
    public TimeSpan LockWait { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>Сколько ждать штатной остановки службы до принудительного завершения (общий срок с прежним recover).</summary>
    public TimeSpan StopWaitBeforeKill { get; init; } = ServiceRecovery.StopWaitBeforeKill;

    /// <summary>Сколько ждать выхода завершаемого процесса.</summary>
    public TimeSpan KillWait { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Сколько ждать запуска службы.</summary>
    public TimeSpan StartWait { get; init; } = TimeSpan.FromSeconds(45);

    /// <summary>Срок одного вызова диспетчера служб внутри шага остановки: не ответил — завершение процессов по пути.</summary>
    public TimeSpan ScmCallTimeout { get; init; } = TimeSpan.FromSeconds(15);

    public TimeSpan PollInterval { get; init; } = TimeSpan.FromMilliseconds(500);

    /// <summary>Срок шага; null — по умолчанию (<see cref="DefaultTimeout"/>).</summary>
    public Func<string, TimeSpan>? StepTimeout { get; init; }

    public TimeSpan TimeoutFor(string step) => StepTimeout?.Invoke(step) ?? DefaultTimeout(step);

    private TimeSpan DefaultTimeout(string step) => step switch
    {
        EmergencySteps.Service => StopWaitBeforeKill + (3 * (KillWait + ScmCallTimeout)) + TimeSpan.FromSeconds(30),
        EmergencySteps.StartService => StartWait + ScmCallTimeout + TimeSpan.FromSeconds(10),
        EmergencySteps.Wfp => TimeSpan.FromMinutes(2),
        EmergencySteps.Dns => TimeSpan.FromSeconds(90),
        EmergencySteps.Routes => TimeSpan.FromSeconds(60),
        EmergencySteps.Ras => TimeSpan.FromSeconds(45),
        EmergencySteps.Flag or EmergencySteps.ClearFlag or EmergencySteps.Wcm => TimeSpan.FromSeconds(15),
        EmergencySteps.FlushDns => TimeSpan.FromSeconds(20),
        EmergencySteps.ServiceRecheck => (2 * (KillWait + ScmCallTimeout)) + TimeSpan.FromMinutes(2),
        _ => TimeSpan.FromSeconds(30),
    };
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

    public Task<EmergencyReport> OffAsync(CancellationToken overall) =>
        RunAsync(EmergencyCommands.Off, includeServiceGuard: true, OffStepsAsync, overall);

    /// <summary>Шаг удаления программы: остановка службы и сеть, без флага и без смены типа запуска.</summary>
    public Task<EmergencyReport> UninstallNetworkAsync(CancellationToken overall) =>
        RunAsync("uninstall-network", includeServiceGuard: false, OffStepsAsync, overall);

    public Task<EmergencyReport> OnAsync(CancellationToken overall) =>
        RunAsync(EmergencyCommands.On, includeServiceGuard: true, OnStepsAsync, overall);

    private async Task<EmergencyReport> RunAsync(string command, bool includeServiceGuard,
        Func<StepRunner, bool, CancellationToken, Task> steps, CancellationToken overall)
    {
        var started = DateTimeOffset.UtcNow;
        if (!SafeIsElevated())
        {
            return Finish(command, started, [], EmergencyExitCodes.NotElevated);
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
            var code = command == EmergencyCommands.On ? OnExitCode(runner.Steps) : OffExitCode(runner.Steps);
            return Finish(command, started, runner.Steps, code, lockNote);
        }
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
        await run.StepAsync(EmergencySteps.Dns, _ => system.RestoreDns(serviceStopped), overall);
        await run.StepAsync(EmergencySteps.Wcm, _ => system.RestoreWcm(), overall);
        await run.StepAsync(EmergencySteps.ServiceRecheck, RecheckService, overall);

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

    /// <summary>
    /// Повторная проверка после сетевых шагов: остались процессы службы (остановка не удалась, процесс не отдал дескриптор
    /// или служба запустилась снова) — они завершаются, и фильтры, маршруты и DNS снимаются ещё раз: живая служба
    /// успела бы вернуть своё. Процессы остались и после этого — шаг не выполнен (код 3), итог говорит, что служба работает.
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

        var failed = false;
        foreach (var (name, action) in new (string, Func<StepResult>)[]
        {
            ("фильтры WFP", system.RemoveFilters),
            ("маршруты", system.RemoveRoutes),
            ("DNS", () => system.RestoreDns(left == 0)),
        })
        {
            if (cancellationToken.IsCancellationRequested)
            {
                notes.Add(name + ": не снято повторно — истёк срок шага");
                failed = true;
                continue;
            }

            try
            {
                var result = action();
                var ok = result.Outcome is EmergencyStepOutcome.Done or EmergencyStepOutcome.Already or EmergencyStepOutcome.Skipped;
                failed |= !ok;
                notes.Add(name + (ok ? " сняты повторно" : ": " + (result.Detail ?? "не снято")));
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                failed = true;
                notes.Add(name + ": " + ex.Message);
            }
        }

        if (left > 0)
        {
            return StepResult.Failed($"{StillRunningDetail}: процессов {left}; " + string.Join("; ", notes));
        }

        return failed ? StepResult.Failed(string.Join("; ", notes)) : StepResult.Done(string.Join("; ", notes));
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
        if (steps.Any(s => s.Required && NetworkSteps.Contains(s.Step) && !s.Succeeded))
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

    /// <summary>Сеть возвращена: каждый сетевой шаг есть в отчёте и выполнен (не запущенный из-за общего срока — не выполнен).</summary>
    internal static bool IsNetworkClean(IReadOnlyList<EmergencyStepReport> steps) =>
        NetworkSteps.All(id => steps.Any(s => s.Step == id && s.Succeeded));

    private static EmergencyReport Finish(string command, DateTimeOffset started, IReadOnlyList<EmergencyStepReport> steps, int code, string? lockNote = null)
    {
        var on = command == EmergencyCommands.On;
        var failed = steps.Where(s => !s.Succeeded).Select(s => s.Title).ToList();
        var serviceConfirmed = steps.FirstOrDefault(s => s.Step == (on ? EmergencySteps.StartService : EmergencySteps.Service)) is { Succeeded: true };
        var stillRunning = steps.Any(s => s.Step == EmergencySteps.ServiceRecheck && !s.Succeeded
            && s.Detail?.StartsWith(StillRunningDetail, StringComparison.Ordinal) == true);
        var summary = EmergencyExitCodes.Describe(code, on)
            + (failed.Count > 0 ? " Не выполнено: " + string.Join(", ", failed) + "." : "")
            + (stillRunning ? " Служба всё ещё работает и может снова применить фильтры, маршруты и DNS." : "")
            + (lockNote is null ? "" : " " + lockNote);
        return new EmergencyReport
        {
            Command = command,
            StartedUtc = started,
            FinishedUtc = DateTimeOffset.UtcNow,
            ExitCode = code,
            Summary = summary,
            NetworkClean = !on && IsNetworkClean(steps),
            ServiceConfirmed = serviceConfirmed,
            Steps = steps,
        };
    }

    /// <summary>Выполняет шаги и записывает их итоги.</summary>
    internal sealed class StepRunner(EmergencyOptions options)
    {
        private readonly List<EmergencyStepReport> _steps = [];

        public IReadOnlyList<EmergencyStepReport> Steps => _steps;

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

                    // Зависший шаг не должен уронить процесс необработанным исключением, когда всё же завершится.
                    _ = task.ContinueWith(t =>
                    {
                        _ = t.Exception;
                        limit.Dispose();
                    }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                }
            }

            var report = new EmergencyStepReport(step, EmergencySteps.Title(step), result.Outcome, result.Detail, watch.ElapsedMilliseconds, required);
            _steps.Add(report);
            return report;
        }
    }
}
