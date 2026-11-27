using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using SplitVpn.Core.Diagnostics;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;
using SplitVpn.Core.Update;

namespace SplitVpn.Service.Coordination;

/// <summary>
/// Обновление самой программы через GitHub Releases: плановая проверка манифеста, проверка его подписи,
/// заблаговременная загрузка установщика и подготовка установки. Устройство то же, что у автообновляемых
/// списков адресов (<c>GeoManager</c>): срок со случайным сдвигом, отказ от фоновой работы в лимитной
/// сети, обращение к сети только тогда, когда его допускает защита.
///
/// Установку запускает интерфейс с правами администратора: служба отдаёт проверенный путь и готовую
/// командную строку. Так согласие видно в окне контроля учётных записей, а служба не получает
/// способность запускать скачанный код от имени SYSTEM.
/// </summary>
internal sealed class UpdateManager(ServiceDependencies deps)
{
    /// <summary>Установка считается брошенной, если за это время версия не сменилась и msiexec не ответил.</summary>
    private static readonly TimeSpan InstallDeadline = TimeSpan.FromMinutes(15);

    /// <summary>
    /// На сколько отметка подготовки установки может оказаться в будущем без перевода часов (погрешность синхронизации):
    /// отметка дальше в будущем значит, что часы перевели назад, и срок установки считается истёкшим.
    /// </summary>
    private static readonly TimeSpan ClockSkewTolerance = TimeSpan.FromMinutes(5);

    /// <summary>Загрузка, упёршаяся в общий срок попытки, но продвинувшаяся, продолжается скоро, а не через час.</summary>
    private static readonly TimeSpan RetryAfterDeadline = TimeSpan.FromMinutes(10);

    /// <summary>Сколько ждать, пока интерфейс сообщит о запуске msiexec (включая запрос прав администратора).</summary>
    private static readonly TimeSpan InstallConfirmDeadline = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Установщик, исчезнувший без кода выхода за это время после запуска, считается не начавшим работу
    /// (1618, 1619, запрет политикой): ему предлагается повтор, а не сообщение о неудаче.
    /// </summary>
    private static readonly TimeSpan QuickInstallerExit = TimeSpan.FromSeconds(10);

    private static readonly TimeSpan RetryAfterFailure = TimeSpan.FromHours(1);

    /// <summary>Пока занят другой установщик Windows, повторять стоит скоро: пользователь ждёт результата.</summary>
    private static readonly TimeSpan RetryWhenBusy = TimeSpan.FromMinutes(10);

    /// <summary>После трёх неудач подряд недокачанный файл выбрасывается и загрузка начинается с нуля.</summary>
    private const int MaxDownloadAttempts = 3;

    /// <summary>
    /// После стольких несовпадений SHA-256 подряд автозагрузка выпуска останавливается: источник раз за разом отдаёт
    /// не тот файл, и ежечасная загрузка десятков мегабайт ничего не даст. Возобновляет её новый выпуск в манифесте
    /// или загрузка по команде пользователя.
    /// </summary>
    internal const int MaxHashMismatches = 3;

    /// <summary>Автозагрузка этого выпуска остановлена после повторных несовпадений контрольной суммы.</summary>
    internal static bool AutoDownloadSuspended(UpdateState state) => state.HashMismatches >= MaxHashMismatches;

    private readonly UpdateStore _store = new(deps.Stores.Paths.Update) { OnCorrupt = deps.CorruptFiles.Add };

    private UpdateState? _state;
    private Task? _work;
    private readonly Lock _downloadGate = new();
    private CancellationTokenSource? _downloadCancellation;
    private Guid? _attemptId;
    private long _downloaded;
    private long _releaseGeneration;
    private long _installGeneration;

    /// <summary>
    /// Когда интерфейс сообщил о запуске msiexec в этом процессе службы. Не сохраняется: после перезапуска службы
    /// установщик заведомо успел поработать, и его исчезновение без кода считается неудачей.
    /// </summary>
    private DateTimeOffset? _installerReportedUtc;

    /// <summary>
    /// Монотонная отметка подготовки установки этим процессом службы: по ней считается срок установки, перевод часов
    /// Windows на него не влияет. После перезапуска службы её нет, и срок считается по отметке в состоянии.
    /// </summary>
    private long? _installPreparedTimestamp;

    /// <summary>
    /// Установщик, переживший срок установки: фаза «Установка» уже отпущена, но, пока он работает, новая установка
    /// не запускается — два msiexec одного пакета параллельно не нужны. Не сохраняется.
    /// </summary>
    private (int ProcessId, DateTimeOffset? StartedBy)? _lingeringInstaller;

    /// <summary>Кто начал идущую загрузку (см. <see cref="StopUnwantedDownload"/>). Под <see cref="_downloadGate"/>.</summary>
    private DownloadOrigin _downloadOrigin;

    /// <summary>Загрузку по команде пользователя настройки не останавливают; автоматическую — да.</summary>
    private enum DownloadOrigin
    {
        /// <summary>Кнопка «Скачать» или установка, для которой файл пропал.</summary>
        User,

        /// <summary>Автозагрузка после проверки по команде: её останавливает выключение автозагрузки.</summary>
        ManualCheck,

        /// <summary>Автозагрузка после плановой проверки: её останавливает и выключение автопроверки.</summary>
        Schedule,
    }

    /// <summary>
    /// Состояние обновления. Читается из файла один раз и заменяется при каждом изменении: снимок для
    /// интерфейса строится после каждой работы очереди и не должен читать диск. Только из очереди актора.
    /// </summary>
    public UpdateState State => _state ??= _store.LoadState();

    /// <summary>Идущая проверка или загрузка; для тестов, которые доводят её до конца.</summary>
    internal Task? Pending => _work;

    /// <summary>При запуске службы: чем кончилась установка, начатая прежним процессом, и уборка каталога.</summary>
    public void StartUp(Coordinator coordinator)
    {
        ReportPreviousAttempt(coordinator);
        if (State is { Phase: UpdatePhase.Installing, InstallerProcessId: { } installer })
        {
            // Служба перезапустилась при идущей установке (откат неудачного обновления запускает прежнюю службу):
            // итог msiexec снова отслеживается, а не ждёт общего срока в 15 минут.
            _ = WatchInstallerAsync(coordinator, installer);
        }

        RecoverInterruptedDownload();
        ForgetInstalledRelease();
        _store.Cleanup(State, deps.Time.GetUtcNow());
    }

    /// <summary>
    /// Предложенная версия уже работает: её поставили вручную, или установщик закончил после срока, когда служба
    /// уже записала «не установилось». Без этого шапка предлагала бы ту же версию, а «Установить» переустановил бы её
    /// с обрывом VPN, пока не придёт полный (не «не изменилось») ответ списка выпусков.
    /// </summary>
    private void ForgetInstalledRelease()
    {
        var state = State;
        if (state.Phase is UpdatePhase.Available or UpdatePhase.Ready or UpdatePhase.Failed
            && UpdateVersion.TryParse(state.AvailableVersion, out var offered) && offered <= deps.ProductVersion)
        {
            Save(Forget(state) with { LastResult = "Установлена последняя версия." });
        }
    }

    /// <summary>
    /// Загрузку, начатую прежним процессом, никто не продолжает: при запуске у службы нет идущей работы.
    /// Состояние «Загружается» вернуло бы кнопки интерфейса в заблокированный вид навсегда (плановая
    /// проверка при выключенной автопроверке не идёт), поэтому оно сбрасывается независимо от настроек.
    /// </summary>
    private void RecoverInterruptedDownload()
    {
        var state = State;
        if (state.Phase != UpdatePhase.Downloading)
        {
            return;
        }

        var ready = state.PackageFileName is { } fileName && state.PackageSize > 0 && FileLength(_store.PackagePath(fileName)) == state.PackageSize;
        var partial = state.PackageFileName is { } name ? FileLength(_store.PartialPath(name)) : 0;
        Save(state with
        {
            Phase = ready ? UpdatePhase.Ready : UpdatePhase.Available,
            DownloadedBytes = ready ? state.PackageSize : partial,
            LastResult = ready ? state.LastResult : "Загрузка обновления прервана перезапуском службы: её можно продолжить.",
        });
    }

    /// <summary>Плановая проверка: по сроку, только при обычной сети или поднятом туннеле.</summary>
    public Task TickAsync(Coordinator coordinator, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(coordinator);
        var settings = coordinator.Settings.AppUpdate;
        var state = State;
        var now = deps.Time.GetUtcNow();
        if (state.Phase == UpdatePhase.Installing)
        {
            ReportPreviousAttempt(coordinator);
            return Task.CompletedTask;
        }

        StopUnwantedDownload(coordinator, settings);
        state = State;
        var due = state.NextCheckUtc is null || now >= state.NextCheckUtc
            // Часы перевели назад: срок в далёком будущем иначе заморозил бы проверки навсегда.
            || state.LastCheckUtc > now + TimeSpan.FromHours(2);
        if (!settings.AutoCheck || !due || _work is { IsCompleted: false } || !coordinator.NetworkPathAllowed)
        {
            return Task.CompletedTask;
        }

        if (settings.DeferOnMetered && deps.IsMeteredNetwork())
        {
            // Фоновая загрузка в лимитной сети откладывается на час; ручная проверка остаётся доступной.
            Save(state with { NextCheckUtc = now.AddHours(1), LastResult = "Отложено: лимитная сеть." });
            return Task.CompletedTask;
        }

        var highest = HighestSeen(state);
        // ETag годится только пока истёк не срок годности манифеста, к которому он относится: после него нужен полный ответ.
        var primaryUrl = UpdateSources.ManifestUrls(settings.ManifestMirrors)[0].AbsoluteUri;
        // ETag годится и только для той версии программы, при которой манифест оценивался: после ручной установки
        // промежуточной версии или отката ответ "не изменилось" скрыл бы выпуск, который теперь подходит.
        var etag = state.LastETagExpiresUtc > now && state.LastETagUrl == primaryUrl && SameProductVersion(state) ? state.LastETag : null;
        _work = Task.Run(() => RunAsync(coordinator, settings, etag, highest, force: false, early: null, cancellationToken), cancellationToken);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Проверка по команде. Вызывается из очереди актора: состояние и настройки читаются здесь,
    /// обращение к сети уходит на пул потоков, применение результата возвращается в очередь.
    /// </summary>
    public Task<IpcResponse> BeginCheckAsync(Coordinator coordinator, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(coordinator);
        if (State.Phase == UpdatePhase.Installing)
        {
            return Task.FromResult(IpcResponse.Failure(IpcErrorCodes.Busy, "Идёт установка обновления."));
        }

        if (_work is { IsCompleted: false })
        {
            return Task.FromResult(IpcResponse.Failure(IpcErrorCodes.Busy, "Проверка обновлений уже идёт."));
        }

        if (!coordinator.NetworkPathAllowed)
        {
            return Task.FromResult(IpcResponse.Failure(IpcErrorCodes.Busy,
                "Проверка обновлений возможна при подключённом VPN или с обычным интернетом."));
        }

        // Проверка по команде не отправляет ETag: иначе ответ «не изменилось» не дал бы вернуть пропущенную версию.
        // Ответ интерфейсу уходит сразу после разбора манифеста: загрузка установщика длится минуты.
        var early = new TaskCompletionSource<IpcResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        _work = RunAsync(coordinator, coordinator.Settings.AppUpdate, etag: null, HighestSeen(State), force: true, early, cancellationToken);
        return early.Task;
    }

    /// <summary>Загрузка установщика по команде, когда автозагрузка выключена.</summary>
    public Task<IpcResponse> BeginDownloadAsync(Coordinator coordinator, string version, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(coordinator);
        var state = State;
        if (state.Phase is UpdatePhase.Installing or UpdatePhase.Downloading || _work is { IsCompleted: false })
        {
            return Task.FromResult(IpcResponse.Failure(IpcErrorCodes.Busy, "Обновление уже загружается."));
        }

        if (state.AvailableVersion is not { } available || !string.Equals(available, version, StringComparison.Ordinal))
        {
            return Task.FromResult(IpcResponse.Failure(IpcErrorCodes.NotFound, "Эта версия обновления не найдена: проверьте обновления заново."));
        }

        if (!coordinator.NetworkPathAllowed)
        {
            return Task.FromResult(IpcResponse.Failure(IpcErrorCodes.Busy,
                "Загрузка обновления возможна при подключённом VPN или с обычным интернетом."));
        }

        // Состояние меняется здесь, в очереди; сама загрузка идёт фоном и отчитывается через статус.
        Save(state with { Phase = UpdatePhase.Downloading });
        Interlocked.Exchange(ref _downloaded, state.DownloadedBytes);
        _work = DownloadAsync(coordinator, state, NewDownloadCancellation(DownloadOrigin.User, cancellationToken), DownloadOrigin.User);
        return Task.FromResult(IpcResponse.Success(coordinator.BuildStatus()));
    }

    /// <summary>
    /// Подготовка установки: контрольная сумма скачанного установщика пересчитывается заново — между
    /// загрузкой и запуском файл мог испортиться. Ответ содержит готовую команду для интерфейса.
    /// </summary>
    public Task<IpcResponse> BeginInstallAsync(Coordinator coordinator, string version, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(coordinator);
        var state = State;
        if (state.Phase == UpdatePhase.Installing)
        {
            return Task.FromResult(IpcResponse.Failure(IpcErrorCodes.Busy, "Установка обновления уже запущена."));
        }

        // Идущая проверка закончится записью найденного выпуска. Фазу «Установка» она не затрёт (см. Evaluate),
        // но, успей она раньше конца пересчёта контрольной суммы, подготовка откажет со сменой предложения.
        // Проверка занимает секунды: честнее сразу попросить повторить.
        if (_work is { IsCompleted: false })
        {
            return Task.FromResult(IpcResponse.Failure(IpcErrorCodes.Busy, "Идёт проверка обновлений: повторите установку через минуту."));
        }

        if (_lingeringInstaller is { } previous)
        {
            if (deps.InstallerRunning(previous.ProcessId, previous.StartedBy))
            {
                return Task.FromResult(IpcResponse.Failure(IpcErrorCodes.Busy,
                    "Прежний установщик обновления ещё работает: дождитесь его завершения или перезагрузите компьютер."));
            }

            _lingeringInstaller = null;
        }

        if (state.Phase is not (UpdatePhase.Ready or UpdatePhase.Failed)
            || state.PackageFileName is not { } fileName || state.PackageSha256 is not { } expected)
        {
            return Task.FromResult(IpcResponse.Failure(IpcErrorCodes.NotFound, "Установщик обновления ещё не готов."));
        }

        if (!string.Equals(state.AvailableVersion, version, StringComparison.Ordinal))
        {
            return Task.FromResult(IpcResponse.Failure(IpcErrorCodes.NotFound, "Запрошена другая версия обновления."));
        }

        var path = _store.PackagePath(fileName);
        var generation = _releaseGeneration;
        if (!File.Exists(path))
        {
            Save(state with { Phase = UpdatePhase.Available, DownloadedBytes = 0, LastResult = "Установщик пропал, требуется загрузка." });
            if (coordinator.NetworkPathAllowed) _ = BeginDownloadAsync(coordinator, version, coordinator.ServiceLifetime);
            return Task.FromResult(IpcResponse.Failure(IpcErrorCodes.NotFound, "Установщик обновления не найден, требуется загрузка."));
        }

        // Пересчёт SHA-256 на 60 МБ занимает доли секунды, но очередь актора им занимать не стоит.
        return Task.Run(async () =>
        {
            string actual;
            try { actual = await ComputeSha256Async(path, cancellationToken); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return IpcResponse.Failure(IpcErrorCodes.Failed, "Не удалось прочитать установщик: " + ex.Message);
            }
            return await coordinator.EnqueueResultAsync("Update:Install",
                () => FinishInstallPreparation(coordinator, version, path, expected, actual, generation), cancellationToken);
        }, cancellationToken);
    }

    /// <summary>Интерфейс сообщил номер процесса установщика; ноль — запуск не состоялся.</summary>
    public IpcResponse InstallStarted(Coordinator coordinator, int processId, Guid? attemptId = null)
    {
        ArgumentNullException.ThrowIfNull(coordinator);
        var state = State;
        if (state.Phase != UpdatePhase.Installing || attemptId is not null && attemptId != _attemptId || state.InstallerProcessId.HasValue)
        {
            return IpcResponse.Success(coordinator.BuildStatus());
        }

        if (processId <= 0)
        {
            Save(state with { Phase = UpdatePhase.Ready, InstallStartedUtc = null, InstallerProcessId = null, LastInstallResult = "Установка не запущена." });
            // Повторный отчёт (интерфейс повторяет недоставленный) сюда не доходит: фаза уже не Installing.
            coordinator.Journal("Сведения", "Установка обновления не запущена: в запросе прав администратора отказано или установщик не запустился.");
            return IpcResponse.Success(coordinator.BuildStatus());
        }

        // Если MSI успеет остановить службу, итог определится по версии при следующем запуске.
        _installerReportedUtc = deps.Time.GetUtcNow();
        Save(state with { InstallerProcessId = processId });
        _ = WatchInstallerAsync(coordinator, processId);
        return IpcResponse.Success(coordinator.BuildStatus());
    }

    public IpcResponse SkipVersion(Coordinator coordinator, string version)
    {
        ArgumentNullException.ThrowIfNull(coordinator);
        var state = State;
        if (version.Length == 0)
        {
            Save(state with { SkippedVersion = null, LastETag = null, LastETagExpiresUtc = null, NextCheckUtc = deps.Time.GetUtcNow() });
            return IpcResponse.Success(coordinator.BuildStatus());
        }

        if (!string.Equals(state.AvailableVersion, version, StringComparison.Ordinal))
        {
            return IpcResponse.Failure(IpcErrorCodes.NotFound, "Эта версия обновления не предлагается.");
        }

        if (state.Phase == UpdatePhase.Installing)
        {
            return IpcResponse.Failure(IpcErrorCodes.Busy, "Дождитесь завершения установки обновления.");
        }

        var next = state with
        {
            SkippedVersion = version,
            Phase = UpdatePhase.Idle,
            AvailableVersion = null,
            Notes = null,
            NotesUrl = null,
            PackageFileName = null,
            PackageSha256 = null,
            PackageSize = 0,
            DownloadedBytes = 0,
            PackageUrls = [],
            LastResult = $"Версия {version} пропущена по решению пользователя.",
        };
        Save(next);
        lock (_downloadGate) _downloadCancellation?.Cancel();
        _releaseGeneration++;
        _store.Cleanup(next, deps.Time.GetUtcNow());
        coordinator.Journal("Сведения", $"Обновление до версии {version} пропущено по решению пользователя.");
        return IpcResponse.Success(coordinator.BuildStatus());
    }

    public UpdateStatusDto BuildStatus()
    {
        var state = State;
        return new UpdateStatusDto
        {
            CurrentVersion = UpdateVersion.Text(deps.ProductVersion),
            Phase = state.Phase,
            AvailableVersion = state.AvailableVersion,
            ReleasedUtc = state.ReleasedUtc,
            Notes = state.Notes,
            NotesUrl = state.NotesUrl,
            PackageSize = state.PackageSize,
            DownloadedBytes = state.Phase == UpdatePhase.Downloading ? Interlocked.Read(ref _downloaded) : state.DownloadedBytes,
            LastCheckUtc = state.LastCheckUtc,
            NextCheckUtc = state.NextCheckUtc,
            LastResult = state.LastResult,
            SkippedVersion = state.SkippedVersion,
            InstallLogPath = state.InstallLogPath,
            LastInstallResult = state.LastInstallResult,
        };
    }

    private static TimeSpan Interval(AppUpdateSettings settings) => TimeSpan.FromDays(Math.Max(1, settings.IntervalDays));

    /// <summary>
    /// Состояние в памяти меняется всегда, файл - если запишется. Иначе сбой записи (антивирус, полный диск)
    /// после загрузки оставлял бы состояние «Загрузка» навсегда: фоновая задача уже кончилась, а кнопки
    /// проверки, загрузки и установки в этом состоянии недоступны. Файл догонит память при следующей записи.
    /// </summary>
    private void Save(UpdateState state)
    {
        _state = state;
        try
        {
            _store.SaveState(state);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            deps.Logger.LogWarning(ex, "Состояние обновления не сохранено в файл: {Phase}", state.Phase);
        }
    }

    /// <summary>Проверка манифеста и, если нужно, загрузка: сеть — вне очереди актора, решения — в ней.</summary>
    private async Task<IpcResponse> RunAsync(
        Coordinator coordinator, AppUpdateSettings settings, string? etag, Version? highest, bool force,
        TaskCompletionSource<IpcResponse>? early, CancellationToken cancellationToken)
    {
        try
        {
            return await CheckAndDownloadAsync(coordinator, settings, etag, highest, force, early, cancellationToken);
        }
        catch (Exception ex)
        {
            deps.Logger.LogWarning(ex, "Обработка обновления программы прервана");
            var failure = IpcResponse.Failure(IpcErrorCodes.Failed, "Проверка обновлений прервана: " + ex.Message);
            early?.TrySetResult(failure);
            return failure;
        }
        finally
        {
            // Ответ интерфейсу обязан прийти даже при неожиданной ошибке: иначе запрос повиснет до таймаута.
            early?.TrySetResult(IpcResponse.Failure(IpcErrorCodes.Failed, "Проверка обновлений прервана."));
        }
    }

    private async Task<IpcResponse> CheckAndDownloadAsync(
        Coordinator coordinator, AppUpdateSettings settings, string? etag, Version? highest, bool force,
        TaskCompletionSource<IpcResponse>? early, CancellationToken cancellationToken)
    {
        ManifestFetch fetch;
        ManifestCheck? checkedManifest = null;
        try
        {
            // Ответ каждого источника проверяется сразу: отвергнутый не мешает спросить следующий.
            fetch = await new ManifestDownloader(deps.Http).FetchAsync(
                UpdateSources.ManifestUrls(settings.ManifestMirrors), etag, f => (checkedManifest = CheckManifest(f, highest)).Problem, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            deps.Logger.LogWarning(ex, "Проверка обновлений программы не удалась");
            fetch = new ManifestFetch { Failure = Core.Net.FetchFailure.Network, Message = ex.Message };
        }

        deps.Logger.LogDebug("Обновление: манифест {Url} — {Result}{Message}, ETag {ETag}, {Bytes} байт",
            LogText.UrlForLog(fetch.Url?.ToString()), fetch.NotModified ? "не изменился" : fetch.Failure.ToString(), fetch.Message is null ? "" : " «" + fetch.Message + "»",
            fetch.ETag, fetch.Manifest?.Length ?? 0);
        var verifiedHash = fetch.Manifest is not null && checkedManifest?.Release is { } candidate
            ? await ExistingPackageHashAsync(candidate, cancellationToken) : null;
        var (response, download) = await coordinator.EnqueueResultAsync("Update:Check",
            () => Evaluate(coordinator, settings, fetch, force, verifiedHash), cancellationToken);
        early?.TrySetResult(response);
        if (download is null)
        {
            return response;
        }

        var origin = force ? DownloadOrigin.ManualCheck : DownloadOrigin.Schedule;
        var cancellation = await coordinator.EnqueueResultAsync<CancellationTokenSource?>("Update:Downloading", () =>
        {
            var current = coordinator.Settings.AppUpdate;
            if (State.Phase != UpdatePhase.Available || !SamePackage(State, download)
                || !current.AutoDownload || AutoDownloadSuspended(State) || !coordinator.NetworkPathAllowed
                || (!force && current.DeferOnMetered && deps.IsMeteredNetwork()))
            {
                return null;
            }

            Save(State with { Phase = UpdatePhase.Downloading });
            return NewDownloadCancellation(origin, cancellationToken);
        }, cancellationToken);
        return cancellation is null ? response : await DownloadAsync(coordinator, download, cancellation, origin);
    }

    /// <summary>Решение по полученному манифесту. Только из очереди актора.</summary>
    private (IpcResponse Response, UpdateState? Download) Evaluate(Coordinator coordinator, AppUpdateSettings settings, ManifestFetch fetch, bool force, string? verifiedHash)
    {
        if (!settings.ManifestMirrors.SequenceEqual(coordinator.Settings.AppUpdate.ManifestMirrors) ||
            !settings.PackageMirrors.SequenceEqual(coordinator.Settings.AppUpdate.PackageMirrors))
            return (IpcResponse.Failure(IpcErrorCodes.Busy, "Источник обновлений изменился, требуется новая проверка."), null);
        settings = coordinator.Settings.AppUpdate;
        if (State.Phase == UpdatePhase.Installing)
        {
            // Установку подготовили, пока манифест шёл по сети. Найденный выпуск или «установлена последняя
            // версия» сбросили бы фазу, и итог msiexec потерялся бы: он применяется только к фазе «Установка».
            // Состояние не меняется; срок проверки остался прежним, и после установки она пройдёт заново.
            return (IpcResponse.Failure(IpcErrorCodes.Busy, "Идёт установка обновления."), null);
        }

        if (fetch.NotModified)
        {
            // 304 допустим, только пока действует срок годности проверенного манифеста, к которому относится ETag:
            // иначе повторяющийся 304 скрывал бы новые версии и обходил защиту от устаревшего манифеста.
            // ETag другой версии программы не отправлялся, поэтому такой 304 ничего не подтверждает.
            if (State.LastETag is null || State.LastETagExpiresUtc is not { } validUntil || validUntil <= deps.Time.GetUtcNow()
                || !SameProductVersion(State))
            {
                return (Complete(coordinator, State, "Проверка обновлений не удалась: ответ \"не изменилось\" без действующего проверенного списка выпусков.",
                    success: false, null, null, settings), null);
            }

            // Найденный раньше выпуск так и не скачался (сон, обрыв, перезапуск службы): «не изменилось» не значит
            // «уже скачано», и автозагрузка продолжается, иначе обновление стояло бы до выхода следующей версии.
            var resume = State.Phase == UpdatePhase.Available && settings.AutoDownload && State.PackageFileName is not null
                && !AutoDownloadSuspended(State)
                && UpdateVersion.TryParse(State.AvailableVersion, out var available) && available > deps.ProductVersion;
            var unchanged = Complete(coordinator, State, "Список выпусков не изменился.", success: true, fetch.RetryAfter, fetch.ETag, settings, validUntil, fetch.Url?.AbsoluteUri);
            return (unchanged, resume ? State : null);
        }

        if (!fetch.Ok)
        {
            return (Complete(coordinator, State, "Проверка обновлений не удалась: " + fetch.Message, success: false, fetch.RetryAfter, null, settings), null);
        }

        var state = State;
        var check = CheckManifest(fetch, HighestSeen(state));
        if (check.Older)
        {
            // Верно подписанный манифест с версией ниже уже известной: кэш зеркала или CDN ещё не обновился, либо
            // подмена ответа. Это не сбой, а «обновлений нет»: младшая версия не предлагается (защита от отката),
            // проверка идёт по обычному расписанию, а в журнал о каждом таком манифесте пишется один раз.
            return (CompleteOlder(coordinator, state, fetch.Manifest!, check.Problem!, settings), null);
        }

        if (check.Release is not { } release)
        {
            // Просроченный манифест — не сбой, а «обновлений нет»: проверка идёт по обычному расписанию.
            // Подпись не сошлась или разбор не прошёл — содержимому верить нельзя. ETag не запоминается
            // ни в одном из случаев: следующая проверка должна получить манифест заново.
            return (Complete(coordinator, state, check.Problem!, success: check.Expired, null, null, settings), null);
        }

        if (release.Version <= deps.ProductVersion)
        {
            return (Complete(coordinator, Forget(state), "Установлена последняя версия.", success: true, null, fetch.ETag, settings, release.Manifest.ExpiresUtc, fetch.Url?.AbsoluteUri), null);
        }

        if (release.MinUpgradable is { } minimum && deps.ProductVersion < minimum)
        {
            return (Complete(coordinator, state,
                $"Для обновления до версии {release.VersionText} нужна промежуточная версия {UpdateVersion.Text(minimum)}: установите её вручную.",
                success: false, null, fetch.ETag, settings, release.Manifest.ExpiresUtc, fetch.Url?.AbsoluteUri), null);
        }

        if (!force && string.Equals(state.SkippedVersion, release.VersionText, StringComparison.Ordinal))
        {
            return (Complete(coordinator, state, $"Версия {release.VersionText} пропущена по решению пользователя.",
                success: true, null, fetch.ETag, settings, release.Manifest.ExpiresUtc, fetch.Url?.AbsoluteUri), null);
        }

        var found = WithRelease(state, release, settings, verifiedHash);
        var message = found.Phase switch
        {
            UpdatePhase.Ready => $"Обновление до версии {release.VersionText} готово к установке.",
            UpdatePhase.Failed => $"Обновление до версии {release.VersionText} не установилось в прошлый раз: {found.LastInstallResult}",
            _ when AutoDownloadSuspended(found) => $"Доступно обновление до версии {release.VersionText}; автозагрузка остановлена: " +
                "контрольная сумма скачанного установщика не совпала несколько раз подряд.",
            _ => $"Доступно обновление до версии {release.VersionText}.",
        };
        var completed = Complete(coordinator, found, message, success: true, null, fetch.ETag, settings, release.Manifest.ExpiresUtc, fetch.Url?.AbsoluteUri);
        _releaseGeneration++;
        var download = found.Phase == UpdatePhase.Available && settings.AutoDownload && !AutoDownloadSuspended(found) ? State : null;
        return (completed, download);
    }

    /// <summary>ETag в состоянии получен при той же версии программы, что работает сейчас.</summary>
    private bool SameProductVersion(UpdateState state) =>
        string.Equals(state.LastETagProductVersion, UpdateVersion.Text(deps.ProductVersion), StringComparison.Ordinal);

    private static Version? HighestSeen(UpdateState state) =>
        UpdateVersion.TryParse(state.HighestSeenVersion, out var highest) ? highest : null;

    /// <summary>
    /// Проверка полученного манифеста: подпись, разбор, откат версии, срок годности. Не читает и не меняет
    /// состояние, поэтому вызывается и вне очереди актора — при переборе источников.
    /// </summary>
    private ManifestCheck CheckManifest(ManifestFetch fetch, Version? highest)
    {
        var manifest = fetch.Manifest!;
        if (deps.ManifestVerifier.Verify(manifest, fetch.Signature!, UpdateManifestParser.ReadKeyId(manifest)) is { } signatureProblem)
        {
            return new ManifestCheck(null, signatureProblem, Expired: false);
        }

        var parsed = UpdateManifestParser.Parse(manifest);
        if (parsed.Release is not { } release)
        {
            return new ManifestCheck(null, parsed.Error!, Expired: false);
        }

        if (highest is not null && release.Version < highest)
        {
            // Подменённый ответ со старым, но верно подписанным манифестом откатил бы программу назад: версия не
            // предлагается. Отвергнутый ответ не мешает спросить зеркала (у них может быть свежий манифест).
            return new ManifestCheck(null,
                $"Список выпусков предлагает версию {release.VersionText} ниже уже известной {UpdateVersion.Text(highest)}: она не предлагается.",
                Expired: false, Older: true);
        }

        return UpdateManifestParser.ExpiryProblem(release, deps.Time.GetUtcNow(), deps.ProductVersion) is { } expired
            ? new ManifestCheck(null, expired, Expired: true)
            : new ManifestCheck(release, null, Expired: false);
    }

    private sealed record ManifestCheck(ReleaseInfo? Release, string? Problem, bool Expired, bool Older = false);

    /// <summary>
    /// Итог проверки, когда лучший ответ - манифест младше уже известной версии: успех по обычному расписанию,
    /// найденный раньше выпуск не трогается. В журнал событий пишется только первый раз для каждого такого манифеста.
    /// </summary>
    private IpcResponse CompleteOlder(Coordinator coordinator, UpdateState state, byte[] manifest, string problem, AppUpdateSettings settings)
    {
        var digest = Convert.ToHexStringLower(SHA256.HashData(manifest));
        var known = string.Equals(state.IgnoredOlderManifestSha256, digest, StringComparison.Ordinal);
        var now = deps.Time.GetUtcNow();
        Save(state with
        {
            LastCheckUtc = now,
            NextCheckUtc = now + Interval(settings) + TimeSpan.FromMinutes(deps.Random.Next(0, 60)),
            LastResult = "Новых версий нет. " + problem,
            IgnoredOlderManifestSha256 = digest,
        });
        if (known)
        {
            deps.Logger.LogDebug("Обновление: снова получен манифест младше известной версии: {Problem}", problem);
        }
        else
        {
            coordinator.Journal("Предупреждение", "Обновление программы: " + problem);
        }

        return IpcResponse.Success(coordinator.BuildStatus());
    }

    /// <summary>Найденный выпуск в состоянии; если установщик уже лежит целиком, загрузка не нужна.</summary>
    private async Task<string?> ExistingPackageHashAsync(ReleaseInfo release, CancellationToken cancellationToken)
    {
        var package = release.Manifest.Package;
        var path = _store.PackagePath(package.FileName);
        if (_store.RedirectionProblem() is not null || FileLength(path) != package.Size) return null;
        try { return await ComputeSha256Async(path, cancellationToken); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            deps.Logger.LogWarning(ex, "Не удалось проверить сохранённый установщик {File}", package.FileName);
            return null;
        }
    }

    private UpdateState WithRelease(UpdateState state, ReleaseInfo release, AppUpdateSettings settings, string? verifiedHash)
    {
        var package = release.Manifest.Package;
        var path = _store.PackagePath(package.FileName);
        var samePackage = state.AvailableVersion == release.VersionText && state.PackageFileName == package.FileName
            && state.PackageSize == package.Size && state.PackageSha256 == package.Sha256;
        var ready = string.Equals(verifiedHash, package.Sha256, StringComparison.OrdinalIgnoreCase) && FileLength(path) == package.Size;
        // Неудачная установка того же выпуска (та же версия и тот же файл) не скрывается следующим ответом манифеста:
        // иначе «Готово» пригласило бы ту же неудачную установку, а причина пропала бы из шапки. Новый выпуск - с нуля.
        var failedBefore = samePackage && state.Phase == UpdatePhase.Failed;
        return state with
        {
            Phase = ready ? (failedBefore ? UpdatePhase.Failed : UpdatePhase.Ready) : UpdatePhase.Available,
            AvailableVersion = release.VersionText,
            ReleasedUtc = release.Manifest.ReleasedUtc,
            Notes = release.Manifest.Notes,
            NotesUrl = release.Manifest.NotesUrl,
            PackageFileName = package.FileName,
            PackageSha256 = package.Sha256,
            PackageSize = package.Size,
            PackageUrls = UpdateSources.PackageUrls(release, settings.PackageMirrors).Select(u => u.ToString()).ToList(),
            DownloadedBytes = ready ? package.Size : Math.Max(0, FileLength(_store.PartialPath(package.FileName))),
            DownloadAttempts = !ready && samePackage ? state.DownloadAttempts : 0,
            HashMismatches = !ready && samePackage ? state.HashMismatches : 0,
            HighestSeenVersion = release.VersionText,
            InstallVersion = null,
            InstallStartedUtc = null, InstallerProcessId = null,
            LastInstallResult = failedBefore ? state.LastInstallResult : null,
        };
    }

    /// <summary>Сведения о выпуске больше не нужны: установлена последняя версия.</summary>
    private static UpdateState Forget(UpdateState state) => state with
    {
        Phase = UpdatePhase.Idle,
        AvailableVersion = null,
        ReleasedUtc = null,
        Notes = null,
        NotesUrl = null,
        PackageFileName = null,
        PackageSha256 = null,
        PackageSize = 0,
        DownloadedBytes = 0,
        DownloadAttempts = 0,
        HashMismatches = 0,
        PackageUrls = [],
        InstallVersion = null,
        InstallStartedUtc = null, InstallerProcessId = null,
    };

    /// <summary>Загрузка установщика вне очереди актора; результат применяется через очередь.</summary>
    private CancellationTokenSource NewDownloadCancellation(DownloadOrigin origin, CancellationToken lifetime)
    {
        lock (_downloadGate)
        {
            _downloadOrigin = origin;
            return _downloadCancellation = CancellationTokenSource.CreateLinkedTokenSource(lifetime);
        }
    }

    /// <summary>
    /// Автозагрузку выключили в настройках (а для загрузки после плановой проверки — и автопроверку): идущая
    /// автоматическая загрузка останавливается, недокачанный файл остаётся для докачки. Загрузку, начатую
    /// пользователем, настройки не останавливают. Только из очереди актора.
    /// </summary>
    private void StopUnwantedDownload(Coordinator coordinator, AppUpdateSettings settings)
    {
        lock (_downloadGate)
        {
            if (_downloadCancellation is not { IsCancellationRequested: false } running || _downloadOrigin == DownloadOrigin.User
                || (settings.AutoDownload && (settings.AutoCheck || _downloadOrigin != DownloadOrigin.Schedule)))
            {
                return;
            }

            running.Cancel();
        }

        // Фазу «Загрузка» возвращает сама очередь: отменённая загрузка результата не применяет.
        if (State.Phase == UpdatePhase.Downloading)
        {
            const string Message = "Загрузка обновления остановлена: автоматическое обновление выключено в настройках. Её можно продолжить вручную.";
            Save(State with { Phase = UpdatePhase.Available, DownloadedBytes = Interlocked.Read(ref _downloaded), LastResult = Message });
            coordinator.Journal("Сведения", Message);
        }
    }

    private async Task<IpcResponse> DownloadAsync(Coordinator coordinator, UpdateState state, CancellationTokenSource cancel, DownloadOrigin origin)
    {
        try
        {
            return await DownloadCoreAsync(coordinator, state, origin, cancel.Token);
        }
        catch (OperationCanceledException) when (cancel.IsCancellationRequested)
        {
            // Загрузку остановили намеренно («Пропустить версию», отключение обновлений, остановка службы): это не сбой.
            deps.Logger.LogInformation("Загрузка обновления отменена");
            // Файлы, которых уже нет в состоянии (версию пропустили, пока качали), убираются сразу, а не при следующем
            // запуске службы: недокачанный файл был открыт загрузкой, и уборка при пропуске его не удалила.
            coordinator.TryEnqueue("Update:DownloadCancelled", () =>
            {
                if (State.Phase != UpdatePhase.Downloading)
                {
                    _store.Cleanup(State, deps.Time.GetUtcNow());
                }

                return Task.CompletedTask;
            });
            return IpcResponse.Failure(IpcErrorCodes.Failed, "Загрузка обновления отменена.");
        }
        catch (Exception ex)
        {
            deps.Logger.LogWarning(ex, "Обработка загруженного обновления прервана");
            return IpcResponse.Failure(IpcErrorCodes.Failed, "Загрузка обновления прервана: " + ex.Message);
        }
        finally
        {
            lock (_downloadGate)
            {
                if (ReferenceEquals(_downloadCancellation, cancel)) _downloadCancellation = null;
                cancel.Dispose();
            }
        }
    }

    private async Task<IpcResponse> DownloadCoreAsync(Coordinator coordinator, UpdateState state, DownloadOrigin origin, CancellationToken cancellationToken)
    {
        var fileName = state.PackageFileName!;
        var urls = state.PackageUrls.Select(u => new Uri(u)).ToList();
        Interlocked.Exchange(ref _downloaded, state.DownloadedBytes);

        PackageDownloadResult result;
        if (_store.RedirectionProblem() is { } redirected)
        {
            result = new PackageDownloadResult { Failure = Core.Net.FetchFailure.Network, Message = redirected };
        }
        else
        {
            deps.Logger.LogDebug("Обновление: загрузка {File} {Size} байт, SHA-256 {Sha}, источники {Urls}",
                fileName, state.PackageSize, state.PackageSha256, string.Join(", ", urls.Select(u => LogText.UrlForLog(u.ToString()))));
            result = await DownloadPackageAsync(state, fileName, urls, cancellationToken);

            // Попытка, начатая пользователем (кнопкой или проверкой по команде), упёрлась в срок, но продвинулась: докачка
            // продолжается сразу. Продолжение по расписанию идёт только при включённых автопроверке и автозагрузке, и без
            // него загрузка, которую пользователь просил, встала бы на месте.
            while (origin != DownloadOrigin.Schedule && result is { DeadlineReached: true, Progressed: true } && !cancellationToken.IsCancellationRequested)
            {
                deps.Logger.LogInformation("Обновление: попытка загрузки упёрлась в срок на {Bytes} байт, загрузка продолжается докачкой", result.Bytes);
                result = await DownloadPackageAsync(state, fileName, urls, cancellationToken);
            }

            deps.Logger.LogDebug("Обновление: загрузка завершена — {Result}{Message}", result.Failure, result.Message is null ? "" : " «" + result.Message + "»");
        }

        // Результат применяется и после отмены загрузки: файл мог уже лечь на место (File.Move), а пропуск версии
        // или выключение автозагрузки пришли позже — тогда ApplyDownload убирает его, а не оставляет до перезапуска.
        return await coordinator.EnqueueResultAsync("Update:Downloaded",
            () => ApplyDownload(coordinator, state, result), coordinator.ServiceLifetime);
    }

    private async Task<PackageDownloadResult> DownloadPackageAsync(UpdateState state, string fileName, List<Uri> urls, CancellationToken cancellationToken)
    {
        try
        {
            return await new PackageDownloader(deps.Http, attemptTimeout: deps.UpdateAttemptTimeout).DownloadAsync(
                urls,
                _store.PartialPath(fileName),
                _store.PackagePath(fileName),
                state.PackageSize,
                state.PackageSha256!,
                new DownloadProgress(this),
                cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            deps.Logger.LogWarning(ex, "Загрузка установщика обновления не удалась");
            return new PackageDownloadResult { Failure = Core.Net.FetchFailure.Network, Message = ex.Message };
        }
    }

    private static bool SamePackage(UpdateState current, UpdateState expected) =>
        current.AvailableVersion == expected.AvailableVersion && current.PackageFileName == expected.PackageFileName
        && current.PackageSha256 == expected.PackageSha256 && current.PackageSize == expected.PackageSize;

    private IpcResponse ApplyDownload(Coordinator coordinator, UpdateState downloaded, PackageDownloadResult result)
    {
        var state = State;
        // Автозагрузку выключили, когда файл уже скачался и прошёл проверку: он не выбрасывается и не качается заново.
        var finishedAfterStop = result.Success && state.Phase == UpdatePhase.Available;
        if ((state.Phase != UpdatePhase.Downloading && !finishedAfterStop) || !SamePackage(state, downloaded))
        {
            // Версию пропустили, пока файл загружался: поздний результат не возвращает её в интерфейс, а уже
            // перенесённый на место установщик пропущенной версии убирается сразу.
            deps.Logger.LogInformation("Загрузка обновления отменена: предложение изменилось, пока файл загружался");
            _store.Cleanup(state, deps.Time.GetUtcNow());
            return IpcResponse.Success(coordinator.BuildStatus());
        }

        if (result.Success)
        {
            var ready = state with
            {
                Phase = UpdatePhase.Ready,
                DownloadedBytes = state.PackageSize,
                DownloadAttempts = 0,
                HashMismatches = 0,
                LastResult = $"Обновление до версии {state.AvailableVersion} готово к установке.",
            };
            Save(ready);
            _store.Cleanup(ready, deps.Time.GetUtcNow());
            coordinator.Journal("Сведения", $"Установщик обновления {state.AvailableVersion} скачан и проверен.");
            return IpcResponse.Success(coordinator.BuildStatus());
        }

        // Попытка упёрлась в общий срок, но продвинулась (медленная связь): это не неудача — счётчик не растёт, иначе
        // после трёх таких попыток недокачанный файл выбрасывался бы и загрузка не кончалась никогда; докачка — скоро.
        // Срок действует, только пока источник поддерживает докачку, а продвижение считает сам загрузчик по длине файла в
        // начале и конце попытки (PackageDownloadResult.Progressed).
        var progressed = result is { DeadlineReached: true, Progressed: true };
        var attempts = result.PartialDiscarded ? 0 : progressed ? state.DownloadAttempts : state.DownloadAttempts + 1;
        var discarded = result.PartialDiscarded;
        if (attempts >= MaxDownloadAttempts && state.PackageFileName is { } fileName)
        {
            // Докачка не идёт: начинаем со следующей попытки с нуля.
            TryDelete(_store.PartialPath(fileName));
            attempts = 0;
            discarded = true;
        }

        // Несовпадение SHA-256 - не обрыв: тот же источник, скорее всего, снова отдаст тот же файл. Повтор
        // откладывается вдвое дольше каждый раз (1, 2, 4 ч), после MaxHashMismatches автозагрузка этого выпуска стоит.
        var mismatches = result.HashMismatch ? state.HashMismatches + 1 : state.HashMismatches;
        var retry = result.HashMismatch ? RetryAfterFailure * (1 << Math.Min(mismatches - 1, 6)) : progressed ? RetryAfterDeadline : RetryAfterFailure;
        if (result.RetryAfter is { } after && after > retry)
        {
            retry = after;
        }

        // Срок попытки с продвижением - не сбой: загрузка приостановлена и продолжится докачкой по расписанию.
        var message = (progressed ? "Загрузка обновления приостановлена: " : "Загрузка обновления не удалась: ") + result.Message;
        var suspended = result.HashMismatch && mismatches >= MaxHashMismatches;
        if (suspended)
        {
            message += string.Create(CultureInfo.InvariantCulture,
                $" Контрольная сумма не совпала {mismatches} раз подряд: автозагрузка версии {state.AvailableVersion} остановлена до выхода нового выпуска; скачать её заново можно вручную на странице обновлений.");
        }

        Save(state with
        {
            Phase = UpdatePhase.Available,
            DownloadedBytes = discarded ? 0 : result.Bytes,
            DownloadAttempts = attempts,
            HashMismatches = mismatches,
            LastResult = message,
            NextCheckUtc = deps.Time.GetUtcNow() + retry,
        });
        coordinator.Journal(progressed ? "Сведения" : "Ошибка", message);
        return IpcResponse.Failure(IpcErrorCodes.Failed, message);
    }

    private IpcResponse FinishInstallPreparation(Coordinator coordinator, string version, string path, string expected, string actual, long generation)
    {
        var state = State;
        if (state.Phase == UpdatePhase.Installing)
        {
            return IpcResponse.Failure(IpcErrorCodes.Busy, "Установка обновления уже запущена.");
        }

        if (generation != _releaseGeneration || state.Phase is not (UpdatePhase.Ready or UpdatePhase.Failed)
            || state.AvailableVersion != version || state.PackageSha256 != expected || state.PackageFileName is not { } fileName
            || _store.PackagePath(fileName) != path || !File.Exists(path))
        {
            return IpcResponse.Failure(IpcErrorCodes.NotFound, "Предложение обновления изменилось: выберите версию заново.");
        }

        if (_store.RedirectionProblem() is { } redirected)
        {
            // Проверенный файл по перенаправленному пути можно подменить до запуска msiexec.
            coordinator.Journal("Ошибка", redirected);
            return IpcResponse.Failure(IpcErrorCodes.Failed, redirected);
        }

        if (!string.Equals(actual, expected, StringComparison.Ordinal))
        {
            TryDelete(path);
            const string Message = "Контрольная сумма установщика не совпала: файл отброшен, обновление будет скачано заново.";
            Save(state with { Phase = UpdatePhase.Available, DownloadedBytes = 0, LastResult = Message });
            coordinator.Journal("Ошибка", Message);
            return IpcResponse.Failure(IpcErrorCodes.Failed, Message);
        }

        var now = deps.Time.GetUtcNow();
        var log = _store.InstallLogPath(version, now);
        _installGeneration++;
        _attemptId = Guid.NewGuid();
        _installPreparedTimestamp = deps.Time.GetTimestamp();
        _installerReportedUtc = null;
        Save(state with
        {
            Phase = UpdatePhase.Installing,
            InstallVersion = version,
            InstallStartedUtc = now,
            InstallerProcessId = null,
            InstallLogPath = log,
            LastInstallResult = null,
        });
        coordinator.Journal("Сведения", $"Начата установка обновления до версии {version}.");
        return IpcResponse.Success(new UpdateInstallDto(MsiExecPath, InstallArguments(path, log), version, log) { AttemptId = _attemptId });
    }

    /// <summary>Полный путь к установщику Windows: команда собирается только из постоянных частей и проверенного пути.</summary>
    private static string MsiExecPath => Path.Combine(Environment.SystemDirectory, "msiexec.exe");

    /// <summary>Формат команды общий с её проверкой в интерфейсе и командной строке (<see cref="UpdateInstallCommand"/>).</summary>
    private static string InstallArguments(string package, string log) => UpdateInstallCommand.BuildArguments(package, log);

    private async Task WatchInstallerAsync(Coordinator coordinator, int processId)
    {
        var generation = _installGeneration;
        var code = await deps.WaitForProcessAsync(processId, CancellationToken.None);
        // Время завершения берётся здесь, а не в действии актора: занятая очередь иначе удлинила бы работу установщика.
        var exitedUtc = deps.Time.GetUtcNow();
        await coordinator.EnqueueAsync("Update:Installed", () =>
        {
            if (_lingeringInstaller?.ProcessId == processId)
            {
                // Переживший срок установщик всё-таки завершился: новая установка больше не ждёт его.
                _lingeringInstaller = null;
            }

            if (generation != _installGeneration || State.InstallerProcessId != processId)
            {
                return Task.CompletedTask;
            }

            if (code is { } exitCode)
            {
                ApplyExitCode(coordinator, exitCode);
            }
            else
            {
                ForgetVanishedInstaller(coordinator, exitedUtc);
            }

            return Task.CompletedTask;
        });
    }

    /// <summary>
    /// Код выхода msiexec неизвестен: процесс исчез раньше, чем служба его открыла, номер занят другой программой
    /// или процесс не открылся для чтения кода. Решает, сколько установщик работал. Почти сразу кончаются отказы,
    /// после которых стоит просто повторить (1618 - Windows занята другим установщиком, 1619, запрет политикой):
    /// сбой не объявляется, фаза остаётся «Установка», а номер процесса забывается - плановый тик
    /// (<see cref="ReportPreviousAttempt"/>) решит по версии: новая работает - установлено, иначе через 5 минут
    /// после подготовки снова «Готово». Установщик, который успел поработать (или служба перезапущена во время
    /// установки - так её возвращает откат неудачного MSI), а версия не сменилась, - это неудачная установка:
    /// её итог «Не удалась» с указанием журнала установки, а не молчаливое повторное предложение.
    /// Сколько установщик работал, считается до <paramref name="exitedUtc"/> - когда его не стало, а не когда
    /// очередь службы дошла до этого действия.
    /// </summary>
    private void ForgetVanishedInstaller(Coordinator coordinator, DateTimeOffset exitedUtc)
    {
        var state = State;
        if (state.Phase != UpdatePhase.Installing)
        {
            return;
        }

        var version = state.InstallVersion ?? state.AvailableVersion ?? "";
        if (UpdateVersion.TryParse(version, out var target) && deps.ProductVersion >= target)
        {
            ReportPreviousAttempt(coordinator);
            return;
        }

        if (_installerReportedUtc is { } reported && exitedUtc - reported <= QuickInstallerExit)
        {
            deps.Logger.LogInformation("Обновление: установщик {Version} завершился сразу, код выхода получить не удалось; итог решит проверка версии",
                state.InstallVersion);
            Save(state with { InstallerProcessId = null });
            return;
        }

        var text = $"Установщик обновления до версии {version} завершился, но его результат определить не удалось: версия не изменилась."
            + " Если Windows просит перезагрузку, перезагрузите компьютер, иначе повторите установку."
            + (state.InstallLogPath is { } log ? $" Подробности - в {Path.GetFileName(log)}." : "");
        Save(state with { Phase = UpdatePhase.Failed, InstallStartedUtc = null, InstallerProcessId = null, LastInstallResult = text, LastResult = text });
        coordinator.Journal("Ошибка", text);
    }

    /// <summary>
    /// Итог msiexec. Успешные коды тоже бывают разными: 3010 и 1641 означают «установлено, нужна
    /// перезагрузка», а 1618 — что Windows занята другим установщиком и попытку стоит повторить.
    /// </summary>
    private void ApplyExitCode(Coordinator coordinator, int exitCode)
    {
        var state = State;
        if (state.Phase != UpdatePhase.Installing)
        {
            return;
        }

        var version = state.InstallVersion ?? state.AvailableVersion ?? "";
        switch (exitCode)
        {
            case 0:
            case 3010:
            case 1641:
                var done = Forget(state) with
                {
                    InstallStartedUtc = null, InstallerProcessId = null,
                    LastInstallResult = exitCode == 0 ? "Обновление установлено." : "Обновление установлено, требуется перезагрузка.",
                    LastResult = "Обновление установлено.",
                };
                Save(done);
                _store.Cleanup(done, deps.Time.GetUtcNow());
                coordinator.Journal("Сведения", $"Обновление до версии {version} установлено.");
                break;
            case 1602:
                Save(state with { Phase = UpdatePhase.Ready, InstallStartedUtc = null, InstallerProcessId = null, LastInstallResult = "Установка отменена." });
                coordinator.Journal("Сведения", "Установка обновления отменена пользователем.");
                break;
            case 1618:
                Save(state with
                {
                    Phase = UpdatePhase.Ready,
                    InstallStartedUtc = null, InstallerProcessId = null,
                    LastInstallResult = "Windows занята установкой другой программы: повторите через несколько минут.",
                    NextCheckUtc = deps.Time.GetUtcNow() + RetryWhenBusy,
                });
                coordinator.Journal("Предупреждение", "Установка обновления не начата: Windows занята другим установщиком.");
                break;
            default:
                var text = string.Create(CultureInfo.InvariantCulture,
                    $"Установка обновления до версии {version} не удалась (код {exitCode}). Подробности — в журнале установки.");
                Save(state with { Phase = UpdatePhase.Failed, InstallStartedUtc = null, InstallerProcessId = null, LastInstallResult = text });
                coordinator.Journal("Ошибка", text);
                break;
        }
    }

    /// <summary>
    /// Чем кончилась установка, о которой служба не успела узнать: её остановил сам MSI. Основной
    /// признак — версия этой сборки; журнал msiexec для решения не читается, он локализован.
    /// </summary>
    private void ReportPreviousAttempt(Coordinator coordinator)
    {
        var state = State;
        if (state.Phase != UpdatePhase.Installing)
        {
            return;
        }

        var version = state.InstallVersion ?? "";
        if (UpdateVersion.TryParse(version, out var target) && deps.ProductVersion >= target)
        {
            var done = Forget(state) with
            {
                InstallStartedUtc = null, InstallerProcessId = null,
                LastInstallResult = "Обновление установлено.",
                LastResult = "Обновление установлено.",
            };
            Save(done);
            _store.Cleanup(done, deps.Time.GetUtcNow());
            coordinator.Journal("Сведения", $"Обновление до версии {version} установлено.");
            return;
        }

        var elapsed = InstallElapsed(state);
        if (state.InstallerProcessId is null && elapsed >= InstallConfirmDeadline)
        {
            // Ответ с командой установки не дошёл до интерфейса (он закрылся или отключился) и msiexec никто
            // не запустил, или msiexec завершился сразу, не сообщив службе код (см. ForgetVanishedInstaller),
            // а версия не сменилась: не держим «Идёт установка» 15 минут, а снова предлагаем установить.
            Save(state with { Phase = UpdatePhase.Ready, InstallStartedUtc = null, InstallerProcessId = null, LastInstallResult = "Установка не запущена или прервана." });
            coordinator.Journal("Сведения", "Установка обновления не подтверждена: установщик не запущен или завершился, не сменив версию программы.");
            return;
        }

        if (elapsed < InstallDeadline)
        {
            // Установщик, скорее всего, ещё работает: решение отложено до следующего тика.
            return;
        }

        if (state.InstallerProcessId is { } installer)
        {
            // Срок вышел, а итога msiexec нет. Номер мог перейти к другой программе: процесс сверяется по имени и,
            // если служба сама получила номер, по времени запуска — не позже отчёта интерфейса.
            var startedBy = _installerReportedUtc + TimeSpan.FromMinutes(1);
            if (deps.InstallerRunning(installer, startedBy))
            {
                // Установщик жив, но работает дольше срока (завис или ждёт чего-то): фаза отпускается — проверка,
                // загрузка и пропуск версии снова доступны, — а новая установка ждёт, пока он не завершится.
                _lingeringInstaller = (installer, startedBy);
                var hung = string.Create(CultureInfo.InvariantCulture, $"Установщик обновления до версии {version} работает дольше {InstallDeadline.TotalMinutes:0} минут и не завершился.")
                    + " Повторная установка станет доступна после его завершения; если он завис, перезагрузите компьютер."
                    + (state.InstallLogPath is { } installLog ? $" Подробности — в {Path.GetFileName(installLog)}." : "");
                Save(state with { Phase = UpdatePhase.Failed, InstallStartedUtc = null, InstallerProcessId = null, LastInstallResult = hung, LastResult = hung });
                coordinator.Journal("Предупреждение", hung);
                return;
            }
        }

        var text = $"Обновление до версии {version} не установилось: работает прежняя версия."
            + (state.InstallLogPath is { } log ? $" Подробности — в {Path.GetFileName(log)}." : "");
        Save(state with { Phase = UpdatePhase.Failed, InstallStartedUtc = null, InstallerProcessId = null, LastInstallResult = text, LastResult = text });
        coordinator.Journal("Ошибка", text);
    }

    /// <summary>
    /// Сколько прошло с подготовки установки; null — отметки нет. Подготовленная этим процессом считается по монотонным
    /// часам: перевод часов Windows срок не сдвигает. Подготовленная прежним процессом — по отметке в состоянии, и
    /// отметка в будущем дальше погрешности (часы перевели назад) считается давно истёкшей: иначе фаза «Установка» и
    /// отказы проверки, загрузки, установки и пропуска версии держались бы, пока часы не догонят.
    /// </summary>
    private TimeSpan? InstallElapsed(UpdateState state)
    {
        if (_installPreparedTimestamp is { } prepared)
        {
            return deps.Time.GetElapsedTime(prepared);
        }

        if (state.InstallStartedUtc is not { } started)
        {
            return null;
        }

        var elapsed = deps.Time.GetUtcNow() - started;
        return elapsed < -ClockSkewTolerance ? TimeSpan.MaxValue : elapsed;
    }

    /// <summary>Записывает срок следующей проверки, итог и ETag; итог уходит в журнал событий.</summary>
    private IpcResponse Complete(
        Coordinator coordinator, UpdateState state, string message, bool success, TimeSpan? retryAfter, string? etag, AppUpdateSettings settings,
        DateTimeOffset? etagExpiresUtc = null, string? etagUrl = null)
    {
        var now = deps.Time.GetUtcNow();
        var retry = success ? Interval(settings) : RetryAfterFailure;
        if (retryAfter is { } after && after > retry)
        {
            retry = after;
        }

        var jitter = TimeSpan.FromMinutes(deps.Random.Next(0, 60));
        Save(state with
        {
            LastCheckUtc = now,
            NextCheckUtc = now + retry + jitter,
            LastResult = message,
            LastETag = etag ?? state.LastETag,
            LastETagUrl = etag is null ? state.LastETagUrl : etagUrl,
            LastETagExpiresUtc = etag is null ? state.LastETagExpiresUtc : etagExpiresUtc,
            LastETagProductVersion = etag is null ? state.LastETagProductVersion : UpdateVersion.Text(deps.ProductVersion),
        });
        coordinator.Journal(success ? "Сведения" : "Ошибка", "Обновление программы: " + message);
        return success
            ? IpcResponse.Success(coordinator.BuildStatus())
            : IpcResponse.Failure(IpcErrorCodes.Failed, message);
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var file = File.OpenRead(path);
        return Convert.ToHexStringLower(await SHA256.HashDataAsync(file, cancellationToken));
    }

    private static long FileLength(string path)
    {
        try
        {
            return File.Exists(path) ? new FileInfo(path).Length : -1;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return -1;
        }
    }

    private void TryDelete(string path)
    {
        if (_store.RedirectionProblem() is not null)
        {
            return;
        }

        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Файл занят: он будет перезаписан или убран при следующей уборке каталога.
        }
    }

    /// <summary>Ход загрузки читается из потока интерфейса, поэтому пишется атомарно и без выделений.</summary>
    private sealed class DownloadProgress(UpdateManager owner) : IProgress<long>
    {
        public void Report(long value) => Interlocked.Exchange(ref owner._downloaded, value);
    }
}
