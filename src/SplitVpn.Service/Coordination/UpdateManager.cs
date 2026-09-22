using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
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

    private static readonly TimeSpan RetryAfterFailure = TimeSpan.FromHours(1);

    /// <summary>Пока занят другой установщик Windows, повторять стоит скоро: пользователь ждёт результата.</summary>
    private static readonly TimeSpan RetryWhenBusy = TimeSpan.FromMinutes(10);

    /// <summary>После трёх неудач подряд недокачанный файл выбрасывается и загрузка начинается с нуля.</summary>
    private const int MaxDownloadAttempts = 3;

    private readonly UpdateStore _store = new(deps.Stores.Paths.Update) { OnCorrupt = deps.CorruptFiles.Add };

    private UpdateState? _state;
    private Task? _work;
    private long _downloaded;

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
        _store.Cleanup(State, deps.Time.GetUtcNow());
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

        var interval = Interval(settings);
        var due = state.NextCheckUtc is null || now >= state.NextCheckUtc
            // Часы перевели назад: срок в далёком будущем иначе заморозил бы проверки навсегда.
            || state.NextCheckUtc > now + interval + TimeSpan.FromHours(2);
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

        _work = Task.Run(() => RunAsync(coordinator, settings, State.LastETag, force: false, early: null, CancellationToken.None), CancellationToken.None);
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
        _work = RunAsync(coordinator, coordinator.Settings.AppUpdate, etag: null, force: true, early, cancellationToken);
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
        _work = DownloadAsync(coordinator, state, cancellationToken);
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
        if (!File.Exists(path))
        {
            Save(state with { Phase = UpdatePhase.Available, DownloadedBytes = 0, LastResult = "Установщик пропал: будет скачан заново." });
            return Task.FromResult(IpcResponse.Failure(IpcErrorCodes.NotFound, "Установщик обновления не найден: он будет скачан заново."));
        }

        // Пересчёт SHA-256 на 60 МБ занимает доли секунды, но очередь актора им занимать не стоит.
        return Task.Run(async () =>
        {
            var actual = await ComputeSha256Async(path, cancellationToken);
            var completion = new TaskCompletionSource<IpcResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
            await coordinator.EnqueueAsync("Update:Install", () =>
            {
                completion.SetResult(FinishInstallPreparation(coordinator, version, path, expected, actual));
                return Task.CompletedTask;
            });
            return await completion.Task;
        }, cancellationToken);
    }

    /// <summary>Интерфейс сообщил номер процесса установщика; ноль — запуск не состоялся.</summary>
    public IpcResponse InstallStarted(Coordinator coordinator, int processId)
    {
        ArgumentNullException.ThrowIfNull(coordinator);
        var state = State;
        if (state.Phase != UpdatePhase.Installing)
        {
            return IpcResponse.Success(coordinator.BuildStatus());
        }

        if (processId <= 0)
        {
            Save(state with { Phase = UpdatePhase.Ready, InstallStartedUtc = null, LastInstallResult = "Установка не запущена." });
            coordinator.Journal("Сведения", "Установка обновления не запущена: в запросе прав администратора отказано.");
            return IpcResponse.Success(coordinator.BuildStatus());
        }

        // Если MSI успеет остановить службу, итог определится по версии при следующем запуске.
        _ = WatchInstallerAsync(coordinator, processId);
        return IpcResponse.Success(coordinator.BuildStatus());
    }

    public IpcResponse SkipVersion(Coordinator coordinator, string version)
    {
        ArgumentNullException.ThrowIfNull(coordinator);
        var state = State;
        if (version.Length == 0)
        {
            Save(state with { SkippedVersion = null });
            return IpcResponse.Success(coordinator.BuildStatus());
        }

        if (!string.Equals(state.AvailableVersion, version, StringComparison.Ordinal))
        {
            return IpcResponse.Failure(IpcErrorCodes.NotFound, "Эта версия обновления не предлагается.");
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

    private void Save(UpdateState state)
    {
        _store.SaveState(state);
        _state = state;
    }

    /// <summary>Проверка манифеста и, если нужно, загрузка: сеть — вне очереди актора, решения — в ней.</summary>
    private async Task<IpcResponse> RunAsync(
        Coordinator coordinator, AppUpdateSettings settings, string? etag, bool force,
        TaskCompletionSource<IpcResponse>? early, CancellationToken cancellationToken)
    {
        try
        {
            return await CheckAndDownloadAsync(coordinator, settings, etag, force, early, cancellationToken);
        }
        finally
        {
            // Ответ интерфейсу обязан прийти даже при неожиданной ошибке: иначе запрос повиснет до таймаута.
            early?.TrySetResult(IpcResponse.Failure(IpcErrorCodes.Failed, "Проверка обновлений прервана."));
        }
    }

    private async Task<IpcResponse> CheckAndDownloadAsync(
        Coordinator coordinator, AppUpdateSettings settings, string? etag, bool force,
        TaskCompletionSource<IpcResponse>? early, CancellationToken cancellationToken)
    {
        ManifestFetch fetch;
        try
        {
            fetch = await new ManifestDownloader(deps.Http)
                .FetchAsync(UpdateSources.ManifestUrls(settings.ManifestMirrors), etag, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            deps.Logger.LogWarning(ex, "Проверка обновлений программы не удалась");
            fetch = new ManifestFetch { Failure = Core.Net.FetchFailure.Network, Message = ex.Message };
        }

        var decision = new TaskCompletionSource<(IpcResponse Response, UpdateState? Download)>(TaskCreationOptions.RunContinuationsAsynchronously);
        await coordinator.EnqueueAsync("Update:Check", () =>
        {
            decision.SetResult(Evaluate(coordinator, settings, fetch, force));
            return Task.CompletedTask;
        });

        var (response, download) = await decision.Task;
        early?.TrySetResult(response);
        if (download is null)
        {
            return response;
        }

        await coordinator.EnqueueAsync("Update:Downloading", () =>
        {
            Save(State with { Phase = UpdatePhase.Downloading });
            return Task.CompletedTask;
        });
        return await DownloadAsync(coordinator, download, cancellationToken);
    }

    /// <summary>Решение по полученному манифесту. Только из очереди актора.</summary>
    private (IpcResponse Response, UpdateState? Download) Evaluate(Coordinator coordinator, AppUpdateSettings settings, ManifestFetch fetch, bool force)
    {
        if (fetch.NotModified)
        {
            return (Complete(coordinator, State, "Список выпусков не изменился.", success: true, fetch.RetryAfter, fetch.ETag, settings), null);
        }

        if (!fetch.Ok)
        {
            return (Complete(coordinator, State, "Проверка обновлений не удалась: " + fetch.Message, success: false, fetch.RetryAfter, null, settings), null);
        }

        var manifest = fetch.Manifest!;
        if (deps.ManifestVerifier.Verify(manifest, fetch.Signature!, UpdateManifestParser.ReadKeyId(manifest)) is { } signatureProblem)
        {
            // Подпись не сошлась — содержимому верить нельзя, и ETag не запоминается.
            return (Complete(coordinator, State, signatureProblem, success: false, null, null, settings), null);
        }

        var parsed = UpdateManifestParser.Parse(manifest);
        if (parsed.Release is not { } release)
        {
            return (Complete(coordinator, State, parsed.Error!, success: false, null, null, settings), null);
        }

        var state = State;
        if (UpdateVersion.TryParse(state.HighestSeenVersion, out var highest) && release.Version < highest)
        {
            // Подменённый ответ со старым, но верно подписанным манифестом откатил бы программу назад.
            return (Complete(coordinator, state,
                $"Список выпусков предлагает версию {release.VersionText} ниже уже известной {UpdateVersion.Text(highest)}.",
                success: false, null, null, settings), null);
        }

        if (release.Version <= deps.ProductVersion)
        {
            return (Complete(coordinator, Forget(state), "Установлена последняя версия.", success: true, null, fetch.ETag, settings), null);
        }

        if (release.MinUpgradable is { } minimum && deps.ProductVersion < minimum)
        {
            return (Complete(coordinator, state,
                $"Для обновления до версии {release.VersionText} нужна промежуточная версия {UpdateVersion.Text(minimum)}: установите её вручную.",
                success: false, null, fetch.ETag, settings), null);
        }

        if (!force && string.Equals(state.SkippedVersion, release.VersionText, StringComparison.Ordinal))
        {
            return (Complete(coordinator, state, $"Версия {release.VersionText} пропущена по решению пользователя.",
                success: true, null, fetch.ETag, settings), null);
        }

        var found = WithRelease(state, release, settings);
        var message = found.Phase == UpdatePhase.Ready
            ? $"Обновление до версии {release.VersionText} готово к установке."
            : $"Доступно обновление до версии {release.VersionText}.";
        var completed = Complete(coordinator, found, message, success: true, null, fetch.ETag, settings);
        var download = found.Phase == UpdatePhase.Available && settings.AutoDownload ? State : null;
        return (completed, download);
    }

    /// <summary>Найденный выпуск в состоянии; если установщик уже лежит целиком, загрузка не нужна.</summary>
    private UpdateState WithRelease(UpdateState state, ReleaseInfo release, AppUpdateSettings settings)
    {
        var package = release.Manifest.Package;
        var path = _store.PackagePath(package.FileName);
        var ready = FileLength(path) == package.Size;
        return state with
        {
            Phase = ready ? UpdatePhase.Ready : UpdatePhase.Available,
            AvailableVersion = release.VersionText,
            ReleasedUtc = release.Manifest.ReleasedUtc,
            Notes = release.Manifest.Notes,
            NotesUrl = release.Manifest.NotesUrl,
            PackageFileName = package.FileName,
            PackageSha256 = package.Sha256,
            PackageSize = package.Size,
            PackageUrls = UpdateSources.PackageUrls(release, settings.PackageMirrors).Select(u => u.ToString()).ToList(),
            DownloadedBytes = ready ? package.Size : FileLength(_store.PartialPath(package.FileName)),
            DownloadAttempts = 0,
            HighestSeenVersion = release.VersionText,
            InstallVersion = null,
            InstallStartedUtc = null,
            LastInstallResult = null,
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
        PackageUrls = [],
        InstallVersion = null,
        InstallStartedUtc = null,
    };

    /// <summary>Загрузка установщика вне очереди актора; результат применяется через очередь.</summary>
    private async Task<IpcResponse> DownloadAsync(Coordinator coordinator, UpdateState state, CancellationToken cancellationToken)
    {
        var fileName = state.PackageFileName!;
        var urls = state.PackageUrls.Select(u => new Uri(u)).ToList();
        Interlocked.Exchange(ref _downloaded, state.DownloadedBytes);

        PackageDownloadResult result;
        try
        {
            result = await new PackageDownloader(deps.Http).DownloadAsync(
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
            result = new PackageDownloadResult { Failure = Core.Net.FetchFailure.Network, Message = ex.Message };
        }

        var completion = new TaskCompletionSource<IpcResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        await coordinator.EnqueueAsync("Update:Downloaded", () =>
        {
            completion.SetResult(ApplyDownload(coordinator, result));
            return Task.CompletedTask;
        });
        return await completion.Task;
    }

    private IpcResponse ApplyDownload(Coordinator coordinator, PackageDownloadResult result)
    {
        var state = State;
        if (result.Success)
        {
            var ready = state with
            {
                Phase = UpdatePhase.Ready,
                DownloadedBytes = state.PackageSize,
                DownloadAttempts = 0,
                LastResult = $"Обновление до версии {state.AvailableVersion} готово к установке.",
            };
            Save(ready);
            _store.Cleanup(ready, deps.Time.GetUtcNow());
            coordinator.Journal("Сведения", $"Установщик обновления {state.AvailableVersion} скачан и проверен.");
            return IpcResponse.Success(coordinator.BuildStatus());
        }

        var attempts = result.PartialDiscarded ? 0 : state.DownloadAttempts + 1;
        if (attempts >= MaxDownloadAttempts && state.PackageFileName is { } fileName)
        {
            // Докачка не идёт: начинаем со следующей попытки с нуля.
            TryDelete(_store.PartialPath(fileName));
            attempts = 0;
        }

        var message = "Загрузка обновления не удалась: " + result.Message;
        Save(state with
        {
            Phase = UpdatePhase.Available,
            DownloadedBytes = result.PartialDiscarded ? 0 : result.Bytes,
            DownloadAttempts = attempts,
            LastResult = message,
            NextCheckUtc = deps.Time.GetUtcNow() + (result.RetryAfter is { } after && after > RetryAfterFailure ? after : RetryAfterFailure),
        });
        coordinator.Journal("Ошибка", message);
        return IpcResponse.Failure(IpcErrorCodes.Failed, message);
    }

    private IpcResponse FinishInstallPreparation(Coordinator coordinator, string version, string path, string expected, string actual)
    {
        var state = State;
        if (state.Phase == UpdatePhase.Installing)
        {
            return IpcResponse.Failure(IpcErrorCodes.Busy, "Установка обновления уже запущена.");
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
        Save(state with
        {
            Phase = UpdatePhase.Installing,
            InstallVersion = version,
            InstallStartedUtc = now,
            InstallLogPath = log,
            LastInstallResult = null,
        });
        coordinator.Journal("Сведения", $"Начата установка обновления до версии {version}.");
        return IpcResponse.Success(new UpdateInstallDto(MsiExecPath, InstallArguments(path, log), version, log));
    }

    /// <summary>Полный путь к установщику Windows: команда собирается только из постоянных частей и проверенного пути.</summary>
    private static string MsiExecPath => Path.Combine(Environment.SystemDirectory, "msiexec.exe");

    private static string InstallArguments(string package, string log) =>
        $"/i \"{package}\" /passive /norestart REBOOT=ReallySuppress /L*v \"{log}\"";

    private async Task WatchInstallerAsync(Coordinator coordinator, int processId)
    {
        var code = await deps.WaitForProcessAsync(processId, CancellationToken.None);
        if (code is null)
        {
            return;
        }

        await coordinator.EnqueueAsync("Update:Installed", () =>
        {
            ApplyExitCode(coordinator, code.Value);
            return Task.CompletedTask;
        });
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
                    InstallStartedUtc = null,
                    LastInstallResult = exitCode == 0 ? "Обновление установлено." : "Обновление установлено, требуется перезагрузка.",
                    LastResult = "Обновление установлено.",
                };
                Save(done);
                _store.Cleanup(done, deps.Time.GetUtcNow());
                coordinator.Journal("Сведения", $"Обновление до версии {version} установлено.");
                break;
            case 1602:
                Save(state with { Phase = UpdatePhase.Ready, InstallStartedUtc = null, LastInstallResult = "Установка отменена." });
                coordinator.Journal("Сведения", "Установка обновления отменена пользователем.");
                break;
            case 1618:
                Save(state with
                {
                    Phase = UpdatePhase.Ready,
                    InstallStartedUtc = null,
                    LastInstallResult = "Windows занята установкой другой программы: повторите через несколько минут.",
                    NextCheckUtc = deps.Time.GetUtcNow() + RetryWhenBusy,
                });
                coordinator.Journal("Предупреждение", "Установка обновления не начата: Windows занята другим установщиком.");
                break;
            default:
                var text = string.Create(CultureInfo.InvariantCulture,
                    $"Установка обновления до версии {version} не удалась (код {exitCode}). Подробности — в журнале установки.");
                Save(state with { Phase = UpdatePhase.Failed, InstallStartedUtc = null, LastInstallResult = text });
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
                InstallStartedUtc = null,
                LastInstallResult = "Обновление установлено.",
                LastResult = "Обновление установлено.",
            };
            Save(done);
            _store.Cleanup(done, deps.Time.GetUtcNow());
            coordinator.Journal("Сведения", $"Обновление до версии {version} установлено.");
            return;
        }

        if (state.InstallStartedUtc is { } started && deps.Time.GetUtcNow() - started < InstallDeadline)
        {
            // Установщик, скорее всего, ещё работает: решение отложено до следующего тика.
            return;
        }

        var text = $"Обновление до версии {version} не установилось: работает прежняя версия."
            + (state.InstallLogPath is { } log ? $" Подробности — в {Path.GetFileName(log)}." : "");
        Save(state with { Phase = UpdatePhase.Failed, InstallStartedUtc = null, LastInstallResult = text, LastResult = text });
        coordinator.Journal("Ошибка", text);
    }

    /// <summary>Записывает срок следующей проверки, итог и ETag; итог уходит в журнал событий.</summary>
    private IpcResponse Complete(
        Coordinator coordinator, UpdateState state, string message, bool success, TimeSpan? retryAfter, string? etag, AppUpdateSettings settings)
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
        });
        coordinator.Journal(success ? "Сведения" : "Ошибка", "Обновление программы: " + message);
        return success
            ? IpcResponse.Success(coordinator.BuildStatus())
            : IpcResponse.Failure(IpcErrorCodes.Failed, message);
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        try
        {
            await using var file = File.OpenRead(path);
            return Convert.ToHexStringLower(await SHA256.HashDataAsync(file, cancellationToken));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return "";
        }
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

    private static void TryDelete(string path)
    {
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
