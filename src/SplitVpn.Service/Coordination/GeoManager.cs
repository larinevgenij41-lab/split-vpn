using System.Text;
using Microsoft.Extensions.Logging;
using SplitVpn.Core.Geo;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;

namespace SplitVpn.Service.Coordination;

/// <summary>
/// Автообновляемый список адресов: загрузка активной версии, плановая проверка обновлений, импорт,
/// откат и ручное подтверждение. Новая ревизия становится активной только после успешной сверки системы.
/// Списков два — RU-база и список обхода блокировок; у каждого своё хранилище и свои настройки обновления.
/// </summary>
internal sealed class GeoManager(ServiceDependencies deps, GeoListKind kind = GeoListKind.Geo)
{
    private readonly GeoStore _store = new(kind == GeoListKind.Bypass ? deps.Stores.Paths.Bypass : deps.Stores.Paths.Geo)
    {
        OnCorrupt = deps.CorruptFiles.Add,
    };

    private Task? _fetch;

    public GeoListKind Kind => kind;

    /// <summary>Как список называется в журнале и сообщениях интерфейса.</summary>
    public string Title => kind == GeoListKind.Bypass ? "Список обхода блокировок" : "RU-база";

    public RangeSet ActiveSet { get; private set; } = RangeSet.Empty;

    public GeoRevision? ActiveRevision { get; private set; }

    public bool HasBase => ActiveSet.Count > 0;

    /// <summary>
    /// Состояние хранилища базы. Читается из файла один раз и заменяется при каждом изменении через этот класс:
    /// снимок состояния для интерфейса строится после каждой работы очереди и не должен каждый раз читать диск.
    /// Только из очереди актора.
    /// </summary>
    public GeoStoreState StoreState => _state ??= _store.LoadState();

    private GeoStoreState? _state;

    public void LoadActive()
    {
        var state = _state = _store.LoadState();
        if (state.Active is null || !_store.HasRevision(state.Active))
        {
            return;
        }

        var validation = GeoUpdateEvaluator.LoadRevision(_store, state.Active, GeoValidationOptions.For(kind));
        ActiveSet = validation.IsValid ? validation.V4 : RangeSet.Empty;
        ActiveRevision = _store.ReadRevisionMeta(state.Active);
    }

    /// <summary>Плановая проверка: по сроку, только при обычной сети или поднятом туннеле.</summary>
    public Task TickAsync(Coordinator coordinator, CancellationToken cancellationToken)
    {
        var settings = UpdateSettings(coordinator);
        var state = StoreState;
        var due = state.NextCheckUtc is null || deps.Time.GetUtcNow() >= state.NextCheckUtc;
        if (!settings.AutoUpdate || !due || _fetch is { IsCompleted: false } || !coordinator.NetworkPathAllowed)
        {
            return Task.CompletedTask;
        }

        if (settings.DeferOnMetered && deps.IsMeteredNetwork())
        {
            // Фоновая загрузка в лимитной сети откладывается на час; ручная («Проверить сейчас») доступна.
            Save(state with { NextCheckUtc = deps.Time.GetUtcNow().AddHours(1), LastResult = "Отложено: лимитная сеть." });
            return Task.CompletedTask;
        }

        _fetch = Task.Run(() => FetchAsync(coordinator, CancellationToken.None), CancellationToken.None);
        return Task.CompletedTask;
    }

    public async Task<IpcResponse> UpdateNowAsync(Coordinator coordinator, CancellationToken cancellationToken)
    {
        if (!coordinator.NetworkPathAllowed)
        {
            return IpcResponse.Failure(IpcErrorCodes.Busy, "Обновление базы возможно при подключённом VPN или с обычным интернетом.");
        }

        var fetch = await FetchContentAsync(UpdateSettings(coordinator), cancellationToken);
        return await ProcessAsync(coordinator, fetch, isManual: false, cancellationToken);
    }

    /// <summary>
    /// Обновление по команде без блокировки очереди актора: проверка допустимости — в очереди (метод
    /// вызывается из неё), загрузка — на пуле потоков, применение — снова через очередь.
    /// </summary>
    public Task<IpcResponse> BeginUpdateNowAsync(Coordinator coordinator, CancellationToken cancellationToken)
    {
        if (!coordinator.NetworkPathAllowed)
        {
            return Task.FromResult(IpcResponse.Failure(IpcErrorCodes.Busy, "Обновление базы возможно при подключённом VPN или с обычным интернетом."));
        }

        var settings = UpdateSettings(coordinator);
        return Task.Run(async () =>
        {
            var fetch = await FetchContentAsync(settings, cancellationToken);
            var applied = new TaskCompletionSource<IpcResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
            await coordinator.EnqueueAsync(kind + ":UpdateNow", async () =>
            {
                try
                {
                    applied.SetResult(await ProcessAsync(coordinator, fetch, isManual: false, cancellationToken));
                }
                catch (Exception ex)
                {
                    applied.SetException(ex);
                }
            });
            return await applied.Task;
        }, cancellationToken);
    }

    public async Task<IpcResponse> ImportAsync(Coordinator coordinator, string content, CancellationToken cancellationToken)
    {
        var fetch = new GeoFetchResult { Status = GeoFetchStatus.Downloaded, Content = Encoding.UTF8.GetBytes(content) };
        return await ProcessAsync(coordinator, fetch, isManual: true, cancellationToken, sourceOverride: GeoSourceFactory.ForImport());
    }

    public async Task<IpcResponse> RollbackAsync(Coordinator coordinator, CancellationToken cancellationToken)
    {
        var state = _store.Rollback();
        _state = state ?? _state;
        if (state is null)
        {
            return IpcResponse.Failure(IpcErrorCodes.NotFound, $"{Title}: предыдущей версии нет.");
        }

        LoadActive();
        coordinator.Journal("Сведения", $"{Title}: возвращена предыдущая версия, заменённая ревизия пропускается.");
        await coordinator.ReconcileAsync(cancellationToken);
        return IpcResponse.Success(coordinator.BuildStatus());
    }

    public async Task<IpcResponse> AcceptPendingAsync(Coordinator coordinator, CancellationToken cancellationToken)
    {
        var state = StoreState;
        if (state.Pending is null)
        {
            return IpcResponse.Failure(IpcErrorCodes.NotFound, $"{Title}: нет версии, ожидающей подтверждения.");
        }

        return await ActivateAsync(coordinator, state.Pending, skipReplaced: false, cancellationToken);
    }

    public IpcResponse RejectPending()
    {
        _state = _store.RejectPending();
        return IpcResponse.Success();
    }

    public IpcResponse ClearSkipped()
    {
        _state = _store.ClearSkipped();
        return IpcResponse.Success();
    }

    /// <summary>Настройки обновления своего списка: у RU-базы и списка обхода блокировок они раздельные.</summary>
    private GeoUpdateSettings UpdateSettings(Coordinator coordinator) =>
        kind == GeoListKind.Bypass ? coordinator.Settings.BypassUpdate : coordinator.Settings.GeoUpdate;

    private void Save(GeoStoreState state)
    {
        _store.SaveState(state);
        _state = state;
    }

    private async Task FetchAsync(Coordinator coordinator, CancellationToken cancellationToken)
    {
        GeoFetchResult fetch;
        try
        {
            fetch = await FetchContentAsync(UpdateSettings(coordinator), cancellationToken);
        }
        catch (Exception ex)
        {
            fetch = new GeoFetchResult { Status = GeoFetchStatus.Failed, Failure = FetchFailure.Network, Message = ex.Message };
        }

        await coordinator.EnqueueAsync(kind + ":Scheduled", () => ProcessAsync(coordinator, fetch, isManual: false, cancellationToken));
    }

    private Task<GeoFetchResult> FetchContentAsync(GeoUpdateSettings settings, CancellationToken cancellationToken)
    {
        var source = GeoSourceFactory.Create(settings);
        // Без активной базы ETag не отправляем: ответ 304 оставил бы систему без базы.
        return new GeoDownloader(deps.Http).FetchAsync(source, HasBase ? _store.LoadState().LastETag : null, cancellationToken);
    }

    /// <summary>
    /// Любая ошибка обработки (разбор, запись ревизии, активация) завершает проверку как неуспешную:
    /// иначе срок следующей проверки остаётся в прошлом и база скачивается на каждом тике.
    /// </summary>
    private async Task<IpcResponse> ProcessAsync(Coordinator coordinator, GeoFetchResult fetch, bool isManual, CancellationToken cancellationToken, IGeoSource? sourceOverride = null)
    {
        try
        {
            return await ProcessCoreAsync(coordinator, fetch, isManual, cancellationToken, sourceOverride);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            deps.Logger.LogError(ex, "{List}: ошибка обработки обновления", Title);
            return Finish(coordinator, $"Ошибка обработки базы ({ex.GetType().Name}): {ex.Message}",
                new GeoFetchResult { Status = GeoFetchStatus.Failed, Message = ex.Message }, success: false);
        }
    }

    private async Task<IpcResponse> ProcessCoreAsync(Coordinator coordinator, GeoFetchResult fetch, bool isManual, CancellationToken cancellationToken, IGeoSource? sourceOverride = null)
    {
        if (fetch.Status != GeoFetchStatus.Downloaded || fetch.Content is null)
        {
            return Finish(coordinator, fetch.Status == GeoFetchStatus.NotModified ? "База не изменилась (HTTP 304)." : "Ошибка загрузки: " + fetch.Message, fetch, success: fetch.Status == GeoFetchStatus.NotModified);
        }

        var source = sourceOverride ?? GeoSourceFactory.Create(UpdateSettings(coordinator));
        var info = new GeoRevisionInfo(fetch.Url, deps.Time.GetUtcNow(), fetch.LastModified, fetch.ETag);
        var evaluation = GeoUpdateEvaluator.Evaluate(fetch.Content, source, StoreState, ActiveSet, info,
            validation: GeoValidationOptions.For(kind), thresholds: GeoAnomalyThresholds.For(kind), isManual: isManual);
        return evaluation.Outcome switch
        {
            GeoEvaluationOutcome.Accept => await StoreAndActivateAsync(coordinator, evaluation, isManual, cancellationToken),
            GeoEvaluationOutcome.NeedsReview => HoldForReview(coordinator, evaluation, fetch),
            _ => Finish(coordinator, evaluation.Message, fetch, success: evaluation.Outcome != GeoEvaluationOutcome.Rejected),
        };
    }

    private async Task<IpcResponse> StoreAndActivateAsync(Coordinator coordinator, GeoEvaluation evaluation, bool isManual, CancellationToken cancellationToken)
    {
        _store.SaveRevision(GeoUpdateEvaluator.ToStoredBytes(evaluation.CidrText!), evaluation.Revision!);
        return await ActivateAsync(coordinator, evaluation.Revision!.Id, skipReplaced: isManual, cancellationToken);
    }

    private IpcResponse HoldForReview(Coordinator coordinator, GeoEvaluation evaluation, GeoFetchResult fetch)
    {
        _store.SaveRevision(GeoUpdateEvaluator.ToStoredBytes(evaluation.CidrText!), evaluation.Revision!);
        var diff = evaluation.Diff!;
        _state = _store.SetPending(evaluation.Revision!.Id, $"покрытие изменилось на {diff.AddressChangeShare:P1}, число диапазонов на {diff.CountChangeShare:P1}");
        return Finish(coordinator, evaluation.Message, fetch, success: true);
    }

    private async Task<IpcResponse> ActivateAsync(Coordinator coordinator, string revisionId, bool skipReplaced, CancellationToken cancellationToken)
    {
        var previousSet = ActiveSet;
        var previousRevision = ActiveRevision;
        var validation = GeoUpdateEvaluator.LoadRevision(_store, revisionId, GeoValidationOptions.For(kind));
        ActiveSet = validation.V4;
        ActiveRevision = _store.ReadRevisionMeta(revisionId);
        await coordinator.ReconcileAsync(cancellationToken);
        if (coordinator.Facts.PartialError is not null)
        {
            ActiveSet = previousSet;
            ActiveRevision = previousRevision;
            await coordinator.ReconcileAsync(cancellationToken);
            return IpcResponse.Failure(IpcErrorCodes.Failed, "Новая база не применена, работает прежняя: " + coordinator.Facts.PartialError);
        }

        _state = _store.Activate(revisionId, skipReplaced);
        coordinator.Journal("Сведения", $"{Title} обновлён: IPv4 {ActiveRevision?.V4Count}, IPv6 {ActiveRevision?.V6Count}.");
        return Finish(coordinator, "База обновлена.", new GeoFetchResult { Status = GeoFetchStatus.Downloaded, ETag = ActiveRevision?.ETag }, success: true);
    }

    private IpcResponse Finish(Coordinator coordinator, string message, GeoFetchResult fetch, bool success)
    {
        var now = deps.Time.GetUtcNow();
        var interval = TimeSpan.FromDays(Math.Max(1, UpdateSettings(coordinator).IntervalDays));
        var retry = success ? interval : TimeSpan.FromHours(1);
        if (fetch.RetryAfter is { } after && after > retry)
        {
            retry = after;
        }

        var jitter = TimeSpan.FromMinutes(deps.Random.Next(0, 60));
        var state = StoreState;
        Save(state with
        {
            LastCheckUtc = now,
            NextCheckUtc = now + retry + jitter,
            LastResult = message,
            LastETag = fetch.ETag ?? state.LastETag,
        });
        coordinator.Journal(success ? "Сведения" : "Ошибка", Title + ": " + message);
        return success ? IpcResponse.Success(coordinator.BuildStatus()) : IpcResponse.Failure(IpcErrorCodes.Failed, message);
    }
}
