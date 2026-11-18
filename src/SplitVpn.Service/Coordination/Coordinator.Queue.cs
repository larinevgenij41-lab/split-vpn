using System.Diagnostics;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using SplitVpn.Core.Ipc;

namespace SplitVpn.Service.Coordination;

/// <summary>
/// Очередь актора: работы с типом и временем постановки, замеры ожидания и выполнения, защита цикла от
/// необработанных исключений и снимок для чтений, которые не ждут долгую работу.
/// </summary>
public sealed partial class Coordinator
{
    /// <summary>Сколько запрос на чтение ждёт очередь, прежде чем получить последний снимок.</summary>
    internal static readonly TimeSpan ReadQueueTimeout = TimeSpan.FromMilliseconds(250);

    private static readonly TimeSpan SlowWorkRun = TimeSpan.FromMilliseconds(500);
    private static readonly TimeSpan SlowWorkWait = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan StuckWork = TimeSpan.FromSeconds(5);

    private readonly Channel<QueuedWork> _queue = Channel.CreateUnbounded<QueuedWork>();
    private int _tickPending;

    /// <summary>Последние известные ответы на чтения; строится в очереди актора, читается из потоков IPC.</summary>
    private volatile ReadSnapshot? _readSnapshot;

    /// <summary>Первая сверка при запуске завершена.</summary>
    private bool _started;

    /// <summary>Очередь разбирает хвост за долгой работой: о первой ждавшей работе уже написано.</summary>
    private bool _backlogReported;
    private int _suppressedWaits;
    private TimeSpan _longestSuppressedWait;

    private sealed record QueuedWork(string Kind, Func<Task> Run, long EnqueuedTimestamp);

    private sealed record ReadSnapshot(StatusDto Status, IReadOnlyList<AdapterDto> Adapters);

    /// <summary>Основной цикл службы: команды из канала, периодический тик.</summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        _serverResolveLifetime = cancellationToken;
        try
        {
            await RunCoreAsync(cancellationToken);
        }
        finally
        {
            await StopServerResolutionsAsync();
        }
    }

    private async Task RunCoreAsync(CancellationToken cancellationToken)
    {
        // Первый снимок — до загрузки базы и сверки: интерфейс сразу получает ответ «Подготовка защиты».
        RefreshReadSnapshot();
        using var networkChanges = SubscribeNetworkChanges(cancellationToken);
        await RunStartupAsync(cancellationToken);
        using var timer = new PeriodicTimer(TickInterval, _deps.Time);
        var tick = Task.Run(async () =>
        {
            while (await timer.WaitForNextTickAsync(cancellationToken))
            {
                QueueTick(cancellationToken);
            }
        }, cancellationToken);

        try
        {
            await foreach (var work in _queue.Reader.ReadAllAsync(cancellationToken))
            {
                await RunWorkAsync(work, cancellationToken);
                RefreshReadSnapshot();
            }
        }
        finally
        {
            timer.Dispose();
            try
            {
                await tick;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // Остановка фонового таймера наблюдается вместе с остановкой актора.
            }
        }
    }

    /// <summary>
    /// Пауза после системного уведомления о смене сети: Windows сообщает о подъёме интерфейса, адресе и
    /// маршруте по умолчанию пачкой, а сверке нужен уже итог.
    /// </summary>
    internal static readonly TimeSpan NetworkChangeDebounce = TimeSpan.FromMilliseconds(300);

    private ITimer? _networkChangeTimer;
    private int _networkChangePending;

    /// <summary>
    /// Новый адаптер (Wi-Fi после сна, загрузки Windows, перезапуска драйвера) остаётся заблокированным, пока
    /// служба не выберет его основным. Тик раз в 2 с узнаёт об этом с опозданием, а Windows, не видя интернета
    /// на только что подключённом Wi-Fi, может сама перезапустить адаптер. Уведомление ставит тик сразу.
    /// </summary>
    private NetworkChangeSubscription? SubscribeNetworkChanges(CancellationToken cancellationToken)
    {
        IDisposable? subscription;
        try
        {
            subscription = _deps.SubscribeNetworkChanges(() => OnNetworkChanged(cancellationToken));
        }
        catch (Exception ex)
        {
            _deps.Logger.LogWarning(ex, "Уведомления о смене сети недоступны: изменения заметит периодическая проверка");
            return null;
        }

        return new NetworkChangeSubscription(subscription, this);
    }

    /// <summary>После уведомления о смене сети детектор конфликтов нужен раньше обычных 5 минут.</summary>
    private int _conflictCheckRequested;

    private void OnNetworkChanged(CancellationToken cancellationToken)
    {
        Volatile.Write(ref _conflictCheckRequested, 1);
        if (cancellationToken.IsCancellationRequested || Interlocked.Exchange(ref _networkChangePending, 1) != 0)
        {
            return;
        }

        var timer = _deps.Time.CreateTimer(_ =>
        {
            Volatile.Write(ref _networkChangePending, 0);
            if (!cancellationToken.IsCancellationRequested)
            {
                QueueTick(cancellationToken, rerunIfRunning: true);
            }
        }, null, NetworkChangeDebounce, Timeout.InfiniteTimeSpan);
        Interlocked.Exchange(ref _networkChangeTimer, timer)?.Dispose();
    }

    /// <summary>Снимает подписку раньше таймера: после остановки уведомление не ставит работу.</summary>
    private sealed class NetworkChangeSubscription(IDisposable? subscription, Coordinator owner) : IDisposable
    {
        public void Dispose()
        {
            subscription?.Dispose();
            Interlocked.Exchange(ref owner._networkChangeTimer, null)?.Dispose();
        }
    }

    private const int TickIdle = 0;
    private const int TickQueued = 1;
    private const int TickRunning = 2;

    /// <summary>Во время сверки пришло уведомление о смене сети: сразу после неё нужна ещё одна.</summary>
    private int _tickRerun;

    /// <summary>
    /// Сверка читает текущее состояние: тик, ещё ждущий в очереди, увидит и более поздние изменения, поэтому
    /// накопленные за долгой работой тики ничего не добавляют. Уже идущая сверка прочитала сеть до
    /// изменения: уведомление о смене сети (<paramref name="rerunIfRunning"/>) ставит повтор после неё,
    /// иначе новый адаптер ждал бы следующего периодического тика. Периодический тик повтор не ставит:
    /// после долгой сверки сверки не должны идти вплотную одна за другой.
    /// </summary>
    private void QueueTick(CancellationToken cancellationToken, bool rerunIfRunning = false)
    {
        var state = Interlocked.CompareExchange(ref _tickPending, TickQueued, TickIdle);
        if (state == TickRunning && rerunIfRunning)
        {
            Volatile.Write(ref _tickRerun, 1);
            // Сверка могла закончиться между проверкой и записью: тогда её finally запрос уже не увидел.
            if (Volatile.Read(ref _tickPending) == TickIdle && Interlocked.Exchange(ref _tickRerun, 0) != 0)
            {
                QueueTick(cancellationToken);
            }

            return;
        }

        if (state != TickIdle)
        {
            return;
        }

        if (!TryEnqueue("Tick", async () =>
        {
            Volatile.Write(ref _tickPending, TickRunning);
            try
            {
                await TickAsync(cancellationToken);
            }
            finally
            {
                Volatile.Write(ref _tickPending, TickIdle);
                if (Interlocked.Exchange(ref _tickRerun, 0) != 0 && !cancellationToken.IsCancellationRequested)
                {
                    QueueTick(cancellationToken);
                }
            }
        }))
        {
            Volatile.Write(ref _tickPending, TickIdle);
        }
    }

    /// <summary>
    /// Запуск под той же защитой, что и работы очереди: ошибка (повреждённые данные, недоступный детектор)
    /// не должна останавливать службу и оставлять статус навсегда в «Подготовке защиты» — обычные тики
    /// повторят сверку.
    /// </summary>
    private async Task RunStartupAsync(CancellationToken cancellationToken)
    {
        try
        {
            await StartupAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _deps.Logger.LogError(ex, "Запуск службы не завершён; служба продолжает работу");
            Journal("Ошибка", $"Запуск службы не завершён ({ex.GetType().Name}: {ex.Message}); защита применится следующей сверкой.");
            Facts.ForceProtection = true;
        }
        finally
        {
            ClearProgress();
            _started = true;
            RefreshReadSnapshot();
        }
    }

    /// <summary>
    /// Выполняет одну работу очереди. Исключение в работе (тик, событие помощника) не выходит из цикла:
    /// иначе служба остановилась бы вместе с защитой. Остановка службы (отмена токена) проходит насквозь.
    /// </summary>
    private async Task RunWorkAsync(QueuedWork work, CancellationToken cancellationToken)
    {
        var started = Stopwatch.GetTimestamp();
        var waited = Stopwatch.GetElapsedTime(work.EnqueuedTimestamp, started);
        try
        {
            await work.Run();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _deps.Logger.LogError(ex, "Очередь службы: необработанная ошибка в работе {Kind}; служба продолжает работу", work.Kind);
            // Работа могла прерваться посреди применения: следующая сверка проверит всё, а не только изменения.
            Facts.ForceProtection = true;
        }

        ReportTiming(work.Kind, waited, Stopwatch.GetElapsedTime(started));
    }

    /// <summary>
    /// Долгие работы — в журнал службы. Пока очередь разбирает хвост за долгой работой, каждая следующая тоже
    /// «ждала»: пишется первая из них и итог, когда очередь опустеет. Быстрые работы не пишутся.
    /// </summary>
    private void ReportTiming(string kind, TimeSpan waited, TimeSpan ran)
    {
        var queued = _queue.Reader.Count;
        TraceWork(kind, waited, ran, queued);
        var slowRun = ran > SlowWorkRun;
        if (!slowRun && waited <= SlowWorkWait)
        {
            EndBacklog();
            return;
        }

        if (!slowRun && _backlogReported)
        {
            _suppressedWaits++;
            _longestSuppressedWait = waited > _longestSuppressedWait ? waited : _longestSuppressedWait;
        }
        else
        {
            var level = ran > StuckWork || waited > StuckWork ? LogLevel.Error : LogLevel.Warning;
            _deps.Logger.Log(level, "Очередь службы: {Kind} выполнялась {Run} мс, ждала {Wait} мс, в очереди {Queued}",
                kind, (int)ran.TotalMilliseconds, (int)waited.TotalMilliseconds, queued);
            _backlogReported = true;
        }

        if (queued == 0)
        {
            EndBacklog();
        }
    }

    /// <summary>
    /// Подробный журнал: каждая команда интерфейса, прочие работы дольше 50 мс, тик дольше 200 мс. Рядовой тик
    /// раз в две секунды и события помощника подробный журнал не засоряют.
    /// </summary>
    private void TraceWork(string kind, TimeSpan waited, TimeSpan ran, int queued)
    {
        if (!_deps.Logger.IsEnabled(LogLevel.Debug))
        {
            return;
        }

        var threshold = kind is "Tick" or "Request:GetStatusRequest" or "Request:GetAdaptersRequest" ? TimeSpan.FromMilliseconds(200)
            : kind.StartsWith("Request:", StringComparison.Ordinal) ? TimeSpan.Zero
            : TimeSpan.FromMilliseconds(50);
        if (ran >= threshold || waited >= SlowWorkWait)
        {
            _deps.Logger.LogDebug("Очередь: {Kind} ждала {Wait} мс, выполнялась {Run} мс, осталось {Queued}",
                kind, (int)waited.TotalMilliseconds, (int)ran.TotalMilliseconds, queued);
        }
    }

    private void EndBacklog()
    {
        if (_suppressedWaits > 0)
        {
            _deps.Logger.Log(_longestSuppressedWait > StuckWork ? LogLevel.Error : LogLevel.Warning,
                "Очередь службы: ещё {Count} работ ждали дольше 1 с, дольше всех — {Wait} мс", _suppressedWaits, (int)_longestSuppressedWait.TotalMilliseconds);
        }

        _backlogReported = false;
        _suppressedWaits = 0;
        _longestSuppressedWait = TimeSpan.Zero;
    }

    /// <summary>Снимок для чтений вне очереди. Вызывается только из очереди актора (или до её запуска).</summary>
    private void RefreshReadSnapshot()
    {
        try
        {
            _readSnapshot = new ReadSnapshot(BuildStatus() with { Progress = ConnectionProgress() }, Adapters());
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _deps.Logger.LogWarning(ex, "Снимок состояния для интерфейса не построен");
        }
    }

    /// <summary>Выполнить запрос IPC в очереди актора и дождаться ответа.</summary>
    public Task<IpcResponse> SubmitAsync(IpcRequest request, CancellationToken cancellationToken) =>
        SubmitAsync(request, cancellationToken, cancellationToken);

    /// <summary>
    /// Выполнить запрос IPC в очереди актора и дождаться ответа. <paramref name="cancellationToken"/> — ожидание
    /// клиента; канал управления отменяет его, когда клиент отключился. Отменяются только чтения и установка
    /// обновления (без интерфейса некому запустить установщик): их результат нужен лишь тому, кто ждёт.
    /// Команды, меняющие состояние, выполняются под <paramref name="lifetime"/> — сроком жизни службы — и тогда,
    /// когда клиент перестал ждать: интерфейс ждёт ответа ограниченное время, и при занятой очереди (как раз когда
    /// сеть сломана) иначе терялись бы «Восстановить сеть», отключение и отмена входа.
    /// </summary>
    public async Task<IpcResponse> SubmitAsync(IpcRequest request, CancellationToken cancellationToken, CancellationToken lifetime)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var token = request is GetStatusRequest or GetAdaptersRequest or ExportReportRequest or GetEventsRequest or GetSettingsRequest
            or CheckAddressRequest or InstallUpdateRequest ? cancellationToken : lifetime;
        var compatible = request.ContractVersion == IpcNames.ContractVersion;
        if (!compatible)
        {
            return IpcResponse.Failure(IpcErrorCodes.BadRequest, "Версия приложения несовместима со службой. Обновите оба компонента.");
        }
        if (compatible && ServeWithoutQueue(request) is { } direct)
        {
            return direct;
        }

        if (compatible && request is CollectDiagnosticsRequest)
        {
            // Сбор читает журналы за неделю и журналы событий Windows — секунды: вне очереди актора.
            return await Task.Run(() => CollectDiagnostics(cancellationToken), cancellationToken);
        }

        // Чтения, для которых годится последний снимок: ждут очередь не дольше ReadQueueTimeout.
        var snapshot = compatible && request is GetStatusRequest or GetAdaptersRequest or ExportReportRequest ? _readSnapshot : null;
        var completion = new TaskCompletionSource<IpcResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        await EnqueueAsync("Request:" + request.GetType().Name, async () =>
        {
            if (completion.Task.IsCompleted || token.IsCancellationRequested)
            {
                // Ответ уже взят из снимка либо вызывающий отменил ожидание чтения до его выполнения.
                return;
            }

            try
            {
                if (request is TestProfileRequest test)
                {
                    // Пробный дозвон длится до минуты: очередь актора не ждёт его, ответ придёт по завершении.
                    _ = BeginProfileTest(test.ProfileId).ContinueWith(t => completion.TrySetResult(t.IsCompletedSuccessfully
                        ? t.Result
                        : IpcResponse.Failure(IpcErrorCodes.Failed, t.Exception?.GetBaseException().Message ?? "Проверка прервана.")), TaskScheduler.Default);
                    return;
                }

                if (request is GeoUpdateNowRequest update)
                {
                    // Загрузка списка длится до минуты на источник: сеть — вне очереди, иначе даже запрос состояния ждёт её.
                    _ = List(update).BeginUpdateNowAsync(this, lifetime).ContinueWith(t => completion.TrySetResult(t.IsCompletedSuccessfully
                        ? t.Result
                        : IpcResponse.Failure(IpcErrorCodes.Failed, t.Exception?.GetBaseException().Message ?? "Обновление списка прервано.")), TaskScheduler.Default);
                    return;
                }

                if (request is CheckAddressRequest check)
                {
                    // Разрешение имени может ждать закрепления в этой же очереди: оно идёт вне её.
                    _ = CheckAddressOutsideQueueAsync(check, cancellationToken).ContinueWith(t => completion.TrySetResult(t.IsCompletedSuccessfully
                        ? t.Result
                        : IpcResponse.Failure(IpcErrorCodes.Failed, t.Exception?.GetBaseException().Message ?? "Проверка адреса прервана.")), TaskScheduler.Default);
                    return;
                }

                if (request is CheckUpdateRequest or DownloadUpdateRequest or InstallUpdateRequest)
                {
                    // Проверка выпусков, загрузка установщика и пересчёт его контрольной суммы идут вне
                    // очереди: иначе даже запрос состояния ждал бы минуты загрузки. Загрузка не прерывается,
                    // если интерфейс закрыли: её ход виден в статусе.
                    _ = HandleRequestAsync(request, token).ContinueWith(t => completion.TrySetResult(t.IsCompletedSuccessfully
                        ? t.Result
                        : IpcResponse.Failure(IpcErrorCodes.Failed, t.Exception?.GetBaseException().Message ?? "Обновление прервано.")), TaskScheduler.Default);
                    return;
                }

                completion.TrySetResult(await HandleRequestAsync(request, token));
            }
            catch (Exception ex)
            {
                var canceledByClient = ex is OperationCanceledException && token == cancellationToken && cancellationToken.IsCancellationRequested;
                if (canceledByClient)
                {
                    _deps.Logger.LogInformation("Запрос {Request} отменён клиентом", request.GetType().Name);
                }
                else
                {
                    _deps.Logger.LogError(ex, "Ошибка обработки запроса {Request}", request.GetType().Name);
                }

                if (request is not (GetStatusRequest or GetAdaptersRequest or ExportReportRequest))
                {
                    // Команда могла прерваться посреди применения (разрыв, маршруты, WFP): состояние
                    // уже изменено, а сверка не выполнена — она назначается на ближайший тик.
                    MarkInterruptedApply(request.GetType().Name, ex, canceledByClient);
                }

                completion.TrySetResult(IpcResponse.Failure(IpcErrorCodes.Failed, ex.Message));
            }
        });

        if (snapshot is null)
        {
            // Снимка ещё нет (служба запускается) или запрос меняет состояние: ждём очередь.
            return await completion.Task.WaitAsync(cancellationToken);
        }

        try
        {
            return await completion.Task.WaitAsync(ReadQueueTimeout, cancellationToken);
        }
        catch (TimeoutException)
        {
            // Очередь занята (долгая работа, промежуток между работами): последний известный ответ.
            // Если очередь всё же успела ответить — отдаётся её ответ, иначе её ответ потом отбрасывается.
            var fallback = FromSnapshot(request, snapshot);
            if (!completion.TrySetResult(fallback))
            {
                return await completion.Task;
            }

            _deps.Logger.LogDebug("Очередь занята дольше {Timeout} мс: {Request} получил ответ из снимка", (int)ReadQueueTimeout.TotalMilliseconds, request.GetType().Name);
            return fallback;
        }
    }

    /// <summary>
    /// Чтения, которые не требуют очереди: журнал событий под своим замком, настройки — неизменяемая запись,
    /// которая заменяется целиком. Ничего, что меняет состояние.
    /// </summary>
    private IpcResponse? ServeWithoutQueue(IpcRequest request) => request switch
    {
        GetEventsRequest events => IpcResponse.Success(_deps.Journal.Since(events.SinceId)),
        GetSettingsRequest => IpcResponse.Success(_settings),
        SetVerboseLoggingRequest verbose => SetVerboseLogging(verbose.Minutes),
        ReadDiagnosticsChunkRequest chunk => ReadDiagnosticsChunk(chunk),
        _ => null,
    };

    private IpcResponse FromSnapshot(IpcRequest request, ReadSnapshot snapshot) => request switch
    {
        GetAdaptersRequest => IpcResponse.Success(snapshot.Adapters),
        ExportReportRequest report => IpcResponse.Success(ExportReport(report.MaskPersonalData, snapshot.Status, snapshot.Adapters)),
        // Срок подробного журнала меняется вне очереди: в ответе из снимка — текущий.
        _ => IpcResponse.Success(snapshot.Status with { VerboseUntilUtc = _deps.Verbose?.UntilUtc, Progress = CurrentProgress(snapshot.Status.Progress) }),
    };

    /// <summary>Для тестов: выполнить всё, что уже поставлено в очередь (результаты дозвона и т. п.).</summary>
    internal async Task DrainAsync()
    {
        while (_queue.Reader.TryRead(out var work))
        {
            await work.Run();
        }
    }

    /// <summary>Поставить работу в очередь актора; тип — для замеров в журнале службы.</summary>
    internal ValueTask EnqueueAsync(string kind, Func<Task> work) =>
        _queue.Writer.WriteAsync(new QueuedWork(kind, work, Stopwatch.GetTimestamp()));

    /// <summary>Возвращает результат фоновой работе, даже если её продолжение в очереди выбросило исключение.</summary>
    internal Task<T> EnqueueResultAsync<T>(string kind, Func<T> work, CancellationToken cancellationToken) =>
        EnqueueResultAsync<T>(kind, () => Task.FromResult(work()), cancellationToken);

    internal async Task<T> EnqueueResultAsync<T>(string kind, Func<Task<T>> work, CancellationToken cancellationToken)
    {
        var completion = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
        await EnqueueAsync(kind, async () =>
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                completion.TrySetResult(await work());
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                completion.TrySetCanceled(cancellationToken);
            }
            catch (Exception ex)
            {
                completion.TrySetException(ex);
            }
        });
        return await completion.Task.WaitAsync(cancellationToken);
    }

    /// <summary>Поставить работу без ожидания записи: очередь неограниченная и не отказывает, пока служба работает.</summary>
    internal bool TryEnqueue(string kind, Func<Task> work) =>
        _queue.Writer.TryWrite(new QueuedWork(kind, work, Stopwatch.GetTimestamp()));

    internal int QueuedCount => _queue.Reader.Count;
}
