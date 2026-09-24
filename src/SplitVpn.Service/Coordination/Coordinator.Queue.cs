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
        // Первый снимок — до загрузки базы и сверки: интерфейс сразу получает ответ «Подготовка защиты».
        RefreshReadSnapshot();
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

    /// <summary>Сверка читает текущее состояние: накопленные за долгой работой тики ничего не добавляют.</summary>
    private void QueueTick(CancellationToken cancellationToken)
    {
        if (Interlocked.CompareExchange(ref _tickPending, 1, 0) != 0)
        {
            return;
        }

        if (!TryEnqueue("Tick", async () =>
        {
            try
            {
                await TickAsync(cancellationToken);
            }
            finally
            {
                Volatile.Write(ref _tickPending, 0);
            }
        }))
        {
            Volatile.Write(ref _tickPending, 0);
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
            _readSnapshot = new ReadSnapshot(BuildStatus(), Adapters());
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _deps.Logger.LogWarning(ex, "Снимок состояния для интерфейса не построен");
        }
    }

    /// <summary>Выполнить запрос IPC в очереди актора и дождаться ответа.</summary>
    public async Task<IpcResponse> SubmitAsync(IpcRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var compatible = request.ContractVersion == IpcNames.ContractVersion;
        if (compatible && ServeWithoutQueue(request) is { } direct)
        {
            return direct;
        }

        // Чтения, для которых годится последний снимок: ждут очередь не дольше ReadQueueTimeout.
        var snapshot = compatible && request is GetStatusRequest or GetAdaptersRequest or ExportReportRequest ? _readSnapshot : null;
        var completion = new TaskCompletionSource<IpcResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        await EnqueueAsync("Request:" + request.GetType().Name, async () =>
        {
            if (completion.Task.IsCompleted || cancellationToken.IsCancellationRequested)
            {
                // Ответ уже взят из снимка либо вызывающий отменил ожидание до выполнения команды.
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
                    _ = List(update).BeginUpdateNowAsync(this, cancellationToken).ContinueWith(t => completion.TrySetResult(t.IsCompletedSuccessfully
                        ? t.Result
                        : IpcResponse.Failure(IpcErrorCodes.Failed, t.Exception?.GetBaseException().Message ?? "Обновление списка прервано.")), TaskScheduler.Default);
                    return;
                }

                if (request is CheckUpdateRequest or DownloadUpdateRequest or InstallUpdateRequest)
                {
                    // Проверка выпусков, загрузка установщика и пересчёт его контрольной суммы идут вне
                    // очереди: иначе даже запрос состояния ждал бы минуты загрузки.
                    _ = HandleRequestAsync(request, cancellationToken).ContinueWith(t => completion.TrySetResult(t.IsCompletedSuccessfully
                        ? t.Result
                        : IpcResponse.Failure(IpcErrorCodes.Failed, t.Exception?.GetBaseException().Message ?? "Обновление прервано.")), TaskScheduler.Default);
                    return;
                }

                completion.TrySetResult(await HandleRequestAsync(request, cancellationToken));
            }
            catch (Exception ex)
            {
                _deps.Logger.LogError(ex, "Ошибка обработки запроса {Request}", request.GetType().Name);
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
            return completion.TrySetResult(fallback) ? fallback : await completion.Task;
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
        _ => null,
    };

    private IpcResponse FromSnapshot(IpcRequest request, ReadSnapshot snapshot) => request switch
    {
        GetAdaptersRequest => IpcResponse.Success(snapshot.Adapters),
        ExportReportRequest report => IpcResponse.Success(ExportReport(report.MaskPersonalData, snapshot.Status, snapshot.Adapters)),
        _ => IpcResponse.Success(snapshot.Status),
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
