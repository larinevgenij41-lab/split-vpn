using Microsoft.Win32.SafeHandles;
using SplitVpn.Windows.Native;

namespace SplitVpn.Service.Diagnostics;

internal sealed record CollectedFile(byte[] Data, DateTime LastWriteTime);

/// <summary>
/// Чтение файла пользователя с пределом времени. Обычный пользователь может держать oplock на своём файле, и открытие
/// правами SYSTEM ждёт его снятия без предела. Поэтому чтение идёт в отдельном потоке, а по истечении срока его
/// синхронный ввод-вывод отменяется (CancelSynchronousIo): поток завершается и освобождает место. Число незавершённых
/// чтений ограничено — поток, который не удалось прервать (ждёт не ввода-вывода), держит место до своего конца.
/// </summary>
internal sealed class DiagnosticsFileReader(int concurrency)
{
    /// <summary>Сколько после срока чтения пытаться прервать его ввод-вывод: отмена может прийти между операциями.</summary>
    internal static readonly TimeSpan CancelWindow = TimeSpan.FromSeconds(2);

    private static readonly TimeSpan CancelRetry = TimeSpan.FromMilliseconds(25);

    private int _reading;

    public CollectedFile? Read(Func<CancellationToken, CollectedFile?> read, TimeSpan timeout, out string? problem)
    {
        problem = null;
        if (Interlocked.Increment(ref _reading) > concurrency)
        {
            Interlocked.Decrement(ref _reading);
            problem = "предел незавершённых чтений пользовательских файлов";
            return null;
        }

        var cancellation = new CancellationTokenSource();
        var done = new TaskCompletionSource<CollectedFile?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var gate = new object();
        SafeWaitHandle? ioThread = null;
        var thread = new Thread(() =>
        {
            var self = SynchronousIo.OpenCurrentThread();
            lock (gate) { ioThread = self; }
            try { done.TrySetResult(read(cancellation.Token)); }
            catch (Exception ex) { done.TrySetException(ex); }
            finally
            {
                lock (gate)
                {
                    ioThread = null;
                    self?.Dispose();
                }

                cancellation.Dispose();
                Interlocked.Decrement(ref _reading);
            }
        })
        {
            IsBackground = true,
            Name = "Чтение файла пользователя",
        };

        try
        {
            thread.Start();
        }
        catch
        {
            cancellation.Dispose();
            Interlocked.Decrement(ref _reading);
            throw;
        }

        try
        {
            if (done.Task.Wait(timeout))
            {
                return done.Task.Result;
            }
        }
        catch (AggregateException ex) when (ex.InnerException is IOException or UnauthorizedAccessException or OperationCanceledException)
        {
            problem = ex.InnerException.Message;
            return null;
        }

        // Срок вышел: чтение после открытия проверяет отмену, а зависшее открытие (oplock) прерывается отменой его
        // синхронного ввода-вывода. Отмена повторяется: поток мог как раз оказаться между операциями.
        try { cancellation.Cancel(); }
        catch (ObjectDisposedException) { }
        var deadline = DateTime.UtcNow + CancelWindow;
        do
        {
            lock (gate)
            {
                if (ioThread is { } handle)
                {
                    SynchronousIo.Cancel(handle);
                }
            }
        }
        while (!thread.Join(CancelRetry) && DateTime.UtcNow < deadline);

        _ = done.Task.ContinueWith(t => _ = t.Exception, CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        problem = thread.IsAlive
            ? "истёк срок чтения пользовательского файла; чтение не прервано"
            : "истёк срок чтения пользовательского файла";
        return null;
    }

    internal static byte[]? ReadBounded(Stream input, long limit, CancellationToken cancellationToken)
    {
        using var output = new MemoryStream();
        var buffer = new byte[81920];
        while (output.Length <= limit)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var count = input.Read(buffer, 0, (int)Math.Min(buffer.Length, limit - output.Length + 1));
            if (count == 0) return output.ToArray();
            if (output.Length + count > limit) return null;
            output.Write(buffer, 0, count);
        }

        return null;
    }
}
