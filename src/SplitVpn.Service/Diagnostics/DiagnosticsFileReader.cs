namespace SplitVpn.Service.Diagnostics;

internal sealed record CollectedFile(byte[] Data, DateTime LastWriteTime);

/// <summary>Таймаут не освобождает слот зависшего открытия: число таких операций ограничено между сборами.</summary>
internal sealed class DiagnosticsFileReader(int concurrency)
{
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
        var task = Task.Run(() =>
        {
            try { return read(cancellation.Token); }
            finally
            {
                cancellation.Dispose();
                Interlocked.Decrement(ref _reading);
            }
        });
        try
        {
            if (task.Wait(timeout))
            {
                return task.Result;
            }

            // Открытие может не поддерживать отмену; чтение после открытия её проверяет.
            try { cancellation.Cancel(); }
            catch (ObjectDisposedException) { }
            _ = task.ContinueWith(t => _ = t.Exception, CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            problem = "истёк срок чтения пользовательского файла";
            return null;
        }
        catch (AggregateException ex) when (ex.InnerException is IOException or UnauthorizedAccessException or OperationCanceledException)
        {
            problem = ex.InnerException.Message;
            return null;
        }
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
