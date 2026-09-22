using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using SplitVpn.Core.Net;

namespace SplitVpn.Core.Update;

public sealed record PackageDownloadResult
{
    public bool Success { get; init; }

    public FetchFailure Failure { get; init; }

    public string? Message { get; init; }

    public TimeSpan? RetryAfter { get; init; }

    /// <summary>Сколько байт лежит в недокачанном файле: показывается в ходе загрузки.</summary>
    public long Bytes { get; init; }

    public Uri? Url { get; init; }

    /// <summary>Недокачанный файл выброшен: следующая попытка начнётся с нуля.</summary>
    public bool PartialDiscarded { get; init; }
}

/// <summary>
/// Загрузка установщика с докачкой и проверкой SHA-256. Установщик весит десятки мегабайт, поэтому
/// он пишется потоком в файл рядом с каталогом обновлений, а не держится в памяти, и обрыв связи
/// не начинает загрузку заново. Итоговый файл появляется только после совпадения контрольной суммы.
/// </summary>
public sealed class PackageDownloader(HttpClient client, TimeSpan? idleTimeout = null, long spareDiskBytes = PackageDownloader.SpareDiskBytes)
{
    /// <summary>Запас на распаковку установщиком Windows в собственный кэш сверх самого файла.</summary>
    public const long SpareDiskBytes = 200L * 1024 * 1024;

    private const int BufferBytes = 81920;

    private readonly TimeSpan _idleTimeout = idleTimeout ?? TimeSpan.FromSeconds(60);

    public async Task<PackageDownloadResult> DownloadAsync(
        IReadOnlyList<Uri> urls,
        string partialPath,
        string packagePath,
        long expectedSize,
        string expectedSha256,
        IProgress<long>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(urls);
        if (FreeSpaceProblem(partialPath, expectedSize + spareDiskBytes) is { } space)
        {
            return new PackageDownloadResult { Failure = FetchFailure.Network, Message = space };
        }

        PackageDownloadResult? last = null;
        foreach (var url in urls)
        {
            last = await FetchAsync(url, partialPath, expectedSize, progress, allowResume: true, cancellationToken);
            // Источник отдал не то, что обещал манифест: у зеркал спрашивать то же самое бессмысленно.
            if (last.Success || last.Failure is FetchFailure.RateLimited or FetchFailure.TooLarge)
            {
                break;
            }
        }

        last ??= new PackageDownloadResult { Failure = FetchFailure.Network, Message = "Не задан адрес установщика." };
        if (!last.Success)
        {
            return last;
        }

        var actual = await ComputeSha256Async(partialPath, cancellationToken);
        if (!string.Equals(actual, expectedSha256, StringComparison.Ordinal))
        {
            TryDelete(partialPath);
            return new PackageDownloadResult
            {
                Failure = FetchFailure.Network,
                Message = "Контрольная сумма установщика не совпала: файл отброшен.",
                Url = last.Url,
                PartialDiscarded = true,
            };
        }

        File.Move(partialPath, packagePath, overwrite: true);
        return last with { Bytes = expectedSize };
    }

    /// <summary>Свободного места должно хватить на сам файл и на кэш установщика Windows.</summary>
    private static string? FreeSpaceProblem(string path, long needed)
    {
        try
        {
            var root = Path.GetPathRoot(Path.GetFullPath(path));
            if (string.IsNullOrEmpty(root))
            {
                return null;
            }

            var free = new DriveInfo(root).AvailableFreeSpace;
            return free >= needed
                ? null
                : string.Create(CultureInfo.InvariantCulture,
                    $"Недостаточно места на диске {root}: нужно около {needed / (1024 * 1024)} МБ, свободно {free / (1024 * 1024)} МБ.");
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException)
        {
            // Не удалось узнать свободное место — попробуем скачать и разберёмся по ошибке записи.
            return null;
        }
    }

    private async Task<PackageDownloadResult> FetchAsync(
        Uri url, string partialPath, long expectedSize, IProgress<long>? progress, bool allowResume, CancellationToken cancellationToken)
    {
        using var idle = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        idle.CancelAfter(_idleTimeout);
        try
        {
            var existing = allowResume ? PartialLength(partialPath) : 0;
            if (existing >= expectedSize)
            {
                // Файл длиннее обещанного: источник сменился или запись повреждена.
                TryDelete(partialPath);
                existing = 0;
            }

            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            if (existing > 0)
            {
                request.Headers.Range = new RangeHeaderValue(existing, null);
            }

            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, idle.Token);
            if (response.StatusCode == HttpStatusCode.RequestedRangeNotSatisfiable && existing > 0)
            {
                TryDelete(partialPath);
                return await FetchAsync(url, partialPath, expectedSize, progress, allowResume: false, cancellationToken);
            }

            if (HttpFailureClassifier.Classify(response) is { } problem)
            {
                return Failed(url, problem, PartialLength(partialPath));
            }

            if (response.StatusCode == HttpStatusCode.NotModified)
            {
                return Failed(url, new FetchProblem(FetchFailure.HttpError, HttpFailureClassifier.Describe(response)), existing);
            }

            // Сервер проигнорировал докачку и отдал файл целиком: начинаем запись с нуля.
            var append = existing > 0 && response.StatusCode == HttpStatusCode.PartialContent;
            var written = append ? existing : 0;
            if (response.Content.Headers.ContentLength is { } length && written + length > expectedSize)
            {
                TryDelete(partialPath);
                return Failed(url, new FetchProblem(FetchFailure.TooLarge, "Размер установщика не совпал с манифестом."), 0, discarded: true);
            }

            written = await WriteAsync(response, partialPath, append, written, expectedSize, progress, idle);
            if (written < 0)
            {
                TryDelete(partialPath);
                return Failed(url, new FetchProblem(FetchFailure.TooLarge, "Размер установщика не совпал с манифестом."), 0, discarded: true);
            }

            return written == expectedSize
                ? new PackageDownloadResult { Success = true, Bytes = written, Url = url }
                : Failed(url, new FetchProblem(FetchFailure.Network, "Загрузка установщика не завершена."), written);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Failed(url, new FetchProblem(FetchFailure.Timeout, "Источник перестал отвечать во время загрузки."), PartialLength(partialPath));
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or UnauthorizedAccessException)
        {
            return Failed(url, DescribeWriteFailure(ex, url), PartialLength(partialPath));
        }
    }

    /// <summary>Пишет тело в файл; возвращает итоговую длину или −1, если тело оказалось длиннее обещанного.</summary>
    private static async Task<long> WriteAsync(
        HttpResponseMessage response, string partialPath, bool append, long written, long expectedSize,
        IProgress<long>? progress, CancellationTokenSource idle)
    {
        var timeout = idle.Token;
        await using var stream = await response.Content.ReadAsStreamAsync(timeout);
        await using var file = new FileStream(partialPath, append ? FileMode.Append : FileMode.Create, FileAccess.Write, FileShare.None);
        var buffer = new byte[BufferBytes];
        int read;
        while ((read = await stream.ReadAsync(buffer, timeout)) > 0)
        {
            written += read;
            if (written > expectedSize)
            {
                return -1;
            }

            await file.WriteAsync(buffer.AsMemory(0, read), timeout);
            progress?.Report(written);
        }

        await file.FlushAsync(timeout);
        return written;
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var file = File.OpenRead(path);
        return Convert.ToHexStringLower(await SHA256.HashDataAsync(file, cancellationToken));
    }

    private static FetchProblem DescribeWriteFailure(Exception exception, Uri url)
    {
        // ERROR_DISK_FULL и ERROR_HANDLE_DISK_FULL: место кончилось уже во время записи.
        const int DiskFull = unchecked((int)0x80070070);
        const int HandleDiskFull = unchecked((int)0x80070027);
        return exception is IOException && exception.HResult is DiskFull or HandleDiskFull
            ? new FetchProblem(FetchFailure.Network, "На диске закончилось место во время загрузки установщика.")
            : HttpFailureClassifier.FromException(exception, url);
    }

    private static long PartialLength(string path)
    {
        try
        {
            return File.Exists(path) ? new FileInfo(path).Length : 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return 0;
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
            // Файл занят: следующая попытка перезапишет его целиком.
        }
    }

    private static PackageDownloadResult Failed(Uri? url, FetchProblem problem, long bytes, bool discarded = false) => new()
    {
        Failure = problem.Failure,
        Message = problem.Message,
        RetryAfter = problem.RetryAfter,
        Bytes = bytes,
        Url = url,
        PartialDiscarded = discarded,
    };
}
