using System.Security.Cryptography;
using SplitVpn.Core.Ipc;

namespace SplitVpn.Service.Diagnostics;

/// <summary>
/// Собранные архивы службы до выдачи интерфейсу. Архив лежит в защищённом каталоге данных, а не по пути,
/// который назвал клиент: служба от SYSTEM не пишет в чужие каталоги. Интерфейс забирает его кусками
/// (кадр IPC ограничен 2 МБ) по случайному токену; после последнего куска или через 15 минут (таймер
/// чистки раз в минуту) файл удаляется. Одновременно собирается один архив.
/// </summary>
public sealed class DiagnosticsPackages : IDisposable
{
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(1);

    public const int ChunkBytes = 1024 * 1024;
    public const int MaxPackages = 3;
    public const long MaxPackageBytes = 256_000_000;
    public const long MaxTotalBytes = 512_000_000;

    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(15);

    private readonly string _directory;
    private readonly TimeProvider _time;
    private readonly ITimer _cleanup;
    private int _building;
    private readonly long _maxPackageBytes;
    private readonly long _maxTotalBytes;

    public DiagnosticsPackages(string directory, TimeProvider time) : this(directory, time, MaxPackageBytes, MaxTotalBytes) { }

    internal DiagnosticsPackages(string directory, TimeProvider time, long maxPackageBytes, long maxTotalBytes)
    {
        _directory = directory;
        _time = time;
        _maxPackageBytes = maxPackageBytes;
        _maxTotalBytes = maxTotalBytes;

        // Архивы прошлого запуска никто уже не заберёт.
        DeleteWhere(_ => true);

        // Брошенный архив (клиент закрыли посреди передачи) не лежит до следующего сбора.
        _cleanup = time.CreateTimer(_ => DeleteExpired(), null, CleanupInterval, CleanupInterval);
    }

    public void Dispose() => _cleanup.Dispose();

    private void DeleteExpired() => DeleteWhere(file => _time.GetUtcNow().UtcDateTime - file.CreationTimeUtc > Lifetime);

    /// <summary>Собрать архив; null — уже идёт другой сбор.</summary>
    public DiagnosticsPackageDto? Create(Func<Stream, IReadOnlyList<string>> write)
    {
        ArgumentNullException.ThrowIfNull(write);
        if (Interlocked.CompareExchange(ref _building, 1, 0) != 0)
        {
            return null;
        }

        try
        {
            DeleteExpired();
            Directory.CreateDirectory(_directory);
            var files = new DirectoryInfo(_directory).GetFiles("*.zip");
            var remaining = _maxTotalBytes - files.Sum(f => f.Length);
            if (files.Length >= MaxPackages || remaining <= 0)
            {
                throw new IOException("Предел хранения диагностики: заберите готовые архивы или дождитесь их удаления через 15 минут.");
            }
            var token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
            var path = PathOf(token);
            IReadOnlyList<string> problems;
            try
            {
                using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (var limited = new QuotaWriteStream(stream, Math.Min(_maxPackageBytes, remaining)))
                {
                    problems = write(limited);
                    if (limited.Exceeded) throw new IOException("Архив превышает предел хранения диагностики.");
                }

                File.SetCreationTimeUtc(path, _time.GetUtcNow().UtcDateTime);
            }
            catch
            {
                TryDelete(path);
                throw;
            }

            using var read = File.OpenRead(path);
            return new DiagnosticsPackageDto(token, read.Length, Convert.ToHexStringLower(SHA256.HashData(read)), problems);
        }
        finally
        {
            Volatile.Write(ref _building, 0);
        }
    }

    /// <summary>Кусок архива; null — такого архива нет (неверный токен, уже выдан или устарел).</summary>
    public DiagnosticsChunkDto? Read(string token, long offset)
    {
        if (!IsToken(token) || offset < 0)
        {
            return null;
        }

        var path = PathOf(token);
        byte[] data;
        bool last;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (offset > stream.Length || _time.GetUtcNow().UtcDateTime - File.GetCreationTimeUtc(path) > Lifetime)
            {
                return null;
            }

            stream.Position = offset;
            data = new byte[(int)Math.Min(ChunkBytes, stream.Length - offset)];
            stream.ReadExactly(data);
            last = offset + data.Length >= stream.Length;
        }
        catch (FileNotFoundException)
        {
            return null;
        }

        if (last)
        {
            TryDelete(path);
        }

        return new DiagnosticsChunkDto(data, last);
    }

    private string PathOf(string token) => Path.Combine(_directory, token + ".zip");

    /// <summary>Только 32 шестнадцатеричных знака: токен не может увести путь за пределы каталога.</summary>
    private static bool IsToken(string token) => token is { Length: 32 } && token.All(Uri.IsHexDigit);

    private void DeleteWhere(Func<FileInfo, bool> predicate)
    {
        try
        {
            foreach (var file in new DirectoryInfo(_directory).EnumerateFiles("*.zip").Where(predicate))
            {
                TryDelete(file.FullName);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Каталога ещё нет.
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
            // Удалится при следующем сборе или запуске.
        }
    }
}
