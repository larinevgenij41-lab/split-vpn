using System.Diagnostics;
using Microsoft.Extensions.Time.Testing;
using SplitVpn.Core.Diagnostics;

namespace SplitVpn.Core.Tests.Diagnostics;

/// <summary>
/// Мьютекс журнала может держать другой процесс (вторая копия программы пишет или зависла): запись не ждёт его
/// на каждой строке и не теряет строки — копит их в памяти и дописывает в общий файл при следующем захвате.
/// Отдельных файлов процесса при этом не появляется: их никто не чистит.
/// </summary>
public sealed class RollingTextLogMutexTests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "splitvpn-rolling-mutex-tests", Guid.NewGuid().ToString("N"));
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 11, 24, 10, 0, 0, TimeSpan.Zero));

    private string LogPath => Path.Combine(_folder, "ui-verbose.log");

    private string ProcessFile => Path.ChangeExtension(LogPath, Environment.ProcessId + ".log");

    public void Dispose()
    {
        if (Directory.Exists(_folder))
        {
            Directory.Delete(_folder, recursive: true);
        }
    }

    /// <summary>Держит мьютекс файла в другом потоке, пока не вызван возвращённый release.</summary>
    private Action HoldMutex()
    {
        var taken = new ManualResetEventSlim();
        var release = new ManualResetEventSlim();
        var holder = new Thread(() =>
        {
            using var mutex = new Mutex(false, RollingTextLog.MutexName(LogPath));
            mutex.WaitOne();
            taken.Set();
            release.Wait();
            mutex.ReleaseMutex();
        });
        holder.Start();
        Assert.True(taken.Wait(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
        return () =>
        {
            release.Set();
            holder.Join();
            taken.Dispose();
            release.Dispose();
        };
    }

    [Fact]
    public void MutexHeldElsewhere_WritesQuickly_ThenFlushesQueuedLinesIntoSharedFile()
    {
        var log = new RollingTextLog(LogPath, _time);
        var release = HoldMutex();
        try
        {
            var watch = Stopwatch.StartNew();
            for (var i = 0; i < 200; i++)
            {
                log.Write("Ui", "строка " + i);
            }

            watch.Stop();

            // Одно короткое ожидание (250 мс), затем без ожидания: ждать на каждой строке значило бы 200 x 250 мс = 50 с
            // и больше. Срок с запасом для параллельного прогона и всё равно в пять раз меньше.
            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(10), $"запись заняла {watch.Elapsed}");
            Assert.False(File.Exists(ProcessFile));
        }
        finally
        {
            release();
        }

        // Мьютекс освободился: следующая запись берёт его сразу (без ожидания конца паузы) и дописывает очередь по порядку.
        log.Write("Ui", "после");
        var text = File.ReadAllText(LogPath);
        var first = text.IndexOf("строка 0" + Environment.NewLine, StringComparison.Ordinal);
        var last = text.IndexOf("строка 199" + Environment.NewLine, StringComparison.Ordinal);
        var after = text.IndexOf("после", StringComparison.Ordinal);
        Assert.True(first >= 0 && last > first && after > last, text);
        Assert.False(File.Exists(ProcessFile));
    }

    [Fact]
    public void MutexHeldLong_QueueIsBounded_AndLossIsNoted()
    {
        var log = new RollingTextLog(LogPath, _time);
        var release = HoldMutex();
        try
        {
            for (var i = 0; i < RollingTextLog.MaxPending + 10; i++)
            {
                log.Write("Ui", "строка " + i);
            }
        }
        finally
        {
            release();
        }

        log.Write("Ui", "после");
        var text = File.ReadAllText(LogPath);
        Assert.Contains("10 строк пропущено", text, StringComparison.Ordinal);
        Assert.DoesNotContain("строка 9" + Environment.NewLine, text, StringComparison.Ordinal);
        Assert.Contains("строка 10" + Environment.NewLine, text, StringComparison.Ordinal);
        Assert.Contains("после", text, StringComparison.Ordinal);
        Assert.False(File.Exists(ProcessFile));
    }
}
