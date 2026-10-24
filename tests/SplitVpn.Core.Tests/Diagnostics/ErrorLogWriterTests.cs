using Microsoft.Extensions.Time.Testing;
using SplitVpn.Core.Diagnostics;

namespace SplitVpn.Core.Tests.Diagnostics;

public sealed class ErrorLogWriterTests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "splitvpn-errorlog-tests", Guid.NewGuid().ToString("N"));
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 9, 14, 12, 0, 0, TimeSpan.Zero));

    private string LogPath => Path.Combine(_folder, "ui-errors.log");

    public void Dispose()
    {
        if (Directory.Exists(_folder))
        {
            Directory.Delete(_folder, recursive: true);
        }
    }

    [Fact]
    public void RepeatedExceptionIsWrittenOnceAndCountedLater()
    {
        var log = new ErrorLogWriter(LogPath, _time);
        var error = Thrown(() => throw new InvalidOperationException("цикл раскладки"));

        for (var i = 0; i < 20; i++)
        {
            Assert.True(log.Record(error));
            _time.Advance(TimeSpan.FromSeconds(1));
        }

        var afterBurst = File.ReadAllText(LogPath);
        Assert.Equal(1, Occurrences(afterBurst, "цикл раскладки"));

        _time.Advance(ErrorLogWriter.RepeatWindow);
        Assert.True(log.Record(error));

        var text = File.ReadAllText(LogPath);
        Assert.Contains("Повторилось 20 раз", text, StringComparison.Ordinal);
    }

    [Fact]
    public void StormOfIdenticalExceptionsStopsTheInterface()
    {
        var log = new ErrorLogWriter(LogPath, _time);
        var error = Thrown(() => throw new InvalidOperationException("шторм"));

        var results = Enumerable.Range(0, ErrorLogWriter.StormCount + 1).Select(_ => log.Record(error)).ToList();

        Assert.True(results[0]);
        Assert.False(results[^1]);
        Assert.Contains("интерфейс завершается", File.ReadAllText(LogPath), StringComparison.Ordinal);
    }

    [Fact]
    public void SlowRepeatsNeverLookLikeStorm()
    {
        var log = new ErrorLogWriter(LogPath, _time);
        var error = Thrown(() => throw new InvalidOperationException("редко"));

        for (var i = 0; i < ErrorLogWriter.StormCount * 3; i++)
        {
            Assert.True(log.Record(error));
            _time.Advance(TimeSpan.FromSeconds(1));
        }
    }

    [Fact]
    public void DifferentExceptionsAreWrittenSeparately()
    {
        var log = new ErrorLogWriter(LogPath, _time);

        log.Record(Thrown(() => throw new InvalidOperationException("первая")));
        log.Record(Thrown(() => throw new ArgumentException("вторая")));

        var text = File.ReadAllText(LogPath);
        Assert.Contains("первая", text, StringComparison.Ordinal);
        Assert.Contains("вторая", text, StringComparison.Ordinal);
    }

    [Fact]
    public void FileIsRotatedAtSizeLimit()
    {
        Directory.CreateDirectory(_folder);
        File.WriteAllText(LogPath, new string('x', (int)ErrorLogWriter.MaxBytes));
        var log = new ErrorLogWriter(LogPath, _time);

        log.Record(Thrown(() => throw new InvalidOperationException("после ротации")));

        Assert.True(new FileInfo(LogPath + ".1").Length >= ErrorLogWriter.MaxBytes);
        Assert.True(new FileInfo(LogPath).Length < 64 * 1024);
        Assert.Contains("после ротации", File.ReadAllText(LogPath), StringComparison.Ordinal);
    }

    [Fact]
    public void LockedFileDoesNotThrow()
    {
        Directory.CreateDirectory(_folder);
        using var locked = new FileStream(LogPath, FileMode.Create, FileAccess.ReadWrite, FileShare.None);
        var log = new ErrorLogWriter(LogPath, _time);

        Assert.True(log.Record(Thrown(() => throw new InvalidOperationException("журнал занят"))));
    }

    private static Exception Thrown(Action action)
    {
        try
        {
            action();
        }
        catch (Exception ex)
        {
            return ex;
        }

        throw new InvalidOperationException("исключение не возникло");
    }

    private static int Occurrences(string text, string value)
    {
        var count = 0;
        for (var index = text.IndexOf(value, StringComparison.Ordinal); index >= 0; index = text.IndexOf(value, index + value.Length, StringComparison.Ordinal))
        {
            count++;
        }

        return count;
    }
}
