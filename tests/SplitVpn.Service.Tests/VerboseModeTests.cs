using Microsoft.Extensions.Time.Testing;
using Serilog.Core;
using Serilog.Events;
using SplitVpn.Core.Diagnostics;
using SplitVpn.Core.Ipc;
using SplitVpn.Service.Coordination;
using SplitVpn.Service.Diagnostics;

namespace SplitVpn.Service.Tests;

/// <summary>Тесты меняют общий флаг <see cref="Verbose"/>: идут без параллельности с остальными.</summary>
[CollectionDefinition("Verbose", DisableParallelization = true)]
public sealed class VerboseTestGroup;

[Collection("Verbose")]
public sealed class VerboseModeTests : IDisposable
{
    private readonly string _logs = Path.Combine(Path.GetTempPath(), "splitvpn-verbose-tests", Guid.NewGuid().ToString("N"));
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 9, 29, 10, 0, 0, TimeSpan.Zero));
    private readonly LoggingLevelSwitch _level = new();
    private readonly List<(string Level, string Text)> _journal = [];
    private string? _stored;

    public VerboseModeTests()
    {
        Directory.CreateDirectory(_logs);
    }

    public void Dispose()
    {
        Verbose.Set(false);
        Directory.Delete(_logs, recursive: true);
    }

    private VerboseMode Create()
    {
        var mode = new VerboseMode(_level, _time, () => _stored, until => _stored = until is { } value ? VerboseRegistry.Format(value) : null, _logs)
        {
            Journal = (level, text) => _journal.Add((level, text)),
        };
        mode.Initialize();
        return mode;
    }

    [Fact]
    public void EnableTurnsEverythingOnAndExpiresByItself()
    {
        using var mode = Create();
        Assert.Null(mode.UntilUtc);
        Assert.Equal(LogEventLevel.Information, _level.MinimumLevel);

        var until = mode.Enable(TimeSpan.FromHours(1));

        Assert.Equal(_time.GetUtcNow() + TimeSpan.FromHours(1), until);
        Assert.Equal(until, mode.UntilUtc);
        Assert.Equal(LogEventLevel.Verbose, _level.MinimumLevel);
        Assert.True(Verbose.IsOn);
        Assert.NotNull(_stored);
        Assert.Contains(_journal, e => e.Text.StartsWith("Подробный журнал включён", StringComparison.Ordinal));

        _time.Advance(TimeSpan.FromMinutes(59));
        Assert.True(Verbose.IsOn);

        _time.Advance(TimeSpan.FromMinutes(1));
        Assert.Null(mode.UntilUtc);
        Assert.False(Verbose.IsOn);
        Assert.Equal(LogEventLevel.Information, _level.MinimumLevel);
        Assert.Null(_stored);
        Assert.Contains(_journal, e => e.Text.Contains("срок истёк", StringComparison.Ordinal));
    }

    [Fact]
    public void StoredTermSurvivesRestart()
    {
        _stored = VerboseRegistry.Format(_time.GetUtcNow() + TimeSpan.FromHours(3));

        using var mode = Create();

        Assert.True(Verbose.IsOn);
        Assert.Equal(_time.GetUtcNow() + TimeSpan.FromHours(3), mode.UntilUtc);
    }

    [Fact]
    public void ExpiredOrGarbageTermIsRemovedOnStart()
    {
        _stored = VerboseRegistry.Format(_time.GetUtcNow() - TimeSpan.FromMinutes(1));
        using (Create())
        {
            Assert.False(Verbose.IsOn);
            Assert.Null(_stored);
        }

        _stored = "не дата";
        using (Create())
        {
            Assert.False(Verbose.IsOn);
            Assert.Null(_stored);
        }
    }

    [Fact]
    public void TermIsCappedAtOneDay()
    {
        _stored = VerboseRegistry.Format(_time.GetUtcNow() + TimeSpan.FromDays(30));
        using var mode = Create();
        Assert.Equal(_time.GetUtcNow() + VerboseRegistry.MaxDuration, mode.UntilUtc);

        // Обрезанный срок записан обратно: после перезагрузки «навсегда» не продлевается ещё на сутки.
        Assert.Equal(VerboseRegistry.Format(_time.GetUtcNow() + VerboseRegistry.MaxDuration), _stored);

        Assert.Equal(_time.GetUtcNow() + VerboseRegistry.MaxDuration, mode.Enable(TimeSpan.FromDays(3)));
        Assert.Equal(_time.GetUtcNow() + VerboseMode.MinDuration, mode.Enable(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public void ManualDisableIsJournaledOnce()
    {
        using var mode = Create();
        mode.Enable(TimeSpan.FromHours(4));

        mode.Disable("выключен вручную");
        mode.Disable("выключен вручную");

        Assert.False(Verbose.IsOn);
        Assert.Null(_stored);
        Assert.Single(_journal, e => e.Text.Contains("выключен вручную", StringComparison.Ordinal));

        // Прежний таймер не срабатывает после выключения.
        _time.Advance(TimeSpan.FromHours(5));
        Assert.Single(_journal, e => e.Text.StartsWith("Подробный журнал выключен", StringComparison.Ordinal));
    }

    [Fact]
    public void OldVerboseFilesAreDeleted()
    {
        var old = Path.Combine(_logs, "verbose-20260901.log");
        var fresh = Path.Combine(_logs, "dns-20260928.log");
        var main = Path.Combine(_logs, "service-20260901.log");
        foreach (var file in new[] { old, fresh, main })
        {
            File.WriteAllText(file, "x");
        }

        File.SetLastWriteTimeUtc(old, _time.GetUtcNow().UtcDateTime - TimeSpan.FromDays(8));
        File.SetLastWriteTimeUtc(fresh, _time.GetUtcNow().UtcDateTime - TimeSpan.FromDays(1));
        File.SetLastWriteTimeUtc(main, _time.GetUtcNow().UtcDateTime - TimeSpan.FromDays(8));

        using var mode = Create();

        Assert.False(File.Exists(old));
        Assert.True(File.Exists(fresh));
        Assert.True(File.Exists(main));
    }

    [Fact]
    public void DebugLinesReachVerboseFileOnlyWhileOn()
    {
        using var mode = Create();
        using (var logger = ServiceLogging.Create(_logs, _level))
        {
            var sink = ServiceLogging.VerboseSink(logger);
            Verbose.Sink = sink;
            try
            {
                Verbose.Write("Ipc", "до включения");
                mode.Enable(TimeSpan.FromHours(1));
                Verbose.Write("Ipc", "запрос GetStatus");
                Verbose.Write("Dns.Query", "A example.com → forward");
                logger.Information("сведения для основного файла");
                mode.Disable("выключен вручную");
                Verbose.Write("Ipc", "после выключения");
            }
            finally
            {
                Verbose.Sink = null;
            }
        }

        var verbose = ReadAll("verbose-*.log");
        var dns = ReadAll("dns-*.log");
        var main = ReadAll("service-*.log");
        Assert.Contains("SplitVpn.Ipc: запрос GetStatus", verbose, StringComparison.Ordinal);
        Assert.Contains("сведения для основного файла", verbose, StringComparison.Ordinal);
        Assert.DoesNotContain("до включения", verbose, StringComparison.Ordinal);
        Assert.DoesNotContain("после выключения", verbose, StringComparison.Ordinal);
        Assert.DoesNotContain("example.com", verbose, StringComparison.Ordinal);
        Assert.Contains("A example.com → forward", dns, StringComparison.Ordinal);
        Assert.Contains("сведения для основного файла", main, StringComparison.Ordinal);
        Assert.DoesNotContain("GetStatus", main, StringComparison.Ordinal);
    }

    [Fact]
    public void TimerFiringBeforeWallClockTermIsRearmed()
    {
        // После включения часы подвели назад на 3 мс (W32Time): таймер срабатывает «раньше срока».
        var lagging = new LaggingTime(_time);
        using var mode = new VerboseMode(_level, lagging, () => _stored, until => _stored = until is { } value ? VerboseRegistry.Format(value) : null, _logs);
        mode.Initialize();
        mode.Enable(TimeSpan.FromHours(1));
        lagging.Lag = TimeSpan.FromMilliseconds(3);

        _time.Advance(TimeSpan.FromHours(1));
        Assert.True(Verbose.IsOn);

        _time.Advance(TimeSpan.FromMilliseconds(5));
        Assert.False(Verbose.IsOn);
        Assert.Null(mode.UntilUtc);
    }

    [Fact]
    public void ExtendedTermIsNotTurnedOffByThePreviousTimer()
    {
        using var mode = Create();
        mode.Enable(TimeSpan.FromMinutes(10));
        _time.Advance(TimeSpan.FromMinutes(9));
        var extended = mode.Enable(TimeSpan.FromHours(1));

        _time.Advance(TimeSpan.FromMinutes(2));

        Assert.True(Verbose.IsOn);
        Assert.Equal(extended, mode.UntilUtc);
        Assert.Equal(VerboseRegistry.Format(extended), _stored);
    }

    [Theory]
    [InlineData(-1, IpcErrorCodes.BadRequest)]
    [InlineData(1441, IpcErrorCodes.BadRequest)]
    [InlineData(30, null)]
    [InlineData(0, null)]
    public async Task CoordinatorChecksVerboseTerm(int minutes, string? error)
    {
        using var world = new FakeWorld();
        using var mode = Create();
        var coordinator = new Coordinator(world.Dependencies() with { Verbose = mode });

        var response = await coordinator.HandleRequestAsync(new SetVerboseLoggingRequest(minutes), CancellationToken.None);

        Assert.Equal(error, response.ErrorCode);
        Assert.Equal(minutes > 0 && error is null, Verbose.IsOn);
    }

    /// <summary>Часы, отстающие от таймеров исходного провайдера.</summary>
    private sealed class LaggingTime(FakeTimeProvider inner) : TimeProvider
    {
        public TimeSpan Lag { get; set; }

        public override DateTimeOffset GetUtcNow() => inner.GetUtcNow() - Lag;

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) =>
            inner.CreateTimer(callback, state, dueTime, period);
    }

    private string ReadAll(string pattern) =>
        string.Concat(Directory.GetFiles(_logs, pattern).Select(File.ReadAllText));
}
