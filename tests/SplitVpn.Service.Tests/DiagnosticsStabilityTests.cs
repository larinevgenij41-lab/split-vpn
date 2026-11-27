using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using SplitVpn.Service.Diagnostics;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Стабильность сбора архива разбора: зависший системный вызов пропускает только свою часть и не запрещает следующий
/// сбор до перезапуска службы; исчерпанная квота даёт усечённый, но целый архив, а не «Архив не собран».
/// </summary>
public sealed class DiagnosticsStabilityTests : IDisposable
{
    private static readonly TimeSpan Guard = TimeSpan.FromSeconds(10);

    private readonly string _root = Path.Combine(Path.GetTempPath(), "splitvpn-diag-stability", Guid.NewGuid().ToString("N"));

    /// <summary>Отпускает «зависшие» части в конце теста: их потоки не переживают его.</summary>
    private readonly ManualResetEventSlim _release = new();

    public DiagnosticsStabilityTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        _release.Set();
        try { Directory.Delete(_root, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        _release.Dispose();
    }

    private DiagnosticsPart Hung(string path) => new(path, () =>
    {
        _release.Wait();
        return "поздний результат";
    });

    private DiagnosticsCollector Collector(Func<IEnumerable<DiagnosticsPart>> systemParts, ServicePaths? paths = null) =>
        new(paths ?? new ServicePaths(Path.Combine(_root, "data")), TimeProvider.System, systemParts, () => [])
        {
            PartTimeout = TimeSpan.FromMilliseconds(200),
        };

    private static Task<IReadOnlyList<string>> WriteAsync(DiagnosticsCollector collector, Stream stream) =>
        Task.Run(() => collector.Write(stream, [new DiagnosticsPart("status.json", () => "{}")], TestContext.Current.CancellationToken))
            .WaitAsync(Guard, TestContext.Current.CancellationToken);

    [Fact]
    public async Task HungSystemPart_IsSkippedByDeadline_AndLateResultIsNotWritten()
    {
        var collector = Collector(() => [Hung("net/wfp.json"), new DiagnosticsPart("system/info.txt", () => "Windows")]);
        using var stream = new MemoryStream();

        var problems = await WriteAsync(collector, stream);

        Assert.Contains(problems, p => p.StartsWith("net/wfp.json: пропущен", StringComparison.Ordinal));
        var length = stream.Length;
        _release.Set();
        await Task.Delay(100, TestContext.Current.CancellationToken);
        Assert.Equal(length, stream.Length);
        stream.Position = 0;
        using var zip = new ZipArchive(stream, ZipArchiveMode.Read);
        Assert.Null(zip.GetEntry("net/wfp.json"));
        Assert.NotNull(zip.GetEntry("system/info.txt"));
        Assert.NotNull(zip.GetEntry("status.json"));
        Assert.NotNull(zip.GetEntry("service-manifest.json"));
    }

    /// <summary>Брошенных потоков не больше предела: дальше части пропускаются сразу, и сбор не ждёт срок каждой.</summary>
    [Fact]
    public async Task StuckParts_AreBounded_AndFurtherPartsAreSkippedAtOnce()
    {
        var collector = Collector(() => [Hung("a.txt"), Hung("b.txt"), Hung("c.txt"), Hung("d.txt")]);
        using var first = new MemoryStream();
        var timer = Stopwatch.StartNew();

        var problems = await WriteAsync(collector, first);

        Assert.Equal(DiagnosticsCollector.DefaultMaxStuckParts, problems.Count(p => p.Contains("не получена", StringComparison.Ordinal)));
        Assert.Equal(2, problems.Count(p => p.Contains("предел незавершённых частей", StringComparison.Ordinal)));
        Assert.True(timer.Elapsed < TimeSpan.FromSeconds(3), timer.Elapsed.ToString());

        // Следующий сбор, пока прежние вызовы не вернулись: ни одна часть не ждёт своего срока.
        using var second = new MemoryStream();
        timer.Restart();
        problems = await WriteAsync(collector, second);
        Assert.Equal(4, problems.Count(p => p.Contains("предел незавершённых частей", StringComparison.Ordinal)));
        Assert.True(timer.Elapsed < TimeSpan.FromMilliseconds(150), timer.Elapsed.ToString());

        // Вызовы вернулись: места освобождены, части снова собираются.
        _release.Set();
        IReadOnlyList<string> recovered = [];
        for (var i = 0; i < 100; i++)
        {
            using var next = new MemoryStream();
            recovered = await WriteAsync(collector, next);
            if (recovered.Count == 0) break;
            await Task.Delay(20, TestContext.Current.CancellationToken);
        }

        Assert.Empty(recovered);
    }

    /// <summary>Зависший системный вызов не оставляет флаг «Архив уже собирается» до перезапуска службы.</summary>
    [Fact]
    public async Task HungPart_DoesNotBlockNextPackage()
    {
        var collector = Collector(() => [Hung("eventlog/services.txt")]);
        using var packages = new DiagnosticsPackages(Path.Combine(_root, "diag"), TimeProvider.System);

        var first = await Task.Run(() => packages.Create(s => collector.Write(s, [], TestContext.Current.CancellationToken)))
            .WaitAsync(Guard, TestContext.Current.CancellationToken);
        var second = await Task.Run(() => packages.Create(s => collector.Write(s, [], TestContext.Current.CancellationToken)))
            .WaitAsync(Guard, TestContext.Current.CancellationToken);

        Assert.NotNull(first);
        Assert.NotNull(second);
        Assert.Contains(first.Problems, p => p.StartsWith("eventlog/services.txt: пропущен", StringComparison.Ordinal));
    }

    /// <summary>
    /// Квота исчерпана посреди журналов: не помещающийся журнал пропускается без попытки записи, архив закрывается
    /// целым, в нём — уместившиеся журналы и манифест с записью о пропуске.
    /// </summary>
    [Fact]
    public void QuotaExhausted_ArchiveIsValidAndListsSkippedFiles()
    {
        var paths = new ServicePaths(Path.Combine(_root, "data"));
        Directory.CreateDirectory(paths.Logs);
        var now = DateTime.UtcNow;
        for (var i = 1; i <= 3; i++)
        {
            var log = Path.Combine(paths.Logs, $"service-2026110{i}.log");
            File.WriteAllBytes(log, RandomNumberGenerator.GetBytes(150_000));
            File.SetLastWriteTimeUtc(log, now.AddMinutes(-i));
        }

        var collector = Collector(() => [], paths);
        using var packages = new DiagnosticsPackages(Path.Combine(_root, "diag"), TimeProvider.System, 600_000, 10_000_000);

        var package = packages.Create(s => collector.Write(s, [new DiagnosticsPart("status.json", () => "{}")], TestContext.Current.CancellationToken));

        Assert.NotNull(package);
        Assert.Contains(package.Problems, p => p.Equals("logs/service-20261103.log: пропущен — архив достиг предела размера", StringComparison.Ordinal));
        using var archive = new MemoryStream();
        for (long offset = 0; ;)
        {
            var chunk = packages.Read(package.Token, offset)!;
            archive.Write(chunk.Data);
            offset += chunk.Data.Length;
            if (chunk.Last) break;
        }

        Assert.True(archive.Length <= 600_000);
        archive.Position = 0;
        using var zip = new ZipArchive(archive, ZipArchiveMode.Read);
        Assert.NotNull(zip.GetEntry("logs/service-20261101.log"));
        Assert.NotNull(zip.GetEntry("logs/service-20261102.log"));
        Assert.Null(zip.GetEntry("logs/service-20261103.log"));
        Assert.Equal(150_000, zip.GetEntry("logs/service-20261102.log")!.Length);
        using var manifest = JsonDocument.Parse(zip.GetEntry("service-manifest.json")!.Open());
        Assert.Contains(manifest.RootElement.GetProperty("problems").EnumerateArray(),
            p => p.GetString()!.StartsWith("logs/service-20261103.log: пропущен", StringComparison.Ordinal));
    }
}
