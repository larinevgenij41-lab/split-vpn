using System.IO.Compression;
using SplitVpn.Core.Diagnostics;
using SplitVpn.Service.Diagnostics;

namespace SplitVpn.Service.Tests;

public sealed class DiagnosticsReviewFixTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "splitvpn-review-tests", Guid.NewGuid().ToString("N"));

    public DiagnosticsReviewFixTests() => Directory.CreateDirectory(_root);
    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Theory]
    [InlineData(1979)]
    [InlineData(2108)]
    public async Task InvalidFileDate_DoesNotAbortEitherArchive(int year)
    {
        var profile = Path.Combine(_root, "user");
        var folder = Path.Combine(profile, "AppData", "Local", "SplitVpn");
        Directory.CreateDirectory(folder);
        var file = Path.Combine(folder, "ui-verbose.log");
        File.WriteAllText(file, "safe synthetic log");
        File.SetLastWriteTimeUtc(file, new DateTime(year, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        var collector = new DiagnosticsCollector(new ServicePaths(Path.Combine(_root, "data")), TimeProvider.System,
            () => [], () => [new UserProfileFolder("user", profile)]);
        using var stream = new MemoryStream();
        var problems = collector.Write(stream, []);
        Assert.Contains(problems, p => p.Contains("дата файла", StringComparison.Ordinal));
        stream.Position = 0;
        using var zip = new ZipArchive(stream, ZipArchiveMode.Read);
        Assert.Equal(1980, zip.GetEntry("users/user/ui-verbose.log")!.LastWriteTime.Year);
        using var log = new StreamReader(zip.GetEntry("users/user/ui-verbose.log")!.Open());
        Assert.Equal("safe synthetic log", log.ReadToEnd());
        var output = Path.Combine(_root, "client.zip");
        var result = await DiagnosticsArchive.BuildAsync(null, [new ArchiveFile("ui/log", file)], output, null, TestContext.Current.CancellationToken);
        Assert.Contains(result.Problems, p => p.Contains("дата файла", StringComparison.Ordinal));
        using var client = ZipFile.OpenRead(output);
        Assert.NotNull(client.GetEntry("ui/log"));
    }

    [Fact]
    public void UnreadPackages_RejectNewBuildWithoutRemovingExistingPackages()
    {
        using var packages = new DiagnosticsPackages(Path.Combine(_root, "packages"), TimeProvider.System);
        var tokens = Enumerable.Range(0, DiagnosticsPackages.MaxPackages).Select(_ => packages.Create(s => { s.WriteByte(1); return []; })!.Token).ToArray();
        Assert.Throws<IOException>(() => packages.Create(_ => []));
        Assert.All(tokens, token => Assert.Equal(new byte[] { 1 }, packages.Read(token, 0)!.Data));
        Assert.NotNull(packages.Create(_ => []));
    }

    [Theory]
    [InlineData(10, 100, 11)]
    [InlineData(100, 10, 11)]
    public void PackageWriteQuota_RemovesPartialPackage(long perFile, long total, int count)
    {
        var folder = Path.Combine(_root, "quota");
        using var packages = new DiagnosticsPackages(folder, TimeProvider.System, perFile, total);
        Assert.Throws<IOException>(() => packages.Create(s => { s.Write(new byte[count]); return []; }));
        Assert.Empty(Directory.GetFiles(folder));
        Assert.NotNull(packages.Create(s => { s.WriteByte(1); return []; }));
    }

    [Fact]
    public void AggregateQuota_PreservesEarlierPackageAndCapsRemainingWrite()
    {
        using var packages = new DiagnosticsPackages(Path.Combine(_root, "total"), TimeProvider.System, 10, 15);
        var first = packages.Create(s => { s.Write(new byte[10]); return []; })!;
        Assert.Throws<IOException>(() => packages.Create(s => { s.Write(new byte[6]); return []; }));
        Assert.Equal(10, packages.Read(first.Token, 0)!.Data.Length);
    }

    [Fact]
    public void SwallowedQuotaError_StillRejectsPackage()
    {
        var folder = Path.Combine(_root, "swallowed");
        using var packages = new DiagnosticsPackages(folder, TimeProvider.System, 10, 100);
        Assert.Throws<IOException>(() => packages.Create(s =>
        {
            try { s.Write(new byte[11]); }
            catch (IOException) { }
            return ["source failed"];
        }));
        Assert.Empty(Directory.GetFiles(folder));
    }

    [Fact]
    public void GrowingStream_IsReadOnlyThroughLimitPlusOne()
    {
        using var stream = new NeverEndingStream();
        Assert.Null(DiagnosticsFileReader.ReadBounded(stream, 123, TestContext.Current.CancellationToken));
        Assert.Equal(124, stream.BytesRead);
    }

    [Fact]
    public async Task TimedOutRead_KeepsSlotUntilItReallyCompletes()
    {
        var reader = new DiagnosticsFileReader(1);
        using var release = new ManualResetEventSlim();
        using var finished = new ManualResetEventSlim();
        try
        {
            var first = reader.Read(token =>
            {
                // Имитирует открытие, которое не поддерживает отмену самого чтения.
                release.Wait(TestContext.Current.CancellationToken);
                try { token.ThrowIfCancellationRequested(); return null; }
                finally { finished.Set(); }
            }, TimeSpan.FromMilliseconds(30), out var problem);
            Assert.Null(first);
            Assert.Contains("срок", problem!, StringComparison.Ordinal);
            for (var i = 0; i < 10; i++)
            {
                Assert.Null(reader.Read(_ => throw new InvalidOperationException("must not start"), TimeSpan.FromMilliseconds(1), out problem));
                Assert.Contains("предел", problem!, StringComparison.Ordinal);
            }
        }
        finally { release.Set(); }
        Assert.True(finished.Wait(TimeSpan.FromSeconds(3), TestContext.Current.CancellationToken));
        CollectedFile? result = null;
        for (var i = 0; i < 100 && result is null; i++)
        {
            result = reader.Read(_ => new CollectedFile([1], DateTime.Now), TimeSpan.FromSeconds(1), out _);
            if (result is null) await Task.Delay(10, TestContext.Current.CancellationToken);
        }
        Assert.NotNull(result);
    }

    [Fact]
    public void EventExport_KeepsNewestMatchingRecordsAndDisposesTheExtraRecord()
    {
        var records = Enumerable.Range(0, 2101).Reverse().Select(i => new Record(i, i == 2100 ? "skip" : "match")).ToArray();
        var index = 0;
        var text = SystemDiagnostics.ExportRecords(() => index < records.Length ? records[index++] : null,
            r => r.Message, (r, _) => "event=" + r.Id, ["match"]);
        Assert.StartsWith("event=2099" + Environment.NewLine, text, StringComparison.Ordinal);
        Assert.Contains("event=100" + Environment.NewLine, text, StringComparison.Ordinal);
        Assert.DoesNotContain("event=99" + Environment.NewLine, text, StringComparison.Ordinal);
        Assert.Contains("усечён", text, StringComparison.Ordinal);
        Assert.Equal(2002, index);
        Assert.All(records.Take(index), r => Assert.True(r.Disposed));
    }

    private sealed class Record(int id, string message) : IDisposable
    {
        public int Id { get; } = id;
        public string Message { get; } = message;
        public bool Disposed { get; private set; }
        public void Dispose() => Disposed = true;
    }

    private sealed class NeverEndingStream : Stream
    {
        public int BytesRead { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => 0; // Начальная длина не гарантирует конечного EOF.
        public override long Position { get => BytesRead; set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) { Array.Clear(buffer, offset, count); BytesRead += count; return count; }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
