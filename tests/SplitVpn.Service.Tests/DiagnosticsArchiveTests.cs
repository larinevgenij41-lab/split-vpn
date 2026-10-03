using System.IO.Compression;
using System.Security.Cryptography;
using Microsoft.Extensions.Time.Testing;
using SplitVpn.Core.Diagnostics;
using SplitVpn.Core.Ipc;
using SplitVpn.Service.Diagnostics;

namespace SplitVpn.Service.Tests;

public sealed class DiagnosticsArchiveTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "splitvpn-diag-tests", Guid.NewGuid().ToString("N"));
    private readonly FakeTimeProvider _time = new(DateTimeOffset.UtcNow);
    private readonly ServicePaths _paths;

    public DiagnosticsArchiveTests()
    {
        _paths = new ServicePaths(Path.Combine(_root, "data"));
        Directory.CreateDirectory(_paths.Logs);
        Directory.CreateDirectory(_paths.Update);
    }

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact]
    public void Collector_TakesLogsFilesAndUserLogsButNeverSecrets()
    {
        var now = _time.GetUtcNow().UtcDateTime;
        Write(Path.Combine(_paths.Logs, "service-20260929.log"), "свежий", now);
        Write(Path.Combine(_paths.Logs, "service-20260901.log"), "старый", now - TimeSpan.FromDays(10));
        Write(Path.Combine(_paths.Logs, "verbose-20260929.log"), "подробный", now);
        Write(Path.Combine(_paths.Logs, "dns-20260929.log"), "A example.com", now);
        Write(_paths.Secrets, "СЕКРЕТ", now);
        Write(_paths.State, "{}", now);
        for (var i = 0; i < 5; i++)
        {
            Write(Path.Combine(_paths.Update, $"install-{i}.log"), "msi", now - TimeSpan.FromHours(i));
        }

        var profile = Path.Combine(_root, "Users", "second");
        var uiFolder = Path.Combine(profile, "AppData", "Local", "SplitVpn");
        Write(Path.Combine(uiFolder, "ui-verbose.log"), "отказ службы", now);
        using (var huge = new FileStream(Path.Combine(uiFolder, "ui-huge.log"), FileMode.Create))
        {
            huge.SetLength(DiagnosticsCollector.MaxUserFileBytes + 1);
        }

        for (var i = 0; i < 6; i++)
        {
            Write(Path.Combine(uiFolder, $"ui-extra{i}.log"), "x", now - TimeSpan.FromMinutes(i + 1));
        }

        using (var stream = new FileStream(Path.Combine(_root, "service.zip"), FileMode.Create))
        {
            var collector = new DiagnosticsCollector(_paths, _time,
                () => [new DiagnosticsPart("system/info.txt", () => "Windows"), new DiagnosticsPart("net/wfp.json", () => throw new InvalidOperationException("BFE недоступна"))],
                () => [new UserProfileFolder("second", profile)]);
            var problems = collector.Write(stream, [new DiagnosticsPart("status.json", () => "{}")]);

            Assert.Contains(problems, p => p.StartsWith("net/wfp.json: InvalidOperationException", StringComparison.Ordinal));
        }

        using var zip = ZipFile.OpenRead(Path.Combine(_root, "service.zip"));
        var names = zip.Entries.Select(e => e.FullName).ToHashSet();
        Assert.Contains("status.json", names);
        Assert.Contains("system/info.txt", names);
        Assert.Contains("logs/service-20260929.log", names);
        Assert.Contains("logs/verbose-20260929.log", names);
        Assert.Contains("logs/dns-20260929.log", names);
        Assert.Contains("files/state.json", names);
        Assert.Contains("users/second/ui-verbose.log", names);
        Assert.DoesNotContain("users/second/ui-huge.log", names);
        // Под предел в четыре самых новых попал и сверхбольшой файл — он пропущен, остаются три.
        Assert.Equal(DiagnosticsCollector.MaxUserFilesPerPattern - 1, names.Count(n => n.StartsWith("users/second/ui-", StringComparison.Ordinal) && n.EndsWith(".log", StringComparison.Ordinal)));
        Assert.Contains("service-manifest.json", names);
        Assert.DoesNotContain("logs/service-20260901.log", names);
        Assert.DoesNotContain(names, n => n.Contains("secrets", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(3, names.Count(n => n.StartsWith("files/update/install-", StringComparison.Ordinal)));
        Assert.All(zip.Entries, e =>
        {
            using var reader = new StreamReader(e.Open());
            Assert.DoesNotContain("СЕКРЕТ", reader.ReadToEnd(), StringComparison.Ordinal);
        });
    }

    [Fact]
    public void Packages_AreReadInChunksAndDeletedAfterTheLast()
    {
        var packages = new DiagnosticsPackages(Path.Combine(_root, "diag"), _time);
        var content = RandomNumberGenerator.GetBytes((DiagnosticsPackages.ChunkBytes * 2) + 12345);

        var package = packages.Create(stream =>
        {
            stream.Write(content);
            return ["пункт не собран"];
        })!;

        Assert.Equal(content.Length, package.Length);
        Assert.Equal(["пункт не собран"], package.Problems);
        var received = new List<byte>();
        DiagnosticsChunkDto chunk;
        do
        {
            chunk = packages.Read(package.Token, received.Count)!;
            received.AddRange(chunk.Data);
        }
        while (!chunk.Last);

        Assert.Equal(content, received.ToArray());
        Assert.Equal(package.Sha256, Convert.ToHexStringLower(SHA256.HashData(received.ToArray())));
        Assert.Null(packages.Read(package.Token, 0));
        Assert.Empty(Directory.GetFiles(Path.Combine(_root, "diag")));
    }

    [Fact]
    public void Packages_RejectForeignTokensConcurrentBuildsAndExpiredArchives()
    {
        var packages = new DiagnosticsPackages(Path.Combine(_root, "diag"), _time);
        DiagnosticsPackageDto? nested = new("x", 0, "", []);

        var package = packages.Create(stream =>
        {
            nested = packages.Create(_ => []);
            stream.Write([1, 2, 3]);
            return [];
        })!;

        Assert.Null(nested);
        Assert.Null(packages.Read("../../settings", 0));
        Assert.Null(packages.Read(new string('0', 32), 0));
        Assert.Null(packages.Read(package.Token, 99));

        _time.Advance(DiagnosticsPackages.Lifetime + TimeSpan.FromMinutes(1));
        Assert.Null(packages.Read(package.Token, 0));
    }

    [Fact]
    public async Task Archive_MergesServicePartUnderServiceAndAddsClientFiles()
    {
        var packages = new DiagnosticsPackages(Path.Combine(_root, "diag"), _time);
        var uiLog = Path.Combine(_root, "ui-verbose.log");
        await File.WriteAllTextAsync(uiLog, "подключение к каналу", TestContext.Current.CancellationToken);
        var output = Path.Combine(_root, "out.zip");

        var result = await DiagnosticsArchive.BuildAsync((request, _) => Task.FromResult(request switch
        {
            CollectDiagnosticsRequest => IpcResponse.Success(packages.Create(stream =>
            {
                using var zip = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true);
                using (var writer = new StreamWriter(zip.CreateEntry("logs/verbose-1.log").Open()))
                {
                    writer.Write("IPC отказ");
                }

                return ["eventlog: нет доступа"];
            })),
            ReadDiagnosticsChunkRequest chunk => IpcResponse.Success(packages.Read(chunk.Token, chunk.Offset)),
            _ => IpcResponse.Failure(IpcErrorCodes.BadRequest, "?"),
        }), [new ArchiveFile("ui/ui-verbose.log", uiLog), new ArchiveFile("ui/environment.json", Text: "{}"), new ArchiveFile("ui/нет.log", Path.Combine(_root, "нет.log"))],
            output, null, TestContext.Current.CancellationToken);

        Assert.True(result.ServiceIncluded);
        Assert.Contains("служба: eventlog: нет доступа", result.Problems);
        using var archive = ZipFile.OpenRead(output);
        var names = archive.Entries.Select(e => e.FullName).ToHashSet();
        Assert.Equal(["README.txt", "manifest.json", "service/logs/verbose-1.log", "ui/environment.json", "ui/ui-verbose.log"], names.Order(StringComparer.Ordinal));
        Assert.False(File.Exists(output + ".part"));
    }

    [Fact]
    public async Task Archive_WithoutServiceExplainsWhy()
    {
        var output = Path.Combine(_root, "denied.zip");

        var result = await DiagnosticsArchive.BuildAsync(
            (_, _) => Task.FromResult(IpcResponse.Failure(IpcErrorCodes.Denied, "Управление службой доступно только администратору компьютера.")),
            [new ArchiveFile("ui/environment.json", Text: "{\"administrators\":\"нет\"}")], output, null, TestContext.Current.CancellationToken);

        Assert.False(result.ServiceIncluded);
        using var archive = ZipFile.OpenRead(output);
        using var reader = new StreamReader(archive.GetEntry("service-missing.txt")!.Open());
        Assert.Contains("denied", await reader.ReadToEndAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
        Assert.NotNull(archive.GetEntry("ui/environment.json"));
    }

    private static void Write(string path, string text, DateTime lastWriteUtc)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, text);
        File.SetLastWriteTimeUtc(path, lastWriteUtc);
    }
}
