using System.Text.Json;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Settings;

/// <summary>Чтение служебных файлов и атомарная запись: повреждение не роняет службу, записи не мешают друг другу.</summary>
public sealed class SafeFileTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "splitvpn-tests", Guid.NewGuid().ToString("N"));

    public SafeFileTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private sealed record Sample(string Name);

    [Fact]
    public void MissingFile_GivesDefault_WithoutReport()
    {
        var found = new List<CorruptFile>();

        var value = Load(Path.Combine(_root, "нет.json"), found);

        Assert.Equal("по умолчанию", value.Name);
        Assert.Empty(found);
    }

    [Fact]
    public void GoodFile_IsParsed()
    {
        var path = Path.Combine(_root, "good.json");
        File.WriteAllText(path, """{"name":"значение"}""");
        var found = new List<CorruptFile>();

        Assert.Equal("значение", Load(path, found).Name);
        Assert.Empty(found);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("{сломано")]
    [InlineData("null")]
    [InlineData("\0\0\0\0")]
    public void BadFile_IsQuarantined_AndReported(string content)
    {
        var path = Path.Combine(_root, "state.json");
        File.WriteAllText(path, content);
        var found = new List<CorruptFile>();

        var value = Load(path, found);

        Assert.Equal("по умолчанию", value.Name);
        Assert.False(File.Exists(path));
        var file = Assert.Single(found);
        Assert.Equal(path, file.FilePath);
        Assert.StartsWith(path + ".corrupt-", file.CopyPath, StringComparison.Ordinal);
        Assert.True(File.Exists(file.CopyPath));
        Assert.Contains("копия: state.json.corrupt-", file.Describe(), StringComparison.Ordinal);
    }

    [Fact]
    public void SecondBadFile_GetsItsOwnCopy()
    {
        var path = Path.Combine(_root, "state.json");
        var found = new List<CorruptFile>();
        File.WriteAllText(path, "{сломано");
        Load(path, found);
        File.WriteAllText(path, "{сломано ещё раз");
        Load(path, found);

        Assert.Equal(2, found.Count);
        Assert.Equal(2, found.Select(f => f.CopyPath).Distinct(StringComparer.Ordinal).Count());
        Assert.All(found, f => Assert.True(File.Exists(f.CopyPath)));
    }

    [Fact]
    public void CorruptFileLog_ReportsEachFileOnce()
    {
        var log = new CorruptFileLog();
        var reported = new List<CorruptFile>();
        log.Reported = reported.Add;

        log.Add(new CorruptFile(@"C:\данные\state.json", null, "повреждён", "ошибка"));
        log.Add(new CorruptFile(@"C:\данные\state.json", null, "повреждён", "ошибка"));
        log.Add(new CorruptFile(@"C:\данные\secrets.bin", null, "повреждён", "ошибка"));

        Assert.Equal(2, reported.Count);
        Assert.Equal(2, log.All.Count);
        Assert.Contains("копию повреждённого файла сохранить не удалось", reported[0].Describe(), StringComparison.Ordinal);
    }

    [Fact]
    public void AtomicWrite_DoesNotDependOnCommonTempFile()
    {
        var path = Path.Combine(_root, "settings.json");
        // Так выглядит общий временный файл прежней записи, который держит другой процесс (например, recover).
        using var busy = new FileStream(path + ".tmp", FileMode.Create, FileAccess.Write, FileShare.None);

        AtomicFile.WriteAllText(path, "настройки");

        Assert.Equal("настройки", File.ReadAllText(path));
        Assert.Empty(Directory.GetFiles(_root, "settings.json.*-*.tmp"));
    }

    private static Sample Load(string path, List<CorruptFile> found) => SafeFile.Load(
        path,
        text => JsonSerializer.Deserialize<Sample>(text, JsonDefaults.Options),
        () => new Sample("по умолчанию"),
        "Пробный файл повреждён",
        found.Add);
}
