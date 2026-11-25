using System.Text;
using SplitVpn.Cli;
using SplitVpn.Cli.Proto;

namespace SplitVpn.Service.Tests;

/// <summary>Ревью 24.11, утилита разработки: остановленная служба для сценариев, отчёты, pktmon, secret-scan, ключ выпуска.</summary>
public sealed class CliReviewNov24Tests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("splitvpn-cli-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    [Fact]
    public void ScenariosRequireStoppedService()
    {
        Assert.Null(ProtoContext.ServiceRunningProblem(0, null));
        Assert.Contains("Остановите службу", ProtoContext.ServiceRunningProblem(1234, null), StringComparison.Ordinal);
        // Состояние не узнали: сценарий не запускается.
        Assert.Contains("отказано", ProtoContext.ServiceRunningProblem(null, "отказано"), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(@"corp\ivan")]
    [InlineData("vpn\"quoted\".example")]
    [InlineData("ivan")]
    public void ReportMasksJsonEscapedSecrets(string secret)
    {
        var json = System.Text.Json.JsonSerializer.Serialize(new { Log = new[] { "вход " + secret + " выполнен" } }, SplitVpn.Core.Settings.JsonDefaults.Options);
        var masked = ScenarioReport.Mask(json, [secret, null, " "]);

        Assert.Contains("<скрыто>", masked, StringComparison.Ordinal);
        Assert.DoesNotContain("ivan", masked, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("quoted", masked, StringComparison.Ordinal);
        // Маскировка не ломает JSON.
        using var document = System.Text.Json.JsonDocument.Parse(masked);
    }

    [Fact]
    public void PktmonParseToleratesUnexpectedShapes()
    {
        var groups = PktmonProbe.Parse("""[{"Group":"Wi-Fi"},{"Group":"Ethernet","Components":[{"Counters":[{"Outbound":{"Packets":5}},{"Inbound":"x"}]}]},7]""", out var problem);
        Assert.Null(problem);
        Assert.Equal(2, groups.Count);
        Assert.Equal(new PktmonGroupCount("Wi-Fi", 0, 0, 0, 0), groups[0]);
        Assert.Equal(5, groups[1].OutboundFlowPackets);

        Assert.Empty(PktmonProbe.Parse("""{"Components":[]}""", out problem));
        Assert.NotNull(problem);
        Assert.Empty(PktmonProbe.Parse("Нет данных", out problem));
        Assert.NotNull(problem);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(31)]
    public void SecretScanFindsNeedleAcrossBlockBoundary(int offset)
    {
        var needle = Encoding.UTF8.GetBytes("пароль");
        var content = new byte[64];
        needle.CopyTo(content, offset);
        using var stream = new MemoryStream(content);
        using var empty = new MemoryStream(new byte[64]);
        using var again = new MemoryStream(content);

        Assert.True(DevCommands.StreamContains(stream, [needle], blockSize: 8));
        Assert.False(DevCommands.StreamContains(empty, [needle], blockSize: 8));
        Assert.False(DevCommands.StreamContains(again, [[]], blockSize: 8));
    }

    [Fact]
    public async Task ReleaseSignWithMissingPasswordFileIsUsageError()
    {
        var missing = Path.Combine(_directory, "нет-такого.txt");
        var args = new CliArgs(["--manifest", Path.Combine(_directory, "update.json"), "--key", Path.Combine(_directory, "key.pem"), "--password-file", missing]);

        var error = await Assert.ThrowsAsync<InputFileException>(() => ReleaseCommands.SignAsync(args));
        Assert.Equal(2, CliExit.ForException(error).Code);

        var keygen = await Assert.ThrowsAsync<InputFileException>(() => ReleaseCommands.KeygenAsync(new CliArgs(["--out", Path.Combine(_directory, "new.pem"), "--password-file", missing])));
        Assert.Equal(2, CliExit.ForException(keygen).Code);
        Assert.False(File.Exists(Path.Combine(_directory, "new.pem")));
    }

    [Fact]
    public void NewKeyIsWrittenWholeWithoutTemporaryLeftovers()
    {
        var path = Path.Combine(_directory, "release.pem");
        ReleaseCommands.WriteNewKey(path, "-----BEGIN ENCRYPTED PRIVATE KEY-----");
        Assert.Equal("-----BEGIN ENCRYPTED PRIVATE KEY-----", File.ReadAllText(path));

        Assert.Throws<IOException>(() => ReleaseCommands.WriteNewKey(path, "replacement"));
        Assert.Equal("-----BEGIN ENCRYPTED PRIVATE KEY-----", File.ReadAllText(path));
        Assert.Equal([path], Directory.GetFiles(_directory));
    }
}
