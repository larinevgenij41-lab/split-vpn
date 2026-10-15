using Microsoft.Extensions.Time.Testing;
using SplitVpn.Core.Diagnostics;

namespace SplitVpn.Core.Tests.Diagnostics;

public sealed class RollingTextLogTests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "splitvpn-rolling-tests", Guid.NewGuid().ToString("N"));
    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 9, 29, 10, 0, 0, TimeSpan.Zero));

    private string LogPath => Path.Combine(_folder, "ui-verbose.log");

    public void Dispose()
    {
        if (Directory.Exists(_folder))
        {
            Directory.Delete(_folder, recursive: true);
        }
    }

    [Fact]
    public void LineHasTimeProcessCategoryAndText()
    {
        new RollingTextLog(LogPath, _time).Write("Ipc", "подключено к SplitVpn.Control.1");

        var line = File.ReadAllText(LogPath);
        Assert.Contains($"[{Environment.ProcessId}] Ipc: подключено к SplitVpn.Control.1", line, StringComparison.Ordinal);
        Assert.StartsWith(_time.GetLocalNow().ToString("yyyy-MM-dd HH:mm:ss.fff", System.Globalization.CultureInfo.InvariantCulture), line, StringComparison.Ordinal);
    }

    [Fact]
    public void RotatesOnceIntoDotOne()
    {
        var log = new RollingTextLog(LogPath, _time, maxBytes: 200);
        for (var i = 0; i < 20; i++)
        {
            log.Write("Ui", "строка " + i);
        }

        Assert.True(File.Exists(LogPath + ".1"));
        Assert.True(new FileInfo(LogPath).Length < 400);
        Assert.Contains("строка 19", File.ReadAllText(LogPath), StringComparison.Ordinal);
    }

    [Fact]
    public void FileOpenByAnotherWriterDoesNotBreakLogging()
    {
        var log = new RollingTextLog(LogPath, _time);
        log.Write("Ui", "первая");
        using (new FileStream(LogPath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete))
        {
            log.Write("Ui", "вторая");
        }

        Assert.Contains("вторая", File.ReadAllText(LogPath), StringComparison.Ordinal);
    }

    [Fact]
    public void RegistryTermIsParsedCappedAndExpired()
    {
        var now = _time.GetUtcNow();
        Assert.Null(VerboseRegistry.Effective(null, now));
        Assert.Null(VerboseRegistry.Effective("мусор", now));
        Assert.Null(VerboseRegistry.Effective(VerboseRegistry.Format(now - TimeSpan.FromSeconds(1)), now));
        Assert.Equal(now + TimeSpan.FromHours(2), VerboseRegistry.Effective(VerboseRegistry.Format(now + TimeSpan.FromHours(2)), now));
        Assert.Equal(now + VerboseRegistry.MaxDuration, VerboseRegistry.Effective(VerboseRegistry.Format(now + TimeSpan.FromDays(9)), now));
    }
}

public sealed class LogTextTests
{
    [Theory]
    [InlineData("https://idp.example.org/adfs/ls/?SAMLRequest=abc&RelayState=xyz", "https://idp.example.org/adfs/ls/?…")]
    [InlineData("https://vpn.example.org:8443/+CSCOE+/saml/sp/acs#token=1", "https://vpn.example.org:8443/+CSCOE+/saml/sp/acs?…")]
    [InlineData("https://vpn.example.org/", "https://vpn.example.org/")]
    [InlineData("https://user:secret@mirror.example.org/list.txt", "https://mirror.example.org/list.txt")]
    [InlineData("не адрес", "<неразбираемый адрес>")]
    [InlineData(null, "<неразбираемый адрес>")]
    public void UrlForLog_DropsQueryAndFragment(string? url, string expected) => Assert.Equal(expected, LogText.UrlForLog(url));

    [Fact]
    public void StripUrls_CleansEveryAddressInJson() => Assert.Equal(
        "{\"mirrors\":[\"https://a.example/x?…\",\"http://b.example/y\"]}",
        LogText.StripUrls("{\"mirrors\":[\"https://a.example/x?token=1\",\"http://u:p@b.example/y\"]}"));
}
