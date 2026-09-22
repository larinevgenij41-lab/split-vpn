using System.Text;
using SplitVpn.Core.Update;

namespace SplitVpn.Core.Tests.Update;

public class UpdateManifestTests
{
    private const string Sha = "3f2a1b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708";

    [Fact]
    public void Valid_IsParsed()
    {
        var release = Parse(Json()).Release;

        Assert.NotNull(release);
        Assert.Equal(new Version(0, 8, 1), release.Version);
        Assert.Equal("0.8.1", release.VersionText);
        Assert.Equal("v0.8.1", release.Manifest.Tag);
        Assert.Equal("SplitVpn-0.8.1.msi", release.Manifest.Package.FileName);
        Assert.Equal(new Version(0, 7, 0), release.MinUpgradable);
        Assert.Single(release.PackageUrls);
        Assert.Equal("sv-2026-09", release.Manifest.Kid);
    }

    /// <summary>Поля, которых эта версия не знает, разбор не ломают: манифест может обрасти новыми.</summary>
    [Fact]
    public void UnknownFields_AreIgnored()
    {
        var json = Json().Replace("\"schema\": 1,", "\"schema\": 1, \"channel\": \"stable\", \"extra\": {\"a\": 1},", StringComparison.Ordinal);

        Assert.NotNull(Parse(json).Release);
    }

    [Theory]
    // Схема новее известной: старая программа не должна толковать чужой формат.
    [InlineData("\"schema\": 1", "\"schema\": 2")]
    [InlineData("\"product\": \"SplitVpn\"", "\"product\": \"Other\"")]
    [InlineData("\"version\": \"0.8.1\"", "\"version\": \"не версия\"")]
    [InlineData("\"version\": \"0.8.1\"", "\"version\": \"0.8.1.2\"")]
    [InlineData("\"version\": \"0.8.1\"", "\"version\": \"v0.8.1\"")]
    [InlineData("\"minUpgradableVersion\": \"0.7.0\"", "\"minUpgradableVersion\": \"нет\"")]
    // Контрольная сумма: ровно 64 знака в нижнем регистре.
    [InlineData(Sha, "3f2a1b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70")]
    [InlineData(Sha, "3F2A1B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708")]
    [InlineData(Sha, "3f2a1b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70z")]
    [InlineData("\"size\": 64123456", "\"size\": 0")]
    [InlineData("\"size\": 64123456", "\"size\": -1")]
    [InlineData("\"size\": 64123456", "\"size\": 1073741824")]
    // Имя файла не должно уводить запись за пределы каталога обновлений.
    [InlineData("SplitVpn-0.8.1.msi", "..\\\\evil.msi")]
    [InlineData("SplitVpn-0.8.1.msi", "sub/SplitVpn.msi")]
    [InlineData("SplitVpn-0.8.1.msi", "SplitVpn-0.8.1.exe")]
    [InlineData("https://github.com/o/r/releases/download/v0.8.1/SplitVpn-0.8.1.msi", "http://github.com/o/r/x.msi")]
    [InlineData("\"https://github.com/o/r/releases/download/v0.8.1/SplitVpn-0.8.1.msi\"", "")]
    public void Invalid_IsRejectedWithReason(string original, string replacement)
    {
        var result = Parse(Json().Replace(original, replacement, StringComparison.Ordinal));

        Assert.Null(result.Release);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
    }

    [Fact]
    public void Oversized_IsRejectedBeforeParsing()
    {
        var padded = Json().Replace("\"notes\": \"Краткий список изменений.\"",
            "\"notes\": \"" + new string('я', 40_000) + "\"", StringComparison.Ordinal);

        Assert.Null(Parse(padded).Release);
    }

    [Fact]
    public void Empty_IsRejected() => Assert.Null(UpdateManifestParser.Parse([]).Release);

    [Fact]
    public void Garbage_IsRejected() => Assert.Null(Parse("{не json").Release);

    [Fact]
    public void KeyId_IsReadBeforeParsing()
    {
        Assert.Equal("sv-2026-09", UpdateManifestParser.ReadKeyId(Encoding.UTF8.GetBytes(Json())));
        Assert.Null(UpdateManifestParser.ReadKeyId(Encoding.UTF8.GetBytes("{не json")));
        Assert.Null(UpdateManifestParser.ReadKeyId(Encoding.UTF8.GetBytes("{\"schema\":1}")));
    }

    private static ManifestParseResult Parse(string json) => UpdateManifestParser.Parse(Encoding.UTF8.GetBytes(json));

    internal static string Json(string version = "0.8.1") => $$"""
        {
          "schema": 1,
          "product": "SplitVpn",
          "version": "{{version}}",
          "tag": "v{{version}}",
          "releasedUtc": "2026-09-28T09:15:00+00:00",
          "minUpgradableVersion": "0.7.0",
          "package": {
            "fileName": "SplitVpn-{{version}}.msi",
            "size": 64123456,
            "sha256": "{{Sha}}",
            "urls": ["https://github.com/o/r/releases/download/v{{version}}/SplitVpn-{{version}}.msi"]
          },
          "notes": "Краткий список изменений.",
          "notesUrl": "https://github.com/o/r/releases/tag/v{{version}}",
          "kid": "sv-2026-09"
        }
        """;
}
