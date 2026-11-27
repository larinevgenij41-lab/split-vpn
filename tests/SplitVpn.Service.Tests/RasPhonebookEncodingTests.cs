using System.Text;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Политика IKEv2 дописывается в файл телефонной книги в той кодировке, в которой его хранит RAS (ANSI, UTF-16 с
/// BOM, UTF-8): раздел записи с кириллическим именем находится, а остальные записи, BOM и переводы строк остаются
/// побайтно.
/// </summary>
public sealed class RasPhonebookEncodingTests : IDisposable
{
    private const string Policy = "020000000400000003000000060000000300000000000000";

    private readonly string _directory = Path.Combine(Path.GetTempPath(), "splitvpn-pbk-" + Guid.NewGuid().ToString("N"));

    public RasPhonebookEncodingTests() => Directory.CreateDirectory(_directory);

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private static string Original(string newline) => string.Join(newline,
        "[Склад]", "Encoding=1", "PhoneNumber=склад.пример.рф", "",
        "[Офис]", "Encoding=1", "DataEncryption=8", "PhoneNumber=vpn.пример.рф", "",
        "[Дом]", "Encoding=1", "PhoneNumber=дом.пример.рф", "");

    private static string Expected(string newline) => string.Join(newline,
        "[Склад]", "Encoding=1", "PhoneNumber=склад.пример.рф", "",
        "[Офис]", "Encoding=1", "DataEncryption=256", "PhoneNumber=vpn.пример.рф", "NumCustomPolicy=1", "CustomIPSecPolicies=" + Policy, "",
        "[Дом]", "Encoding=1", "PhoneNumber=дом.пример.рф", "");

    private string Write(byte[] bytes)
    {
        var path = Path.Combine(_directory, "book.pbk");
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private static byte[] WithPreamble(byte[] preamble, byte[] body) => [.. preamble, .. body];

    [Fact]
    public void Ansi1251_SectionFound_EncodingAndOtherEntriesKept()
    {
        var cp1251 = CodePagesEncodingProvider.Instance.GetEncoding(1251)!;
        var path = Write(cp1251.GetBytes(Original("\r\n")));

        RasPhonebook.ApplyIkev2Policy(path, "Офис", ansiCodePage: 1251);

        Assert.Equal(cp1251.GetBytes(Expected("\r\n")), File.ReadAllBytes(path));
    }

    [Fact]
    public void Utf16LeWithBom_SectionFound_BomAndLineEndingsKept()
    {
        var utf16 = new UnicodeEncoding(bigEndian: false, byteOrderMark: false);
        var path = Write(WithPreamble([0xFF, 0xFE], utf16.GetBytes(Original("\r\n"))));

        RasPhonebook.ApplyIkev2Policy(path, "Офис", ansiCodePage: 1251);

        Assert.Equal(WithPreamble([0xFF, 0xFE], utf16.GetBytes(Expected("\r\n"))), File.ReadAllBytes(path));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Utf8_WithOrWithoutBom_KeptAsIs(bool bom)
    {
        var utf8 = new UTF8Encoding(false);
        byte[] preamble = bom ? [0xEF, 0xBB, 0xBF] : [];
        var path = Write(WithPreamble(preamble, utf8.GetBytes(Original("\n"))));

        RasPhonebook.ApplyIkev2Policy(path, "Офис", ansiCodePage: 1251);

        Assert.Equal(WithPreamble(preamble, utf8.GetBytes(Expected("\n"))), File.ReadAllBytes(path));
    }

    [Fact]
    public void LastSectionWithoutTrailingNewline_GetsKeysOnNewLines()
    {
        var path = Write(Encoding.ASCII.GetBytes("[Other]\r\nType=2\r\n\r\n[Vpn]\r\nType=2"));

        RasPhonebook.ApplyIkev2Policy(path, "Vpn", ansiCodePage: 1251);

        Assert.Equal(
            "[Other]\r\nType=2\r\n\r\n[Vpn]\r\nType=2\r\nDataEncryption=256\r\nNumCustomPolicy=1\r\nCustomIPSecPolicies=" + Policy + "\r\n",
            File.ReadAllText(path));
    }

    [Fact]
    public void UnknownEncoding_FileUntouched_ClearError()
    {
        // Байты не UTF-8, BOM нет, ANSI-кодировки нет (системная страница — UTF-8): файл не трогается.
        var cp1251 = CodePagesEncodingProvider.Instance.GetEncoding(1251)!;
        var original = cp1251.GetBytes(Original("\r\n"));
        var path = Write(original);

        var error = Assert.Throws<InvalidOperationException>(() => RasPhonebook.ApplyIkev2Policy(path, "Офис", ansiCodePage: 65001));

        Assert.Contains("Кодировка телефонной книги", error.Message, StringComparison.Ordinal);
        Assert.Equal(original, File.ReadAllBytes(path));
    }

    [Fact]
    public void MissingEntry_FileUntouched()
    {
        var cp1251 = CodePagesEncodingProvider.Instance.GetEncoding(1251)!;
        var original = cp1251.GetBytes(Original("\r\n"));
        var path = Write(original);

        Assert.Throws<InvalidOperationException>(() => RasPhonebook.ApplyIkev2Policy(path, "Нет такой", ansiCodePage: 1251));
        Assert.Equal(original, File.ReadAllBytes(path));
        Assert.Single(Directory.GetFiles(_directory));
    }
}
