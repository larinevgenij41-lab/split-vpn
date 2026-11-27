using System.Globalization;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Dns;

/// <summary>
/// IsPublicZone и IsTopLevelDomain принимают имя после SettingsSerializer.NormalizeSuffix (нижний регистр, IDNA,
/// без точек по краям). Контракт проверяется через ту же нормализацию, что в проверке настроек: регистр, точка в
/// конце и запись Unicode/punycode не меняют ответа.
/// </summary>
public sealed class PublicSuffixesBoundaryTests
{
    private static bool TopLevel(string suffix) => PublicSuffixes.IsTopLevelDomain(SettingsSerializer.NormalizeSuffix(suffix));

    private static bool PublicZone(string suffix) => PublicSuffixes.IsPublicZone(SettingsSerializer.NormalizeSuffix(suffix));

    [Theory]
    [InlineData("com")]
    [InlineData("COM")]
    [InlineData("com.")]
    [InlineData(".com")]
    [InlineData(" Com. ")]
    [InlineData("ru")]
    [InlineData("RU")]
    [InlineData("de")]
    [InlineData("arpa")]
    [InlineData("рф")]
    [InlineData("РФ.")]
    [InlineData("xn--p1ai")]
    [InlineData("XN--P1AI")]
    [InlineData("рус")]
    [InlineData("москва")]
    [InlineData("онлайн")]
    [InlineData("сайт")]
    public void TopLevel_Recognized_AfterNormalization(string suffix) => Assert.True(TopLevel(suffix));

    [Theory]
    [InlineData("")]
    [InlineData(".")]
    [InlineData("lan")]
    [InlineData("local")]
    [InlineData("corp")]
    [InlineData("home.arpa")]
    [InlineData("example.com")]
    [InlineData("r")]
    [InlineData("r1")]
    [InlineData("12")]
    [InlineData("a-")]
    [InlineData("xn--")]
    [InlineData("comm")]
    public void TopLevel_NotRecognized(string suffix) => Assert.False(TopLevel(suffix));

    /// <summary>Кириллические TLD в списке записаны в IDNA вручную: они должны совпадать с тем, что даёт нормализация.</summary>
    [Theory]
    [InlineData("рф", "xn--p1ai")]
    [InlineData("рус", "xn--p1acf")]
    [InlineData("москва", "xn--80adxhks")]
    [InlineData("онлайн", "xn--80asehdb")]
    [InlineData("сайт", "xn--80aswg")]
    public void CyrillicTopLevel_MatchesIdnaEncoding(string unicode, string ascii) =>
        Assert.Equal(ascii, new IdnMapping().GetAscii(unicode));

    /// <summary>Двухбуквенная метка - код страны только из латиницы: кириллица из двух букв в Unicode-виде не проходит.</summary>
    [Theory]
    [InlineData("ру", false)]
    [InlineData("ab", true)]
    [InlineData("AB", true)]
    public void TwoLetterLabel_OnlyAsciiLettersCount(string normalized, bool expected) =>
        Assert.Equal(expected, PublicSuffixes.IsTopLevelDomain(normalized));

    [Theory]
    [InlineData("co.uk")]
    [InlineData("CO.UK")]
    [InlineData("co.uk.")]
    [InlineData(" Com.Ru ")]
    [InlineData("msk.ru")]
    [InlineData("com.ua")]
    public void PublicZone_Recognized_AfterNormalization(string suffix) => Assert.True(PublicZone(suffix));

    [Theory]
    [InlineData("")]
    [InlineData("uk")]
    [InlineData("example.co.uk")]
    [InlineData("co.uk.com")]
    [InlineData("co..uk")]
    [InlineData("co.u")]
    public void PublicZone_NotRecognized(string suffix) => Assert.False(PublicZone(suffix));

    /// <summary>Без нормализации (как вызывать нельзя) регистр не мешает, а точка в конце и Unicode - мешают.</summary>
    [Theory]
    [InlineData("CO.UK", true)]
    [InlineData("co.uk.", false)]
    public void PublicZone_RawInput_IsCaseInsensitiveOnly(string raw, bool expected) =>
        Assert.Equal(expected, PublicSuffixes.IsPublicZone(raw));

    /// <summary>Турецкая культура: «I» в нижнем регистре там «ı». Нормализация инвариантная, ответ тот же.</summary>
    [Theory]
    [InlineData("INFO")]
    [InlineData("BIZ")]
    [InlineData("MIL")]
    [InlineData("INT")]
    [InlineData("SITE")]
    [InlineData("LINK")]
    public void Normalization_IsCultureInvariant_ForDottedI(string suffix)
    {
        TestCulture.AssertSameUnderAll(() => TopLevel(suffix));
        Assert.True(TestCulture.Run(CultureInfo.GetCultureInfo("tr-TR"), () => TopLevel(suffix)));
    }

    /// <summary>Локальный суффикс-TLD («com») - предупреждение проверки настроек, обычный локальный («lan») - нет.</summary>
    [Theory]
    [InlineData("com", true)]
    [InlineData("РФ", true)]
    [InlineData("co.uk.", true)]
    [InlineData("lan", false)]
    [InlineData("home.arpa", false)]
    [InlineData("corp.example.org", false)]
    public void Validator_WarnsForPublicLocalSuffix(string suffix, bool warned)
    {
        var result = SettingsValidator.Validate(new AppSettings { LocalDnsSuffixes = [suffix] });

        Assert.Equal(warned, result.Warnings.Any(w => w.Contains(suffix, StringComparison.Ordinal) && w.Contains("публичная зона", StringComparison.Ordinal)));
    }
}
