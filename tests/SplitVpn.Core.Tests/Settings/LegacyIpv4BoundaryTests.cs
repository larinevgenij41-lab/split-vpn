using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Settings;

/// <summary>
/// Приведение IPv4 с ведущими нулями из старых настроек. Контракт: однозначные октеты (восьмеричное = десятичное)
/// приводятся, неоднозначные оставляются и попадают в предупреждение; меняется только хост поля; повторное
/// приведение ничего не меняет; без изменений возвращается тот же объект.
/// </summary>
public sealed class LegacyIpv4BoundaryTests
{
    [Theory]
    [InlineData("001.002.003.004", "1.2.3.4")]
    [InlineData("007.000.00.0", "7.0.0.0")]
    [InlineData("0000000001.1.1.1", "1.1.1.1")]
    [InlineData("001.1.1.1:0053", "1.1.1.1:0053")]
    [InlineData("001.1.1.1/024", "1.1.1.1/024")]
    [InlineData("https://001.1.1.1", "https://1.1.1.1")]
    [InlineData("https://u:p@001.1.1.1:8443/x?y#z", "https://u:p@1.1.1.1:8443/x?y#z")]
    [InlineData("a@b@001.1.1.1", "a@b@1.1.1.1")]
    [InlineData("\t001.1.1.1\r\n", "\t1.1.1.1\r\n")]
    [InlineData("001.1.1.1 :53", "1.1.1.1 :53")]
    public void UnambiguousHosts_AreCanonicalized(string text, string expected)
    {
        var ambiguous = new List<string>();

        Assert.Equal(expected, LegacyIpv4.Canonicalize(text, ambiguous));
        Assert.Empty(ambiguous);
    }

    [Theory]
    [InlineData("://")]
    [InlineData("http://")]
    [InlineData("@")]
    [InlineData(":")]
    [InlineData("?")]
    [InlineData("#")]
    [InlineData("   ")]
    [InlineData("@:/")]
    [InlineData("https://@")]
    [InlineData("001.1.1.1.")]
    [InlineData(".001.1.1.1")]
    [InlineData("001..1.1")]
    [InlineData("[001.1.1.1]")]
    [InlineData("001.1.1.1\u0000")]
    [InlineData("\u0661.1.1.1")]
    [InlineData("a/b://001.1.1.1")]
    public void DegenerateInput_IsLeftUntouched_WithoutThrowing(string text)
    {
        var ambiguous = new List<string>();

        Assert.Equal(text, LegacyIpv4.Canonicalize(text, ambiguous));
        Assert.Empty(ambiguous);
    }

    [Theory]
    [InlineData("010.0.0.1")]
    [InlineData("1.1.1.010")]
    [InlineData("0377.0.0.1")]
    [InlineData("001.010.0.1")]
    public void AmbiguousOctet_AnywhereInHost_LeavesWholeStringAndReportsIt(string text)
    {
        var ambiguous = new List<string>();

        Assert.Equal(text, LegacyIpv4.Canonicalize(text, ambiguous));
        Assert.Equal([text], ambiguous);
    }

    [Theory]
    [InlineData("001.002.003.004")]
    [InlineData("https://u@007.0.0.1:0443/01.02")]
    [InlineData("010.0.0.1")]
    public void Canonicalize_IsIdempotent(string text)
    {
        var once = LegacyIpv4.Canonicalize(text, new List<string>());

        Assert.Equal(once, LegacyIpv4.Canonicalize(once, new List<string>()));
    }

    [Fact]
    public void Settings_EveryIpv4Field_IsCanonicalized_AndCheckTargetSeparatorsKept()
    {
        var profile = new ConnectionProfile { Name = "VPN", Server = "001.002.003.004", UserName = "u" };
        var settings = new AppSettings
        {
            Profiles = [profile],
            UpstreamDns = ["008.8.8.8", "001.1.1.1"],
            LocalDnsServer = "192.168.001.001",
            CheckTargets = new CheckTargets { Foreign = "001.1.1.1:443 ; 1.0.0.01:80", Russian = "\t007.88.8.8:53," },
        };

        var result = LegacyIpv4.Canonicalize(settings, out var warning);

        Assert.Null(warning);
        Assert.Equal("1.2.3.4", Assert.Single(result.Profiles).Server);
        Assert.Equal(["008.8.8.8", "1.1.1.1"], result.UpstreamDns);
        Assert.Equal("192.168.1.1", result.LocalDnsServer);
        Assert.Equal("1.1.1.1:443 ; 1.0.0.1:80", result.CheckTargets.Foreign);
        Assert.Equal("\t7.88.8.8:53,", result.CheckTargets.Russian);
    }

    [Fact]
    public void Settings_AmbiguousCheckTarget_IsReportedOncePerDistinctValue()
    {
        var settings = new AppSettings
        {
            UpstreamDns = ["010.0.0.1", "010.0.0.1"],
            CheckTargets = new CheckTargets { Foreign = "010.0.0.1:443", Russian = "1.1.1.1:443" },
        };

        var result = LegacyIpv4.Canonicalize(settings, out var warning);

        Assert.NotNull(warning);
        Assert.Equal(1, CountOf(warning, "«010.0.0.1»"));
        Assert.Equal(1, CountOf(warning, "«010.0.0.1:443»"));
        Assert.Equal("010.0.0.1:443", result.CheckTargets.Foreign);
    }

    [Fact]
    public void Settings_NothingToChange_ReturnsSameInstance()
    {
        var settings = new AppSettings
        {
            Profiles = [new ConnectionProfile { Name = "VPN", Server = "vpn.example.org", UserName = "u" }],
            UpstreamDns = ["1.1.1.1"],
            CheckTargets = new CheckTargets { Foreign = "1.1.1.1:443, 1.0.0.1:80", Russian = "" },
        };

        Assert.Same(settings, LegacyIpv4.Canonicalize(settings, out var warning));
        Assert.Null(warning);
    }

    private static int CountOf(string text, string part)
    {
        var count = 0;
        for (var at = text.IndexOf(part, StringComparison.Ordinal); at >= 0; at = text.IndexOf(part, at + part.Length, StringComparison.Ordinal))
        {
            count++;
        }

        return count;
    }
}
