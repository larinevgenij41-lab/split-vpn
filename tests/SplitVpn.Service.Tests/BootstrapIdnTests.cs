using SplitVpn.Core.Net;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Начальное разрешение сервера с именем на национальном алфавите: в hosts имя бывает записано и по-русски,
/// и в Punycode, а в настройках — как ввёл пользователь. Совпадать должны оба написания.
/// </summary>
public sealed class BootstrapIdnTests
{
    private const string Unicode = "vpn.пример.рф";
    private const string Punycode = "vpn.xn--e1afmkfd.xn--p1ai";

    [Theory]
    [InlineData(Punycode, Unicode)]
    [InlineData(Unicode, Punycode)]
    [InlineData(Unicode, Unicode)]
    [InlineData("VPN.XN--E1AFMKFD.XN--P1AI.", "Vpn.Пример.рф")]
    public void HostsFile_MatchesUnicodeAndPunycodeSpellings(string inFile, string asked)
    {
        var lines = new[] { "# пример", "192.0.2.10 " + inFile + " # сервер", "192.0.2.11 other.example" };

        Assert.Equal([Ipv4.Parse("192.0.2.10")], HostsFile.Parse(lines, asked));
    }

    [Fact]
    public void HostsFile_DoesNotMatchAnotherIdnName()
    {
        var lines = new[] { "192.0.2.10 vpn.другой.рф", "192.0.2.12 vpn..рф" };

        Assert.Empty(HostsFile.Parse(lines, Unicode));
    }

    [Fact]
    public async Task Resolve_InvalidIdnName_ReturnsEmptyInsteadOfThrowing()
    {
        // Имя не переводится в IDNA: ни hosts, ни сеть не опрашиваются, исключения нет.
        var result = await BootstrapResolver.ResolveAsync("vpn..рф", [Ipv4.Parse("192.0.2.53")], null, TestContext.Current.CancellationToken);

        Assert.Empty(result);
    }
}
