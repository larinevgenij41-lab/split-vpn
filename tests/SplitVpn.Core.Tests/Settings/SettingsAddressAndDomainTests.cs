using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Settings;

/// <summary>Проверки адресов сервера и DNS и правил для доменов.</summary>
public class SettingsAddressAndDomainTests
{
    private static AppSettings Valid()
    {
        var profile = new ConnectionProfile { Name = "Германия", Server = "vpn.example.org", UserName = "user", Role = ProfileRole.Primary };
        return new AppSettings { Profiles = [profile], DefaultTarget = RouteTarget.Tunnel(profile.Id) };
    }

    private static IReadOnlyList<string> ServerErrors(string server)
    {
        var baseline = Valid();
        return SettingsValidator.Validate(baseline with { Profiles = [baseline.Profiles[0] with { Server = server }] }).Errors;
    }

    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("255.255.255.255")]
    [InlineData("127.0.0.1")]
    [InlineData("127.10.20.30")]
    public void Validator_RejectsServiceAddressesAsServer(string server)
    {
        Assert.Contains(ServerErrors(server), e => e.Contains("не может быть адресом VPN-сервера", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("203.0.113.10")]
    [InlineData("vpn.example.org")]
    public void Validator_AcceptsUsualServer(string server)
    {
        Assert.Empty(ServerErrors(server));
    }

    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("255.255.255.255")]
    public void Validator_RejectsServiceAddressesAsDns(string address)
    {
        var errors = SettingsValidator.Validate(Valid() with { UpstreamDns = [address] }).Errors;

        Assert.Contains(errors, e => e.Contains("служебным адресом", StringComparison.Ordinal));
    }

    [Fact]
    public void Validator_RejectsLoopbackAsLocalDnsServer()
    {
        var errors = SettingsValidator.Validate(Valid() with { LocalDnsServer = "127.0.0.1" }).Errors;

        Assert.Contains(errors, e => e.Contains("loopback", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("com")]
    [InlineData("ru")]
    [InlineData(".RU.")]
    public void Validator_RejectsTopLevelDomainRule(string suffix)
    {
        var errors = SettingsValidator.Validate(Valid() with { DomainRules = [new DomainRuleSetting { Suffix = suffix, Target = RouteTarget.Direct }] }).Errors;

        Assert.Contains(errors, e => e.Contains("домена верхнего уровня", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("example.ru")]
    [InlineData("office.example.org")]
    public void Validator_AcceptsDomainRuleWithDot(string suffix)
    {
        var errors = SettingsValidator.Validate(Valid() with { DomainRules = [new DomainRuleSetting { Suffix = suffix, Target = RouteTarget.Direct }] }).Errors;

        Assert.Empty(errors);
    }

    [Theory]
    [InlineData("lan")]
    [InlineData("local")]
    [InlineData("home.arpa")]
    public void Validator_KeepsSingleWordLocalDnsSuffixes(string suffix)
    {
        var errors = SettingsValidator.Validate(Valid() with { LocalDnsSuffixes = [suffix] }).Errors;

        Assert.Empty(errors);
        Assert.True(SettingsSerializer.IsValidSuffix(suffix));
        Assert.False(SettingsSerializer.IsValidDomainSuffix("lan"));
    }
}
