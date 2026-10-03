using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Settings;

/// <summary>
/// Файл настроек приходит от прежних версий, с другой платформы и из-под рук пользователя: «null» вместо
/// списка или строки и повторяющиеся идентификаторы не должны ронять загрузку, валидатор и политику.
/// </summary>
public class SettingsNormalizationTests
{
    private static AppSettings Valid()
    {
        var profile = new ConnectionProfile { Name = "Германия", Server = "vpn.example.org", UserName = "user", Role = ProfileRole.Primary };
        return new AppSettings
        {
            Profiles = [profile],
            DefaultTarget = RouteTarget.Tunnel(profile.Id),
            Rules = [new UserRuleSetting { Cidr = "77.88.8.0/24", Target = RouteTarget.Tunnel(profile.Id) }],
            DomainRules = [new DomainRuleSetting { Suffix = "example.org", Target = RouteTarget.Direct }],
            LocalDnsSuffixes = ["lan"],
            UpstreamDns = ["8.8.8.8"],
        };
    }

    [Fact]
    public void Deserialize_NullCollectionsAndStrings_BecomeEmptyValues()
    {
        var json = """
        {
          "schemaVersion": 3,
          "profiles": [{ "name": null, "server": null, "userName": null, "eap": null, "anyConnect": null, "retry": null }],
          "groups": null,
          "rules": null,
          "domainRules": null,
          "localDnsSuffixes": null,
          "upstreamDns": null,
          "geoUpdate": null,
          "checkTargets": null
        }
        """;

        var loaded = SettingsSerializer.Deserialize(json);

        Assert.True(loaded.IsSuccess, loaded.Error);
        var settings = loaded.Settings!;
        Assert.Empty(settings.Groups);
        Assert.Empty(settings.Rules);
        Assert.Empty(settings.DomainRules);
        Assert.Empty(settings.LocalDnsSuffixes);
        Assert.Empty(settings.UpstreamDns);
        var profile = Assert.Single(settings.Profiles);
        Assert.Equal("", profile.Name);
        Assert.Equal("", profile.Server);
        Assert.Equal("", profile.UserName);
        Assert.Empty(profile.Eap.TrustedRootThumbprints);
        Assert.Equal(AnyConnectSettings.DefaultUserAgent, profile.AnyConnect.UserAgent);
        Assert.True(profile.Retry.Enabled);
        Assert.Equal(new CheckTargets().Foreign, settings.CheckTargets.Foreign);
        Assert.Equal(1, settings.GeoUpdate.IntervalDays);
    }

    [Fact]
    public void Deserialize_NullItemsInLists_AreDropped()
    {
        var json = """
        {
          "schemaVersion": 3,
          "profiles": [null, { "name": "Основное", "server": "vpn.example.org", "userName": "user" }],
          "groups": [null],
          "upstreamDns": [null, "8.8.8.8"],
          "localDnsSuffixes": [null]
        }
        """;

        var settings = SettingsSerializer.Deserialize(json).Settings!;

        Assert.Equal("Основное", Assert.Single(settings.Profiles).Name);
        Assert.Empty(settings.Groups);
        Assert.Equal("8.8.8.8", Assert.Single(settings.UpstreamDns));
        Assert.Empty(settings.LocalDnsSuffixes);
    }

    [Fact]
    public void Validator_DoesNotThrowOnIncompleteModel()
    {
        var broken = new AppSettings
        {
            Profiles = null!,
            Groups = null!,
            Rules = null!,
            DomainRules = null!,
            LocalDnsSuffixes = null!,
            UpstreamDns = null!,
            GeoUpdate = null!,
            CheckTargets = null!,
        };

        var result = SettingsValidator.Validate(broken);

        Assert.True(result.IsValid, string.Join("; ", result.Errors));
    }

    [Fact]
    public void Validator_DoesNotThrowOnProfileWithNullFields()
    {
        var settings = new AppSettings
        {
            Profiles = [new ConnectionProfile { Name = null!, Server = null!, UserName = null!, Eap = null!, AnyConnect = null!, Retry = null! }],
        };

        var errors = SettingsValidator.Validate(settings).Errors;

        Assert.Contains(errors, e => e.Contains("не задано название", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.Contains("неверный адрес сервера", StringComparison.Ordinal));
    }

    [Fact]
    public void Deserialize_DuplicateIds_KeepFirstEntry()
    {
        var id = Guid.NewGuid();
        var group = Guid.NewGuid();
        var json = $$"""
        {
          "schemaVersion": 3,
          "profiles": [
            { "id": "{{id}}", "name": "Первое", "server": "vpn.example.org", "userName": "user", "role": "Secondary" },
            { "id": "{{id}}", "name": "Второе", "server": "vpn2.example.org", "userName": "user" }
          ],
          "groups": [
            { "id": "{{group}}", "name": "Первая", "members": ["{{id}}"] },
            { "id": "{{group}}", "name": "Вторая", "members": [] }
          ]
        }
        """;

        var loaded = SettingsSerializer.Deserialize(json);
        var settings = loaded.Settings!;

        Assert.Equal("Первое", Assert.Single(settings.Profiles).Name);
        Assert.Equal("Первая", Assert.Single(settings.Groups).Name);
        Assert.NotNull(loaded.Warning);
        Assert.Contains("подключения «Второе»", loaded.Warning, StringComparison.Ordinal);
        Assert.Contains("группы «Вторая»", loaded.Warning, StringComparison.Ordinal);
        Assert.Null(SettingsSerializer.Deserialize(SettingsSerializer.Serialize(settings)).Warning);
    }

    [Fact]
    public void Validator_ReportsDuplicateIds()
    {
        var baseline = Valid();
        var profile = baseline.Profiles[0];
        var settings = baseline with { Profiles = [profile, profile with { Name = "Копия", Role = ProfileRole.Off }] };

        var errors = SettingsValidator.Validate(settings).Errors;

        Assert.Contains(errors, e => e.Contains("Внутренний номер подключения повторяется", StringComparison.Ordinal));
    }

    [Fact]
    public void Validator_ReportsDuplicateGroupIds()
    {
        var baseline = Valid();
        var group = new TunnelGroupSetting { Name = "Балансировка", Members = [baseline.Profiles[0].Id] };
        var settings = baseline with { Groups = [group, group with { Name = "Копия" }] };

        var errors = SettingsValidator.Validate(settings).Errors;

        Assert.Contains(errors, e => e.Contains("Внутренний номер группы повторяется", StringComparison.Ordinal));
    }

    [Fact]
    public void PolicyCompiler_SurvivesDuplicateGroupIds()
    {
        var first = Guid.NewGuid();
        var second = Guid.NewGuid();
        var group = Guid.NewGuid();
        var input = new PolicyInput
        {
            DefaultTarget = RouteTarget.Group(group),
            Groups = [new TunnelGroup(group, [first]), new TunnelGroup(group, [second])],
        };

        var policy = PolicyCompiler.Compile(input);

        Assert.Contains(first, policy.Tunnels);
        Assert.DoesNotContain(second, policy.Tunnels);
    }

    [Fact]
    public void Normalization_KeepsCorrectSettingsUnchanged()
    {
        var json = SettingsSerializer.Serialize(Valid());

        var again = SettingsSerializer.Serialize(SettingsSerializer.Deserialize(json).Settings!);

        Assert.Equal(json, again);
    }

    [Fact]
    public void UnknownSections_SurviveRoundTrip()
    {
        var id = Guid.NewGuid();
        var json = $$"""
        {
          "schemaVersion": 3,
          "profiles": [{ "id": "{{id}}", "name": "Основное", "server": "vpn.example.org", "userName": "user", "certificateSha256": "AA", "verifyHostname": false }],
          "apps": { "listMode": "AllExcept", "packages": { "ru.example": "Bypass" } },
          "ui": { "theme": "dark" }
        }
        """;

        var settings = SettingsSerializer.Deserialize(json).Settings!;
        var written = SettingsSerializer.Deserialize(SettingsSerializer.Serialize(settings)).Settings!;

        Assert.NotNull(written.Extra);
        Assert.Contains("apps", written.Extra!.Keys);
        Assert.Contains("ui", written.Extra.Keys);
        var profile = Assert.Single(written.Profiles);
        Assert.NotNull(profile.Extra);
        Assert.Contains("certificateSha256", profile.Extra!.Keys);
        Assert.Contains("verifyHostname", profile.Extra.Keys);
        Assert.Equal("dark", written.Extra["ui"].GetProperty("theme").GetString());
    }

    [Fact]
    public void UnknownSections_SurviveProfileEdit()
    {
        var json = """
        {
          "schemaVersion": 3,
          "profiles": [{ "name": "Основное", "server": "vpn.example.org", "userName": "user", "verifyHostname": false }],
          "apps": { "listMode": "AllExcept" }
        }
        """;

        var settings = SettingsSerializer.Deserialize(json).Settings!;
        var edited = ConnectionEdits.SaveProfile(settings, settings.Profiles[0] with { Name = "Работа" });

        Assert.Contains("apps", edited.Extra!.Keys);
        Assert.Contains("verifyHostname", Assert.Single(edited.Profiles).Extra!.Keys);
    }

    [Fact]
    public void Deserialize_LeadingZeroIpv4_WithSameOctalValue_IsCanonicalized()
    {
        var json = """
        {
          "schemaVersion": 3,
          "profiles": [{ "name": "Основное", "server": "192.000.002.001:0443", "userName": "user" }],
          "rules": [{ "cidr": "10.001.0.0/16", "target": { "kind": "Direct" } }],
          "upstreamDns": ["192.168.001.001", "8.8.8.8"],
          "localDnsServer": "192.168.000.007",
          "checkTargets": { "foreign": "001.1.1.1:443", "russian": "77.88.55.242:443" }
        }
        """;

        var loaded = SettingsSerializer.Deserialize(json);

        Assert.True(loaded.IsSuccess, loaded.Error);
        Assert.Null(loaded.Warning);
        var settings = loaded.Settings!;
        Assert.Equal("192.0.2.1:0443", Assert.Single(settings.Profiles).Server);
        Assert.Equal("10.1.0.0/16", Assert.Single(settings.Rules).Cidr);
        Assert.Equal(["192.168.1.1", "8.8.8.8"], settings.UpstreamDns);
        Assert.Equal("192.168.0.7", settings.LocalDnsServer);
        Assert.Equal("1.1.1.1:443", settings.CheckTargets.Foreign);
        Assert.DoesNotContain(SettingsValidator.Validate(settings).Errors, e => e.Contains("DNS", StringComparison.Ordinal));
    }

    [Fact]
    public void Deserialize_LeadingZeroIpv4_WithDifferentOctalValue_IsKeptAndReported()
    {
        var json = """
        {
          "schemaVersion": 3,
          "profiles": [{ "name": "Основное", "server": "https://010.0.0.1/staff", "userName": "user" }],
          "rules": [{ "cidr": "10.010.0.0/16", "target": { "kind": "Direct" } }],
          "upstreamDns": ["192.168.001.0255"]
        }
        """;

        var loaded = SettingsSerializer.Deserialize(json);

        Assert.True(loaded.IsSuccess, loaded.Error);
        var settings = loaded.Settings!;
        Assert.Equal("https://010.0.0.1/staff", Assert.Single(settings.Profiles).Server);
        Assert.Equal("10.010.0.0/16", Assert.Single(settings.Rules).Cidr);
        Assert.Equal("192.168.001.0255", Assert.Single(settings.UpstreamDns));
        Assert.NotNull(loaded.Warning);
        Assert.Contains("«https://010.0.0.1/staff»", loaded.Warning, StringComparison.Ordinal);
        Assert.Contains("«10.010.0.0/16»", loaded.Warning, StringComparison.Ordinal);
        Assert.Contains("«192.168.001.0255»", loaded.Warning, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("vpn.001.example.org", "vpn.001.example.org")]
    [InlineData("1.2.3.4.5", "1.2.3.4.5")]
    [InlineData("10.0.0.08", "10.0.0.08")]
    [InlineData("0.00.000.0000", "0.0.0.0")]
    public void LegacyIpv4_TouchesOnlyUnambiguousDottedQuads(string text, string expected)
    {
        var ambiguous = new List<string>();

        Assert.Equal(expected, LegacyIpv4.Canonicalize(text, ambiguous));
        Assert.Empty(ambiguous);
    }

    [Fact]
    public void Deserialize_DuplicateIdsAndAmbiguousIpv4_WarningsAreCombined()
    {
        var id = Guid.NewGuid();
        var json = $$"""
        {
          "schemaVersion": 3,
          "profiles": [{ "id": "{{id}}", "name": "Первое" }, { "id": "{{id}}", "name": "Второе" }],
          "upstreamDns": ["010.0.0.1"]
        }
        """;

        var warning = SettingsSerializer.Deserialize(json).Warning;

        Assert.NotNull(warning);
        Assert.Contains("подключения «Второе»", warning, StringComparison.Ordinal);
        Assert.Contains("«010.0.0.1»", warning, StringComparison.Ordinal);
    }
}
