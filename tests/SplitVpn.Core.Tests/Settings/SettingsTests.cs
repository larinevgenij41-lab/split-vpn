using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Settings;

public class SettingsTests
{
    private static AppSettings Valid()
    {
        var profile = new ConnectionProfile { Name = "Германия", Server = "330399.fornex.cloud", UserName = "user", Role = ProfileRole.Primary };
        return new AppSettings
        {
            Profiles = [profile],
            DefaultTarget = RouteTarget.Tunnel(profile.Id),
            Rules = [new UserRuleSetting { Cidr = "77.88.8.0/24", Target = RouteTarget.Tunnel(profile.Id) }],
        };
    }

    [Fact]
    public void Serializer_RoundTrips()
    {
        var settings = Valid();

        var loaded = SettingsSerializer.Deserialize(SettingsSerializer.Serialize(settings));

        Assert.True(loaded.IsSuccess);
        Assert.Equal(settings.DefaultTarget, loaded.Settings!.DefaultTarget);
        Assert.Equal("Германия", loaded.Settings.PrimaryProfile?.Name);
        Assert.Equal(settings.Rules[0].Target, loaded.Settings.Rules[0].Target);
    }

    [Theory]
    [InlineData("{\"schemaVersion\":7}")]
    [InlineData("{}")]
    [InlineData("{broken")]
    public void Serializer_RejectsUnknownSchemaOrCorruption(string json)
    {
        var loaded = SettingsSerializer.Deserialize(json);

        Assert.False(loaded.IsSuccess);
        Assert.NotNull(loaded.Error);
    }

    [Fact]
    public void Validator_AcceptsValidSettings()
    {
        Assert.True(SettingsValidator.Validate(Valid()).IsValid);
    }

    [Theory]
    [InlineData("vpn.example.org", true)]
    [InlineData("203.0.113.10:4443", true)]
    [InlineData("vpn.example.org:0", false)]
    [InlineData("vpn example", false)]
    public void Validator_AcceptsServerWithPort(string server, bool valid)
    {
        var baseline = Valid();
        var settings = baseline with { Profiles = [baseline.Profiles[0] with { Server = server }] };

        Assert.Equal(valid, SettingsValidator.Validate(settings).IsValid);
    }

    [Fact]
    public void Validator_RejectsTargetOnDisabledOrMissingProfile()
    {
        var baseline = Valid();
        var disabled = SettingsValidator.Validate(baseline with { Profiles = [baseline.Profiles[0] with { Role = ProfileRole.Off }] }).Errors;
        Assert.Contains(disabled, e => e.Contains("выключено", StringComparison.OrdinalIgnoreCase));

        var missing = SettingsValidator.Validate(baseline with { DefaultTarget = RouteTarget.Tunnel(Guid.NewGuid()) }).Errors;
        Assert.Contains(missing, e => e.Contains("которого нет в списке", StringComparison.Ordinal));

        Assert.True(SettingsValidator.Validate(new AppSettings()).IsValid);
    }

    [Fact]
    public void Validator_ChecksGroupsAndDomainRules()
    {
        var baseline = Valid();
        var group = new TunnelGroupSetting { Name = "Балансировка", Members = [baseline.Profiles[0].Id] };
        var settings = baseline with
        {
            Groups = [group],
            DefaultTarget = RouteTarget.Group(group.Id),
            DomainRules = [new DomainRuleSetting { Suffix = "example.org", Target = RouteTarget.Direct }],
        };
        Assert.True(SettingsValidator.Validate(settings).IsValid);

        var empty = SettingsValidator.Validate(settings with { Groups = [group with { Members = [] }] }).Errors;
        Assert.Contains(empty, e => e.Contains("нет ни одного подключения", StringComparison.Ordinal));

        var unknownGroup = SettingsValidator.Validate(baseline with { DefaultTarget = RouteTarget.Group(Guid.NewGuid()) }).Errors;
        Assert.Contains(unknownGroup, e => e.Contains("группа, которой нет", StringComparison.Ordinal));

        var badDomain = SettingsValidator.Validate(settings with { DomainRules = [new DomainRuleSetting { Suffix = "не домен", Target = RouteTarget.Direct }] }).Errors;
        Assert.Contains(badDomain, e => e.Contains("неверный домен", StringComparison.Ordinal));

        var duplicate = SettingsValidator.Validate(settings with
        {
            DomainRules =
            [
                new DomainRuleSetting { Suffix = "example.org", Target = RouteTarget.Direct },
                new DomainRuleSetting { Suffix = ".Example.ORG.", Target = RouteTarget.Blocked },
            ],
        }).Errors;
        Assert.Contains(duplicate, e => e.Contains("указан дважды", StringComparison.Ordinal));
    }

    [Fact]
    public void Migration_FromSchemaV1_KeepsBehaviour()
    {
        var id = Guid.NewGuid();
        var json = $$"""
        {
          "schemaVersion": 1,
          "profiles": [{ "id": "{{id}}", "name": "Германия", "server": "vpn.example.org", "userName": "user" }],
          "activeProfileId": "{{id}}",
          "routingMode": "RussiaDirect",
          "rules": [
            { "cidr": "1.2.3.0/24", "action": "Vpn" },
            { "cidr": "5.6.7.0/24", "action": "Direct" },
            { "cidr": "9.9.9.0/24", "action": "Block" }
          ]
        }
        """;

        var loaded = SettingsSerializer.Deserialize(json);

        Assert.True(loaded.IsSuccess, loaded.Error);
        Assert.True(loaded.Migrated);
        var settings = loaded.Settings!;
        Assert.Equal(ProfileRole.Primary, settings.Profiles[0].Role);
        Assert.Equal(RouteTarget.Tunnel(id), settings.DefaultTarget);
        Assert.Equal(RouteTarget.Direct, settings.GeoTarget);
        Assert.Equal(RouteTarget.Tunnel(id), settings.Rules[0].Target);
        Assert.Equal(RouteTarget.Direct, settings.Rules[1].Target);
        Assert.Equal(RouteTarget.Blocked, settings.Rules[2].Target);
        Assert.True(SettingsValidator.Validate(settings).IsValid);
    }

    [Fact]
    public void Migration_FromSchemaV1_AllViaVpn_SendsGeoToTunnel()
    {
        var id = Guid.NewGuid();
        var json = $$"""
        {
          "schemaVersion": 1,
          "profiles": [{ "id": "{{id}}", "name": "Германия", "server": "vpn.example.org", "userName": "user" }],
          "activeProfileId": "{{id}}",
          "routingMode": "AllViaVpn"
        }
        """;

        var settings = SettingsSerializer.Deserialize(json).Settings!;

        Assert.Equal(RouteTarget.Tunnel(id), settings.GeoTarget);
        Assert.Equal(RouteTarget.Tunnel(id), settings.DefaultTarget);
    }

    [Fact]
    public void Validator_ExplainsIpv6RuleLimitation()
    {
        var settings = Valid() with { Rules = [new UserRuleSetting { Cidr = "2a00:1450::/32", Target = RouteTarget.Direct }] };

        var result = SettingsValidator.Validate(settings);

        Assert.Contains(result.Errors, e => e.Contains("IPv6 ограничен", StringComparison.Ordinal));
    }

    [Fact]
    public void Validator_ReportsProfileAndGeoProblems()
    {
        var duplicate = new ConnectionProfile { Name = "германия", Server = "bad host name", UserName = "" };
        var settings = Valid() with
        {
            Profiles = [.. Valid().Profiles, duplicate],
            GeoUpdate = new GeoUpdateSettings { IntervalDays = 2, Source = GeoSourceKind.CustomUrl, CustomUrl = "http://insecure.example/ru.txt" },
            UpstreamDns = ["127.0.0.1"],
        };

        var errors = SettingsValidator.Validate(settings).Errors;

        Assert.Contains(errors, e => e.Contains("неверный адрес сервера", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.Contains("имя пользователя", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.Contains("должны различаться", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.Contains("Интервал", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.Contains("HTTPS", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.Contains("loopback", StringComparison.Ordinal));
    }

    [Fact]
    public void ParseRules_ReportsHostBits()
    {
        var (rules, errors) = SettingsSerializer.ParseRules([new UserRuleSetting { Cidr = "1.2.3.4/24" }, new UserRuleSetting { Cidr = "1.2.3.0/24" }]);

        Assert.Single(rules);
        Assert.Contains("биты хоста", Assert.Single(errors), StringComparison.Ordinal);
    }

    [Fact]
    public void AtomicFile_ReplacesContent()
    {
        var path = Path.Combine(Path.GetTempPath(), "splitvpn-tests", Guid.NewGuid().ToString("N"), "settings.json");
        try
        {
            AtomicFile.WriteAllText(path, "one");
            AtomicFile.WriteAllText(path, "two");

            Assert.Equal("two", File.ReadAllText(path));
            Assert.False(File.Exists(path + ".tmp"));
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
        }
    }
}
