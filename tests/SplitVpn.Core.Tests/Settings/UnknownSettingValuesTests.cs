using System.Text.Json;
using System.Text.Json.Nodes;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Settings;

/// <summary>
/// Файл настроек более новой версии программы (откат после обновления): неизвестные значения перечислений
/// не делают весь файл нечитаемым, остальные подключения и правила остаются, исходные значения переживают запись.
/// </summary>
public sealed class UnknownSettingValuesTests
{
    private static readonly Guid Future = new("aaaaaaaa-1111-0000-0000-000000000001");
    private static readonly Guid Office = new("bbbbbbbb-2222-0000-0000-000000000002");

    private static string TwoProfiles(string protocol = "WireGuard", int schema = AppSettings.CurrentSchemaVersion) => $$"""
        {
          "schemaVersion": {{schema}},
          "profiles": [
            { "id": "{{Future}}", "name": "Новый", "server": "wg.example.org:51820", "protocol": "{{protocol}}", "role": "Primary", "userName": "" },
            { "id": "{{Office}}", "name": "Офис", "server": "vpn.example.org", "userName": "user", "role": "Secondary" }
          ],
          "defaultTarget": { "kind": "Tunnel", "id": "{{Future}}" },
          "rules": [
            { "cidr": "10.1.0.0/16", "target": { "kind": "Tunnel", "id": "{{Office}}" } },
            { "cidr": "10.2.0.0/16", "target": { "kind": "Tunnel", "id": "{{Future}}" } }
          ],
          "domainRules": [ { "suffix": "example.org", "target": { "kind": "Direct" } } ]
        }
        """;

    [Fact]
    public void UnknownProtocol_DisablesOnlyThatProfile_AndKeepsTheRest()
    {
        var result = SettingsSerializer.Deserialize(TwoProfiles());

        Assert.True(result.IsSuccess, result.Error);
        Assert.NotNull(result.Warning);
        Assert.Contains("WireGuard", result.Warning, StringComparison.Ordinal);
        var settings = result.Settings!;
        Assert.Equal(2, settings.Profiles.Count);
        Assert.Equal(ProfileRole.Off, settings.Profiles[0].Role);
        Assert.True(UnknownSettingValues.HasPreservedValues(settings.Profiles[0]));
        Assert.Equal(ProfileRole.Secondary, settings.Profiles[1].Role);
        Assert.False(UnknownSettingValues.HasPreservedValues(settings.Profiles[1]));
        Assert.Equal(2, settings.Rules.Count);
        Assert.Equal(RouteTarget.Tunnel(Office), settings.Rules[0].Target);
        // Выключенное подключение служба не поднимает: направленное в него блокируется, а не уходит напрямую.
        Assert.Equal(RouteTarget.Blocked, settings.Rules[1].Target);
        Assert.Equal(RouteTarget.Blocked, settings.DefaultTarget);
        Assert.Single(settings.DomainRules);

        // Такие настройки сохраняются: проверка не отклоняет их из-за подставленных значений.
        Assert.True(SettingsValidator.Validate(settings).IsValid, string.Join(" ", SettingsValidator.Validate(settings).Errors));
    }

    [Fact]
    public void PreservedValues_AreWrittenBackUnderOriginalKeys()
    {
        var settings = SettingsSerializer.Deserialize(TwoProfiles()).Settings!;

        var written = SettingsSerializer.Serialize(settings);

        // Ни повторов ключей, ни служебного раздела: файл читает и более новая версия программы.
        var profile = JsonNode.Parse(written)!["profiles"]![0]!.AsObject();
        Assert.Equal("WireGuard", profile["protocol"]!.GetValue<string>());
        Assert.Equal("Primary", profile["role"]!.GetValue<string>());
        Assert.False(profile.ContainsKey(UnknownSettingValues.PreservedKey));
        Assert.Equal("Secondary", JsonNode.Parse(written)!["profiles"]![1]!["role"]!.GetValue<string>());

        // Этой версией тот же файл читается так же: подключение снова выключено, значения при нём.
        var again = SettingsSerializer.Deserialize(written);
        Assert.True(again.IsSuccess, again.Error);
        Assert.Equal(ProfileRole.Off, again.Settings!.Profiles[0].Role);
        Assert.Equal(written, SettingsSerializer.Serialize(again.Settings));
    }

    [Fact]
    public void PreservedValues_SurviveIpcRoundTrip_WithSameRevision()
    {
        var settings = SettingsSerializer.Deserialize(TwoProfiles()).Settings!;

        var received = JsonSerializer.Deserialize<AppSettings>(JsonSerializer.Serialize(settings, JsonDefaults.Compact), JsonDefaults.Compact)!;

        Assert.True(UnknownSettingValues.HasPreservedValues(received.Profiles[0]));
        Assert.Equal(SettingsSerializer.Revision(settings), SettingsSerializer.Revision(received));
    }

    [Fact]
    public void ProfileWithPreservedValues_CannotBeEnabled()
    {
        var settings = SettingsSerializer.Deserialize(TwoProfiles()).Settings!;
        var enabled = settings with { Profiles = [settings.Profiles[0] with { Role = ProfileRole.Secondary }, settings.Profiles[1]] };

        Assert.Contains(SettingsValidator.Validate(enabled).Errors, e => e.Contains("более новой версией", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("authMethod", "Passkey")]
    [InlineData("role", "Standby")]
    [InlineData("ipsecAuthentication", "Quantum")]
    [InlineData("primaryAdapter", "Smart")]
    [InlineData("protocol", "99")]
    public void OtherUnknownProfileValues_AlsoDisableTheProfile(string field, string value)
    {
        var json = JsonNode.Parse(TwoProfiles("Sstp"))!.AsObject();
        var profile = json["profiles"]![0]!.AsObject();
        profile[field] = int.TryParse(value, out var number) ? JsonValue.Create(number) : JsonValue.Create(value);

        var result = SettingsSerializer.Deserialize(json.ToJsonString());

        Assert.True(result.IsSuccess, result.Error);
        Assert.NotNull(result.Warning);
        Assert.Equal(ProfileRole.Off, result.Settings!.Profiles[0].Role);
        Assert.Equal(ProfileRole.Secondary, result.Settings.Profiles[1].Role);
        var written = JsonNode.Parse(SettingsSerializer.Serialize(result.Settings))!["profiles"]![0]!;
        Assert.Equal(profile[field]!.ToJsonString(), written[field]!.ToJsonString());
    }

    [Fact]
    public void UnknownTargetKind_BecomesBlock()
    {
        var result = SettingsSerializer.Deserialize("""
            {
              "schemaVersion": 3,
              "defaultTarget": { "kind": "Pool" },
              "geoTarget": { "kind": "Direct" },
              "bypassTarget": { "kind": "Mesh", "id": "cccccccc-0000-0000-0000-000000000003" },
              "rules": [ { "cidr": "10.0.0.0/8", "target": { "kind": "Pool" } } ],
              "routingFolders": [ { "name": "Папка", "target": { "kind": "Pool" } } ]
            }
            """);

        Assert.True(result.IsSuccess, result.Error);
        Assert.NotNull(result.Warning);
        Assert.Equal(RouteTarget.Blocked, result.Settings!.DefaultTarget);
        Assert.Equal(RouteTarget.Direct, result.Settings.GeoTarget);
        Assert.Equal(RouteTarget.Blocked, result.Settings.BypassTarget);
        Assert.Equal(RouteTarget.Blocked, result.Settings.Rules[0].Target);
        Assert.Equal(RouteTarget.Blocked, result.Settings.RoutingFolders[0].Target);
    }

    [Fact]
    public void OtherUnknownValues_BecomeDefaults_WithWarning()
    {
        var result = SettingsSerializer.Deserialize("""
            {
              "schemaVersion": 3,
              "outageMode": "Panic",
              "geoUpdate": { "source": "Satellite", "intervalDays": 3 },
              "groups": [ { "name": "Группа", "mode": "RoundRobin", "members": [] } ],
              "rules": [ { "cidr": "10.0.0.0/8", "priority": "Urgent", "target": { "kind": "Block" } } ]
            }
            """);

        Assert.True(result.IsSuccess, result.Error);
        var settings = result.Settings!;
        Assert.Equal(new AppSettings().OutageMode, settings.OutageMode);
        Assert.Equal(new GeoUpdateSettings().Source, settings.GeoUpdate.Source);
        Assert.Equal(3, settings.GeoUpdate.IntervalDays);
        Assert.Equal(BalanceMode.Distribute, settings.Groups[0].Mode);
        Assert.Equal(RouteTarget.Blocked, settings.Rules[0].Target);
        Assert.Contains("Panic", result.Warning, StringComparison.Ordinal);
        Assert.Contains("Satellite", result.Warning, StringComparison.Ordinal);
        Assert.Contains("RoundRobin", result.Warning, StringComparison.Ordinal);
        Assert.Contains("Urgent", result.Warning, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(AppSettings.CurrentSchemaVersion + 1)]
    [InlineData(7)]
    public void NewerSchema_IsRead_WithWarning(int schema)
    {
        var json = JsonNode.Parse(TwoProfiles("Sstp", schema))!.AsObject();
        json["futureSection"] = new JsonObject { ["enabled"] = true };
        json["profiles"]![0]!["userName"] = "user";

        var result = SettingsSerializer.Deserialize(json.ToJsonString());

        Assert.True(result.IsSuccess, result.Error);
        Assert.NotNull(result.Warning);
        var settings = result.Settings!;
        Assert.Equal(AppSettings.CurrentSchemaVersion, settings.SchemaVersion);
        Assert.Equal(2, settings.Profiles.Count);
        Assert.Equal(ProfileRole.Primary, settings.Profiles[0].Role);
        Assert.Equal(RouteTarget.Tunnel(Future), settings.Rules[1].Target);
        Assert.True(settings.Extra!.ContainsKey("futureSection"));
        Assert.True(SettingsValidator.Validate(settings).IsValid, string.Join(" ", SettingsValidator.Validate(settings).Errors));
    }

    [Fact]
    public void UnknownTargetNumber_IsBlockedOnLoadRepair()
    {
        var settings = new AppSettings
        {
            DefaultTarget = new RouteTarget((TargetKind)7),
            Rules = [new UserRuleSetting { Cidr = "10.0.0.0/8", Target = new RouteTarget((TargetKind)9) }],
        };

        var repaired = SettingsValidator.RepairOnLoad(settings, out var repairs);

        Assert.Equal(RouteTarget.Blocked, repaired.DefaultTarget);
        Assert.Equal(RouteTarget.Blocked, repaired.Rules[0].Target);
        Assert.Equal(2, repairs.Count);
        Assert.True(SettingsValidator.Validate(repaired).IsValid);
    }

    [Fact]
    public void UnknownTargetNumberInFile_IsBlockedByLoadRepair()
    {
        var loaded = SettingsSerializer.Deserialize("""{"schemaVersion":3,"defaultTarget":{"kind":7}}""");
        Assert.True(loaded.IsSuccess, loaded.Error);

        var repaired = SettingsValidator.RepairOnLoad(loaded.Settings!, out var repairs);

        Assert.Equal(RouteTarget.Blocked, repaired.DefaultTarget);
        Assert.Single(repairs);
    }
}
