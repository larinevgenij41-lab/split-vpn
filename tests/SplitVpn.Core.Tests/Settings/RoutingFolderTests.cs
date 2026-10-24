using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Settings;

public class RoutingFolderTests
{
    [Fact]
    public void FoldersAndRuleLinks_RoundTripWithoutChangingRules()
    {
        var folder = new RoutingFolderSetting { Name = "Kimi и Moonshot", Target = RouteTarget.Blocked };
        var settings = new AppSettings
        {
            RoutingFolders = [folder],
            Rules = [new UserRuleSetting { Cidr = "192.0.2.0/24", Target = folder.Target, FolderId = folder.Id }],
            DomainRules = [new DomainRuleSetting { Suffix = "kimi.com", Target = folder.Target, FolderId = folder.Id }],
        };

        var loaded = SettingsSerializer.Deserialize(SettingsSerializer.Serialize(settings));

        Assert.True(loaded.IsSuccess, loaded.Error);
        var restored = loaded.Settings!;
        Assert.Equal(folder, Assert.Single(restored.RoutingFolders));
        Assert.Equal(folder.Id, Assert.Single(restored.Rules).FolderId);
        Assert.Equal(folder.Id, Assert.Single(restored.DomainRules).FolderId);
        Assert.Equal(folder.Target, restored.Rules[0].Target);
        Assert.Equal(folder.Target, restored.DomainRules[0].Target);
        Assert.True(SettingsValidator.Validate(restored).IsValid, string.Join("; ", SettingsValidator.Validate(restored).Errors));
    }

    [Fact]
    public void SettingsWithoutFolders_LoadAsUngroupedRules()
    {
        const string json = """
        {
          "schemaVersion": 3,
          "rules": [{ "cidr": "192.0.2.0/24", "target": { "kind": "Direct" } }],
          "domainRules": [{ "suffix": "example.org", "target": { "kind": "Direct" } }]
        }
        """;

        var loaded = SettingsSerializer.Deserialize(json);

        Assert.True(loaded.IsSuccess, loaded.Error);
        Assert.Empty(loaded.Settings!.RoutingFolders);
        Assert.Null(loaded.Settings.Rules[0].FolderId);
        Assert.Null(loaded.Settings.DomainRules[0].FolderId);
    }

    [Fact]
    public void Normalization_RepairsNullFolders()
    {
        var normalized = SettingsSerializer.Normalize(new AppSettings { RoutingFolders = null! });

        Assert.Empty(normalized.RoutingFolders);
        Assert.True(SettingsValidator.Validate(normalized).IsValid);
    }

    [Fact]
    public void Validator_ReportsBrokenFolderMetadataAndLinks()
    {
        var folder = new RoutingFolderSetting { Name = "Сервисы", Target = RouteTarget.Direct };
        var duplicate = folder with { Target = RouteTarget.Blocked };
        var settings = new AppSettings
        {
            RoutingFolders = [folder, duplicate, folder with { Id = Guid.NewGuid(), Name = "" }],
            Rules = [new UserRuleSetting { Cidr = "192.0.2.0/24", FolderId = Guid.NewGuid() }],
            DomainRules = [new DomainRuleSetting { Suffix = "example.org", FolderId = Guid.NewGuid() }],
        };

        var errors = SettingsValidator.Validate(settings).Errors;

        Assert.Contains(errors, e => e.Contains("Названия папок", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.Contains("Внутренний номер папки", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.Contains("У папки правил не задано название", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.Contains("Подсеть 192.0.2.0/24", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.Contains("Домен «example.org»", StringComparison.Ordinal));
    }

    [Fact]
    public void RemoveProfile_RetargetsFolderAndKeepsItsMembersLinked()
    {
        var main = new ConnectionProfile { Name = "Основное", Server = "vpn.example.org", UserName = "user", Role = ProfileRole.Primary };
        var extra = new ConnectionProfile { Name = "Дополнительное", Server = "vpn2.example.org", UserName = "user", Role = ProfileRole.Secondary };
        var folder = new RoutingFolderSetting { Name = "Работа", Target = RouteTarget.Tunnel(extra.Id) };
        var settings = new AppSettings
        {
            Profiles = [main, extra],
            RoutingFolders = [folder],
            DomainRules = [new DomainRuleSetting { Suffix = "example.org", Target = folder.Target, FolderId = folder.Id }],
        };

        var updated = ConnectionEdits.RemoveProfile(settings, extra.Id);

        Assert.Equal(RouteTarget.Direct, Assert.Single(updated.RoutingFolders).Target);
        Assert.Equal(RouteTarget.Direct, Assert.Single(updated.DomainRules).Target);
        Assert.Equal(folder.Id, updated.DomainRules[0].FolderId);
    }

    [Fact]
    public void Deserialize_DuplicateFolderIdsKeepFirstAndWarn()
    {
        var id = Guid.NewGuid();
        var json = $$"""
        {
          "schemaVersion": 3,
          "routingFolders": [
            { "id": "{{id}}", "name": "Первая", "target": { "kind": "Direct" } },
            { "id": "{{id}}", "name": "Вторая", "target": { "kind": "Block" } }
          ]
        }
        """;

        var loaded = SettingsSerializer.Deserialize(json);

        Assert.True(loaded.IsSuccess, loaded.Error);
        Assert.Equal("Первая", Assert.Single(loaded.Settings!.RoutingFolders).Name);
        Assert.Contains("папки правил «Вторая»", loaded.Warning, StringComparison.Ordinal);
    }
}
