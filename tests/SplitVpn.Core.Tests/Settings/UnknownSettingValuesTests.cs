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

    private static JsonElement Element(string json) => JsonDocument.Parse(json).RootElement.Clone();

    private static AppSettings IpcRoundTrip(AppSettings settings) =>
        JsonSerializer.Deserialize<AppSettings>(JsonSerializer.Serialize(settings, JsonDefaults.Compact), JsonDefaults.Compact)!;

    /// <summary>Клиент подложил раздел в обычное подключение: раздел снят, подключение проверено полностью, в файле — роль «Выключено».</summary>
    [Fact]
    public void ForgedSection_FromClient_IsDropped_AndProfileIsFullyValidated()
    {
        var plain = new ConnectionProfile { Id = Office, Name = "Офис", Server = "vpn.example.org", UserName = "user" };
        var current = new AppSettings { Profiles = [plain] };
        var forged = plain with
        {
            Server = "",
            Extra = new Dictionary<string, JsonElement> { [UnknownSettingValues.PreservedKey] = Element("""{"role":"Primary","authMethod":"Pap"}""") },
        };
        var incoming = IpcRoundTrip(current with { Profiles = [forged] });
        Assert.True(UnknownSettingValues.HasPreservedValues(incoming.Profiles[0]));

        var trusted = UnknownSettingValues.KeepOnlyTrusted(incoming, current);

        Assert.False(UnknownSettingValues.HasPreservedValues(trusted.Profiles[0]));
        // Полная проверка: пустой адрес сервера теперь замечен.
        Assert.Contains(SettingsValidator.Validate(trusted).Errors, e => e.Contains("адрес сервера", StringComparison.Ordinal));
        var fixedServer = trusted with { Profiles = [trusted.Profiles[0] with { Server = "vpn.example.org" }] };
        var reread = SettingsSerializer.Deserialize(SettingsSerializer.Serialize(fixedServer)).Settings!;
        Assert.Equal(ProfileRole.Off, reread.Profiles[0].Role);
        Assert.Equal(AuthMethod.MsChapV2, reread.Profiles[0].AuthMethod);
    }

    /// <summary>Раздел в другом регистре имени тоже снимается и в файл не попадает.</summary>
    [Fact]
    public void ForgedSection_WithOtherCase_IsDropped()
    {
        var plain = new ConnectionProfile { Id = Office, Name = "Офис", Server = "vpn.example.org", UserName = "user" };
        var forged = plain with { Extra = new Dictionary<string, JsonElement> { ["PreservedUnknownValues"] = Element("""{"role":"Primary"}""") } };

        var trusted = UnknownSettingValues.KeepOnlyTrusted(new AppSettings { Profiles = [forged] }, new AppSettings { Profiles = [plain] });

        Assert.Null(trusted.Profiles[0].Extra);
        Assert.DoesNotContain("preservedunknownvalues", SettingsSerializer.Serialize(trusted), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Подмена способа входа в настоящем разделе: раздел не совпал со своим — снят, PAP в файл не уходит.</summary>
    [Fact]
    public void TamperedSection_IsDropped_AndForgedValueIsNotWritten()
    {
        var current = SettingsSerializer.Deserialize(TwoProfiles()).Settings!;
        var received = IpcRoundTrip(current);
        var tampered = received.Profiles[0] with
        {
            Extra = new Dictionary<string, JsonElement> { [UnknownSettingValues.PreservedKey] = Element("""{"protocol":"WireGuard","role":"Primary","authMethod":"Pap"}""") },
        };

        var trusted = UnknownSettingValues.KeepOnlyTrusted(received with { Profiles = [tampered, received.Profiles[1]] }, current);

        Assert.False(UnknownSettingValues.HasPreservedValues(trusted.Profiles[0]));
        var written = SettingsSerializer.Serialize(trusted);
        Assert.DoesNotContain("Pap", written, StringComparison.Ordinal);
        Assert.Equal("Off", JsonNode.Parse(written)!["profiles"]![0]!["role"]!.GetValue<string>());
    }

    /// <summary>Раздел другого подключения (перенос по идентификатору) не принимается.</summary>
    [Fact]
    public void SectionMovedToAnotherProfile_IsDropped()
    {
        var current = SettingsSerializer.Deserialize(TwoProfiles()).Settings!;
        var received = IpcRoundTrip(current);
        var moved = received.Profiles[1] with { Extra = received.Profiles[0].Extra };

        var trusted = UnknownSettingValues.KeepOnlyTrusted(received with { Profiles = [received.Profiles[0], moved] }, current);

        Assert.True(UnknownSettingValues.HasPreservedValues(trusted.Profiles[0]));
        Assert.False(UnknownSettingValues.HasPreservedValues(trusted.Profiles[1]));
    }

    /// <summary>
    /// Честный путь: файл новой версии → загрузка службой → приложение получает и возвращает настройки как есть →
    /// запись. Разделы приняты, исходные значения, цели и группы вернулись на свои места.
    /// </summary>
    [Fact]
    public void HonestRoundTrip_RestoresOriginalValuesTargetsAndGroups()
    {
        var json = JsonNode.Parse(TwoProfiles())!.AsObject();
        var mixed = new Guid("cccccccc-3333-0000-0000-000000000003");
        var only = new Guid("dddddddd-4444-0000-0000-000000000004");
        json["groups"] = JsonNode.Parse($$"""
            [ { "id": "{{mixed}}", "name": "Смешанная", "members": [ "{{Future}}", "{{Office}}" ] },
              { "id": "{{only}}", "name": "Только новое", "members": [ "{{Future}}" ] } ]
            """);
        json["geoTarget"] = JsonNode.Parse($$"""{ "kind": "Group", "id": "{{only}}" }""");
        var original = SettingsSerializer.Serialize(SettingsSerializer.Deserialize(json.ToJsonString()).Settings!);
        var current = SettingsSerializer.Deserialize(json.ToJsonString()).Settings!;
        Assert.Single(current.Groups);
        Assert.Equal(RouteTarget.Blocked, current.GeoTarget);

        var trusted = UnknownSettingValues.KeepOnlyTrusted(IpcRoundTrip(current), current);
        var written = JsonNode.Parse(SettingsSerializer.Serialize(trusted))!.AsObject();

        Assert.Equal(original, written.ToJsonString(JsonDefaults.Options));
        Assert.False(written.ContainsKey(UnknownSettingValues.BlockedTargetsKey));
        Assert.Equal("Primary", written["profiles"]![0]!["role"]!.GetValue<string>());
        Assert.Equal("WireGuard", written["profiles"]![0]!["protocol"]!.GetValue<string>());
        Assert.Equal(Future.ToString(), written["defaultTarget"]!["id"]!.GetValue<string>());
        Assert.Equal(Future.ToString(), written["rules"]![1]!["target"]!["id"]!.GetValue<string>());
        Assert.Equal("Group", written["geoTarget"]!["kind"]!.GetValue<string>());
        var groups = written["groups"]!.AsArray();
        Assert.Equal(2, groups.Count);
        Assert.Equal(2, groups.Single(g => g!["id"]!.GetValue<string>() == mixed.ToString())!["members"]!.AsArray().Count);
    }

    /// <summary>Цель, которую пользователь сменил после загрузки, остаётся его выбором; несменённые возвращаются.</summary>
    [Fact]
    public void ChangedTarget_IsNotRestored()
    {
        var current = SettingsSerializer.Deserialize(TwoProfiles()).Settings!;
        var edited = current with { DefaultTarget = RouteTarget.Direct };

        var written = JsonNode.Parse(SettingsSerializer.Serialize(UnknownSettingValues.KeepOnlyTrusted(IpcRoundTrip(edited), current)))!;

        Assert.Equal("Direct", written["defaultTarget"]!["kind"]!.GetValue<string>());
        Assert.Equal(Future.ToString(), written["rules"]![1]!["target"]!["id"]!.GetValue<string>());
    }

    /// <summary>Подключение удалено: цели на него не возвращаются, файл не ссылается на несуществующее подключение.</summary>
    [Fact]
    public void DeletedProfile_TargetsAreNotRestored()
    {
        var current = SettingsSerializer.Deserialize(TwoProfiles()).Settings!;
        var edited = current with { Profiles = [current.Profiles[1]] };

        var written = SettingsSerializer.Serialize(UnknownSettingValues.KeepOnlyTrusted(IpcRoundTrip(edited), current));

        Assert.DoesNotContain(Future.ToString(), written, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(UnknownSettingValues.BlockedTargetsKey, written, StringComparison.Ordinal);
    }

    /// <summary>Подложенный раздел целей настроек снимается: блокировка не превращается в чужую цель.</summary>
    [Fact]
    public void ForgedTargetsSection_IsDropped()
    {
        var current = SettingsSerializer.Deserialize(TwoProfiles()).Settings!;
        var received = IpcRoundTrip(current);
        var forged = received with
        {
            Rules = [.. received.Rules, new UserRuleSetting { Cidr = "10.9.0.0/16", Target = RouteTarget.Blocked }],
            Extra = new Dictionary<string, JsonElement>
            {
                [UnknownSettingValues.BlockedTargetsKey] = Element($$$"""{"targets":[{"where":"rules","index":2,"key":"10.9.0.0/16","target":{"kind":"Tunnel","id":"{{{Future}}}"}}],"groups":[]}"""),
            },
        };

        var written = JsonNode.Parse(SettingsSerializer.Serialize(UnknownSettingValues.KeepOnlyTrusted(forged, current)))!;

        Assert.Equal("Block", written["rules"]![2]!["target"]!["kind"]!.GetValue<string>());
    }

    /// <summary>Restore снимает служебный раздел любого вида и не ставит на место роли объект или массив.</summary>
    [Fact]
    public void Restore_RemovesMalformedSection_AndSkipsNonPlainValues()
    {
        var root = JsonNode.Parse($$"""
            { "profiles": [
                { "id": "{{Future}}", "role": "Off", "preservedUnknownValues": "мусор" },
                { "id": "{{Office}}", "role": "Off", "authMethod": "MsChapV2",
                  "preservedUnknownValues": { "role": { "nested": 1 }, "authMethod": [1, 2], "protocol": "Wire Guard", "primaryAdapter": 7 } }
              ], "preservedBlockedTargets": 5 }
            """)!.AsObject();

        UnknownSettingValues.Restore(root);

        Assert.DoesNotContain("preserved", root.ToJsonString(), StringComparison.OrdinalIgnoreCase);
        var office = root["profiles"]![1]!;
        Assert.Equal("Off", office["role"]!.GetValue<string>());
        Assert.Equal("MsChapV2", office["authMethod"]!.GetValue<string>());
        Assert.Null(office["protocol"]);
        Assert.Equal(7, office["primaryAdapter"]!.GetValue<int>());
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
