using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Settings;

/// <summary>
/// Миграция схемы 2 без активного подключения: то, что шло через VPN, не уходит молча напрямую и не указывает
/// на подключение, которого нет, — оно блокируется, а предупреждение перечисляет изменённое.
/// </summary>
public sealed class MigrationWithoutActiveProfileTests
{
    [Fact]
    public void AllViaVpn_WithoutActiveProfile_BlocksVpnTargets()
    {
        var result = SettingsSerializer.Deserialize("""
            {
              "schemaVersion": 2,
              "routingMode": "AllViaVpn",
              "rules": [
                { "cidr": "1.2.3.0/24", "action": "Vpn" },
                { "cidr": "5.6.7.0/24", "action": "Direct" }
              ]
            }
            """);

        Assert.True(result.IsSuccess, result.Error);
        Assert.True(result.Migrated);
        Assert.NotNull(result.Warning);
        Assert.Contains("1.2.3.0/24", result.Warning, StringComparison.Ordinal);
        var settings = result.Settings!;
        Assert.Equal(RouteTarget.Blocked, settings.GeoTarget);
        Assert.Equal(RouteTarget.Blocked, settings.Rules[0].Target);
        Assert.Equal(RouteTarget.Direct, settings.Rules[1].Target);
        // Подключений в файле нет: «остальной интернет» через VPN не шёл и идти не мог.
        Assert.Equal(RouteTarget.Direct, settings.DefaultTarget);
    }

    [Fact]
    public void ActiveProfileMissingFromList_BlocksVpnTargets_AndSettingsStaySavable()
    {
        var profile = Guid.NewGuid();
        var result = SettingsSerializer.Deserialize($$"""
            {
              "schemaVersion": 2,
              "profiles": [ { "id": "{{profile}}", "name": "Германия", "server": "vpn.example.org", "userName": "user", "protocol": "Sstp" } ],
              "activeProfileId": "{{Guid.NewGuid()}}",
              "routingMode": "RussiaDirect",
              "rules": [ { "cidr": "1.2.3.0/24", "action": "Vpn" } ]
            }
            """);

        Assert.True(result.IsSuccess, result.Error);
        Assert.NotNull(result.Warning);
        var settings = result.Settings!;
        Assert.Equal(ProfileRole.Off, settings.Profiles[0].Role);
        Assert.Equal(RouteTarget.Blocked, settings.DefaultTarget);
        Assert.Equal(RouteTarget.Direct, settings.GeoTarget);
        Assert.Equal(RouteTarget.Blocked, settings.Rules[0].Target);
        Assert.True(SettingsValidator.Validate(settings).IsValid, string.Join(" ", SettingsValidator.Validate(settings).Errors));
    }

    [Fact]
    public void ValidActiveProfile_MigratesWithoutWarning()
    {
        var profile = Guid.NewGuid();
        var result = SettingsSerializer.Deserialize($$"""
            {
              "schemaVersion": 2,
              "profiles": [ { "id": "{{profile}}", "name": "Германия", "server": "vpn.example.org", "userName": "user", "protocol": "Sstp" } ],
              "activeProfileId": "{{profile}}",
              "routingMode": "AllViaVpn",
              "rules": [ { "cidr": "1.2.3.0/24", "action": "Vpn" } ]
            }
            """);

        Assert.True(result.IsSuccess, result.Error);
        Assert.Null(result.Warning);
        Assert.Equal(RouteTarget.Tunnel(profile), result.Settings!.GeoTarget);
        Assert.Equal(RouteTarget.Tunnel(profile), result.Settings.Rules[0].Target);
    }
}
