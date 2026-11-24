using SplitVpn.Core.Settings;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Файл настроек более новой версии программы (откат после обновления): служба не подменяет его настройками по
/// умолчанию, откладывает исходный файл рядом, а запись сохраняет неизвестные значения на своих местах.
/// </summary>
public sealed class NewerSettingsFileTests
{
    [Fact]
    public void UnknownProtocol_KeepsOtherProfiles_CopyAndValuesSurviveSave()
    {
        using var world = new FakeWorld();
        var future = Guid.NewGuid();
        var office = Guid.NewGuid();
        var original = $$"""
        {
          "schemaVersion": {{AppSettings.CurrentSchemaVersion + 1}},
          "profiles": [
            { "id": "{{future}}", "name": "Новый", "server": "wg.example.org:51820", "protocol": "WireGuard", "role": "Primary" },
            { "id": "{{office}}", "name": "Офис", "server": "vpn.example.org", "userName": "user", "role": "Secondary" }
          ],
          "rules": [ { "cidr": "10.1.0.0/16", "target": { "kind": "Tunnel", "id": "{{office}}" } } ]
        }
        """;
        File.WriteAllText(world.Paths.Settings, original);
        var found = new List<CorruptFile>();
        var store = new ServiceStores(world.Paths) { OnCorrupt = found.Add };

        var settings = store.LoadSettings(out var error);

        Assert.Null(error);
        Assert.Equal(2, settings.Profiles.Count);
        Assert.Single(settings.Rules);
        var report = Assert.Single(found);
        Assert.NotNull(report.CopyPath);
        Assert.Equal(original, File.ReadAllText(report.CopyPath!));
        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(world.Paths.Settings)!, Path.GetFileName(world.Paths.Settings) + ".unreadable-*"));

        store.SaveSettings(settings);
        var written = File.ReadAllText(world.Paths.Settings);
        Assert.Contains("\"WireGuard\"", written, StringComparison.Ordinal);
        Assert.Equal(2, store.LoadSettings(out _).Profiles.Count);
    }

    [Fact]
    public void UnreadableFile_IsSetAsideBeforeDefaultsAreUsed()
    {
        using var world = new FakeWorld();
        const string original = """{"schemaVersion":3,"profiles":"не список"}""";
        File.WriteAllText(world.Paths.Settings, original);
        var store = new ServiceStores(world.Paths) { OnCorrupt = _ => { } };

        var settings = store.LoadSettings(out var error);

        Assert.NotNull(error);
        Assert.Empty(settings.Profiles);
        var copy = Assert.Single(Directory.GetFiles(Path.GetDirectoryName(world.Paths.Settings)!, Path.GetFileName(world.Paths.Settings) + ".unreadable-*"));
        Assert.Equal(original, File.ReadAllText(copy));
    }
}
