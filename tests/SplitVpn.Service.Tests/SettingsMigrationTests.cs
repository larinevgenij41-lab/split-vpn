using SplitVpn.Core.Settings;

namespace SplitVpn.Service.Tests;

public sealed class SettingsMigrationTests
{
    [Fact]
    public void LegacyBackupSurvivesSubsequentSaves()
    {
        using var world = new FakeWorld();
        const string original = """{"schemaVersion":1,"profiles":[]}""";
        File.WriteAllText(world.Paths.Settings, original);
        var store = new ServiceStores(world.Paths);
        store.SaveSettings(new AppSettings());
        store.SaveSettings(new AppSettings { AutoConnect = true });
        Assert.Equal(original, File.ReadAllText(world.Paths.Settings + ".v1.bak"));
        Assert.Equal(AppSettings.CurrentSchemaVersion, store.LoadSettings(out _).SchemaVersion);
    }

    [Fact]
    public void CorruptExistingSettingsCanStillBeReplaced()
    {
        using var world = new FakeWorld();
        File.WriteAllText(world.Paths.Settings, "{broken");
        var store = new ServiceStores(world.Paths);
        store.SaveSettings(new AppSettings());
        Assert.Equal(AppSettings.CurrentSchemaVersion, store.LoadSettings(out var error).SchemaVersion);
        Assert.Null(error);
        Assert.False(File.Exists(world.Paths.Settings + ".v1.bak"));
    }

    [Fact]
    public void DuplicateIds_KeepOriginalCopyAndReportWarning()
    {
        using var world = new FakeWorld();
        var id = Guid.NewGuid();
        var original = $$"""
        {
          "schemaVersion": {{AppSettings.CurrentSchemaVersion}},
          "profiles": [
            { "id": "{{id}}", "name": "Первое", "server": "vpn.example.org", "userName": "user" },
            { "id": "{{id}}", "name": "Второе", "server": "vpn2.example.org", "userName": "user" }
          ]
        }
        """;
        File.WriteAllText(world.Paths.Settings, original);
        var found = new List<CorruptFile>();
        var store = new ServiceStores(world.Paths) { OnCorrupt = found.Add };

        var settings = store.LoadSettings(out var error);
        store.SaveSettings(settings);
        store.LoadSettings(out _);

        Assert.Null(error);
        Assert.Equal("Первое", Assert.Single(settings.Profiles).Name);
        var copy = Directory.GetFiles(Path.GetDirectoryName(world.Paths.Settings)!, Path.GetFileName(world.Paths.Settings) + ".duplicates-*");
        Assert.Equal(original, File.ReadAllText(Assert.Single(copy)));
        var report = Assert.Single(found);
        Assert.Equal(copy[0], report.CopyPath);
        Assert.Contains("«Второе»", report.Describe(), StringComparison.Ordinal);
    }

    [Fact]
    public void DuplicateIds_NewFileIsKeptSeparately_SameFileOnce()
    {
        using var world = new FakeWorld();
        var store = new ServiceStores(world.Paths) { OnCorrupt = _ => { } };
        string Duplicates(string name)
        {
            var id = Guid.NewGuid();
            return $$"""
            {
              "schemaVersion": {{AppSettings.CurrentSchemaVersion}},
              "profiles": [
                { "id": "{{id}}", "name": "{{name}}", "server": "vpn.example.org", "userName": "user" },
                { "id": "{{id}}", "name": "Повтор", "server": "vpn2.example.org", "userName": "user" }
              ]
            }
            """;
        }

        var first = Duplicates("Первое");
        File.WriteAllText(world.Paths.Settings, first);
        store.LoadSettings(out _);
        store.LoadSettings(out _);

        // Позже в настройках появились другие повторы: прежняя копия их не содержит — нужна своя.
        var second = Duplicates("Второе");
        File.WriteAllText(world.Paths.Settings, second);
        store.LoadSettings(out _);

        var copies = Directory.GetFiles(Path.GetDirectoryName(world.Paths.Settings)!, Path.GetFileName(world.Paths.Settings) + ".duplicates-*")
            .Select(File.ReadAllText).ToList();
        Assert.Equal(2, copies.Count);
        Assert.Contains(first, copies);
        Assert.Contains(second, copies);
    }
}
