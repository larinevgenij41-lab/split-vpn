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
}
