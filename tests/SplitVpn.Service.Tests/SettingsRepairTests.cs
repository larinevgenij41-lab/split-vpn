using SplitVpn.Core.Geo;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Значения вне допустимых в файле настроек (ручная правка, другая версия программы) проверка при сохранении
/// не видит. При загрузке они заменяются значениями по умолчанию: иначе служба не собирала бы политику или
/// падала бы на плановом обновлении списков, а остальные настройки пользователя пропадать не должны.
/// </summary>
public sealed class SettingsRepairTests
{
    [Fact]
    public void LoadSettings_RepairsOutOfRangeValues_KeepsTheRest_AndReportsOnce()
    {
        using var world = new FakeWorld();
        var profile = new ConnectionProfile { Name = "Нидерланды", Server = "vpn.example.org", UserName = "user", Role = ProfileRole.Primary };
        var original = SettingsSerializer.Serialize(new AppSettings
        {
            Profiles = [profile],
            DefaultTarget = RouteTarget.Tunnel(profile.Id),
            BypassAggregatePrefix = 8,
            GeoUpdate = new GeoUpdateSettings { Mirrors = ["не адрес", "https://mirror.example.org/geo.txt"], IntervalDays = 5 },
            BypassUpdate = new GeoUpdateSettings { Source = GeoSourceKind.CustomUrl, CustomUrl = null },
            AppUpdate = new AppUpdateSettings { ManifestMirrors = ["http://plain.example.org/manifest.json"] },
        });
        File.WriteAllText(world.Paths.Settings, original);
        var found = new List<CorruptFile>();
        var store = new ServiceStores(world.Paths) { OnCorrupt = found.Add };

        var settings = store.LoadSettings(out var error);

        Assert.Null(error);
        Assert.Equal(profile.Id, Assert.Single(settings.Profiles).Id);
        Assert.Equal(RouteTarget.Tunnel(profile.Id), settings.DefaultTarget);
        Assert.Equal(BypassAggregation.DefaultPrefix, settings.BypassAggregatePrefix);
        Assert.Equal("https://mirror.example.org/geo.txt", Assert.Single(settings.GeoUpdate.Mirrors));
        Assert.Equal(1, settings.GeoUpdate.IntervalDays);
        Assert.Equal(GeoSourceKind.ReFilter, settings.BypassUpdate.Source);
        Assert.Empty(settings.AppUpdate.ManifestMirrors);
        // Источники списков после исправления собираются без исключений.
        Assert.NotNull(GeoSourceFactory.Create(settings.GeoUpdate));
        Assert.NotNull(GeoSourceFactory.Create(settings.BypassUpdate));

        var report = Assert.Single(found);
        Assert.Contains("свёртки", report.Describe(), StringComparison.Ordinal);
        Assert.Contains("не адрес", report.Describe(), StringComparison.Ordinal);
        var copy = Directory.GetFiles(Path.GetDirectoryName(world.Paths.Settings)!, Path.GetFileName(world.Paths.Settings) + ".repaired-*");
        Assert.Equal(original, File.ReadAllText(Assert.Single(copy)));

        // Исправленные значения записаны в файл: следующий запуск загружает его без исправлений и ни о чём не сообщает.
        var next = new List<CorruptFile>();
        var reloaded = new ServiceStores(world.Paths) { OnCorrupt = next.Add }.LoadSettings(out var nextError);
        Assert.Null(nextError);
        Assert.Empty(next);
        Assert.Equal(BypassAggregation.DefaultPrefix, reloaded.BypassAggregatePrefix);
        Assert.Equal(1, reloaded.GeoUpdate.IntervalDays);
        Assert.Equal(profile.Id, Assert.Single(reloaded.Profiles).Id);
    }

    /// <summary>Копию исходного файла отложить не удалось: исправленные значения не записываются поверх единственного экземпляра.</summary>
    [Fact]
    public void LoadSettings_RepairWithoutCopy_KeepsOriginalFile()
    {
        using var world = new FakeWorld();
        var original = SettingsSerializer.Serialize(new AppSettings { BypassAggregatePrefix = 8 });
        File.WriteAllText(world.Paths.Settings, original);
        // Прежняя копия занята другой программой: сравнить с ней содержимое нельзя, и новая копия не делается.
        var busy = world.Paths.Settings + ".repaired-busy";
        File.WriteAllText(busy, "{}");
        var found = new List<CorruptFile>();
        var store = new ServiceStores(world.Paths) { OnCorrupt = found.Add };

        using (new FileStream(busy, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            var settings = store.LoadSettings(out _);
            Assert.Equal(BypassAggregation.DefaultPrefix, settings.BypassAggregatePrefix);
        }

        Assert.Null(Assert.Single(found).CopyPath);
        Assert.Equal(original, File.ReadAllText(world.Paths.Settings));
    }

    [Fact]
    public void LoadSettings_ValidFile_IsNotReported()
    {
        using var world = new FakeWorld();
        var store = new ServiceStores(world.Paths);
        store.SaveSettings(new AppSettings { BypassAggregatePrefix = BypassAggregation.Off });
        var found = new List<CorruptFile>();
        store.OnCorrupt = found.Add;

        var settings = store.LoadSettings(out _);

        Assert.Equal(BypassAggregation.Off, settings.BypassAggregatePrefix);
        Assert.Empty(found);
    }

    [Fact]
    public void RepairOnLoad_WithoutProblems_ReturnsSameInstance()
    {
        var settings = SettingsSerializer.Normalize(new AppSettings());

        var repaired = SettingsValidator.RepairOnLoad(settings, out var repairs);

        Assert.Same(settings, repaired);
        Assert.Empty(repairs);
    }
}
