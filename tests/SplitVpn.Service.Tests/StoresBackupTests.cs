using SplitVpn.Core.Settings;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Копии файла настроек: сбой записи копии прежней схемы не роняет запуск службы, а копия .bak переживает
/// мгновенную блокировку (антивирус) и, не сумев записаться, отменяет сохранение, не трогая файл настроек.
/// </summary>
public sealed class StoresBackupTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "splitvpn-stores-" + Guid.NewGuid().ToString("N"));
    private readonly ServicePaths _paths;

    public StoresBackupTests()
    {
        _paths = new ServicePaths(_root);
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch (IOException) { }
    }

    private const string SchemaV1 = """
        {
          "schemaVersion": 1,
          "profiles": [{ "id": "6f1e3c1a-1111-4a5b-9c1d-000000000001", "name": "Старый", "server": "203.0.113.10:4443", "userName": "user" }],
          "activeProfileId": "6f1e3c1a-1111-4a5b-9c1d-000000000001",
          "routingMode": "RussiaDirect"
        }
        """;

    /// <summary>
    /// Копию прежней схемы записать нельзя (на её месте каталог): загрузка не бросает исключение, а сообщает о сбое.
    /// Первое сохранение тоже не может отложить копию и отказывает, не трогая исходный файл; когда запись снова
    /// возможна, сохранение откладывает копию прежней схемы перед перезаписью — настройки пользователя не теряются.
    /// </summary>
    [Fact]
    public void MigrationBackupFailure_DoesNotStopLoad_AndSaveKeepsOldFile()
    {
        File.WriteAllText(_paths.Settings, SchemaV1);
        var stores = new ServiceStores(_paths);
        var reports = new List<CorruptFile>();
        stores.OnCorrupt = reports.Add;
        Directory.CreateDirectory(stores.PreviousSchemaBackup);

        var settings = stores.LoadSettings(out var error);

        Assert.Null(error);
        Assert.True(stores.Migrated);
        Assert.True(stores.PreviousSchemaBackupFailed);
        Assert.Single(settings.Profiles);
        var report = Assert.Single(reports);
        Assert.Equal(stores.PreviousSchemaBackup, report.FilePath);
        // Копии нет - сообщение на неё не ссылается (прежде копией значился сам settings.json).
        Assert.Null(report.CopyPath);

        var failure = Assert.ThrowsAny<Exception>(() => stores.SaveSettings(settings));
        Assert.True(failure is IOException or UnauthorizedAccessException, failure.ToString());
        Assert.Equal(SchemaV1, File.ReadAllText(_paths.Settings));

        Directory.Delete(stores.PreviousSchemaBackup);
        stores.SaveSettings(settings);

        Assert.Equal(SchemaV1, File.ReadAllText(stores.PreviousSchemaBackup));
        Assert.NotEqual(SchemaV1, File.ReadAllText(_paths.Settings));
    }

    /// <summary>Копию .bak на мгновение держит другой процесс: сохранение повторяет копирование и проходит.</summary>
    [Fact]
    public async Task SettingsBak_BrieflyLocked_SaveSucceeds()
    {
        var stores = new ServiceStores(_paths);
        stores.SaveSettings(new AppSettings());
        stores.SaveSettings(new AppSettings());
        var before = File.ReadAllText(_paths.Settings);
        var settings = new AppSettings { Profiles = [new ConnectionProfile { Name = "Работа", Server = "work.example", UserName = "user" }] };

        var locked = new FileStream(_paths.Settings + ".bak", FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        // Блокировку снимает свой поток, а не задача пула: SaveSettings ждёт повторов синхронно, и при занятом пуле
        // отложенная задача могла не успеть за все ~2,2 с повторов FileRetry.
        var release = new Thread(() =>
        {
            Thread.Sleep(150);
            locked.Dispose();
        }) { IsBackground = true };
        release.Start();
        try
        {
            stores.SaveSettings(settings);
        }
        finally
        {
            await Task.Run(() => release.Join(), TestContext.Current.CancellationToken);
        }

        Assert.Equal(before, File.ReadAllText(_paths.Settings + ".bak"));
        Assert.Contains("work.example", File.ReadAllText(_paths.Settings), StringComparison.Ordinal);
    }

    /// <summary>Копия .bak так и не записалась: сохранение отменяется, файл настроек остаётся прежним.</summary>
    [Fact]
    public void SettingsBak_StaysLocked_SaveFailsAndKeepsSettings()
    {
        var stores = new ServiceStores(_paths);
        stores.SaveSettings(new AppSettings());
        stores.SaveSettings(new AppSettings());
        var before = File.ReadAllText(_paths.Settings);
        var settings = new AppSettings { Profiles = [new ConnectionProfile { Name = "Работа", Server = "work.example", UserName = "user" }] };

        var bak = File.ReadAllText(_paths.Settings + ".bak");
        var watch = System.Diagnostics.Stopwatch.StartNew();
        using (new FileStream(_paths.Settings + ".bak", FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            Assert.ThrowsAny<IOException>(() => stores.SaveSettings(settings));
        }

        watch.Stop();
        // Отказ - только после повторов FileRetry (паузы в сумме 2,2 с), а не с первой попытки, как до исправления.
        Assert.True(watch.Elapsed >= TimeSpan.FromMilliseconds(1800), $"отказ через {watch.ElapsedMilliseconds} мс, без повторов");
        Assert.Equal(before, File.ReadAllText(_paths.Settings));
        Assert.Equal(bak, File.ReadAllText(_paths.Settings + ".bak"));
    }
}
