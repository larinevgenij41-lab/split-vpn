using System.Globalization;
using System.Text.Json;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;

namespace SplitVpn.Service;

/// <summary>Настройки и состояние службы на диске; запись атомарная.</summary>
public sealed class ServiceStores(ServicePaths paths)
{
    /// <summary>Суффикс копии настроек, которые не удалось прочитать.</summary>
    private const string UnreadableSuffix = ".unreadable-";

    public ServicePaths Paths => paths;

    /// <summary>Куда сообщать о повреждённых файлах: журнал событий и предупреждение в статусе.</summary>
    public Action<CorruptFile>? OnCorrupt { get; set; }

    /// <summary>Копия настроек прежней схемы: откат на старую версию программы иначе остался бы без настроек.</summary>
    public string PreviousSchemaBackup => paths.Settings + ".v1.bak";

    public AppSettings LoadSettings(out string? error)
    {
        error = null;
        if (!File.Exists(paths.Settings))
        {
            return new AppSettings();
        }

        var text = File.ReadAllText(paths.Settings);
        var result = SettingsSerializer.Deserialize(text);
        error = result.Error;
        if (error is not null)
        {
            // Дальше служба работает с настройками по умолчанию и первым же сохранением перезапишет файл:
            // исходный откладывается рядом, чтобы подключения и правила можно было вернуть вручную.
            OnCorrupt?.Invoke(new CorruptFile(paths.Settings, KeepUnreadable(),
                "Настройки не прочитаны — служба работает с настройками по умолчанию", error));
            return new AppSettings();
        }

        if (result.Migrated)
        {
            if (!File.Exists(PreviousSchemaBackup))
            {
                AtomicFile.WriteAllText(PreviousSchemaBackup, text);
            }

            Migrated = true;
        }

        return result.Settings ?? new AppSettings();
    }

    /// <summary>Настройки при загрузке переведены на новую схему; прежний файл сохранён рядом.</summary>
    public bool Migrated { get; private set; }

    /// <summary>
    /// Копия нечитаемого файла настроек. Делается один раз: повторные запуски службы с тем же файлом
    /// не плодят копии, а первая сохраняет настройки до того, как их перезапишет первое сохранение.
    /// </summary>
    private string? KeepUnreadable()
    {
        try
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath(paths.Settings))!;
            var name = Path.GetFileName(paths.Settings);
            if (Directory.EnumerateFiles(directory, name + UnreadableSuffix + "*").FirstOrDefault() is { } existing)
            {
                return existing;
            }

            var target = paths.Settings + UnreadableSuffix + DateTime.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
            File.Copy(paths.Settings, target, overwrite: false);
            return target;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return null;
        }
    }

    public void SaveSettings(AppSettings settings)
    {
        if (File.Exists(paths.Settings))
        {
            // Файл прежней схемы сохраняется один раз: откат на старую версию программы иначе остался бы без настроек.
            if (ReadSchemaVersion(File.ReadAllText(paths.Settings)) is 1 or 2 && !File.Exists(PreviousSchemaBackup))
            {
                File.Copy(paths.Settings, PreviousSchemaBackup);
            }

            File.Copy(paths.Settings, paths.Settings + ".bak", overwrite: true);
        }

        AtomicFile.WriteAllText(paths.Settings, SettingsSerializer.Serialize(settings));
    }

    private static int ReadSchemaVersion(string json)
    {
        try
        {
            using var previous = JsonDocument.Parse(json);
            return previous.RootElement.ValueKind == JsonValueKind.Object && previous.RootElement.TryGetProperty("schemaVersion", out var version)
                && version.ValueKind == JsonValueKind.Number && version.TryGetInt32(out var schema) ? schema : 0;
        }
        catch (JsonException) { return 0; }
    }

    /// <summary>Состояние службы; повреждённый файл откладывается в копию, служба стартует с намерением «Отключено».</summary>
    public ServiceStateFile LoadState() => SafeFile.Load(
        paths.State,
        text => JsonSerializer.Deserialize<ServiceStateFile>(text, JsonDefaults.Options),
        () => new ServiceStateFile(),
        "Файл состояния службы был повреждён и заменён значениями по умолчанию",
        OnCorrupt);

    public void SaveState(ServiceStateFile state) => AtomicFile.WriteAllText(paths.State, JsonSerializer.Serialize(state, JsonDefaults.Options));
}

/// <summary>Кольцевой журнал значимых событий для экрана «Диагностика». Имена доменов сюда не пишутся.</summary>
public sealed class EventJournal(TimeProvider time, int capacity = 500)
{
    private readonly LinkedList<ServiceEvent> _events = new();
    private readonly Lock _lock = new();
    private long _nextId = 1;

    public void Add(string level, string text)
    {
        lock (_lock)
        {
            _events.AddLast(new ServiceEvent(_nextId++, time.GetUtcNow(), level, text));
            while (_events.Count > capacity)
            {
                _events.RemoveFirst();
            }
        }
    }

    /// <summary>
    /// События после указанного. Номер, которого ещё не было, означает, что интерфейс помнит журнал прежнего
    /// запуска службы: тогда отдаётся весь журнал, и интерфейс по первому номеру понимает, что список начат заново.
    /// </summary>
    public IReadOnlyList<ServiceEvent> Since(long id)
    {
        lock (_lock)
        {
            return id >= _nextId ? _events.ToList() : _events.Where(e => e.Id > id).ToList();
        }
    }
}
