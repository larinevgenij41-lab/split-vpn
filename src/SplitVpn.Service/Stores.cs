using System.Globalization;
using System.Text.Json;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;

namespace SplitVpn.Service;

/// <summary>Настройки и состояние службы на диске; запись атомарная.</summary>
public sealed class ServiceStores(ServicePaths paths)
{
    /// <summary>Суффикс копии настроек, которые не удалось прочитать.</summary>
    private const string UnreadableSuffix = ".unreadable-";

    /// <summary>Суффикс копии настроек, из которых при загрузке отброшены повторы или в которых остались неоднозначные адреса.</summary>
    private const string DuplicatesSuffix = ".duplicates-";

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
            OnCorrupt?.Invoke(new CorruptFile(paths.Settings, KeepCopy(UnreadableSuffix),
                "Настройки не прочитаны — служба работает с настройками по умолчанию", error));
            return new AppSettings();
        }

        if (result.Warning is not null)
        {
            // Повторы уже отброшены, и первое сохранение перезапишет файл без них: исходный откладывается
            // рядом, а пользователь видит предупреждение в статусе, как о повреждённом файле.
            OnCorrupt?.Invoke(new CorruptFile(paths.Settings, KeepCopy(DuplicatesSuffix),
                result.Warning.TrimEnd('.'), "записи настроек, требующие внимания"));
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
    /// Копия файла настроек, который служба не может сохранить как есть (нечитаемый, с повторами). Одна на
    /// содержимое: повторные запуски службы с тем же файлом не плодят копии, а другой такой же файл (новые
    /// повторы, новое повреждение) откладывается своей копией до того, как его перезапишет первое сохранение.
    /// </summary>
    private string? KeepCopy(string suffix)
    {
        try
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath(paths.Settings))!;
            var name = Path.GetFileName(paths.Settings);
            var content = File.ReadAllBytes(paths.Settings);
            if (Directory.EnumerateFiles(directory, name + suffix + "*").FirstOrDefault(copy => File.ReadAllBytes(copy).AsSpan().SequenceEqual(content)) is { } existing)
            {
                return existing;
            }

            var target = paths.Settings + suffix + DateTime.Now.ToString("yyyyMMdd-HHmmss-fff", CultureInfo.InvariantCulture);
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

    /// <summary>
    /// Состояние службы. Повреждённый файл откладывается в копию, и служба стартует с намерением «Отключено,
    /// защита сохранена»: каким было намерение, неизвестно, а «Отключено» молча сняло бы защиту. Это состояние
    /// сразу записывается: иначе следующий запуск не нашёл бы файла и начал бы с «Отключено» - защита снялась бы,
    /// если до перезапуска ничто не сохранило состояние. Нет файла (первый запуск) — намерение «Отключено», как прежде.
    /// </summary>
    public ServiceStateFile LoadState()
    {
        CorruptFile? corrupt = null;
        var state = SafeFile.Load(
            paths.State,
            text => NormalizeState(JsonSerializer.Deserialize<ServiceStateFile>(text, JsonDefaults.Options)),
            () => new ServiceStateFile(),
            "Файл состояния службы был повреждён и заменён значениями по умолчанию; защита оставлена включённой",
            file =>
            {
                corrupt = file;
                OnCorrupt?.Invoke(file);
            });
        if (corrupt is null)
        {
            return state;
        }

        var protectedState = state with { Intent = Intent.Protected };
        // Копию отложить не удалось - повреждённый файл остался на месте: следующий запуск снова даст «защита
        // сохранена», а запись поверх стёрла бы единственный экземпляр, по которому можно разобрать причину.
        if (corrupt.CopyPath is not null)
        {
            try
            {
                SaveState(protectedState);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Запуск службы не срывается: защита держится в памяти, а первая же запись состояния её сохранит.
            }
        }

        return protectedState;
    }

    /// <summary>
    /// «null» вместо списка и неверные адреса в кеше серверов (ручная правка, чужая версия) убираются при
    /// загрузке: иначе каждая сверка падала бы на разборе кеша, а обычные команды файл не исправляют.
    /// </summary>
    private static ServiceStateFile? NormalizeState(ServiceStateFile? state) => state is null ? null : state with
    {
        Servers = (state.Servers ?? []).OfType<ServerCacheEntry>().Select(entry => entry with
        {
            Addresses = ValidAddresses(entry.Addresses),
            SessionAddresses = entry.SessionAddresses is null ? null : ValidAddresses(entry.SessionAddresses),
            SessionDns = entry.SessionDns is null ? null : ValidAddresses(entry.SessionDns),
            RevocationHosts = entry.RevocationHosts?.OfType<string>().ToList(),
        }).ToList(),
    };

    private static List<string> ValidAddresses(IReadOnlyList<string?>? addresses) =>
        (addresses ?? []).Where(a => Ipv4.TryParse(a, out _)).Select(a => a!).ToList();

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
