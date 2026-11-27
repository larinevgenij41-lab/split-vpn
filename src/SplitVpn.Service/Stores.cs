using System.Globalization;
using System.Text.Json;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
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

    /// <summary>Суффикс копии настроек, в которых при загрузке значения вне допустимых заменены значениями по умолчанию.</summary>
    private const string RepairedSuffix = ".repaired-";

    public ServicePaths Paths => paths;

    /// <summary>Куда сообщать о повреждённых файлах: журнал событий и предупреждение в статусе.</summary>
    public Action<CorruptFile>? OnCorrupt { get; set; }

    /// <summary>Копия настроек прежней схемы: откат на старую версию программы иначе остался бы без настроек.</summary>
    public string PreviousSchemaBackup => paths.Settings + ".v1.bak";

    public bool SettingsReadPending { get; private set; }

    public AppSettings LoadSettings(out string? error)
    {
        SettingsReadPending = false;
        PreviousSchemaBackupFailed = false;
        error = null;
        string text;
        try { text = File.ReadAllText(paths.Settings); }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return new AppSettings();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            SettingsReadPending = true;
            error = "Не удалось прочитать настройки: " + ex.Message;
            return new AppSettings();
        }
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

        // Проверка настроек идёт только при сохранении: значение вне допустимых (ручная правка, другая версия
        // программы) иначе загрузилось бы и срывало каждую сверку. Такие значения заменяются значениями по
        // умолчанию, остальные настройки остаются; прочие ошибки проверки покажет первое сохранение, как прежде.
        var settings = SettingsValidator.RepairOnLoad(result.Settings ?? new AppSettings(), out var repairs);
        var repaired = repairs.Count == 0 ? null
            : "Часть настроек вне допустимых значений заменена значениями по умолчанию: " + string.Join("; ", repairs.Select(r => r.TrimEnd('.')));
        string? copy = null;
        if (result.Warning is not null || repaired is not null)
        {
            // Повторы уже отброшены, значения исправлены, и первое сохранение перезапишет файл: исходный
            // откладывается рядом, а пользователь видит предупреждение в статусе, как о повреждённом файле.
            // Сообщение одно на файл: журнал повреждённых файлов принимает по одной записи на путь.
            var summary = string.Join(" ", new[] { result.Warning, repaired }.OfType<string>()).TrimEnd('.');
            copy = KeepCopy(result.Warning is not null ? DuplicatesSuffix : RepairedSuffix);
            OnCorrupt?.Invoke(new CorruptFile(paths.Settings, copy, summary, "записи настроек, требующие внимания"));
        }

        if (result.Migrated)
        {
            if (!File.Exists(PreviousSchemaBackup))
            {
                // Сбой записи копии не срывает запуск службы: исключение из конструктора координатора остановило бы
                // службу с оставленными фильтрами. Файл прежней схемы остаётся на месте, и SaveSettings отложит его
                // копию перед первой перезаписью, а не сумев - откажет в сохранении.
                try
                {
                    AtomicFile.WriteAllText(PreviousSchemaBackup, text);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // Копии нет: ссылки на неё в сообщении тоже нет (прежде полем копии значился сам settings.json).
                    PreviousSchemaBackupFailed = true;
                    OnCorrupt?.Invoke(new CorruptFile(PreviousSchemaBackup, null,
                        "Копию настроек прежней версии сохранить не удалось; она будет сделана при первом сохранении настроек", ex.Message));
                }
            }

            Migrated = true;
        }

        if (repaired is not null && copy is not null)
        {
            // Исправленные значения сразу записываются в файл: иначе до первого сохранения каждый запуск службы
            // повторял бы ошибку в журнале и предупреждение в статусе. Только при отложенной копии исходного файла -
            // без неё запись стёрла бы единственный экземпляр.
            try
            {
                SaveSettings(settings);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Запуск службы не срывается: исправленные значения действуют в памяти, файл перезапишет первое сохранение.
            }
        }

        return settings;
    }

    /// <summary>
    /// Настройки при загрузке переведены на новую схему; прежний файл сохранён рядом (<see cref="PreviousSchemaBackup"/>),
    /// если не <see cref="PreviousSchemaBackupFailed"/>.
    /// </summary>
    public bool Migrated { get; private set; }

    /// <summary>
    /// При переводе на новую схему копию прежнего файла записать не удалось: её отложит первое сохранение настроек
    /// (<see cref="SaveSettings"/>), а до того файл прежней схемы остаётся на месте.
    /// </summary>
    public bool PreviousSchemaBackupFailed { get; private set; }

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
            foreach (var copy in Directory.EnumerateFiles(directory, name + suffix + "*"))
            {
                try { if (File.ReadAllBytes(copy).AsSpan().SequenceEqual(content)) return copy; }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
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
                FileRetry.Run(() => File.Copy(paths.Settings, PreviousSchemaBackup, overwrite: true));
            }

            // Файл только что прочитан или записан - антивирус может держать его мгновение. Окончательный сбой
            // копии отменяет сохранение: .bak - единственный откат к прежней версии, а если копию нечитаемого файла
            // отложить не удалось, то и единственный экземпляр исходного. Вызывающие сообщают отказ клиенту.
            FileRetry.Run(() => File.Copy(paths.Settings, paths.Settings + ".bak", overwrite: true));
        }

        AtomicFile.WriteAllText(paths.Settings, SettingsSerializer.Serialize(settings));
        SettingsReadPending = false;
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
            () => new ServiceStateFile { Intent = Directory.Exists(paths.Root) &&
                Directory.EnumerateFiles(paths.Root, Path.GetFileName(paths.State) + ".corrupt-*").Any() ? Intent.Protected : Intent.Off },
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
        Servers = (state.Servers ?? []).OfType<ServerCacheEntry>().DistinctBy(entry => entry.ProfileId).Select(entry => entry with
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

    /// <summary>Версия формата файла закреплений: файл другой версии не читается (закрепления просто не восстанавливаются).</summary>
    internal const int PinFileVersion = 2;

    /// <summary>Предел размера файла закреплений: больший файл - чужой или испорченный, его не читаем.</summary>
    internal const long MaxPinFileBytes = 16L * 1024 * 1024;

    /// <summary>
    /// Закрепления прежнего запуска службы; null - файла нет. Испорченный, слишком большой файл или файл другой версии -
    /// <see cref="InvalidDataException"/>: закрепления - лишь подсказка для первой сверки, их потеря не мешает работе,
    /// поэтому файл не откладывается в копию и не попадает в повреждённые (его перезапишет первое же сохранение).
    /// </summary>
    internal PinFileContent? LoadPins()
    {
        string text;
        try
        {
            var info = new FileInfo(paths.Pins);
            if (!info.Exists)
            {
                return null;
            }

            if (info.Length > MaxPinFileBytes)
            {
                throw new InvalidDataException($"файл закреплений больше {MaxPinFileBytes / (1024 * 1024)} МБ");
            }

            text = File.ReadAllText(paths.Pins);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }

        PinFileContent? content;
        try
        {
            content = JsonSerializer.Deserialize<PinFileContent>(text, JsonDefaults.Options);
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("файл закреплений не разобран: " + ex.Message, ex);
        }

        if (content is null)
        {
            throw new InvalidDataException("файл закреплений пуст");
        }

        if (content.Version != PinFileVersion)
        {
            throw new InvalidDataException(string.Create(CultureInfo.InvariantCulture,
                $"файл закреплений другой версии ({content.Version}, ожидается {PinFileVersion})"));
        }

        return content;
    }

    /// <summary>
    /// Записывает файл закреплений; возвращает число записанных закреплений. Записи идут от самых свежих: если файл
    /// не укладывается в предел чтения <see cref="MaxPinFileBytes"/> с запасом (длинные имена), отбрасывается старшая
    /// половина, пока не уложится - иначе следующий запуск отверг бы файл целиком. Замена через временный файл (старое
    /// или новое содержимое), но без сброса на диск: файл - лишь подсказка, после сбоя питания он не нужен (перезагрузка
    /// закрепления всё равно не восстанавливает). Каталог данных не создаётся: его нет - служба удаляется.
    /// </summary>
    internal int SavePins(PinFileContent content)
    {
        ArgumentNullException.ThrowIfNull(content);
        var pins = content.Pins ?? [];
        var bytes = JsonSerializer.SerializeToUtf8Bytes(content, JsonDefaults.Compact);
        while (bytes.Length > MaxPinFileBytes / 2 && pins.Count > 0)
        {
            pins = pins.Take(pins.Count / 2).ToList();
            bytes = JsonSerializer.SerializeToUtf8Bytes(content with { Pins = pins }, JsonDefaults.Compact);
        }

        var temp = string.Create(CultureInfo.InvariantCulture,
            $"{paths.Pins}.{Environment.ProcessId}-{Interlocked.Increment(ref _pinTempSequence)}.tmp");
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.Write(bytes);
            }

            FileRetry.Run(() => File.Move(temp, paths.Pins, overwrite: true));
        }
        finally
        {
            try
            {
                File.Delete(temp);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Недописанный временный файл удалит следующий запуск службы (DeleteStalePinTemps) или удаление программы
                // (pins.json*); работе он не мешает.
            }
        }

        return pins.Count;
    }

    private static long _pinTempSequence;

    /// <summary>Закреплений нет (защита снята, все истекли): файл удаляется, а не хранит пустой список.</summary>
    internal void DeletePins() => File.Delete(paths.Pins);

    /// <summary>
    /// Удаляет недописанные временные файлы <see cref="SavePins"/>, оставшиеся от процесса, завершённого посреди записи:
    /// только в каталоге файла закреплений (без подкаталогов) и только с именем точно «pins.json.&lt;число&gt;-&lt;число&gt;.tmp».
    /// Каталога нет - удалять нечего. Возвращает число удалённых; не удалось удалить хоть один - исключение.
    /// </summary>
    internal int DeleteStalePinTemps()
    {
        var directory = Path.GetDirectoryName(paths.Pins);
        if (directory is null || !Directory.Exists(directory))
        {
            return 0;
        }

        var name = Path.GetFileName(paths.Pins);
        var deleted = 0;
        foreach (var file in Directory.EnumerateFiles(directory, name + ".*.tmp", SearchOption.TopDirectoryOnly))
        {
            if (!IsPinTempName(name, Path.GetFileName(file)))
            {
                continue;
            }

            File.Delete(file);
            deleted++;
        }

        return deleted;
    }

    /// <summary>Имя временного файла записи закреплений: «&lt;файл&gt;.&lt;номер процесса&gt;-&lt;номер записи&gt;.tmp».</summary>
    internal static bool IsPinTempName(string pinFileName, string fileName)
    {
        if (fileName.Length <= pinFileName.Length + 1 + ".tmp".Length
            || !fileName.StartsWith(pinFileName + ".", StringComparison.OrdinalIgnoreCase)
            || !fileName.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var middle = fileName.AsSpan(pinFileName.Length + 1, fileName.Length - pinFileName.Length - 1 - ".tmp".Length);
        var dash = middle.IndexOf('-');
        return dash > 0 && dash < middle.Length - 1 && AllDigits(middle[..dash]) && AllDigits(middle[(dash + 1)..]);

        static bool AllDigits(ReadOnlySpan<char> text)
        {
            foreach (var c in text)
            {
                if (!char.IsAsciiDigit(c))
                {
                    return false;
                }
            }

            return true;
        }
    }
}

/// <summary>
/// Файл закреплений по правилам для доменов (<see cref="ServicePaths.Pins"/>): время записи по настенным часам UTC, время
/// работы Windows (<see cref="Coordination.ServiceDependencies.SystemUptime"/>) и номер загрузки на момент записи. По ним
/// следующий запуск узнаёт перезагрузку (тогда закрепления не восстанавливаются) и длительность простоя - по монотонному
/// счётчику, а не по настенным часам, которые за это время могли перевести.
/// </summary>
internal sealed record PinFileContent(int Version, DateTimeOffset SavedUtc, TimeSpan? SavedUptime, string? BootId,
    IReadOnlyList<PinFileEntry?>? Pins);

/// <summary>
/// Одно закрепление: адрес, цель и правило (суффикс), запрошенное имя и исходное имя CNAME (по ним закрепление
/// перепроверяется так же, как живое), основной срок и срок продления. Цель без вида (null) - запись испорчена:
/// вид по умолчанию был бы «напрямую».
/// </summary>
internal sealed record PinFileEntry(string? Address, TargetKind? Kind, Guid? Id, string? Suffix, string? Name, string? Origin,
    DateTimeOffset ExpiresUtc, DateTimeOffset LingerUntilUtc);

/// <summary>Кольцевой журнал значимых событий для экрана «Диагностика». Имена доменов сюда не пишутся.</summary>
public sealed class EventJournal(TimeProvider time, int capacity = 500)
{
    private readonly LinkedList<ServiceEvent> _events = new();
    private readonly Lock _lock = new();
    private readonly long _epoch = Random.Shared.NextInt64(1, int.MaxValue) << 32;
    private long _sequence;

    /// <summary>
    /// Длина текста события: в текст попадают данные извне (ответы шлюзов, имена чужих подключений), а журнал целиком
    /// уходит одним кадром канала (GetEventsRequest(0), отчёт). 500 событий по этому пределу помещаются в кадр.
    /// </summary>
    public const int MaxTextLength = 1800;

    public void Add(string level, string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        // Список событий программы показывает эти строки: тот же разбор, что у журнала службы (Coordinator.Journal).
        text = Core.Diagnostics.LogText.SingleLine(text);
        if (text.Length > MaxTextLength)
        {
            text = text[..MaxTextLength] + "…";
        }

        lock (_lock)
        {
            _events.AddLast(new ServiceEvent(_epoch + ++_sequence, time.GetUtcNow(), level, text));
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
            return (id >> 32) != (_epoch >> 32) || id > _epoch + _sequence ? _events.ToList() : _events.Where(e => e.Id > id).ToList();
        }
    }
}
