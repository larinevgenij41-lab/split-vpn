using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SplitVpn.Core.Settings;

public static class JsonDefaults
{
    public static JsonSerializerOptions Options { get; } = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Converters = { new JsonStringEnumConverter() },
    };

    /// <summary>Компактный вариант для IPC.</summary>
    public static JsonSerializerOptions Compact { get; } = new(Options) { WriteIndented = false };
}

public static class AtomicFile
{
    private static long _sequence;

    /// <summary>Запись через временный файл и замену: при сбое остаётся либо старое, либо новое содержимое.</summary>
    public static void WriteAllText(string path, string content)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        // Имя временного файла своё у каждой записи: иначе служба и команда восстановления, пишущие один
        // файл одновременно, затирали бы общий «.tmp» друг у друга.
        var temp = string.Create(CultureInfo.InvariantCulture,
            $"{path}.{Environment.ProcessId}-{Interlocked.Increment(ref _sequence)}.tmp");
        try
        {
            using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var writer = new StreamWriter(stream))
            {
                writer.Write(content);
                writer.Flush();
                stream.Flush(flushToDisk: true);
            }

            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            // Незавершённая запись не оставляет мусор рядом с настройками и состоянием.
            if (File.Exists(temp))
            {
                TryDelete(temp);
            }
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Файл занят: он будет перезаписан следующей попыткой с тем же именем.
        }
    }
}

/// <summary>
/// Служебный файл, который не удалось прочитать: копия отложена рядом, а служба работает со значениями
/// по умолчанию. Текст идёт в журнал событий и в предупреждения статуса.
/// </summary>
public sealed record CorruptFile(string FilePath, string? CopyPath, string Summary, string Error)
{
    /// <summary>Что случилось и где искать копию — без технической причины.</summary>
    public string Describe() => CopyPath is null
        ? Summary + " (копию повреждённого файла сохранить не удалось)"
        : $"{Summary} (копия: {Path.GetFileName(CopyPath)})";
}

/// <summary>
/// Находки о повреждённых служебных файлах. Записи приходят из любого потока (часть чтений идёт вне
/// очереди актора), читаются при сборке статуса; на каждый файл — одно сообщение.
/// </summary>
public sealed class CorruptFileLog
{
    private readonly ConcurrentDictionary<string, CorruptFile> _files = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Вызывается один раз на файл: служба пишет находку в журнал событий.</summary>
    public Action<CorruptFile>? Reported { get; set; }

    /// <summary>Все находки с запуска службы: предупреждение видно, пока службу не перезапустили.</summary>
    public IReadOnlyList<CorruptFile> All => _files.Values.ToList();

    public void Add(CorruptFile file)
    {
        ArgumentNullException.ThrowIfNull(file);
        if (_files.TryAdd(file.FilePath, file))
        {
            Reported?.Invoke(file);
        }
    }
}

/// <summary>Чтение служебных файлов, которое не роняет службу: повреждённый файл откладывается в копию.</summary>
public static class SafeFile
{
    /// <summary>
    /// Читает файл и разбирает его. Ошибка разбора или формата означает повреждение: файл переименовывается
    /// в «имя.corrupt-ГГГГММДД-ЧЧММСС» (если переименовать не вышло — остаётся на месте), вызывающий получает
    /// значение по умолчанию, а находка уходит в onCorrupt. Отсутствие файла ошибкой не считается; ошибки
    /// ввода-вывода (файл занят, нет доступа) проходят наверх — они не означают порчу содержимого.
    /// </summary>
    public static T Load<T>(string path, Func<string, T?> parse, Func<T> fallback, string summary, Action<CorruptFile>? onCorrupt)
        where T : class?
    {
        ArgumentNullException.ThrowIfNull(parse);
        ArgumentNullException.ThrowIfNull(fallback);
        if (!File.Exists(path))
        {
            return fallback();
        }

        string error;
        try
        {
            if (parse(File.ReadAllText(path)) is { } value)
            {
                return value;
            }

            error = "файл пуст";
        }
        catch (Exception ex) when (IsBadContent(ex))
        {
            error = ex.Message;
        }

        onCorrupt?.Invoke(new CorruptFile(path, Quarantine(path), summary, error));
        return fallback();
    }

    /// <summary>
    /// Ошибки содержимого: разбор JSON, неверный формат, неожиданные значения. Отмена (OperationCanceledException)
    /// и ошибки ввода-вывода сюда не попадают.
    /// </summary>
    private static bool IsBadContent(Exception ex) =>
        ex is JsonException or NotSupportedException or FormatException or ArgumentException
            or InvalidOperationException or OverflowException or KeyNotFoundException;

    /// <summary>Отложить повреждённый файл рядом: по нему потом можно разобрать причину и вернуть данные вручную.</summary>
    private static string? Quarantine(string path)
    {
        try
        {
            var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
            var target = path + ".corrupt-" + stamp;
            for (var attempt = 2; File.Exists(target) && attempt < 100; attempt++)
            {
                target = string.Create(CultureInfo.InvariantCulture, $"{path}.corrupt-{stamp}-{attempt}");
            }

            File.Move(path, target);
            return target;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or System.Security.SecurityException)
        {
            return null;
        }
    }
}
