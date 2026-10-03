using System.Globalization;
using System.Text;

namespace SplitVpn.Core.Diagnostics;

/// <summary>
/// Журнал необработанных ошибок интерфейса. Размер ограничен одной ротацией; одинаковые исключения
/// пишутся полностью один раз в <see cref="RepeatWindow"/>, повторы — счётчиком. Лавина одинаковых
/// исключений (цикл раскладки, ошибка в опросе) распознаётся, чтобы вызывающий мог завершить интерфейс,
/// а не крутить UI-поток и диск бесконечно.
/// </summary>
public sealed class ErrorLogWriter(string path, TimeProvider time)
{
    public const long MaxBytes = 5 * 1024 * 1024;
    public const int StormCount = 50;
    public static readonly TimeSpan StormWindow = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan RepeatWindow = TimeSpan.FromMinutes(1);

    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly object _lock = new();

    /// <summary>Записать исключение. false — лавина одинаковых ошибок: продолжать работу бессмысленно.</summary>
    public bool Record(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        lock (_lock)
        {
            var now = time.GetUtcNow();
            var key = KeyOf(exception);
            if (!_entries.TryGetValue(key, out var entry))
            {
                entry = new Entry(now);
                _entries[key] = entry;
                Write($"{now:O} {exception}");
                return true;
            }

            if (now - entry.StormStart > StormWindow)
            {
                entry.StormStart = now;
                entry.StormCount = 0;
            }

            entry.StormCount++;
            entry.Suppressed++;
            if (entry.StormCount >= StormCount)
            {
                Write($"{now:O} Одинаковая ошибка повторилась {entry.Suppressed + 1} раз, интерфейс завершается: {exception}");
                return false;
            }

            if (now - entry.LastWritten >= RepeatWindow)
            {
                Write($"{now:O} Повторилось {entry.Suppressed} раз с {entry.LastWritten.ToString("O", CultureInfo.InvariantCulture)}: {Headline(exception)}");
                entry.LastWritten = now;
                entry.Suppressed = 0;
            }

            return true;
        }
    }

    /// <summary>Тип, сообщение и первая строка стека: одинаковые ошибки из одного места.</summary>
    internal static string KeyOf(Exception exception)
    {
        var stack = exception.StackTrace ?? "";
        var firstFrame = stack.Split('\n', 2)[0].Trim();
        return exception.GetType().FullName + "|" + exception.Message + "|" + firstFrame;
    }

    private static string Headline(Exception exception) => exception.GetType().FullName + ": " + exception.Message;

    private void Write(string text)
    {
        try
        {
            var folder = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(folder))
            {
                Directory.CreateDirectory(folder);
            }

            var info = new FileInfo(path);
            if (info.Exists && info.Length >= MaxBytes)
            {
                File.Move(path, path + ".1", overwrite: true);
            }

            File.AppendAllText(path, text + Environment.NewLine, Encoding.UTF8);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            // Журнал недоступен (занят, нет прав) — ошибка интерфейса не должна порождать новую.
        }
    }

    private sealed class Entry(DateTimeOffset now)
    {
        public DateTimeOffset LastWritten { get; set; } = now;

        public DateTimeOffset StormStart { get; set; } = now;

        public int StormCount { get; set; }

        public int Suppressed { get; set; }
    }
}
