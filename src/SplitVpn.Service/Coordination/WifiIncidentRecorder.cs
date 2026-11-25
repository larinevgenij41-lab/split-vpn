using System.Globalization;
using System.Text;
using Microsoft.Extensions.Logging;

namespace SplitVpn.Service.Coordination;

/// <summary>Событие службы автонастройки WLAN, по которому служба узнаёт о подключении Wi-Fi и о его восстановлении Windows.</summary>
public enum WifiEventKind
{
    /// <summary>WLAN 8001: подключение к сети выполнено.</summary>
    Connected,

    /// <summary>WLAN 8003: отключение от сети.</summary>
    Disconnected,

    /// <summary>WLAN 11004: проверка безопасности остановлена.</summary>
    SecurityStopped,

    /// <summary>WLAN 11005: проверка безопасности выполнена.</summary>
    SecuritySucceeded,

    /// <summary>System 4003: Windows сочла подключение ограниченным и перезапускает адаптер.</summary>
    Recovery,
}

/// <param name="InterfaceGuid">Адаптер Wi-Fi; у события 4003 его нет.</param>
/// <param name="Detail">Поля события одной строкой: для записи разбора.</param>
public sealed record WifiEvent(WifiEventKind Kind, Guid? InterfaceGuid, DateTimeOffset Time, string Detail);

/// <summary>
/// Самописец подключения Wi-Fi. Windows после загрузки нередко сама перезапускает адаптер Wi-Fi («ограниченные
/// возможности подключения», событие 4003), и все туннели рвутся; что именно ей не нравится, из обычных журналов
/// не видно, а ручную трассировку нужная загрузка не дожидается. Самописец держит в памяти последние события
/// Wi-Fi и действия службы в одной шкале времени и пишет их в файл <c>wifi-incident-*.log</c>, как только
/// Windows начала восстановление: сразу, не дожидаясь перезапуска адаптера, — компьютер могут выключить раньше.
/// Потокобезопасен: события Windows приходят из чужого потока.
/// </summary>
public sealed class WifiIncidentRecorder(string? directory, TimeProvider time, ILogger logger)
{
    public const string FilePattern = "wifi-incident-*.log";

    /// <summary>Сколько строк хранится до происшествия.</summary>
    internal const int Capacity = 400;

    /// <summary>Строки старше этого срока к происшествию не относятся.</summary>
    internal static readonly TimeSpan History = TimeSpan.FromMinutes(5);

    /// <summary>Сколько после начала восстановления запись продолжается: перезапуск на 32-й секунде, отключение на 65-й и возврат.</summary>
    internal static readonly TimeSpan Follow = TimeSpan.FromMinutes(4);

    /// <summary>Сколько файлов хранится: старые удаляются.</summary>
    internal const int KeptFiles = 20;

    /// <summary>Предел одного файла: дальше запись продолжается в новом файле, старые удаляются по <see cref="KeptFiles"/>.</summary>
    internal const long MaxFileBytes = 2 * 1024 * 1024;

    /// <summary>
    /// Дольше одно происшествие не продлевается: мигающая связь (признак каждые несколько минут) открывает новое — с
    /// новым файлом и своей предысторией, — а не растит один файл бесконечно.
    /// </summary>
    internal static readonly TimeSpan MaxIncident = TimeSpan.FromMinutes(30);

    private readonly Lock _gate = new();
    private readonly Queue<(DateTimeOffset Time, string Text)> _lines = new();
    private string? _file;
    private DateTimeOffset _fileUntil;
    private DateTimeOffset _incidentStarted;
    private long _fileBytes;
    private bool _writeFailed;

    /// <summary>Файл текущего или последнего происшествия.</summary>
    public string? LastFile { get; private set; }

    /// <summary>Строка в запись: событие Windows или действие службы, которое действительно что-то изменило.</summary>
    public void Note(string text)
    {
        var now = time.GetUtcNow();
        lock (_gate)
        {
            _lines.Enqueue((now, text));
            while (_lines.Count > Capacity || (_lines.Count > 0 && now - _lines.Peek().Time > History))
            {
                _lines.Dequeue();
            }

            if (_file is not null)
            {
                if (now <= _fileUntil)
                {
                    AppendFollowing(now, Format(now, text) + Environment.NewLine);
                }
                else
                {
                    _file = null;
                }
            }
        }
    }

    /// <summary>
    /// Windows начала восстановление Wi-Fi: накопленное пишется в файл, дальнейшее дописывается в него же. Повторный
    /// признак продлевает запись, но не дальше <see cref="MaxIncident"/> от начала происшествия; позже — новое происшествие.
    /// </summary>
    public void Trigger(string reason)
    {
        var now = time.GetUtcNow();
        lock (_gate)
        {
            if (_file is not null && now <= _fileUntil && now - _incidentStarted < MaxIncident)
            {
                var limit = _incidentStarted + MaxIncident;
                _fileUntil = now + Follow < limit ? now + Follow : limit;
                AppendFollowing(now, Format(now, "ПРИЗНАК: " + reason) + Environment.NewLine);
                return;
            }

            if (directory is null)
            {
                return;
            }

            _file = NewFileName(now);
            _fileUntil = now + Follow;
            _incidentStarted = now;
            _fileBytes = 0;
            LastFile = _file;
            var text = new StringBuilder();
            text.AppendLine("Запись подключения Wi-Fi: Windows начала восстановление адаптера. Время местное.");
            text.AppendLine("Признак: " + reason);
            text.AppendLine("--- до признака");
            foreach (var (lineTime, line) in _lines)
            {
                text.AppendLine(Format(lineTime, line));
            }

            text.AppendLine("--- после признака");
            AppendFollowing(now, text.ToString());
            Prune();
        }
    }

    /// <summary>Новый файл с отметкой времени; занятое имя (два файла за секунду) получает номер.</summary>
    private string NewFileName(DateTimeOffset now)
    {
        var stamp = "wifi-incident-" + now.ToLocalTime().ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        var path = Path.Combine(directory!, stamp + ".log");
        for (var n = 2; File.Exists(path) && n < 1000; n++)
        {
            path = Path.Combine(directory!, stamp + "-" + n.ToString(CultureInfo.InvariantCulture) + ".log");
        }

        return path;
    }

    /// <summary>
    /// Дописывает в файл происшествия; на пределе <see cref="MaxFileBytes"/> запись продолжается в новом файле (то же
    /// происшествие, тот же срок), а старые файлы удаляются по <see cref="KeptFiles"/>.
    /// </summary>
    private void AppendFollowing(DateTimeOffset now, string text)
    {
        var bytes = Encoding.UTF8.GetByteCount(text);
        if (_fileBytes > 0 && _fileBytes + bytes > MaxFileBytes)
        {
            _file = NewFileName(now);
            LastFile = _file;
            _fileBytes = 0;
            var header = "Продолжение записи подключения Wi-Fi: прежний файл достиг " + (MaxFileBytes / 1024 / 1024).ToString(CultureInfo.InvariantCulture) + " МБ." + Environment.NewLine;
            _fileBytes += Encoding.UTF8.GetByteCount(header);
            Append(_file, header);
            Prune();
        }

        _fileBytes += bytes;
        Append(_file!, text);
    }

    /// <summary>Накопленные строки: для испытаний и архива разбора.</summary>
    internal IReadOnlyList<string> Snapshot()
    {
        lock (_gate)
        {
            return _lines.Select(l => l.Text).ToList();
        }
    }

    private static string Format(DateTimeOffset moment, string text) =>
        moment.ToLocalTime().ToString("HH:mm:ss.fff", CultureInfo.InvariantCulture) + " " + text;

    private void Append(string path, string text)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.AppendAllText(path, text, Encoding.UTF8);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            if (!_writeFailed)
            {
                _writeFailed = true;
                logger.LogWarning(ex, "Запись подключения Wi-Fi не сохранена: {Path}", path);
            }
        }
    }

    private void Prune()
    {
        try
        {
            foreach (var old in new DirectoryInfo(directory!).GetFiles(FilePattern).OrderByDescending(f => f.Name, StringComparer.Ordinal).Skip(KeptFiles))
            {
                old.Delete();
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Старые записи удалит следующее происшествие.
        }
    }
}
