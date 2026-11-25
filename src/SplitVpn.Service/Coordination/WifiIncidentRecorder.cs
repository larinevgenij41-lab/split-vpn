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

    private readonly Lock _gate = new();
    private readonly Queue<(DateTimeOffset Time, string Text)> _lines = new();
    private string? _file;
    private DateTimeOffset _fileUntil;
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
                    Append(_file, Format(now, text) + Environment.NewLine);
                }
                else
                {
                    _file = null;
                }
            }
        }
    }

    /// <summary>Windows начала восстановление Wi-Fi: накопленное пишется в файл, дальнейшее дописывается в него же.</summary>
    public void Trigger(string reason)
    {
        var now = time.GetUtcNow();
        lock (_gate)
        {
            if (_file is not null && now <= _fileUntil)
            {
                _fileUntil = now + Follow;
                Append(_file, Format(now, "ПРИЗНАК: " + reason) + Environment.NewLine);
                return;
            }

            if (directory is null)
            {
                return;
            }

            _file = Path.Combine(directory, "wifi-incident-" + now.ToLocalTime().ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + ".log");
            _fileUntil = now + Follow;
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
            Append(_file, text.ToString());
            Prune();
        }
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
