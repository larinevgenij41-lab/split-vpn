using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace SplitVpn.Core.Diagnostics;

/// <summary>
/// Текстовый журнал с одной ротацией в «.1». Файл открывается на каждую запись с общим доступом: его пишут
/// несколько процессов (два сеанса одного пользователя) и читает служба при сборе архива. Ошибки
/// ввода-вывода проглатываются — журнал не должен ломать программу.
/// </summary>
public sealed class RollingTextLog(string path, TimeProvider time, long maxBytes = RollingTextLog.DefaultMaxBytes)
{
    public const long DefaultMaxBytes = 10 * 1024 * 1024;

    private static readonly int ProcessId = Environment.ProcessId;
    private readonly Lock _lock = new();

    /// <summary>Строки, записанные, пока мьютекс был занят: дописываются при следующем захвате.</summary>
    private readonly Queue<string> _pending = new();

    /// <summary>Сколько строк вытеснено из переполненной очереди: при дописывании об этом остаётся отметка.</summary>
    private int _dropped;

    /// <summary>Предел очереди строк, ждущих мьютекса: пауза ожидания длится до минут, а память не должна расти.</summary>
    internal const int MaxPending = 512;

    public string Path => path;

    public void Write(string category, string text)
    {
        var line = string.Create(CultureInfo.InvariantCulture,
            $"{time.GetLocalNow():yyyy-MM-dd HH:mm:ss.fff zzz} [{ProcessId}] {category}: {text}{Environment.NewLine}");
        lock (_lock)
        {
            // Ротация и запись под межпроцессным мьютексом: иначе процесс B дописывает в уже переименованный
            // файл «.1», а следующая ротация затирает его вместе с записями. Мьютекс просто занят (другая копия
            // пишет или держит его слишком долго) - строка ждёт в памяти и дописывается при следующем захвате.
            // Мьютекс недоступен в принципе (создан чужой учётной записью) - у процесса свой файл: ротацию общего
            // файла он тогда не трогает.
            var held = Acquire();
            if (!held && !_mutexUnavailable)
            {
                if (_pending.Count == MaxPending)
                {
                    _pending.Dequeue();
                    _dropped++;
                }

                _pending.Enqueue(line);
                return;
            }

            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
                var target = held ? path : System.IO.Path.ChangeExtension(path, ProcessId + ".log");
                Rotate(target);
                using var stream = new FileStream(target, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                if (_dropped > 0)
                {
                    stream.Write(Encoding.UTF8.GetBytes(string.Create(CultureInfo.InvariantCulture,
                        $"{time.GetLocalNow():yyyy-MM-dd HH:mm:ss.fff zzz} [{ProcessId}] Журнал: {_dropped} строк пропущено, пока файл был занят{Environment.NewLine}")));
                    _dropped = 0;
                }

                while (_pending.TryPeek(out var pending))
                {
                    stream.Write(Encoding.UTF8.GetBytes(pending));
                    _pending.Dequeue();
                }

                stream.Write(Encoding.UTF8.GetBytes(line));
            }
            catch (Exception ex) when (IsLogFailure(ex))
            {
                // Журнал не должен ломать программу.
            }
            finally
            {
                if (held)
                {
                    _mutex!.ReleaseMutex();
                }
            }
        }
    }

    private Mutex? _mutex;
    private bool _mutexUnavailable;

    /// <summary>До этого момента (Environment.TickCount64) мьютекс не ждём: его недавно держали слишком долго.</summary>
    private long _waitResumesAt;
    private TimeSpan _backoff = MinBackoff;

    /// <summary>
    /// Берёт мьютекс файла на короткое время; false — мьютекса нет (<see cref="_mutexUnavailable"/>: пишем в файл
    /// процесса) или он занят (строка ждёт в очереди). После таймаута
    /// ожидание не повторяется на каждой записи (иначе каждая строка, в том числе на потоке интерфейса, ждала бы):
    /// до конца паузы мьютекс только пробуется без ожидания, пауза растёт до <see cref="MaxBackoff"/>.
    /// </summary>
    private bool Acquire()
    {
        if (_mutexUnavailable)
        {
            return false;
        }

        try
        {
            _mutex ??= new Mutex(false, MutexName(path));
            var backingOff = Environment.TickCount64 < _waitResumesAt;
            if (_mutex.WaitOne(backingOff ? TimeSpan.Zero : MutexWait))
            {
                _backoff = MinBackoff;
                _waitResumesAt = 0;
                return true;
            }

            if (!backingOff)
            {
                _waitResumesAt = Environment.TickCount64 + (long)_backoff.TotalMilliseconds;
                _backoff = _backoff * 2 > MaxBackoff ? MaxBackoff : _backoff * 2;
            }

            return false;
        }
        catch (AbandonedMutexException)
        {
            // Предыдущий владелец оборвался — мьютекс теперь наш.
            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or WaitHandleCannotBeOpenedException or ArgumentException)
        {
            // Мьютекс создан другой учётной записью. Пишем отдельно от его владельца.
            _mutexUnavailable = true;
            return false;
        }
    }

    /// <summary>Имя межпроцессного мьютекса файла журнала.</summary>
    internal static string MutexName(string path) => @"Global\SplitVpnLog-" + Convert.ToHexString(SHA256.HashData(
        Encoding.UTF8.GetBytes(System.IO.Path.GetFullPath(path).ToUpperInvariant())), 0, 8);

    private static bool IsLogFailure(Exception ex) => ex is IOException or UnauthorizedAccessException or NotSupportedException
        or ArgumentException or System.Security.SecurityException;

    /// <summary>Чужая запись строки держит мьютекс миллисекунды; дольше ждать нет смысла.</summary>
    private static readonly TimeSpan MutexWait = TimeSpan.FromMilliseconds(250);

    private static readonly TimeSpan MinBackoff = TimeSpan.FromSeconds(5);

    private static readonly TimeSpan MaxBackoff = TimeSpan.FromMinutes(5);

    private void Rotate(string target)
    {
        var info = new FileInfo(target);
        if (!info.Exists || info.Length < maxBytes)
        {
            return;
        }

        try
        {
            File.Move(target, target + ".1", overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Файл переносит другой процесс: запись продолжится в текущий, ротация — в следующий раз.
        }
    }
}
