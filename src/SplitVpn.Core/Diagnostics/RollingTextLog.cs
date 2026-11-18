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
    private readonly Queue<string> _pending = new();

    public string Path => path;

    public void Write(string category, string text)
    {
        var line = string.Create(CultureInfo.InvariantCulture,
            $"{time.GetLocalNow():yyyy-MM-dd HH:mm:ss.fff zzz} [{ProcessId}] {category}: {text}{Environment.NewLine}");
        lock (_lock)
        {
            // Ротация и запись под межпроцессным мьютексом: иначе процесс B дописывает в уже переименованный
            // файл «.1», а следующая ротация затирает его вместе с записями.
            var held = Acquire();
            if (!held && !_mutexUnavailable)
            {
                if (_pending.Count == 64) { _pending.Dequeue(); }
                _pending.Enqueue(line);
                return;
            }
            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
                // Если именованный объект Windows недоступен этой учетной записи, у процесса свой файл.
                var target = held ? path : System.IO.Path.ChangeExtension(path, ProcessId + ".log");
                Rotate(target);
                using var stream = new FileStream(target, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                while (_pending.TryPeek(out var pending))
                {
                    stream.Write(Encoding.UTF8.GetBytes(pending));
                    _pending.Dequeue();
                }
                stream.Write(Encoding.UTF8.GetBytes(line));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
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

    /// <summary>Берёт мьютекс файла на короткое время; false — мьютекса нет или занят слишком долго: пишем без него.</summary>
    private bool Acquire()
    {
        if (_mutexUnavailable)
        {
            return false;
        }

        try
        {
            _mutex ??= new Mutex(false, @"Global\SplitVpnLog-" + Convert.ToHexString(SHA256.HashData(
                Encoding.UTF8.GetBytes(System.IO.Path.GetFullPath(path).ToUpperInvariant())), 0, 8));
            return _mutex.WaitOne(MutexWait);
        }
        catch (AbandonedMutexException)
        {
            // Предыдущий владелец оборвался — мьютекс теперь наш.
            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or WaitHandleCannotBeOpenedException)
        {
            // Мьютекс создан другой учётной записью. Пишем отдельно от его владельца.
            _mutexUnavailable = true;
            return false;
        }
    }

    private static readonly TimeSpan MutexWait = TimeSpan.FromSeconds(2);

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
