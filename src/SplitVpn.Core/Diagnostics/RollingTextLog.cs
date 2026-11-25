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

    /// <summary>До этого момента (Environment.TickCount64) недоступный мьютекс не открывается снова.</summary>
    private long _unavailableUntil;
    private TimeSpan _unavailableBackoff = MinUnavailableRetry;

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
            if (Environment.TickCount64 < _unavailableUntil)
            {
                return false;
            }

            // Мьютекс мог исчезнуть вместе с создавшей его копией (например, запущенной от администратора): пробуем снова.
            _mutexUnavailable = false;
        }

        try
        {
            _mutex ??= CreateMutex(MutexName(path));
            var backingOff = Environment.TickCount64 < _waitResumesAt;
            if (_mutex.WaitOne(backingOff ? TimeSpan.Zero : MutexWait))
            {
                _backoff = MinBackoff;
                _waitResumesAt = 0;
                _unavailableBackoff = MinUnavailableRetry;
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
            // Мьютекс создан другой учётной записью или прежней версией без явных прав. Пока он недоступен, пишем
            // отдельно от его владельца, но не до конца процесса: после паузы мьютекс пробуется снова.
            _mutex?.Dispose();
            _mutex = null;
            _mutexUnavailable = true;
            _unavailableUntil = Environment.TickCount64 + (long)_unavailableBackoff.TotalMilliseconds;
            _unavailableBackoff = _unavailableBackoff * 2 > MaxBackoff ? MaxBackoff : _unavailableBackoff * 2;
            return false;
        }
    }

    /// <summary>
    /// Мьютекс с явными правами: учётная запись пользователя (её SID), SYSTEM и Administrators. Без них мьютекс,
    /// созданный копией программы от администратора, получал права повышенного маркера, и обычная копия того же
    /// пользователя не могла его открыть — и писала в отдельный файл процесса до своего завершения.
    /// </summary>
    internal static Mutex CreateMutex(string name)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new Mutex(false, name);
        }

        // Существующий открывается только с нужными правами: создание (MutexAcl.Create) открыло бы его с полным доступом,
        // которого явные права не дают.
        const System.Security.AccessControl.MutexRights needed = System.Security.AccessControl.MutexRights.Synchronize | System.Security.AccessControl.MutexRights.Modify;
        if (System.Threading.MutexAcl.TryOpenExisting(name, needed, out var existing))
        {
            return existing;
        }

        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var security = new System.Security.AccessControl.MutexSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[]
        {
            identity.User!,
            new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null),
            new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null),
        })
        {
            security.AddAccessRule(new System.Security.AccessControl.MutexAccessRule(sid,
                System.Security.AccessControl.MutexRights.Synchronize | System.Security.AccessControl.MutexRights.Modify,
                System.Security.AccessControl.AccessControlType.Allow));
        }

        return System.Threading.MutexAcl.Create(false, name, out _, security);
    }

    /// <summary>
    /// Удаляет отдельные файлы процессов («имя.&lt;pid&gt;.log» и их «.1»), не тронутые дольше <paramref name="maxAge"/>:
    /// их оставляли копии, которым мьютекс общего файла был недоступен. Файл своего процесса не трогается. Возвращает
    /// число удалённых.
    /// </summary>
    public static int PruneProcessFiles(string path, TimeSpan maxAge, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(time);
        var directory = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path));
        var stem = System.IO.Path.GetFileNameWithoutExtension(path);
        if (directory is null || !Directory.Exists(directory))
        {
            return 0;
        }

        var limit = time.GetUtcNow().UtcDateTime - maxAge;
        var removed = 0;
        try
        {
            foreach (var file in new DirectoryInfo(directory).EnumerateFiles(stem + ".*.log*"))
            {
                if (!IsProcessFile(file.Name, stem, out var pid) || pid == ProcessId || file.LastWriteTimeUtc >= limit)
                {
                    continue;
                }

                try
                {
                    file.Delete();
                    removed++;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // Файл держит живой процесс: удалится при следующем запуске.
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Каталог недоступен: журнал не должен ломать программу.
        }

        return removed;
    }

    /// <summary>«stem.&lt;цифры&gt;.log» или «stem.&lt;цифры&gt;.log.1».</summary>
    internal static bool IsProcessFile(string name, string stem, out int pid)
    {
        pid = 0;
        if (!name.StartsWith(stem + ".", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var rest = name[(stem.Length + 1)..];
        var end = rest.EndsWith(".log.1", StringComparison.OrdinalIgnoreCase) ? rest.Length - 6
            : rest.EndsWith(".log", StringComparison.OrdinalIgnoreCase) ? rest.Length - 4 : -1;
        return end > 0 && int.TryParse(rest.AsSpan(0, end), NumberStyles.None, CultureInfo.InvariantCulture, out pid);
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

    /// <summary>Первая пауза перед повторной попыткой открыть недоступный мьютекс; дальше растёт до <see cref="MaxBackoff"/>.</summary>
    private static readonly TimeSpan MinUnavailableRetry = TimeSpan.FromMinutes(1);

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
