using System.IO;
using SplitVpn.Core.Diagnostics;

namespace SplitVpn.App.Services;

/// <summary>
/// Межпроцессная блокировка одного пользователя (его копии интерфейса в разных сеансах). Берутся обе блокировки
/// в едином порядке: сначала файловая в %LOCALAPPDATA%\SplitVpn (туда чужие пользователи не пишут), затем
/// именованный мьютекс Global\…&lt;SID&gt;. Имя мьютекса может заранее занять другой локальный пользователь с
/// запрещающим DACL или удерживать его - тогда копии этого пользователя всё равно исключают друг друга по файлу:
/// прежде при таймауте мьютекса переход на файл не давал исключения, ведь законная вторая копия, державшая мьютекс,
/// файл не держала. Недоступен мьютекс - работа под одной файловой, недоступна и она - без блокировки; оба случая с
/// предупреждением в журнале: критичные действия (снятие прокси шлюза, запись настроек) не должны срываться.
/// </summary>
internal static class UserGate
{
    private static readonly TimeSpan RetryDelay = TimeSpan.FromMilliseconds(50);

    /// <summary>Захватить блокировку; null — выполнять без неё (предупреждение уже записано).</summary>
    public static IDisposable? Enter(string mutexName, string lockFile, TimeSpan timeout, string area)
    {
        var file = TryFile(lockFile, timeout, out var fileProblem);
        IDisposable? mutex;
        string? problem;
        try
        {
            mutex = TryMutex(mutexName, timeout, out problem);
        }
        catch
        {
            file?.Dispose();
            throw;
        }

        if (file is null && mutex is null)
        {
            Warn(area, $"файловая блокировка {lockFile} ({fileProblem}) и блокировка {mutexName} ({problem}) недоступны; " +
                "действие выполняется без межпроцессной блокировки");
            return null;
        }

        if (file is null)
        {
            Warn(area, $"файловая блокировка {lockFile} недоступна ({fileProblem}); действие выполняется под блокировкой {mutexName}");
        }
        else if (mutex is null)
        {
            Warn(area, $"блокировка {mutexName} недоступна ({problem}); действие выполняется под файловой блокировкой {lockFile}");
        }

        return new Held(file, mutex);
    }

    /// <summary>Какие блокировки получены (для проверок).</summary>
    internal static (bool File, bool Mutex) Parts(IDisposable? gate) =>
        gate is Held held ? (held.File is not null, held.Mutex is not null) : (false, false);

    internal static IDisposable? TryMutex(string name, TimeSpan timeout, out string? problem)
    {
        Mutex? mutex = null;
        try
        {
            mutex = new Mutex(false, name);
            bool acquired;
            try
            {
                acquired = mutex.WaitOne(timeout);
            }
            catch (AbandonedMutexException)
            {
                // Прежний владелец завершился, блокировка получена.
                acquired = true;
            }

            if (acquired)
            {
                problem = null;
                var held = new HeldMutex(mutex);
                mutex = null;
                return held;
            }

            problem = "занята дольше " + timeout.TotalSeconds.ToString("0.#", System.Globalization.CultureInfo.InvariantCulture) + " с";
            return null;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or WaitHandleCannotBeOpenedException or IOException)
        {
            problem = ex.Message;
            return null;
        }
        finally
        {
            mutex?.Dispose();
        }
    }

    internal static FileStream? TryFile(string path, TimeSpan timeout, out string? problem)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (true)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                problem = null;
                return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException ex) when ((ex.HResult & 0xffff) is 32 or 33 && DateTime.UtcNow < deadline)
            {
                // Файл держит другая копия интерфейса: ждём.
                Thread.Sleep(RetryDelay);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                problem = ex.Message;
                return null;
            }
        }
    }

    /// <summary>Предупреждение пишется в журнал интерфейса и при выключенном подробном режиме.</summary>
    private static void Warn(string area, string text)
    {
        if (Verbose.IsOn)
        {
            Verbose.Write(area, text);
            return;
        }

        try
        {
            Verbose.Sink?.Invoke(area, text);
        }
#pragma warning disable CA1031 // Журнал не должен мешать снятию прокси и записи настроек.
        catch (Exception)
#pragma warning restore CA1031
        {
        }
    }

    /// <summary>Обе блокировки; освобождаются в обратном порядке: мьютекс, затем файл.</summary>
    private sealed class Held(FileStream? file, IDisposable? mutex) : IDisposable
    {
        public FileStream? File => file;

        public IDisposable? Mutex => mutex;

        public void Dispose()
        {
            try
            {
                mutex?.Dispose();
            }
            finally
            {
                file?.Dispose();
            }
        }
    }

    private sealed class HeldMutex(Mutex mutex) : IDisposable
    {
        public void Dispose()
        {
            mutex.ReleaseMutex();
            mutex.Dispose();
        }
    }
}
