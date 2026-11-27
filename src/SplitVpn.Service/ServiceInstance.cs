using System.Security.AccessControl;
using System.Security.Principal;

namespace SplitVpn.Service;

/// <summary>Что делать при запуске SplitVpn.Service.exe без команды восстановления.</summary>
public enum LaunchDecision
{
    /// <summary>Запуск службы: её запустил диспетчер служб или разработчик явным ключом <see cref="ServiceInstance.ConsoleOption"/>.</summary>
    Run,

    /// <summary>Запуск из консоли без ключа: отказ с подсказкой.</summary>
    RefuseConsole,
}

/// <summary>
/// Единственный экземпляр службы. Второй координатор рядом со службой переписал бы в HKLM имя канала управления (пульт и
/// командная строка пошли бы к нему, а после его выхода — на мёртвое имя), уборка остатков завершила бы рабочие процессы
/// движка SSH настоящей службы, и оба процесса параллельно сверяли бы WFP, маршруты и DNS и писали один state.json.
/// Поэтому служба запускается только диспетчером служб (или явным ключом для разработки) и только под глобальным
/// мьютексом. Команды восстановления (emergency-off, emergency-on, recover) разбираются раньше и мьютекс не берут: по
/// замыслу они работают рядом с запущенной службой (останавливают её) или без неё.
/// </summary>
public static class ServiceInstance
{
    /// <summary>Ключ разработки: запуск службы в консоли (Ctrl+C — остановка). Хосту не передаётся.</summary>
    public const string ConsoleOption = "--console";

    /// <summary>
    /// Мьютекс единственного экземпляра. Пространство Global\ общее для всех сеансов, и создавать в нём объекты могут
    /// только службы и администраторы (SeCreateGlobalPrivilege): обычный пользователь не займёт имя до запуска службы.
    /// </summary>
    public const string MutexName = @"Global\SplitVpn.Service.Instance";

    /// <summary>Код выхода: запуск из консоли без <see cref="ConsoleOption"/>.</summary>
    public const int RefusedExitCode = 2;

    /// <summary>Код выхода: служба уже запущена (мьютекс занят) или мьютекс не создан.</summary>
    public const int BusyExitCode = 3;

    /// <summary>
    /// Сколько ждать мьютекса. Прежний процесс службы после SERVICE_STOPPED ещё сбрасывает журнал и выходит, а установщик
    /// при обновлении и команда emergency-on запускают новую службу сразу: отказ без ожидания сорвал бы её запуск (MSI —
    /// ошибка 1920 и откат обновления). Диспетчер служб ждёт подключения процесса 30 с — ожидание укладывается.
    /// </summary>
    public static readonly TimeSpan AcquireWait = TimeSpan.FromSeconds(10);

    public const string ConsoleRefusal =
        "SplitVpn.Service.exe — служба Windows «Раздельный VPN»; её запускает диспетчер служб (sc start SplitVpn), а не консоль. "
        + "Команды для запуска вручную от имени администратора: emergency-off, emergency-on, recover. "
        + "Для разработки служба запускается в консоли ключом " + ConsoleOption + " (только когда установленная служба остановлена).";

    public const string BusyText = "Служба «Раздельный VPN» уже запущена другим процессом SplitVpn.Service.exe: второй экземпляр не запускается.";

    /// <summary>Решение по аргументам и тому, запущен ли процесс диспетчером служб.</summary>
    public static LaunchDecision Decide(IReadOnlyList<string> args, bool isWindowsService)
    {
        ArgumentNullException.ThrowIfNull(args);
        return isWindowsService || HasConsoleOption(args) ? LaunchDecision.Run : LaunchDecision.RefuseConsole;
    }

    /// <summary>Аргументы для хоста — без <see cref="ConsoleOption"/>: разбор командной строки хоста принял бы его за ключ настройки со значением.</summary>
    public static string[] HostArguments(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        return args.Where(a => !IsConsoleOption(a)).ToArray();
    }

    private static bool HasConsoleOption(IReadOnlyList<string> args) => args.Any(IsConsoleOption);

    private static bool IsConsoleOption(string argument) => string.Equals(argument, ConsoleOption, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Захватывает мьютекс <paramref name="name"/> (права — только SYSTEM и Administrators) не дольше <paramref name="wait"/>;
    /// null — занят или не создан (причина — в <paramref name="problem"/>). Захваченный мьютекс держится до выхода процесса:
    /// владеет им поток, который его захватил (в службе — главный поток, он живёт до конца процесса), а выход процесса
    /// освобождает его и без ReleaseMutex. Мьютекс, брошенный упавшим процессом, — свободен.
    /// </summary>
    public static Mutex? TryAcquire(string name, TimeSpan wait, out string? problem)
    {
        problem = null;
        Mutex mutex;
        try
        {
            mutex = MutexAcl.Create(initiallyOwned: false, name, out _, CreateSecurity());
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or WaitHandleCannotBeOpenedException)
        {
            // Объект с этим именем уже есть, но без прав на него (создан не службой) или другого типа: служба не запускается.
            problem = "мьютекс " + name + " недоступен: " + ex.Message;
            return null;
        }

        try
        {
            if (mutex.WaitOne(wait))
            {
                return mutex;
            }
        }
        catch (AbandonedMutexException)
        {
            // Прежний процесс службы завершился, не освободив мьютекс: теперь он наш.
            return mutex;
        }

        mutex.Dispose();
        problem = "мьютекс " + name + " занят другим процессом";
        return null;
    }

    private static MutexSecurity CreateSecurity()
    {
        var security = new MutexSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
        {
            security.AddAccessRule(new MutexAccessRule(new SecurityIdentifier(sid, null), MutexRights.FullControl, AccessControlType.Allow));
        }

        return security;
    }

    /// <summary>
    /// Сообщение до появления журнала службы: в консоль, а у процесса под диспетчером служб (консоли нет) — ещё и в журнал
    /// «Приложение» Windows от источника хоста. Сбой записи не мешает выходу.
    /// </summary>
    public static void ReportEarly(string text, bool isWindowsService)
    {
        try
        {
            Console.Error.WriteLine(text);
        }
        catch (IOException)
        {
        }

        if (!isWindowsService)
        {
            return;
        }

        try
        {
            System.Diagnostics.EventLog.WriteEntry("SplitVpn.Service", text, System.Diagnostics.EventLogEntryType.Error);
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or System.ComponentModel.Win32Exception
            or System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
        }
    }
}
