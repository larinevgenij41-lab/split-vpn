using System.Text.Json;
using SplitVpn.Core.Settings;
using SplitVpn.Windows.Diagnostics;
using SplitVpn.Windows.Native;
using SplitVpn.Windows.Security;

namespace SplitVpn.Cli.Proto;

internal sealed record ProtoProfile(string Server, string UserName, string? Domain);

/// <summary>Окружение прототипа: отдельный каталог, телефонная книга и секрет, не пересекающиеся с продуктом.</summary>
internal static class ProtoContext
{
    public const string EntryName = "SplitVpn Proto";

    public static readonly Guid ProfileId = new("8a2d4a4e-7c43-4b8b-9e7f-4f1c2a0b9d01");

    /// <summary>Второй сервер для спайка нескольких туннелей.</summary>
    public static readonly Guid ProfileId2 = new("8a2d4a4e-7c43-4b8b-9e7f-4f1c2a0b9d02");

    /// <summary>Имя записи телефонной книги по номеру слота.</summary>
    public static string EntryNameFor(int slot) => slot <= 1 ? EntryName : EntryName + " " + slot.ToString(System.Globalization.CultureInfo.InvariantCulture);

    public static Guid ProfileIdFor(int slot) => slot <= 1 ? ProfileId : ProfileId2;

    public static string ProfilePathFor(int slot) => slot <= 1 ? ProfilePath : Path.Combine(Root, "proto2.json");

    public static ProtoProfile LoadProfile(int slot)
    {
        var path = ProfilePathFor(slot);
        if (!File.Exists(path))
        {
            throw new InvalidOperationException($"Профиль прототипа {slot} не задан: выполните «creds set --slot {slot} --server <адрес> --user <имя>».");
        }

        return JsonSerializer.Deserialize<ProtoProfile>(File.ReadAllText(path), JsonDefaults.Options)
            ?? throw new InvalidOperationException($"Профиль прототипа {slot} повреждён.");
    }

    public static char[] LoadPassword(int slot)
    {
        return Secrets().TryLoad(ProfileIdFor(slot))
            ?? throw new InvalidOperationException($"Пароль прототипа {slot} не сохранён: выполните «creds set --slot {slot}».");
    }

    public static string Root { get; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SplitVpn.Dev");

    public static string Phonebook => Path.Combine(Root, "proto.pbk");

    public static string SecretPath => Path.Combine(Root, "secret.bin");

    /// <summary>
    /// Секрет прототипа — в прежней схеме с областью компьютера: его пишет администратор, а читают и
    /// администратор, и сценарии от SYSTEM (scripts\elevated.ps1 -AsSystem).
    /// </summary>
    public static SecretStore Secrets() => new(SecretPath) { MachineScope = true };

    public static string ProfilePath => Path.Combine(Root, "proto.json");

    public static string DnsBackupPath => Path.Combine(Root, "dns-backup.json");

    public static string GeoPath(CliArgs args) => args.Option("--geo") ?? Path.Combine(Root, "ru.txt");

    public static string ReportDirectory(CliArgs args) => args.Option("--report-dir") ?? Path.Combine(Root, "reports");

    public static ProtoProfile LoadProfile()
    {
        if (!File.Exists(ProfilePath))
        {
            throw new InvalidOperationException("Профиль прототипа не задан: выполните «creds set --server <адрес> --user <имя>».");
        }

        return JsonSerializer.Deserialize<ProtoProfile>(File.ReadAllText(ProfilePath), JsonDefaults.Options)
            ?? throw new InvalidOperationException("Профиль прототипа повреждён.");
    }

    public static char[] LoadPassword()
    {
        return Secrets().TryLoad(ProfileId)
            ?? throw new InvalidOperationException("Пароль прототипа не сохранён: выполните «creds set».");
    }

    /// <summary>
    /// Каталог прототипа — по правилам каталога данных службы (<see cref="SecretStore.SecureDataRoot"/>): заранее
    /// созданный обычным пользователем каталог или ссылка на его месте переносится в сторону, а не присваивается сменой
    /// DACL (владелец сохранил бы WRITE_DAC). Файл секрета, если его ещё нет, создаётся сразу с правами только SYSTEM и
    /// Administrators — не наследует ничьих прав и в промежутке между созданием и сменой ACL не открыт.
    /// </summary>
    public static void EnsureRoot()
    {
        foreach (var warning in SecretStore.SecureDataRoot(Root))
        {
            Console.Error.WriteLine(warning);
        }

        CreateProtectedSecretFile(SecretPath);
    }

    /// <summary>Пустой файл секрета («{}») с защищённым DACL при создании; существующий не трогается.</summary>
    internal static void CreateProtectedSecretFile(string path)
    {
        if (File.Exists(path))
        {
            return;
        }

        var security = new System.Security.AccessControl.FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { System.Security.Principal.WellKnownSidType.LocalSystemSid, System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid })
        {
            security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier(sid, null),
                System.Security.AccessControl.FileSystemRights.FullControl, System.Security.AccessControl.AccessControlType.Allow));
        }

        try
        {
            using var stream = new FileInfo(path).Create(FileMode.CreateNew, System.Security.AccessControl.FileSystemRights.Write, FileShare.None, 4096, FileOptions.None, security);
            stream.Write("{}"u8);
        }
        catch (IOException) when (File.Exists(path))
        {
            // Файл появился одновременно: его права приведёт к норме следующая запись секрета.
        }
    }

    /// <summary>Служба не установлена (ERROR_SERVICE_DOES_NOT_EXIST): её маршрутам ничто не грозит.</summary>
    private const uint ErrorServiceDoesNotExist = 1060;

    /// <summary>
    /// Сценарии, меняющие маршруты, DNS или WFP, работают только при остановленной службе SplitVpn: маршруты
    /// прототипа ставятся с той же меткой-метрикой, что у службы, и очистка сценария удалила бы её маршруты,
    /// а служба при сверке — маршруты сценария. Возвращает false (с ошибкой в отчёте), если служба работает
    /// или её состояние не удалось узнать.
    /// </summary>
    public static bool RequireServiceStopped(ScenarioReport report)
    {
        uint? processId;
        string? queryError = null;
        try
        {
            processId = SystemMetrics.ServiceStatus("SplitVpn").ProcessId;
        }
        catch (NativeCallException ex) when (ex.Code == ErrorServiceDoesNotExist)
        {
            processId = 0;
        }
        catch (NativeCallException ex)
        {
            processId = null;
            queryError = ex.Message;
        }

        if (ServiceRunningProblem(processId, queryError) is not { } problem)
        {
            return true;
        }

        report.Fail("Служба SplitVpn остановлена", new InvalidOperationException(problem));
        return false;
    }

    /// <summary>
    /// Почему сценарий нельзя запускать при таком состоянии службы; null — можно. <paramref name="processId"/> —
    /// процесс службы (0 — остановлена или не установлена, null — состояние узнать не удалось).
    /// </summary>
    internal static string? ServiceRunningProblem(uint? processId, string? queryError) => processId switch
    {
        0 => null,
        null => $"Не удалось узнать состояние службы SplitVpn ({queryError}). Сценарий меняет маршруты, DNS или WFP: остановите службу и повторите.",
        _ => "Остановите службу SplitVpn перед сценарием: маршруты прототипа помечены той же меткой, что и маршруты службы, "
            + "и сценарий с ней снимали бы маршруты друг друга.",
    };
}
