using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using SplitVpn.Core.Settings;
using SplitVpn.Windows.Native;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security.Cryptography;

namespace SplitVpn.Windows.Security;

/// <summary>
/// Пароли профилей: DPAPI с областью учётной записи (у службы — SYSTEM) и дополнительной энтропией, файл
/// с ACL только для SYSTEM и Administrators. Пароль не попадает в настройки, журнал и телефонную книгу.
///
/// До 0.9.6 пароли защищались с областью компьютера: такой блок расшифровывает любой процесс на машине,
/// получивший копию файла. Старые значения читаются и сразу перезаписываются в новой схеме. Отличить их
/// можно только по метке: CryptUnprotectData расшифровывает блок области компьютера и без флага, поэтому
/// «попробовать новую схему, при неудаче — старую» по результату расшифровки не различить.
/// </summary>
public sealed unsafe partial class SecretStore(string path)
{
    private const uint ProtectLocalMachine = 0x4;
    private const uint ProtectUiForbidden = 0x1;
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("SplitVpn.Secrets.v1");

    /// <summary>Метка значения, защищённого с областью учётной записи; без метки — старая схема (область компьютера).</summary>
    private const string UserScopePrefix = "user:";

    /// <summary>Куда сообщать о повреждённом файле паролей: журнал событий и предупреждение в статусе.</summary>
    public Action<CorruptFile>? OnCorrupt { get; init; }

    /// <summary>
    /// Прежняя схема с областью компьютера — только для секрета прототипа (splitvpn-cli creds): его пишет
    /// администратор, а читают и администратор, и сценарии от SYSTEM. Секреты службы её не используют.
    /// </summary>
    public bool MachineScope { get; init; }

    public void Save(Guid profileId, ReadOnlySpan<char> password)
    {
        var bytes = new byte[Encoding.Unicode.GetByteCount(password)];
        try
        {
            Encoding.Unicode.GetBytes(password, bytes);
            var all = LoadRaw();
            MigrateLegacy(all);
            all[profileId.ToString("D")] = Encode(bytes);
            Write(all);
        }
        finally
        {
            CryptographicClear(bytes);
        }
    }

    /// <summary>Пароль в массиве символов: вызывающий обязан очистить его после использования.</summary>
    public char[]? TryLoad(Guid profileId)
    {
        var all = LoadRaw();
        if (!all.TryGetValue(profileId.ToString("D"), out var encoded))
        {
            return null;
        }

        var bytes = Decode(encoded);
        try
        {
            if (!MachineScope && !encoded.StartsWith(UserScopePrefix, StringComparison.Ordinal))
            {
                RewriteLegacy(all);
            }

            return Encoding.Unicode.GetChars(bytes);
        }
        finally
        {
            CryptographicClear(bytes);
        }
    }

    public bool Contains(Guid profileId) => LoadRaw().ContainsKey(profileId.ToString("D"));

    public void Delete(Guid profileId)
    {
        var all = LoadRaw();
        if (all.Remove(profileId.ToString("D")))
        {
            Write(all);
        }
    }

    /// <summary>Каталог и файл доступны только SYSTEM и Administrators, наследование отключено.</summary>
    public static void RestrictToSystemAndAdministrators(string fileOrDirectory)
    {
        var rules = new[]
        {
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
        };

        if (Directory.Exists(fileOrDirectory))
        {
            new DirectoryInfo(fileOrDirectory).SetAccessControl(ProtectedDirectorySecurity());
            return;
        }

        var fileSecurity = new FileSecurity();
        fileSecurity.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in rules)
        {
            fileSecurity.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
        }

        new FileInfo(fileOrDirectory).SetAccessControl(fileSecurity);
    }

    /// <summary>
    /// Каталог данных службы при запуске. Сменить DACL мало: владелец каталога сохраняет право менять его
    /// права (WRITE_DAC), а пользователь, создавший %ProgramData%\SplitVpn до установки, мог оставить
    /// в нём ссылки, файлы с явными правами и открытые дескрипторы. Поэтому:
    /// <list type="bullet">
    /// <item>каталог-ссылка или каталог чужого владельца (не SYSTEM и не Administrators) переносится
    /// в сторону, а данные службы начинаются заново — чужому содержимому (settings.json) верить нельзя,
    /// и чужие дескрипторы уходят вместе с перенесённым каталогом;</item>
    /// <item>свой каталог (владелец SYSTEM или Administrators) получает защищённый DACL без наследования от ProgramData;</item>
    /// <item>у потомков убираются ссылки, явные ACE и чужие владельцы: права только наследуются от корня.</item>
    /// </list>
    /// Возвращает предупреждения: журнал службы на момент вызова ещё не открыт.
    /// </summary>
    public static IReadOnlyList<string> SecureDataRoot(string root)
    {
        var warnings = new List<string>();
        var stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", System.Globalization.CultureInfo.InvariantCulture);
        for (var attempt = 1; ; attempt++)
        {
            if (!Directory.Exists(root) && !File.Exists(root))
            {
                // Сразу с нужными правами: созданный обычным способом каталог до смены ACL наследовал бы права
                // ProgramData, где пользователи создают файлы и становятся их владельцами.
                ProtectedDirectorySecurity().CreateDirectory(root);
            }

            if (UntrustedRoot(root, warnings) is not { } problem)
            {
                break;
            }

            if (attempt > 3)
            {
                throw new UnauthorizedAccessException($"Каталог данных {root} {problem}, перенести его в сторону не удалось.");
            }

            warnings.Add(SetAsideRoot(root, $"{root}.untrusted-{stamp}-{attempt}", problem));
        }

        // Владелец уже SYSTEM или Administrators (иначе каталог перенесён выше): меняется только DACL.
        new DirectoryInfo(root).SetAccessControl(ProtectedDirectorySecurity());
        ResetDescendants(new DirectoryInfo(root), stamp, warnings);
        return warnings;
    }

    /// <summary>
    /// Недоверенный корень — в сторону. Перенос может не пройти (чужие открытые дескрипторы, права): тогда
    /// ссылка или файл на месте корня удаляются — удаляется сама ссылка, не то, на что она указывает. Каталог
    /// постороннего владельца на месте не исправляется: его содержимому (settings.json) верить нельзя, а
    /// работать на нём — значит отдать настройки службы от SYSTEM обычному пользователю. Такая служба не
    /// запускается вовсе (исключение уходит в журнал приложений .NET Runtime): это безопаснее, чем работать.
    /// </summary>
    private static string SetAsideRoot(string root, string aside, string problem)
    {
        var isFile = File.Exists(root);
        try
        {
            if (isFile)
            {
                File.Move(root, aside);
            }
            else
            {
                // Для ссылки переносится сама ссылка, не каталог, на который она указывает.
                Directory.Move(root, aside);
            }

            return $"Каталог данных {root} {problem}: перенесён в {aside}, данные службы начаты заново.";
        }
        catch (Exception moveError) when (moveError is IOException or UnauthorizedAccessException)
        {
            var info = new DirectoryInfo(root);
            if (!isFile && info.LinkTarget is null)
            {
                throw new UnauthorizedAccessException($"Каталог данных {root} {problem}, перенести его в сторону не удалось: {moveError.Message}", moveError);
            }

            try
            {
                if (isFile)
                {
                    File.Delete(root);
                }
                else
                {
                    info.Delete();
                }
            }
            catch (Exception deleteError) when (deleteError is IOException or UnauthorizedAccessException)
            {
                throw new UnauthorizedAccessException(
                    $"Каталог данных {root} {problem}: не перенести ({moveError.Message}) и не удалить ({deleteError.Message}).", deleteError);
            }

            return $"Каталог данных {root} {problem}: перенести не удалось ({moveError.Message}), удалён; данные службы начаты заново.";
        }
    }

    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);

    private static readonly SecurityIdentifier AdministratorsSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    private static DirectorySecurity ProtectedDirectorySecurity()
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in new[] { SystemSid, AdministratorsSid })
        {
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        }

        return security;
    }

    private static bool IsTrustedOwner(IdentityReference? owner) => owner is not null && (owner.Equals(SystemSid) || owner.Equals(AdministratorsSid));

    /// <summary>
    /// Почему корню данных нельзя доверять; null — можно. Каталог, созданный повышенным администратором при
    /// политике «владелец — создатель», принадлежит его учётной записи, а не группе Administrators: такой
    /// владелец и так может всё, поэтому каталог не переносится, а получает владельца SYSTEM (служба от SYSTEM
    /// назначает себя владельцем без особых привилегий; право WRITE_OWNER ей даёт унаследованный от ProgramData
    /// DACL). Не вышло — каталог переносится, как чужой.
    /// </summary>
    private static string? UntrustedRoot(string root, List<string> warnings)
    {
        var info = new DirectoryInfo(root);
        if (!info.Exists)
        {
            return "оказался файлом";
        }

        if (info.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            return "оказался ссылкой на другой путь";
        }

        IdentityReference? owner;
        try
        {
            owner = info.GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier));
        }
        catch (UnauthorizedAccessException)
        {
            return "закрыт для службы правами владельца";
        }

        if (IsTrustedOwner(owner))
        {
            return null;
        }

        if (owner is not SecurityIdentifier account || !IsLocalAdministrator(account))
        {
            return $"принадлежит посторонней учётной записи {owner}";
        }

        try
        {
            var security = ProtectedDirectorySecurity();
            security.SetOwner(SystemSid);
            info.SetAccessControl(security);
            warnings.Add($"Каталог данных {root} принадлежал администратору {owner}: владелец заменён на SYSTEM, права сброшены.");
            return null;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or InvalidOperationException or IOException)
        {
            // InvalidOperationException — владельца SYSTEM не назначить (процесс запущен не от SYSTEM).
            return $"принадлежит администратору {owner}, а сменить владельца не удалось ({ex.Message})";
        }
    }

    /// <summary>
    /// Прямой член локальной группы Administrators. Вложенные группы (например, администраторы домена) не
    /// раскрываются: такой каталог переносится в сторону — это безопасный исход. Ошибка запроса — «нет».
    /// </summary>
    internal static bool IsLocalAdministrator(SecurityIdentifier account)
    {
        string group;
        try
        {
            // Имя группы локализовано («Администраторы»), а NetLocalGroupGetMembers принимает только имя.
            group = AdministratorsSid.Translate(typeof(NTAccount)).Value;
        }
        catch (SystemException)
        {
            // IdentityNotMappedException или ошибка LSA: членство не подтвердить — «нет».
            return false;
        }

        group = group[(group.IndexOf('\\', StringComparison.Ordinal) + 1)..];
        if (NetLocalGroupGetMembers(null, group, 0, out var buffer, MaxPreferredLength, out var count, out _, 0) != 0)
        {
            return false;
        }

        try
        {
            for (var i = 0; i < count; i++)
            {
                // LOCALGROUP_MEMBERS_INFO_0 — единственное поле, указатель на SID.
                if (new SecurityIdentifier(Marshal.ReadIntPtr(buffer, i * IntPtr.Size)).Equals(account))
                {
                    return true;
                }
            }

            return false;
        }
        finally
        {
            _ = NetApiBufferFree(buffer);
        }
    }

    private const uint MaxPreferredLength = uint.MaxValue;

    [LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint NetLocalGroupGetMembers(string? serverName, string groupName, uint level, out nint buffer,
        uint preferredMaxLength, out uint entriesRead, out uint totalEntries, nint resumeHandle);

    [LibraryImport("netapi32.dll")]
    private static partial uint NetApiBufferFree(nint buffer);

    /// <summary>
    /// Потомки без ссылок, явных ACE и чужих владельцев; неисправимые переносятся в сторону. Ошибки ввода-вывода
    /// здесь не прерывают запуск службы: корень к этому моменту уже свой и закрыт от пользователей, поэтому
    /// оставшийся потомок — вопрос одного файла, а без службы нет ни журнала с причиной, ни защиты. Каждая такая
    /// ошибка попадает в предупреждения, и запуск продолжается с тем, что удалось исправить.
    /// </summary>
    internal static void ResetDescendants(DirectoryInfo directory, string stamp, List<string> warnings)
    {
        List<FileSystemInfo> entries;
        try
        {
            entries = directory.EnumerateFileSystemInfos().ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            warnings.Add($"Содержимое {directory.FullName} не проверено: {ex.Message}");
            return;
        }

        foreach (var entry in entries)
        {
            // Уже перенесённое в сторону при прошлом запуске не переименовывается повторно: исправить его права
            // пробуется, но при неудаче оно просто остаётся как есть.
            var setAside = entry.Name.Contains(".untrusted-", StringComparison.Ordinal);

            // Только ссылки (symlink, junction, точка монтирования). Другие точки повторной обработки — сжатие
            // WOF (compact /exe), дедупликация, облачные файлы — это сами данные, их удаление стёрло бы файл.
            var link = IsLink(entry);
            if (link == true)
            {
                warnings.Add(DeleteLink(entry, stamp, setAside));
                continue;
            }

            if (link is null)
            {
                // Не удалять (это могут быть данные) и не менять права: смена прав по имени прошла бы по ссылке.
                if (!setAside)
                {
                    warnings.Add(MoveAside(entry, $"{entry.FullName}.untrusted-{stamp}", "точка повторной обработки не читается"));
                }

                continue;
            }

            try
            {
                ResetEntry(entry);
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or InvalidOperationException or IOException)
            {
                // InvalidOperationException — владельца SYSTEM не назначить (процесс запущен не от SYSTEM).
                if (!setAside)
                {
                    warnings.Add(MoveAside(entry, $"{entry.FullName}.untrusted-{stamp}", "закрыт для службы правами владельца"));
                }

                continue;
            }

            if (entry is DirectoryInfo child)
            {
                ResetDescendants(child, stamp, warnings);
            }
        }
    }

    /// <summary>Ссылка ли это; null — точку повторной обработки не прочитать.</summary>
    private static bool? IsLink(FileSystemInfo entry)
    {
        try
        {
            return entry.LinkTarget is not null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Удаляется ссылка, а не то, на что она указывает; не удалилась — переносится в сторону.</summary>
    private static string DeleteLink(FileSystemInfo entry, string stamp, bool setAside)
    {
        try
        {
            entry.Delete();
            return $"В каталоге данных удалена ссылка {entry.FullName}.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return setAside
                ? $"Ссылка {entry.FullName} не удаляется: {ex.Message}"
                : MoveAside(entry, $"{entry.FullName}.untrusted-{stamp}", $"ссылка не удаляется ({ex.Message})");
        }
    }

    /// <summary>Перенос хватает права родителя на удаление потомков: собственный DACL потомка не мешает.</summary>
    private static string MoveAside(FileSystemInfo entry, string aside, string reason)
    {
        var name = entry.FullName;
        try
        {
            if (entry is DirectoryInfo directory)
            {
                directory.MoveTo(aside);
            }
            else
            {
                ((FileInfo)entry).MoveTo(aside);
            }

            return $"{name}: {reason}, перенесён в {aside}.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return $"{name}: {reason}, и не переносится: {ex.Message}";
        }
    }

    /// <summary>Владелец SYSTEM, если был чужой; явные ACE убираются, права только наследуются от родителя.</summary>
    private static void ResetEntry(FileSystemInfo entry)
    {
        FileSystemSecurity security = entry is DirectoryInfo directory ? directory.GetAccessControl() : ((FileInfo)entry).GetAccessControl();
        var ownerTrusted = IsTrustedOwner(security.GetOwner(typeof(SecurityIdentifier)));
        var explicitRules = security.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier));
        if (ownerTrusted && !security.AreAccessRulesProtected && explicitRules.Count == 0)
        {
            return;
        }

        foreach (FileSystemAccessRule rule in explicitRules)
        {
            security.RemoveAccessRuleSpecific(rule);
        }

        security.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
        if (!ownerTrusted)
        {
            security.SetOwner(SystemSid);
        }

        if (entry is DirectoryInfo target)
        {
            target.SetAccessControl((DirectorySecurity)security);
        }
        else
        {
            ((FileInfo)entry).SetAccessControl((FileSecurity)security);
        }
    }

    private string Encode(byte[] plain) => MachineScope
        ? Convert.ToBase64String(Protect(plain, ProtectLocalMachine | ProtectUiForbidden))
        : UserScopePrefix + Convert.ToBase64String(Protect(plain, ProtectUiForbidden));

    /// <summary>Расшифровка любой из схем: блок сам несёт свою область, флаг при расшифровке не нужен.</summary>
    private static byte[] Decode(string encoded) => Unprotect(Convert.FromBase64String(Payload(encoded)));

    private static string Payload(string encoded) =>
        encoded.StartsWith(UserScopePrefix, StringComparison.Ordinal) ? encoded[UserScopePrefix.Length..] : encoded;

    /// <summary>Значения старой схемы перешифровываются в новую; нерасшифровываемые остаются как есть.</summary>
    private void MigrateLegacy(Dictionary<string, string> all)
    {
        if (MachineScope || all.Values.All(v => v.StartsWith(UserScopePrefix, StringComparison.Ordinal)))
        {
            return;
        }

        if (all.Values.All(v => !v.StartsWith(UserScopePrefix, StringComparison.Ordinal)))
        {
            BackupLegacyFile();
        }

        foreach (var (key, value) in all.ToList())
        {
            if (value.StartsWith(UserScopePrefix, StringComparison.Ordinal))
            {
                continue;
            }

            byte[] plain;
            try
            {
                plain = Decode(value);
            }
            catch (NativeCallException)
            {
                continue;
            }

            try
            {
                all[key] = Encode(plain);
            }
            finally
            {
                CryptographicClear(plain);
            }
        }
    }

    /// <summary>Копия файла до первого переноса: версия 0.9.5 метку «user:» не читает.</summary>
    public string LegacyBackupPath => path + LegacyBackupSuffix;

    public const string LegacyBackupSuffix = ".v095";

    /// <summary>
    /// Файл только со старыми значениями копируется как есть до первого переноса: 0.9.5 считает значение
    /// с меткой повреждённым и заменяет весь файл пустым, поэтому после отката на неё пароли пропали бы.
    /// Копия возвращается на место вручную (docs\LIMITATIONS.md). Существующая копия не перезаписывается —
    /// она и есть последнее состояние, читаемое 0.9.5. Копия создаётся сразу с ACL только для SYSTEM и
    /// Administrators; не создалась — перенос не выполняется (исключение), старые значения остаются.
    /// </summary>
    private void BackupLegacyFile()
    {
        if (!File.Exists(path) || File.Exists(LegacyBackupPath))
        {
            return;
        }

        var bytes = File.ReadAllBytes(path);
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(SystemSid, FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(AdministratorsSid, FileSystemRights.FullControl, AccessControlType.Allow));
        var stream = new FileInfo(LegacyBackupPath).Create(FileMode.CreateNew, FileSystemRights.Write, FileShare.None, 4096, FileOptions.WriteThrough, security);
        try
        {
            using (stream)
            {
                stream.Write(bytes);
            }
        }
        catch
        {
            // Неполная копия не должна остаться «существующей»: иначе следующая попытка её не заменила бы.
            File.Delete(LegacyBackupPath);
            throw;
        }
    }

    /// <summary>Перезапись при чтении: сбой записи не мешает вернуть пароль — перенос повторится при следующем чтении.</summary>
    private void RewriteLegacy(Dictionary<string, string> all)
    {
        try
        {
            MigrateLegacy(all);
            Write(all);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NativeCallException)
        {
            // Пароль прочитан; старая схема останется до следующей удачной записи.
        }
    }

    private static byte[] Protect(byte[] data, uint flags)
    {
        fixed (byte* input = data)
        fixed (byte* entropy = Entropy)
        {
            var inBlob = new CRYPT_INTEGER_BLOB { cbData = (uint)data.Length, pbData = input };
            var entropyBlob = new CRYPT_INTEGER_BLOB { cbData = (uint)Entropy.Length, pbData = entropy };
            if (!PInvoke.CryptProtectData(inBlob, null, entropyBlob, null, flags, out var outBlob))
            {
                throw new NativeCallException("CryptProtectData", (uint)Marshal.GetLastPInvokeError());
            }

            return CopyAndFree(outBlob);
        }
    }

    private static byte[] Unprotect(byte[] data)
    {
        fixed (byte* input = data)
        fixed (byte* entropy = Entropy)
        {
            var inBlob = new CRYPT_INTEGER_BLOB { cbData = (uint)data.Length, pbData = input };
            var entropyBlob = new CRYPT_INTEGER_BLOB { cbData = (uint)Entropy.Length, pbData = entropy };
            if (!PInvoke.CryptUnprotectData(inBlob, entropyBlob, null, ProtectUiForbidden, out var outBlob))
            {
                throw new NativeCallException("CryptUnprotectData", (uint)Marshal.GetLastPInvokeError());
            }

            return CopyAndFree(outBlob);
        }
    }

    private static byte[] CopyAndFree(CRYPT_INTEGER_BLOB blob)
    {
        try
        {
            return new ReadOnlySpan<byte>(blob.pbData, (int)blob.cbData).ToArray();
        }
        finally
        {
            new Span<byte>(blob.pbData, (int)blob.cbData).Clear();
            PInvoke.LocalFree(new HLOCAL(blob.pbData));
        }
    }

    private static void CryptographicClear(byte[] bytes) => Array.Clear(bytes);

    /// <summary>
    /// Защищённые пароли как есть. Повреждённый файл (не JSON, не base64) откладывается в копию и заменяется
    /// пустым: служба запускается, а пароли пользователь вводит заново.
    /// </summary>
    private Dictionary<string, string> LoadRaw() => SafeFile.Load(
        path,
        ParseRaw,
        () => new Dictionary<string, string>(StringComparer.Ordinal),
        "Сохранённые пароли не прочитаны — введите их заново",
        OnCorrupt);

    /// <summary>Значения проверяются сразу: разбор base64 при чтении пароля падал бы уже во время дозвона.</summary>
    private static Dictionary<string, string>? ParseRaw(string text)
    {
        var all = JsonSerializer.Deserialize<Dictionary<string, string>>(text, JsonDefaults.Options);
        if (all is null)
        {
            return null;
        }

        foreach (var (key, value) in all)
        {
            if (value is null || !Convert.TryFromBase64String(Payload(value), new byte[value.Length], out _))
            {
                throw new FormatException($"значение «{key}» не является base64");
            }
        }

        return all;
    }

    private void Write(Dictionary<string, string> all)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
        Directory.CreateDirectory(directory);
        AtomicFile.WriteAllText(path, JsonSerializer.Serialize(all, JsonDefaults.Options));
        RestrictToSystemAndAdministrators(path);
    }
}
