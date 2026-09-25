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
/// Пароли профилей: DPAPI с областью компьютера и дополнительной энтропией, файл с ACL только для
/// SYSTEM и Administrators. Пароль не попадает в настройки, журнал и телефонную книгу.
/// </summary>
public sealed unsafe class SecretStore(string path)
{
    private const uint ProtectLocalMachine = 0x4;
    private const uint ProtectUiForbidden = 0x1;
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("SplitVpn.Secrets.v1");

    /// <summary>Куда сообщать о повреждённом файле паролей: журнал событий и предупреждение в статусе.</summary>
    public Action<CorruptFile>? OnCorrupt { get; init; }

    public void Save(Guid profileId, ReadOnlySpan<char> password)
    {
        var bytes = new byte[Encoding.Unicode.GetByteCount(password)];
        try
        {
            Encoding.Unicode.GetBytes(password, bytes);
            var all = LoadRaw();
            all[profileId.ToString("D")] = Convert.ToBase64String(Protect(bytes));
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
        if (!LoadRaw().TryGetValue(profileId.ToString("D"), out var encoded))
        {
            return null;
        }

        var bytes = Unprotect(Convert.FromBase64String(encoded));
        try
        {
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
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            foreach (var sid in rules)
            {
                security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            }

            new DirectoryInfo(fileOrDirectory).SetAccessControl(security);
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

    private static byte[] Protect(byte[] data)
    {
        fixed (byte* input = data)
        fixed (byte* entropy = Entropy)
        {
            var inBlob = new CRYPT_INTEGER_BLOB { cbData = (uint)data.Length, pbData = input };
            var entropyBlob = new CRYPT_INTEGER_BLOB { cbData = (uint)Entropy.Length, pbData = entropy };
            if (!PInvoke.CryptProtectData(inBlob, null, entropyBlob, null, ProtectLocalMachine | ProtectUiForbidden, out var outBlob))
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
            if (value is null || !Convert.TryFromBase64String(value, new byte[value.Length], out _))
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
