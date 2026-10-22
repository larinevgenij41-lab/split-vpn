using System.Security.Principal;
using SplitVpn.Windows.Security;
using Xunit.Sdk;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Переход паролей с DPAPI области компьютера на область учётной записи. Файл паролей получает ACL только
/// для SYSTEM и Administrators, поэтому тест идёт только в повышенном процессе.
/// </summary>
public sealed class SecretStoreTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "splitvpn-secrets-" + Guid.NewGuid().ToString("N"));

    public SecretStoreTests() => Directory.CreateDirectory(_root);

    private static void RequireElevation()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            throw SkipException.ForSkip("Тест запускается в повышенном процессе: файл паролей закрыт для остальных.");
        }
    }

    private string SecretPath => Path.Combine(_root, "secrets.bin");

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Временный каталог уберёт система.
        }
    }

    [Fact]
    public void LegacyMachineScope_IsReadAndRewrittenInUserScope()
    {
        RequireElevation();
        var first = Guid.NewGuid();
        var second = Guid.NewGuid();
        var legacy = new SecretStore(SecretPath) { MachineScope = true };
        legacy.Save(first, "пароль-1");
        legacy.Save(second, "пароль-2");
        Assert.DoesNotContain("user:", File.ReadAllText(SecretPath), StringComparison.Ordinal);

        var store = new SecretStore(SecretPath);
        Assert.Equal("пароль-1", new string(store.TryLoad(first)));

        // Перезаписаны все значения старой схемы, а не только прочитанное.
        var text = File.ReadAllText(SecretPath);
        Assert.Equal(2, text.Split("user:").Length - 1);
        Assert.Equal("пароль-2", new string(store.TryLoad(second)));
        Assert.Equal("пароль-1", new string(new SecretStore(SecretPath).TryLoad(first)));
    }

    /// <summary>
    /// Перед первым переносом сохраняется копия, читаемая 0.9.5; повторный перенос копию не перезаписывает.
    /// </summary>
    [Fact]
    public void LegacyFile_IsBackedUpOnceBeforeMigration()
    {
        RequireElevation();
        var first = Guid.NewGuid();
        var legacy = new SecretStore(SecretPath) { MachineScope = true };
        legacy.Save(first, "пароль-1");
        var original = File.ReadAllBytes(SecretPath);

        var store = new SecretStore(SecretPath);
        Assert.Equal("пароль-1", new string(store.TryLoad(first)));

        var backup = SecretPath + SecretStore.LegacyBackupSuffix;
        Assert.Equal(original, File.ReadAllBytes(backup));
        Assert.DoesNotContain("user:", File.ReadAllText(backup), StringComparison.Ordinal);
        var rules = new FileInfo(backup).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<System.Security.AccessControl.FileSystemAccessRule>().Select(r => r.IdentityReference.Value).Order().ToArray();
        string[] expected = [new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value, new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value];
        Assert.Equal(expected.Order(), rules);

        // Ещё одно старое значение и новый перенос: копия остаётся первой.
        legacy.Save(Guid.NewGuid(), "пароль-2");
        Assert.NotNull(store.TryLoad(first));
        Assert.Equal(original, File.ReadAllBytes(backup));
    }

    /// <summary>Файл только с новыми значениями копии не получает.</summary>
    [Fact]
    public void UserScopedFile_IsNotBackedUp()
    {
        RequireElevation();
        var store = new SecretStore(SecretPath);
        store.Save(Guid.NewGuid(), "секрет");
        store.Save(Guid.NewGuid(), "секрет-2");

        Assert.False(File.Exists(SecretPath + SecretStore.LegacyBackupSuffix));
    }

    /// <summary>Прямые члены группы Administrators распознаются; посторонние SID — нет.</summary>
    [Fact]
    public void IsLocalAdministrator_RecognizesMembers()
    {
        Assert.False(SecretStore.IsLocalAdministrator(new SecurityIdentifier(WellKnownSidType.WorldSid, null)));
        Assert.False(SecretStore.IsLocalAdministrator(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null)));

        // Администратор здесь — прямой член группы (локальная учётная запись разработчика); членство через
        // вложенную доменную группу функция намеренно не раскрывает.
        using var identity = WindowsIdentity.GetCurrent();
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value;
        if (!identity.Claims.Any(c => c.Value == administrators))
        {
            throw SkipException.ForSkip("Тест запускается под учётной записью администратора.");
        }

        Assert.True(SecretStore.IsLocalAdministrator(identity.User!));
    }

    /// <summary>
    /// Потомки каталога данных: ссылка удаляется без цели, сжатый WOF файл (тоже точка повторной обработки)
    /// не удаляется, а уже перенесённое при прошлом запуске не переименовывается снова. Процесс не от SYSTEM
    /// не назначит владельца SYSTEM, поэтому свои файлы переносятся в сторону — данные при этом целы.
    /// </summary>
    [Fact]
    public void ResetDescendants_DeletesOnlyLinksAndKeepsSetAside()
    {
        var data = Path.Combine(_root, "data");
        var target = Path.Combine(_root, "target");
        Directory.CreateDirectory(data);
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(target, "keep.txt"), "цель");
        CreateJunction(Path.Combine(data, "link"), target);
        var compressed = Path.Combine(data, "compressed.bin");
        File.WriteAllBytes(compressed, new byte[256 * 1024]);
        RunCompact(compressed);
        var setAside = Path.Combine(data, "old.untrusted-20260101-000000");
        File.WriteAllText(setAside, "старое");

        var warnings = new List<string>();
        SecretStore.ResetDescendants(new DirectoryInfo(data), "20260927-000000", warnings);

        Assert.False(Directory.Exists(Path.Combine(data, "link")));
        Assert.True(File.Exists(Path.Combine(target, "keep.txt")));
        var survivors = Directory.GetFiles(data).Select(Path.GetFileName).ToList();
        Assert.Contains(survivors, n => n!.StartsWith("compressed.bin", StringComparison.Ordinal));
        Assert.Contains("old.untrusted-20260101-000000", survivors);
        Assert.DoesNotContain(survivors, n => n!.StartsWith("old.untrusted-20260101-000000.untrusted-", StringComparison.Ordinal));
        Assert.All(Directory.GetFiles(data, "compressed.bin*"), f => Assert.Equal(256 * 1024, new FileInfo(f).Length));
    }

    /// <summary>Точка соединения: в отличие от символьной ссылки, создаётся без повышения прав.</summary>
    private static void CreateJunction(string link, string target) =>
        Run("cmd.exe", $"/c mklink /J \"{link}\" \"{target}\"");

    private static void Run(string file, string arguments)
    {
        using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(file, arguments)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
        })!;
        process.StandardOutput.ReadToEnd();
        process.WaitForExit();
    }

    /// <summary>
    /// Сжатие WOF: файл получает точку повторной обработки, не будучи ссылкой. В новых сборках Windows 11
    /// атрибут у сжатого файла может не появляться — тогда файл проверяется как обычный.
    /// </summary>
    private static void RunCompact(string file) => Run("compact.exe", $"/c /exe:xpress4k \"{file}\"");

    [Fact]
    public void NewValues_AreUserScoped()
    {
        RequireElevation();
        var id = Guid.NewGuid();
        var store = new SecretStore(SecretPath);

        store.Save(id, "секрет");

        Assert.Contains("user:", File.ReadAllText(SecretPath), StringComparison.Ordinal);
        Assert.Equal("секрет", new string(store.TryLoad(id)));
        Assert.True(store.Contains(id));
    }
}
