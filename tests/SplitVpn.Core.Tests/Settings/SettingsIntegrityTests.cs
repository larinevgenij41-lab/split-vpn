using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Versioning;
using System.Text.Json;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Settings;

/// <summary>Целостность настроек и служебных файлов: исправления аудита 2026-11-01 (ID35, ID62, ID64, ID84).</summary>
public sealed class SettingsIntegrityTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "splitvpn-tests", Guid.NewGuid().ToString("N"));

    public SettingsIntegrityTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private static AppSettings Valid(string name = "Германия")
    {
        var profile = new ConnectionProfile { Name = name, Server = "vpn.example.org", UserName = "user", Role = ProfileRole.Primary };
        return new AppSettings { Profiles = [profile], DefaultTarget = RouteTarget.Tunnel(profile.Id) };
    }

    /// <summary>ID62: номер схемы вне диапазона int — повреждённый файл, а не исключение при запуске службы.</summary>
    [Theory]
    [InlineData("""{"schemaVersion":2147483648}""")]
    [InlineData("""{"schemaVersion":1e400}""")]
    [InlineData("""{"schemaVersion":-2147483649}""")]
    public void SchemaVersionOutOfRange_IsReportedAsCorrupt(string json)
    {
        var result = SettingsSerializer.Deserialize(json);

        Assert.False(result.IsSuccess);
        Assert.StartsWith("Файл настроек повреждён", result.Error, StringComparison.Ordinal);
    }

    /// <summary>ID35: слишком длинное название не проходит проверку, а сообщение не повторяет его целиком.</summary>
    [Fact]
    public void TooLongNames_AreRejected_WithShortMessage()
    {
        var name = new string('я', 1_100_000);
        var settings = Valid(name) with
        {
            Groups = [new TunnelGroupSetting { Name = new string('г', SettingsValidator.MaxNameLength + 1) }],
            RoutingFolders = [new RoutingFolderSetting { Name = new string('п', SettingsValidator.MaxNameLength + 1) }],
        };

        var result = SettingsValidator.Validate(settings);

        Assert.Equal(3, result.Errors.Count);
        Assert.All(result.Errors, e => Assert.True(e.Length < 200, e));
        Assert.True(SettingsValidator.Validate(Valid(new string('я', SettingsValidator.MaxNameLength))).IsValid);
    }

    /// <summary>ID64: правило в папке следует цели папки — так его показывает доска маршрутизации.</summary>
    [Fact]
    public void RuleInFolder_TakesFolderTarget()
    {
        var folder = new RoutingFolderSetting { Name = "Блок", Target = RouteTarget.Blocked };
        var settings = Valid() with
        {
            RoutingFolders = [folder],
            Rules =
            [
                new UserRuleSetting { Cidr = "77.88.8.0/24", Target = RouteTarget.Direct, FolderId = folder.Id },
                new UserRuleSetting { Cidr = "77.88.9.0/24", Target = RouteTarget.Direct },
            ],
            DomainRules = [new DomainRuleSetting { Suffix = "example.org", Target = RouteTarget.Direct, FolderId = folder.Id }],
        };

        var loaded = SettingsSerializer.Deserialize(SettingsSerializer.Serialize(settings)).Settings!;

        Assert.Equal(RouteTarget.Blocked, loaded.Rules[0].Target);
        Assert.Equal(RouteTarget.Direct, loaded.Rules[1].Target);
        Assert.Equal(RouteTarget.Blocked, loaded.DomainRules[0].Target);
        var (rules, _) = SettingsSerializer.ParseRules(SettingsSerializer.Normalize(settings).Rules);
        Assert.Equal(RouteTarget.Blocked, rules[0].Target);

        // Согласованные настройки нормализация не меняет.
        var consistent = SettingsSerializer.Normalize(settings);
        Assert.Equal(SettingsSerializer.Serialize(consistent), SettingsSerializer.Serialize(SettingsSerializer.Normalize(consistent)));
    }

    /// <summary>
    /// ID84: существующий, но недоступный файл не подменяется значениями по умолчанию. Запрет чтения атрибутов
    /// файла и просмотра каталога заставляет File.Exists ответить «нет»: прежде это означало молчаливую замену.
    /// </summary>
    [Fact]
    [SupportedOSPlatform("windows")]
    public void InaccessibleFile_IsNotTreatedAsMissing()
    {
        var directory = Path.Combine(_root, "закрыт");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "state.json");
        File.WriteAllText(path, """{"name":"значение"}""");
        using var identity = WindowsIdentity.GetCurrent();
        var user = identity.User!;
        var fileDeny = new FileSystemAccessRule(user, FileSystemRights.ReadAttributes | FileSystemRights.ReadData, AccessControlType.Deny);
        var directoryDeny = new FileSystemAccessRule(user, FileSystemRights.ListDirectory, AccessControlType.Deny);
        var fileInfo = new FileInfo(path);
        var directoryInfo = new DirectoryInfo(directory);
        var fileSecurity = fileInfo.GetAccessControl();
        fileSecurity.AddAccessRule(fileDeny);
        fileInfo.SetAccessControl(fileSecurity);
        var directorySecurity = directoryInfo.GetAccessControl();
        directorySecurity.AddAccessRule(directoryDeny);
        directoryInfo.SetAccessControl(directorySecurity);
        try
        {
            var found = new List<CorruptFile>();
            Assert.Throws<UnauthorizedAccessException>(() => SafeFile.Load(
                path,
                text => JsonSerializer.Deserialize<Sample>(text, JsonDefaults.Options),
                () => new Sample("по умолчанию"),
                "Пробный файл повреждён",
                found.Add));
            Assert.Empty(found);
        }
        finally
        {
            directorySecurity.RemoveAccessRule(directoryDeny);
            directoryInfo.SetAccessControl(directorySecurity);
            fileSecurity.RemoveAccessRule(fileDeny);
            fileInfo.SetAccessControl(fileSecurity);
        }
    }

    /// <summary>Ключ, повторённый при ручной правке файла, - повреждённый файл, а не исключение при запуске службы.</summary>
    [Fact]
    public void DuplicateKey_IsReportedAsCorruptOrLoaded()
    {
        var result = SettingsSerializer.Deserialize("""{"schemaVersion":3,"rules":[],"rules":[]}""");

        Assert.True(result.IsSuccess || result.Error!.StartsWith("Файл настроек повреждён", StringComparison.Ordinal));
    }

    /// <summary>«null» вместо списка доверенных адаптеров превращается в пустой список, а не в сбой сверки.</summary>
    [Fact]
    public void NullTrustedAdapters_AreNormalizedToEmpty()
    {
        var result = SettingsSerializer.Deserialize("""{"schemaVersion":3,"trustedAdapters":null}""");

        Assert.True(result.IsSuccess, result.Error);
        Assert.NotNull(result.Settings!.TrustedAdapters);
        Assert.Empty(result.Settings.TrustedAdapters);
    }

    /// <summary>Число вместо имени значения: неизвестный режим, источник базы или выбор адаптера не проходят проверку.</summary>
    [Fact]
    public void UnknownEnumNumbers_AreRejected()
    {
        var valid = Valid();
        Assert.Empty(SettingsValidator.Validate(valid).Errors);

        Assert.NotEmpty(SettingsValidator.Validate(valid with { OutageMode = (OutageMode)7 }).Errors);
        Assert.NotEmpty(SettingsValidator.Validate(valid with { GeoUpdate = valid.GeoUpdate with { Source = (GeoSourceKind)9 } }).Errors);
        Assert.NotEmpty(SettingsValidator.Validate(valid with { Profiles = [valid.Profiles[0] with { PrimaryAdapter = (AdapterSelection)5 }] }).Errors);
    }

    private sealed record Sample(string Name);
}
