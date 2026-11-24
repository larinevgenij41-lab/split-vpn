using System.Security.AccessControl;
using System.Security.Principal;
using SplitVpn.Cli;
using SplitVpn.Cli.Proto;

namespace SplitVpn.Service.Tests;

/// <summary>Аудит 24.11: коды возврата CLI, ревизия настроек, одноразовые файлы пароля, экспорт пароля.</summary>
public sealed class CliAuditNov24Tests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("splitvpn-cli-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    [Fact]
    public void UsageErrorsMapToCodeTwo()
    {
        Assert.Equal(2, CliExit.ForException(new ArgumentException("Требуется значение параметра --out")).Code);
        Assert.Equal(2, CliExit.ForException(new InputFileException("x.json", new UnauthorizedAccessException("нет доступа"))).Code);
        Assert.Equal(2, CliExit.ForException(new FileNotFoundException("нет файла", "x.json")).Code);
        Assert.Equal(1, CliExit.ForException(new InvalidOperationException("сбой")).Code);
    }

    [Fact]
    public void SettingsSetRequiresRevisionOrForce()
    {
        var file = Path.Combine(_directory, "settings.json");
        Assert.False(ServiceCommands.TryExpectedRevision(new CliArgs(["set", "--file", file]), file, out _));

        Assert.True(ServiceCommands.TryExpectedRevision(new CliArgs(["set", "--file", file, "--force"]), file, out var forced));
        Assert.Null(forced);

        Assert.True(ServiceCommands.TryExpectedRevision(new CliArgs(["set", "--file", file, "--revision", "ABC"]), file, out var explicitRevision));
        Assert.Equal("ABC", explicitRevision);
        Assert.False(ServiceCommands.TryExpectedRevision(new CliArgs(["set", "--file", file, "--revision", "ABC", "--force"]), file, out _));

        File.WriteAllText(ServiceCommands.RevisionPath(file), "DEF\r\n");
        Assert.True(ServiceCommands.TryExpectedRevision(new CliArgs(["set", "--file", file]), file, out var fromFile));
        Assert.Equal("DEF", fromFile);

        // --force не съедает позиционный аргумент после себя.
        Assert.Equal("set", new CliArgs(["--force", "set"]).Positional(0));
    }

    [Fact]
    public void PasswordFileIsDeletedOnlyAfterServiceAccepted()
    {
        var file = Path.Combine(_directory, "password.txt");
        File.WriteAllText(file, "secret");

        ServiceCommands.ConsumePasswordFile(file, accepted: false);
        Assert.True(File.Exists(file));

        ServiceCommands.ConsumePasswordFile(file, accepted: true);
        Assert.False(File.Exists(file));
    }

    [Fact]
    public void ExportRefusesExistingFile()
    {
        var security = new FileSecurity();
        security.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl, AccessControlType.Allow));

        var existing = Path.Combine(_directory, "existing.txt");
        File.WriteAllText(existing, "чужой файл");
        Assert.Null(CredsCommand.CreateExclusive(existing, security));
        Assert.Equal("чужой файл", File.ReadAllText(existing));

        var fresh = Path.Combine(_directory, "fresh.txt");
        using (var stream = CredsCommand.CreateExclusive(fresh, security))
        {
            Assert.NotNull(stream);
        }

        Assert.True(File.Exists(fresh));
    }

    [Fact]
    public void CredsDeleteCoversEverySlot()
    {
        Assert.Equal(2, CredsCommand.Slots.Select(ProtoContext.ProfileIdFor).Distinct().Count());
        Assert.Equal(2, CredsCommand.Slots.Select(ProtoContext.ProfilePathFor).Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }
}
