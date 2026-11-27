using SplitVpn.App.Services;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Update;

namespace SplitVpn.App.Tests;

/// <summary>
/// Второй рубеж в пульте: с повышением прав запускается только msiexec из System32 и только для пакета из каталога
/// обновлений службы. Команда собрана так же, как её собирает служба (UpdateManager.InstallArguments).
/// </summary>
public sealed class UpdateLauncherCommandTests
{
    private const string SystemRoot = @"C:\Windows";
    private const string Updates = @"C:\ProgramData\SplitVpn\update";
    private const string MsiExec = @"C:\WINDOWS\system32\msiexec.exe";

    private static string Arguments(string package, string log) =>
        $"/i \"{package}\" /passive /norestart REBOOT=ReallySuppress /L*v \"{log}\"";

    private static UpdateInstallDto Command(string fileName = MsiExec, string? arguments = null) => new(
        fileName,
        arguments ?? Arguments(Updates + @"\SplitVpn-0.20.0.msi", Updates + @"\install-0.20.0-20261127-101500.log"),
        "0.20.0",
        Updates + @"\install-0.20.0-20261127-101500.log");

    private static string? Problem(UpdateInstallDto install) => UpdateLauncher.CommandProblem(install, SystemRoot, Updates);

    [Fact]
    public void ServiceCommand_IsAccepted() => Assert.Null(Problem(Command()));

    [Fact]
    public void ServiceCommand_TrailingSeparatorInDirectory_IsAccepted() =>
        Assert.Null(UpdateLauncher.CommandProblem(Command(), SystemRoot + @"\", Updates + @"\"));

    /// <summary>
    /// Команда в формате службы: аргументы строит та же функция ядра, что и UpdateManager.InstallArguments. Поменяется
    /// формат в ядре без проверки в пульте (или наоборот) — упадёт этот случай, а не установка обновлений у всех.
    /// </summary>
    [Theory]
    [InlineData(@"\SplitVpn-0.20.0.msi", @"\install-0.20.0-20261127-101500.log")]
    [InlineData(@"\SplitVpn-1.2.3_x64.msi", @"\install.log")]
    public void CommandBuiltByCore_IsAccepted(string package, string log)
    {
        var install = new UpdateInstallDto(MsiExec, UpdateInstallCommand.BuildArguments(Updates + package, Updates + log),
            "0.20.0", Updates + log);
        Assert.Null(Problem(install));
        Assert.Null(UpdateLauncher.CommandProblem(install, SystemRoot + @"\", Updates + @"\"));
    }

    [Fact]
    public void CommandBuiltByCore_MatchesManualFormat() =>
        Assert.Equal(Arguments(Updates + @"\SplitVpn-0.20.0.msi", Updates + @"\install.log"),
            UpdateInstallCommand.BuildArguments(Updates + @"\SplitVpn-0.20.0.msi", Updates + @"\install.log"));

    [Fact]
    public void CommandBuiltByCore_PackageOutsideUpdateDirectory_IsRefused()
    {
        var install = new UpdateInstallDto(MsiExec,
            UpdateInstallCommand.BuildArguments(@"C:\Users\user\Downloads\SplitVpn-0.20.0.msi", Updates + @"\install.log"),
            "0.20.0", Updates + @"\install.log");
        Assert.NotNull(Problem(install));
    }

    [Theory]
    [InlineData("msiexec.exe")]
    [InlineData(@"C:\Windows\SysWOW64\msiexec.exe")]
    [InlineData(@"C:\Users\user\AppData\Local\Temp\msiexec.exe")]
    [InlineData(@"C:\Windows\System32\..\Temp\msiexec.exe")]
    [InlineData(@"C:\Windows\System32\cmd.exe")]
    [InlineData(@"\\server\share\msiexec.exe")]
    [InlineData("")]
    public void OtherExecutable_IsRefused(string fileName)
    {
        var problem = Problem(Command(fileName));
        Assert.NotNull(problem);
        Assert.Contains("отклонена", problem, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(@"C:\Users\user\Downloads\SplitVpn-0.20.0.msi")]
    [InlineData(@"C:\ProgramData\SplitVpn\update\..\SplitVpn-0.20.0.msi")]
    [InlineData(@"C:\ProgramData\SplitVpn\update\sub\SplitVpn-0.20.0.msi")]
    [InlineData(@"C:\ProgramData\SplitVpn\updates\SplitVpn-0.20.0.msi")]
    [InlineData(@"C:\ProgramData\SplitVpn\update\SplitVpn-0.20.0.exe")]
    [InlineData(@"C:\ProgramData\SplitVpn\update\SplitVpn-0.20.0.msi.")]
    [InlineData(@"\\?\C:\ProgramData\SplitVpn\update\SplitVpn-0.20.0.msi")]
    [InlineData(@"C:/ProgramData/SplitVpn/update/SplitVpn-0.20.0.msi")]
    [InlineData(@"SplitVpn-0.20.0.msi")]
    public void PackageOutsideUpdateDirectory_IsRefused(string package)
    {
        var problem = Problem(Command(arguments: Arguments(package, Updates + @"\install.log")));
        Assert.NotNull(problem);
    }

    [Theory]
    [InlineData(@"/i ""C:\ProgramData\SplitVpn\update\SplitVpn-0.20.0.msi"" /passive /norestart REBOOT=ReallySuppress /L*v ""C:\ProgramData\SplitVpn\update\install.log"" TRANSFORMS=""C:\x.mst""")]
    [InlineData(@"/i ""C:\ProgramData\SplitVpn\update\SplitVpn-0.20.0.msi"" /qn /L*v ""C:\ProgramData\SplitVpn\update\install.log""")]
    [InlineData(@"/x ""C:\ProgramData\SplitVpn\update\SplitVpn-0.20.0.msi"" /passive /norestart REBOOT=ReallySuppress /L*v ""C:\ProgramData\SplitVpn\update\install.log""")]
    [InlineData(@"/i ""C:\ProgramData\SplitVpn\update\SplitVpn-0.20.0.msi"" /passive /norestart REBOOT=ReallySuppress /L*v ""C:\Users\user\install.log""")]
    [InlineData("")]
    public void UnexpectedArguments_AreRefused(string arguments) =>
        Assert.NotNull(Problem(Command(arguments: arguments)));
}
