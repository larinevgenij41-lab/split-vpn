using System.Diagnostics;
using SplitVpn.Windows.Security;

namespace SplitVpn.Service.Tests;

/// <summary>Служба от SYSTEM не должна читать через подложенную в профиль ссылку чужой файл.</summary>
public sealed class ConfinedFileTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "splitvpn-confined-tests", Guid.NewGuid().ToString("N"));
    private readonly string _profile;
    private readonly string _outside;

    public ConfinedFileTests()
    {
        _profile = Path.Combine(_root, "profile");
        _outside = Path.Combine(_root, "outside");
        Directory.CreateDirectory(_profile);
        Directory.CreateDirectory(_outside);
        File.WriteAllText(Path.Combine(_outside, "secret.txt"), "чужой файл");
    }

    public void Dispose()
    {
        // Junction удаляется как каталог без содержимого цели.
        foreach (var link in Directory.GetDirectories(_profile))
        {
            Directory.Delete(link);
        }

        Directory.Delete(_root, recursive: true);
    }

    [Fact]
    public void OrdinaryFileInsideProfileIsRead()
    {
        var file = Path.Combine(_profile, "ui-verbose.log");
        File.WriteAllText(file, "строка");

        using var stream = ConfinedFile.OpenRead(file, _profile);

        Assert.NotNull(stream);
    }

    [Fact]
    public void JunctionOutOfProfileIsRejected()
    {
        var junction = Path.Combine(_profile, "AppData");
        Mklink("/J", junction, _outside);

        using var stream = ConfinedFile.OpenRead(Path.Combine(junction, "secret.txt"), _profile);

        Assert.Null(stream);
    }

    [Fact]
    public void HardLinkToOutsideFileIsRejected()
    {
        var link = Path.Combine(_profile, "ui-verbose.log");
        Mklink("/H", link, Path.Combine(_outside, "secret.txt"));

        using var stream = ConfinedFile.OpenRead(link, _profile);

        Assert.Null(stream);
    }

    private static void Mklink(string kind, string link, string target)
    {
        using var mklink = Process.Start(new ProcessStartInfo("cmd.exe", $"/c mklink {kind} \"{link}\" \"{target}\"") { CreateNoWindow = true, UseShellExecute = false })!;
        mklink.WaitForExit();
        Assert.Equal(0, mklink.ExitCode);
    }
}
