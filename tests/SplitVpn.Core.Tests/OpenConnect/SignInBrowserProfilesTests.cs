using SplitVpn.Core.OpenConnect;

namespace SplitVpn.Core.Tests.OpenConnect;

/// <summary>Профили встроенного браузера входа AnyConnect: перенос общего профиля прежних версий и удаление.</summary>
public sealed class SignInBrowserProfilesTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "splitvpn-webview-" + Guid.NewGuid().ToString("N"));
    private readonly SignInBrowserProfiles _profiles;
    private readonly Guid _first = Guid.NewGuid();
    private readonly Guid _second = Guid.NewGuid();

    public SignInBrowserProfilesTests() => _profiles = new SignInBrowserProfiles(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private void CreateLegacy()
    {
        Directory.CreateDirectory(Path.Combine(_profiles.LegacyFolder, "EBWebView"));
        File.WriteAllText(Path.Combine(_profiles.LegacyFolder, "EBWebView", "Cookies"), "idp");
    }

    [Fact]
    public void Prepare_MovesLegacyProfileToFirstConnectionOnly()
    {
        CreateLegacy();

        var first = _profiles.Prepare(_first);
        var second = _profiles.Prepare(_second);

        Assert.Equal(_profiles.FolderOf(_first), first);
        Assert.True(File.Exists(Path.Combine(first, "EBWebView", "Cookies")));
        Assert.False(Directory.Exists(_profiles.LegacyFolder));
        Assert.Equal(_profiles.FolderOf(_second), second);
        Assert.False(Directory.Exists(second));
    }

    /// <summary>
    /// Перенос не удался (профиль занят): общий профиль с cookie организации не достаётся следующему подключению —
    /// он удаляется, как только освободится.
    /// </summary>
    [Fact]
    public void Prepare_FailedMigration_NeverMovesLegacyIntoAnotherConnection()
    {
        CreateLegacy();
        using (new FileStream(Path.Combine(_profiles.LegacyFolder, "EBWebView", "Cookies"), FileMode.Open, FileAccess.Read, FileShare.None))
        {
            _profiles.Prepare(_first);
            Assert.True(Directory.Exists(_profiles.LegacyFolder));
            Assert.False(Directory.Exists(_profiles.FolderOf(_first)));
        }

        var second = _profiles.Prepare(_second);

        Assert.False(Directory.Exists(second));
        Assert.False(Directory.Exists(_profiles.LegacyFolder));
    }

    /// <summary>Профили подключений уже есть (перенос решён раньше): оставшийся общий профиль удаляется, а не переносится.</summary>
    [Fact]
    public void Prepare_WhenProfilesExist_DeletesLeftoverLegacyProfile()
    {
        Directory.CreateDirectory(_profiles.FolderOf(_first));
        CreateLegacy();

        var second = _profiles.Prepare(_second);

        Assert.False(Directory.Exists(second));
        Assert.False(Directory.Exists(_profiles.LegacyFolder));
        Assert.True(Directory.Exists(_profiles.FolderOf(_first)));
    }

    [Fact]
    public void Delete_RemovesOnlyThatConnectionsProfile()
    {
        Directory.CreateDirectory(Path.Combine(_profiles.FolderOf(_first), "EBWebView"));
        Directory.CreateDirectory(_profiles.FolderOf(_second));

        _profiles.Delete(_first);
        _profiles.Delete(Guid.NewGuid());

        Assert.False(Directory.Exists(_profiles.FolderOf(_first)));
        Assert.True(Directory.Exists(_profiles.FolderOf(_second)));
    }
}
