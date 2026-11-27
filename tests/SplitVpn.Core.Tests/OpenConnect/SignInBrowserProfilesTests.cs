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

    [Fact]
    public void BusyDeletedProfile_IsRetriedBeforeNextSignIn()
    {
        var old = Directory.CreateDirectory(_profiles.FolderOf(_first));
        using (File.Open(Path.Combine(old.FullName, "Cookies"), FileMode.Create, FileAccess.ReadWrite, FileShare.None))
        {
            _profiles.Delete(_first);
            Assert.Throws<IOException>(() => _profiles.Prepare(_first));
            Assert.Equal(_profiles.FolderOf(_second), _profiles.Prepare(_second));
        }
        _profiles.Prepare(_second);
        Assert.False(Directory.Exists(old.FullName));
        Assert.False(File.Exists(old.FullName + ".delete"));
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

    private void CreateCookies(Guid id) =>
        File.WriteAllText(Path.Combine(Directory.CreateDirectory(_profiles.FolderOf(id)).FullName, "Cookies"), "idp");

    /// <summary>Профиль прежней версии без отметки шлюза сохраняется и получает отметку; тот же шлюз — тоже сохраняется.</summary>
    [Fact]
    public void Prepare_SameOrUnknownHost_KeepsProfile()
    {
        CreateCookies(_first);

        _profiles.Prepare(_first, "vpn.org-a.example");
        _profiles.Prepare(_first, "VPN.org-a.example");

        Assert.True(File.Exists(Path.Combine(_profiles.FolderOf(_first), "Cookies")));
        Assert.Equal("vpn.org-a.example", File.ReadAllText(_profiles.HostMarkerOf(_first)));
    }

    /// <summary>Адрес шлюза сменили на другую организацию: её вход не наследует cookie прежней.</summary>
    [Fact]
    public void Prepare_OtherHost_ResetsProfile()
    {
        CreateCookies(_first);
        _profiles.Prepare(_first, "vpn.org-a.example");

        _profiles.Prepare(_first, "vpn.org-b.example");

        Assert.False(Directory.Exists(_profiles.FolderOf(_first)));
        Assert.Equal("vpn.org-b.example", File.ReadAllText(_profiles.HostMarkerOf(_first)));
    }

    [Fact]
    public void Prepare_OtherHost_BusyProfileIsNotReused()
    {
        CreateCookies(_first);
        _profiles.Prepare(_first, "vpn.org-a.example");
        using (File.Open(Path.Combine(_profiles.FolderOf(_first), "Cookies"), FileMode.Open, FileAccess.Read, FileShare.None))
        {
            Assert.Throws<IOException>(() => _profiles.Prepare(_first, "vpn.org-b.example"));
        }

        Assert.Equal("vpn.org-a.example", File.ReadAllText(_profiles.HostMarkerOf(_first)));
    }

    [Fact]
    public void PruneOrphans_DeletesOnlyProfilesMissingFromSettings()
    {
        CreateCookies(_first);
        CreateCookies(_second);
        _profiles.Prepare(_second, "vpn.org-b.example");
        Directory.CreateDirectory(Path.Combine(_profiles.ProfilesFolder, "not-a-guid"));

        Assert.Equal(1, _profiles.PruneOrphans([_first]));

        Assert.True(Directory.Exists(_profiles.FolderOf(_first)));
        Assert.False(Directory.Exists(_profiles.FolderOf(_second)));
        Assert.False(File.Exists(_profiles.HostMarkerOf(_second)));
        Assert.True(Directory.Exists(Path.Combine(_profiles.ProfilesFolder, "not-a-guid")));
    }

    /// <summary>Пустой список подключений не применяется: так выглядели бы и сброшенные после сбоя чтения настройки.</summary>
    [Fact]
    public void PruneOrphans_EmptySettings_DeletesNothing()
    {
        CreateCookies(_first);

        Assert.Equal(0, _profiles.PruneOrphans([]));
        Assert.True(Directory.Exists(_profiles.FolderOf(_first)));
    }
}
