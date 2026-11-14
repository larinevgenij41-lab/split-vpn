using System.IO;
using System.Text.Json;
using SplitVpn.App.Services;
using SplitVpn.App.ViewModels;
using SplitVpn.Core.Settings;

namespace SplitVpn.App.Tests;

public sealed partial class SettingsSaveTests
{
    private static MemoryService EditorStore() => new()
    {
        Settings = new AppSettings { Profiles = [
            new ConnectionProfile { Name = "Первый", Server = "vpn.example", UserName = "user", Protocol = VpnProtocol.L2tpIpsec },
            new ConnectionProfile { Name = "Второй", Server = "other.example", UserName = "other" }] },
    };

    [Fact]
    public Task EditorKeepsSeparateSecretsAcrossSelectionAndReload() => RunStaAsync(async () =>
    {
        var store = EditorStore();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();
        var first = page.Selected!;
        page.Password = "first-password";
        first.Security.PreSharedKey = "first-key";
        page.Selected = page.Profiles[1];
        Assert.Empty(page.Password);
        page.Password = "second-password";
        await page.OnOpenedAsync();
        Assert.Equal("second-password", page.Password);
        page.Selected = page.Profiles[0];
        Assert.Same(first, page.Selected);
        Assert.Equal("first-password", page.Password);
        Assert.Equal("first-key", first.Security.PreSharedKey);
        Assert.DoesNotContain("first-password", JsonSerializer.Serialize(first.ToProfile()), StringComparison.Ordinal);
        Assert.DoesNotContain("first-key", JsonSerializer.Serialize(first.ToProfile()), StringComparison.Ordinal);
    });

    [Fact]
    public Task EditorCopyAndAddDoNotInheritSecrets() => RunStaAsync(async () =>
    {
        using var service = new ServiceConnection(EditorStore().SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();
        var first = page.Selected!;
        page.Password = "private";
        first.Security.PreSharedKey = "key";
        page.CopyCommand.Execute(null);
        Assert.Empty(page.Password);
        Assert.Empty(page.Selected!.Security.PreSharedKey);
        Assert.True(page.Selected.IsNew);
        page.AddCommand.Execute(null);
        Assert.Empty(page.Password);
        Assert.Empty(page.Selected!.Security.PreSharedKey);
        page.Selected = first;
        Assert.Equal("private", page.Password);
        Assert.Equal("key", first.Security.PreSharedKey);
    });

    [Fact]
    public Task EditorSavingAnotherProfileDoesNotClearItsPassword() => RunStaAsync(async () =>
    {
        var store = EditorStore();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();
        var first = page.Selected!;
        page.Password = "first";
        store.AfterSave = async () => { await Task.Yield(); page.Selected = page.Profiles[1]; page.Password = "second"; };
        await page.SaveCommand.ExecuteAsync(null);
        Assert.False(page.MessageIsError);
        Assert.Equal("first", store.LastConnection!.Password);
        Assert.Empty(first.PasswordDraft);
        Assert.Equal("second", page.Password);
        page.Selected = page.Profiles[0];
        Assert.Empty(page.Password);
    });

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public Task EditorKeepsPasswordAfterFailedSaveOrConcurrentTyping(bool fail) => RunStaAsync(async () =>
    {
        var store = EditorStore();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();
        page.Password = "submitted";
        store.AfterSave = async () => { await Task.Yield(); if (fail) { throw new IOException("test"); } page.Password = "new-draft"; };
        await page.SaveCommand.ExecuteAsync(null);
        Assert.Equal(fail, page.MessageIsError);
        Assert.Equal(fail ? "submitted" : "new-draft", page.Password);
        Assert.True(page.Selected!.IsDirty);
    });

    [Fact]
    public Task EditorHiddenSecretsRemainDraftsUntilTheirProtocolIsSaved() => RunStaAsync(async () =>
    {
        var store = EditorStore();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();
        var item = page.Selected!;
        page.Password = "draft";
        item.Security.PreSharedKey = "key";
        item.Security.Protocol = VpnProtocol.AnyConnect;
        await page.SaveCommand.ExecuteAsync(null);
        Assert.False(page.MessageIsError);
        Assert.Null(store.LastConnection!.Password);
        Assert.Null(store.LastConnection.PreSharedKey);
        Assert.Same(item, page.Selected);
        item.Security.Protocol = VpnProtocol.L2tpIpsec;
        Assert.Equal("draft", page.Password);
        Assert.Equal("key", item.Security.PreSharedKey);
    });

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public Task EditorReusesStoredSecretsOnlyAfterConfirmation(bool confirmed) => RunStaAsync(async () =>
    {
        var store = EditorStore();
        var source = store.Settings.Profiles[0];
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();
        page.Selected!.Server = "new.example";
        main.Confirm = (_, text, _) => { Assert.Contains("new.example", text, StringComparison.Ordinal); return Task.FromResult(confirmed); };
        await page.SaveCommand.ExecuteAsync(null);
        if (confirmed)
        {
            Assert.Equal(source.Id, store.LastConnection!.ReuseCredentialsFrom!.Id);
            Assert.False(ConnectionEdits.PasswordBindingChanged(source, store.LastConnection.ReuseCredentialsFrom));
            Assert.Null(store.LastConnection.Password);
            Assert.Null(store.LastConnection.PreSharedKey);
            Assert.False(page.Selected!.IsDirty);
        }
        else { Assert.Null(store.LastConnection); Assert.True(page.Selected!.IsDirty); }
    });

    [Fact]
    public Task EditorRejectsChangedCredentialBindingDuringConfirmation() => RunStaAsync(async () =>
    {
        var store = EditorStore();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        await main.Connections.LoadAsync();
        main.Connections.Selected!.Server = "new.example";
        main.Confirm = (_, _, _) =>
        {
            store.Settings = store.Settings with { Profiles = [store.Settings.Profiles[0] with { UserName = "changed-elsewhere" }, store.Settings.Profiles[1]] };
            return Task.FromResult(true);
        };
        await main.Connections.SaveCommand.ExecuteAsync(null);
        Assert.Null(store.LastConnection);
        Assert.True(main.Connections.MessageIsError);
    });

    [Fact]
    public Task EditorOrdinaryEditsKeepPasswordWithoutConfirmation() => RunStaAsync(async () =>
    {
        var store = EditorStore();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        await main.Connections.LoadAsync();
        main.Confirm = (_, _, _) => throw new InvalidOperationException("Unexpected confirmation");
        main.Connections.Selected!.Name = "Новое имя";
        await main.Connections.SaveCommand.ExecuteAsync(null);
        Assert.False(main.Connections.MessageIsError);
        Assert.Null(store.LastConnection!.Password);
        Assert.Null(store.LastConnection.ReuseCredentialsFrom);
    });

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public Task EditorRevertRestoresSettingsAndClearsOnlyChosenDraft(bool confirmed) => RunStaAsync(async () =>
    {
        using var service = new ServiceConnection(EditorStore().SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();
        page.Selected = page.Profiles[1]; page.Password = "second";
        page.Selected = page.Profiles[0]; page.Password = "first";
        page.Selected!.Name = "Изменено";
        page.Selected.Security.PreSharedKey = "key";
        main.Confirm = (_, _, _) => Task.FromResult(confirmed);
        await page.RevertCommand.ExecuteAsync(null);
        Assert.Equal(confirmed ? "Первый" : "Изменено", page.Selected!.Name);
        Assert.Equal(confirmed ? "" : "first", page.Password);
        Assert.Equal(confirmed ? "" : "key", page.Selected.Security.PreSharedKey);
        page.Selected = page.Profiles[1]; Assert.Equal("second", page.Password);
    });

    [Fact]
    public Task EditorRevertDoesNotDiscardTypingDuringConfirmation() => RunStaAsync(async () =>
    {
        using var service = new ServiceConnection(EditorStore().SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        await main.Connections.LoadAsync();
        main.Connections.Password = "first";
        main.Confirm = (_, _, _) => { main.Connections.Password = "new"; return Task.FromResult(true); };
        await main.Connections.RevertCommand.ExecuteAsync(null);
        Assert.Equal("new", main.Connections.Password);
        Assert.True(main.Connections.MessageIsError);
    });

    [Fact]
    public Task EditorCredentialConfirmationKeepsOtherSettingsChangedMeanwhile() => RunStaAsync(async () =>
    {
        var store = EditorStore();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        await main.Connections.LoadAsync();
        main.Connections.Selected!.Server = "new.example";
        main.Confirm = (_, _, _) =>
        {
            store.Settings = store.Settings with { LocalDnsServer = "10.0.0.53" };
            return Task.FromResult(true);
        };
        await main.Connections.SaveCommand.ExecuteAsync(null);
        Assert.False(main.Connections.MessageIsError);
        Assert.Equal("10.0.0.53", store.LastConnection!.Settings.LocalDnsServer);
    });
}
