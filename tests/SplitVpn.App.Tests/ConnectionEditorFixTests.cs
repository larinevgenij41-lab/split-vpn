using System.IO;
using SplitVpn.App.Services;
using SplitVpn.App.ViewModels;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;

namespace SplitVpn.App.Tests;

/// <summary>Редактор подключений и журнал диагностики: исправления по ревью 0.15.18.</summary>
public sealed partial class SettingsSaveTests
{
    /// <summary>Набранное, но ненужное сохранённому профилю, после сохранения отбрасывается: профиль не остаётся "Не сохранено".</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public Task EditorSaveDiscardsDraftsTheSavedProfileDoesNotUse(bool key) => RunStaAsync(async () =>
    {
        var store = EditorStore();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        main.Confirm = (_, _, _) => Task.FromResult(true);
        var page = main.Connections;
        await page.LoadAsync();
        var item = page.Selected!;
        if (key)
        {
            // Ключ IPsec набран, затем L2TP сменён на SSTP.
            item.Security.PreSharedKey = "key";
            item.Security.Protocol = VpnProtocol.Sstp;
        }
        else
        {
            // Пароль набран, затем вход сменён на сертификат.
            page.Password = "draft";
            item.Security.AuthMethod = AuthMethod.EapTls;
        }

        await page.SaveCommand.ExecuteAsync(null);

        Assert.False(page.MessageIsError);
        Assert.Null(store.LastConnection!.Password);
        Assert.Null(store.LastConnection.PreSharedKey);
        Assert.Equal(item.Id, page.Selected!.Id);
        Assert.False(page.Selected.IsDirty);
    });

    /// <summary>Отметка "Удалить сохранённый ключ IPsec" вне L2TP/PSK тоже не держит профиль несохранённым.</summary>
    [Fact]
    public Task EditorSaveDiscardsKeyRemovalTheSavedProfileDoesNotUse() => RunStaAsync(async () =>
    {
        var store = EditorStore();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();
        var item = page.Selected!;
        item.Security.ClearPreSharedKey = true;
        item.Security.IpsecAuthentication = IpsecAuthentication.MachineCertificate;

        await page.SaveCommand.ExecuteAsync(null);

        Assert.False(page.MessageIsError);
        Assert.Null(store.LastConnection!.PreSharedKey);
        Assert.False(page.Selected!.IsDirty);
    });

    /// <summary>У SSTP не было ключа IPsec: при переходе на L2TP/PSK без ключа предлагается ввести его, а не "использовать прежний".</summary>
    [Fact]
    public Task EditorAsksForKeyTheSavedProfileNeverHad() => RunStaAsync(async () =>
    {
        var store = EditorStore();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        main.Confirm = (_, _, _) => throw new InvalidOperationException("Unexpected confirmation");
        var page = main.Connections;
        await page.LoadAsync();
        page.Selected = page.Profiles[1];
        page.Selected!.Security.Protocol = VpnProtocol.L2tpIpsec;

        await page.SaveCommand.ExecuteAsync(null);

        Assert.True(page.MessageIsError);
        Assert.Contains("ключ IPsec", page.Message, StringComparison.Ordinal);
        Assert.Null(store.LastConnection);
    });

    /// <summary>Вход по сертификату пароля не хранил: при переходе на вход по паролю без пароля предлагается ввести его.</summary>
    [Fact]
    public Task EditorAsksForPasswordTheSavedProfileNeverHad() => RunStaAsync(async () =>
    {
        var store = new MemoryService
        {
            Settings = new AppSettings { Profiles = [new ConnectionProfile { Name = "Сертификат", Server = "vpn.example", UserName = "user", AuthMethod = AuthMethod.EapTls }] },
        };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        main.Confirm = (_, _, _) => throw new InvalidOperationException("Unexpected confirmation");
        var page = main.Connections;
        await page.LoadAsync();
        page.Selected!.Security.AuthMethod = AuthMethod.MsChapV2;

        await page.SaveCommand.ExecuteAsync(null);

        Assert.True(page.MessageIsError);
        Assert.Contains("пароль", page.Message, StringComparison.Ordinal);
        Assert.Null(store.LastConnection);
    });

    /// <summary>Подтверждение называет только то, что действительно будет использовано: новый ключ введён, прежним остаётся пароль.</summary>
    [Fact]
    public Task EditorReuseConfirmationNamesOnlyWhatIsReused() => RunStaAsync(async () =>
    {
        var store = EditorStore();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        string? confirmation = null;
        main.Confirm = (_, text, _) => { confirmation = text; return Task.FromResult(true); };
        var page = main.Connections;
        await page.LoadAsync();
        page.Selected = page.Profiles[1];
        page.Selected!.Security.Protocol = VpnProtocol.L2tpIpsec;
        page.Selected.Security.PreSharedKey = "new-key";

        await page.SaveCommand.ExecuteAsync(null);

        Assert.False(page.MessageIsError);
        Assert.NotNull(confirmation);
        Assert.Contains("сохранённый пароль", confirmation, StringComparison.Ordinal);
        Assert.DoesNotContain("ключ IPsec", confirmation, StringComparison.Ordinal);
        Assert.Equal("new-key", store.LastConnection!.PreSharedKey);
        Assert.NotNull(store.LastConnection.ReuseCredentialsFrom);
    });

    /// <summary>
    /// Новый профиль записан службой, а сохранение секрета упало: профиль больше не считается новым, черновик
    /// остаётся, и "Удалить" удаляет его из службы, а не только строку.
    /// </summary>
    [Fact]
    public Task EditorNewProfileWrittenBeforeFailureIsDeletedFromService() => RunStaAsync(async () =>
    {
        var store = EditorStore();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();
        page.AddCommand.Execute(null);
        var item = page.Selected!;
        item.Server = "new.example";
        page.Password = "new-password";
        store.AfterSave = async () => { await Task.Yield(); throw new IOException("пароль не сохранён"); };

        await page.SaveCommand.ExecuteAsync(null);

        Assert.True(page.MessageIsError);
        Assert.NotNull(store.Settings.Profile(item.Id));
        Assert.False(item.IsNew);
        Assert.True(item.IsDirty);
        Assert.Equal("new-password", page.Password);

        store.AfterSave = null;
        main.Confirm = (_, _, _) => Task.FromResult(true);
        page.Selected = item;
        await page.DeleteCommand.ExecuteAsync(null);

        Assert.Null(store.Settings.Profile(item.Id));
    });

    /// <summary>Профиль, отмеченный новым, но уже записанный службой, удаляется из службы.</summary>
    [Fact]
    public Task EditorDeleteChecksServiceForProfileMarkedNew() => RunStaAsync(async () =>
    {
        var store = EditorStore();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();
        page.AddCommand.Execute(null);
        var item = page.Selected!;
        store.Settings = store.Settings with { Profiles = [.. store.Settings.Profiles, item.ToProfile()] };
        main.Confirm = (_, _, _) => Task.FromResult(true);

        await page.DeleteCommand.ExecuteAsync(null);

        Assert.Null(store.Settings.Profile(item.Id));
        Assert.DoesNotContain(page.Profiles, p => p.Id == item.Id);
    });

    /// <summary>Блок параметров безопасности раскрывается сам для L2TP/PSK и после того, как его свернули вручную.</summary>
    [Fact]
    public Task EditorSecurityDetailsExpandForProfilesThatNeedThem() => RunStaAsync(async () =>
    {
        using var service = new ServiceConnection(EditorStore().SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();
        var l2tp = page.Selected!;
        Assert.True(l2tp.Security.DetailsExpanded);

        // Пользователь свернул блок: это не правка профиля.
        l2tp.Security.DetailsExpanded = false;
        Assert.False(l2tp.IsDirty);

        page.Selected = page.Profiles[1];
        Assert.False(page.Selected!.Security.DetailsExpanded);
        page.Selected = l2tp;
        Assert.True(l2tp.Security.DetailsExpanded);

        // Протокол сменился на требующий параметров: блок раскрывается сам.
        var sstp = page.Profiles[1];
        sstp.Security.DetailsExpanded = false;
        sstp.Security.Protocol = VpnProtocol.L2tpIpsec;
        Assert.True(sstp.Security.DetailsExpanded);
    });

    /// <summary>
    /// Служба перезапустилась и успела записать не меньше событий, чем было у прежней: после потери связи
    /// список заменяется событиями нового экземпляра, а не остаётся прежним.
    /// </summary>
    [Fact]
    public Task DiagnosticsReplacesEventsAfterServiceConnectionLoss() => RunStaAsync(async () =>
    {
        static ServiceEvent Event(long id, string text) => new(id, DateTimeOffset.UnixEpoch, "Сведения", text);
        List<ServiceEvent> journal = [Event(1, "прежний 1"), Event(2, "прежний 2")];
        Task<IpcResponse> Send(IpcRequest request, CancellationToken token) => Task.FromResult(request switch
        {
            GetEventsRequest events => IpcResponse.Success(journal.Where(e => e.Id > events.SinceId).ToList()),
            GetSettingsRequest => IpcResponse.Success(new AppSettings()),
            GetAdaptersRequest => IpcResponse.Success(new List<AdapterDto>()),
            _ => IpcResponse.Failure(IpcErrorCodes.BadRequest, "Неожиданный запрос " + request.GetType().Name),
        });

        using var service = new ServiceConnection(Send);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Diagnostics;
        main.IsWindowVisible = true;
        main.CurrentPage = page;
        await WaitUntilAsync(() => page.Events.Count == 2 && !page.IsBusy);

        page.OnStatus(null);
        journal = [Event(1, "новый 1"), Event(2, "новый 2"), Event(3, "новый 3")];
        page.OnStatus(new StatusDto());
        await WaitUntilAsync(() => page.Events.Count == 3 && page.Events.All(e => e.Text.StartsWith("новый", StringComparison.Ordinal)));

        Assert.Equal(new[] { "новый 3", "новый 2", "новый 1" }, page.Events.Select(e => e.Text));
    });

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        for (var i = 0; i < 200 && !condition(); i++)
        {
            await Task.Delay(10, TestContext.Current.CancellationToken);
        }

        Assert.True(condition());
    }
}
