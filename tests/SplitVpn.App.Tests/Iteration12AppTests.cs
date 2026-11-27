using System.Windows.Threading;
using SplitVpn.App.Services;
using SplitVpn.App.ViewModels;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;

namespace SplitVpn.App.Tests;

/// <summary>
/// Итерация 12: повтор сохранения после незаписанного секрета,
/// проверка формы до отправки, смена протокола на AnyConnect, импорт, диапазоны на доске, повтор после дозвона.
/// </summary>
public sealed class Iteration12AppTests
{
    private static readonly ConnectionProfile Work = new() { Name = "Работа", Server = "work.example", UserName = "user", Role = ProfileRole.Primary };

    [Fact]
    public void PrimaryChangeText_NamesDemotedProfileAndMovedTargets()
    {
        var before = new AppSettings { Profiles = [Work], DefaultTarget = RouteTarget.Tunnel(Work.Id), GeoTarget = RouteTarget.Direct };
        var added = new ConnectionProfile { Name = "Новое", Server = "vpn.example", Role = ProfileRole.Primary };
        var after = ConnectionEdits.SaveProfile(before, added) with { DefaultTarget = RouteTarget.Tunnel(added.Id), GeoTarget = RouteTarget.Direct };

        var text = ConnectionsViewModel.PrimaryChangeText(before, after, added.Id)!;

        Assert.Contains("«Новое» станет опорным подключением, «Работа» — дополнительным.", text, StringComparison.Ordinal);
        Assert.Contains("«Остальной интернет»: сейчас через «Работа», будет через «Новое»", text, StringComparison.Ordinal);
        // DNS по умолчанию и защита при обрыве идут за «Остальным интернетом» (служба: DnsAnchor, IsOutage), не за ролью.
        Assert.Contains("на «Новое» перейдут DNS по умолчанию и защита при обрыве", text, StringComparison.Ordinal);
        Assert.DoesNotContain("перестанет", text, StringComparison.Ordinal);
        Assert.DoesNotContain("RU-база", text, StringComparison.Ordinal);
        // Адаптер у обоих выбирается автоматически: от смены роли он не меняется — и не упомянут.
        Assert.DoesNotContain("адаптер", text, StringComparison.Ordinal);
        Assert.DoesNotContain("Отмена", text, StringComparison.Ordinal);
        // Опорного не было (первое подключение) или сохраняется само опорное — спрашивать не о чем.
        Assert.Null(ConnectionsViewModel.PrimaryChangeText(new AppSettings(), after, added.Id));
        Assert.Null(ConnectionsViewModel.PrimaryChangeText(before, before, Work.Id));
    }

    /// <summary>
    /// «Остальной интернет» остаётся на прежнем подключении: смена роли не трогает ни его, ни DNS по умолчанию, ни
    /// защиту при обрыве — текст так и говорит. Меняется основной адаптер, если его настройки у подключений разные.
    /// </summary>
    [Fact]
    public void PrimaryChangeText_DefaultStays_SaysDnsAndOutageUnchanged_NamesAdapter()
    {
        var pinned = Work with { PrimaryAdapter = AdapterSelection.Pinned, PinnedInterfaceGuid = Guid.NewGuid() };
        var spare = new ConnectionProfile { Name = "Резерв", Server = "backup.example", UserName = "user", Role = ProfileRole.Secondary };
        var before = new AppSettings { Profiles = [pinned, spare], DefaultTarget = RouteTarget.Tunnel(Work.Id) };
        var after = ConnectionEdits.SaveProfile(before, spare with { Role = ProfileRole.Primary });
        Assert.Equal(before.DefaultTarget, after.DefaultTarget);

        var text = ConnectionsViewModel.PrimaryChangeText(before, after, spare.Id)!;

        Assert.Contains("«Резерв» станет опорным подключением, «Работа» — дополнительным.", text, StringComparison.Ordinal);
        Assert.Contains("«Остальной интернет», DNS по умолчанию и защита при обрыве не меняются.", text, StringComparison.Ordinal);
        Assert.Contains("Основной сетевой адаптер будет выбираться по настройке «Резерв»: автоматически.", text, StringComparison.Ordinal);
        Assert.DoesNotContain("перейдут", text, StringComparison.Ordinal);
    }

    /// <summary>
    /// Дополнительное подключение делают опорным: перед сохранением спрашивают, прежнее опорное названо. Согласие
    /// сохраняет (прежнее становится дополнительным), отказ ничего не отправляет и оставляет правку в форме.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public Task EditorPrimaryChange_AsksBeforeDemotingCurrentPrimary(bool confirmed) => RunStaAsync(async () =>
    {
        var other = new ConnectionProfile { Name = "Резерв", Server = "backup.example", UserName = "user", Role = ProfileRole.Secondary };
        var store = new Store { Settings = new AppSettings { Profiles = [Work, other], DefaultTarget = RouteTarget.Tunnel(Work.Id) } };
        var asked = new List<(string Title, string Text)>();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences()) { Confirm = (title, text, _) => { asked.Add((title, text)); return Task.FromResult(confirmed); } };
        var page = main.Connections;
        await page.LoadAsync();
        var item = page.Profiles.Single(p => p.Id == other.Id);
        page.Selected = item;
        item.Role = ProfileRole.Primary;

        await page.SaveCommand.ExecuteAsync(null);

        var (title, text) = Assert.Single(asked);
        Assert.Equal("Сменить опорное подключение?", title);
        Assert.Contains("«Резерв» станет опорным подключением, «Работа» — дополнительным.", text, StringComparison.Ordinal);
        if (!confirmed)
        {
            Assert.Equal(0, store.ConnectionSaves);
            Assert.Equal(ProfileRole.Primary, store.Settings.Profile(Work.Id)!.Role);
            Assert.Equal(ProfileRole.Primary, item.Role);
            Assert.True(item.IsDirty);
            return;
        }

        Assert.False(page.MessageIsError, page.Message);
        Assert.Equal(1, store.ConnectionSaves);
        Assert.Equal(ProfileRole.Primary, store.Settings.Profile(other.Id)!.Role);
        Assert.Equal(ProfileRole.Secondary, store.Settings.Profile(Work.Id)!.Role);
    });

    /// <summary>
    /// «Добавить подключение» с главной, пока список подключений ещё читается: черновик создаётся после чтения и
    /// поэтому опорный. Сохранение первого подключения ни о чём не спрашивает (прежнего опорного нет).
    /// </summary>
    [Fact]
    public Task HomeAddConnection_WaitsForListAndCreatesPrimaryDraft() => RunStaAsync(async () =>
    {
        var store = new Store();
        async Task<IpcResponse> Slow(IpcRequest request, CancellationToken token)
        {
            if (request is GetSettingsRequest)
            {
                await Task.Delay(30, token);
            }

            return await store.SendAsync(request, token);
        }

        using var service = new ServiceConnection(Slow);
        using var main = new MainViewModel(service, new UiPreferences()) { ServiceAvailable = true };
        var home = main.Home;
        await home.OnOpenedAsync();
        home.OnStatus(new StatusDto { Intent = Intent.Off });
        Assert.Equal(HomeSetupAction.AddConnection, home.SetupAction);
        Assert.False(main.Connections.Loaded);

        await home.PrimaryActionCommand.ExecuteAsync(null);

        var page = main.Connections;
        Assert.True(page.Loaded);
        var draft = Assert.Single(page.Profiles);
        Assert.True(draft.IsNew);
        Assert.Equal(ProfileRole.Primary, draft.Role);
        Assert.Same(draft, page.Selected);
        Assert.True(page.ShowDefaultTakeoverHint);

        draft.Server = "vpn.example";
        draft.UserName = "user";
        page.Password = "secret";
        await page.SaveCommand.ExecuteAsync(null);
        Assert.False(page.MessageIsError, page.Message);
        Assert.Equal(1, store.ConnectionSaves);
        Assert.Equal(RouteTarget.Tunnel(draft.Id), store.Settings.DefaultTarget);
    });

    /// <summary>
    /// «Добавить» на странице, пока список ещё не получен: черновик создаётся выключенным. Первая удачная загрузка с
    /// пустым списком делает его опорным (AnyConnect — дополнительным), а «Добавить подключение» с главной открывает
    /// его же. Роль, выбранную пользователем, загрузка не трогает; второй черновик тоже не повышается.
    /// </summary>
    [Theory]
    [InlineData("untouched", ProfileRole.Primary)]
    [InlineData("anyconnect", ProfileRole.Secondary)]
    [InlineData("user-off", ProfileRole.Off)]
    [InlineData("user-secondary", ProfileRole.Secondary)]
    [InlineData("two-drafts", ProfileRole.Off)]
    public Task PageAddBeforeLoad_FirstDraftBecomesPrimary(string scenario, ProfileRole expected) => RunStaAsync(async () =>
    {
        var store = new Store();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences()) { ServiceAvailable = true };
        var page = main.Connections;
        Assert.False(page.Loaded);
        page.AddCommand.Execute(null);
        var draft = Assert.Single(page.Profiles);
        Assert.Equal(ProfileRole.Off, draft.Role);
        switch (scenario)
        {
            case "anyconnect":
                draft.Security.Protocol = VpnProtocol.AnyConnect;
                break;
            case "user-off":
                // Выбор той же роли через промежуточную — всё равно выбор пользователя.
                draft.Role = ProfileRole.Secondary;
                draft.Role = ProfileRole.Off;
                break;
            case "user-secondary":
                draft.Role = ProfileRole.Secondary;
                break;
            case "two-drafts":
                page.AddCommand.Execute(null);
                break;
        }

        await main.Connections.AddOrOpenDraftAsync();

        Assert.True(page.Loaded);
        Assert.Same(draft, page.Selected);
        Assert.Equal(expected, draft.Role);
        Assert.All(page.Profiles.Where(p => !ReferenceEquals(p, draft)), p => Assert.Equal(ProfileRole.Off, p.Role));
        if (scenario == "anyconnect")
        {
            // Понижение из-за протокола обратимо, как у опорного, созданного после загрузки.
            draft.Security.Protocol = VpnProtocol.Sstp;
            Assert.Equal(ProfileRole.Primary, draft.Role);
        }
    });

    /// <summary>
    /// Опорного нет, сохранённое дополнительное подключение делают опорным: подтверждения не будет (понижать некого),
    /// поэтому форма сама говорит, что через него пойдёт «Остальной интернет». У уже опорного пояснения нет.
    /// </summary>
    [Fact]
    public Task ExistingProfileBecomingPrimary_ShowsDefaultTakeoverHint() => RunStaAsync(async () =>
    {
        var spare = new ConnectionProfile { Name = "Резерв", Server = "backup.example", UserName = "user", Role = ProfileRole.Secondary };
        var off = new ConnectionProfile { Name = "Запас", Server = "spare.example", UserName = "user", Role = ProfileRole.Off };
        var store = new Store { Settings = new AppSettings { Profiles = [spare, off], DefaultTarget = RouteTarget.Blocked } };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();
        var item = page.Profiles.Single(p => p.Id == spare.Id);
        page.Selected = item;
        Assert.False(page.ShowDefaultTakeoverHint);

        item.Role = ProfileRole.Primary;
        Assert.True(page.ShowDefaultTakeoverHint);
        item.Role = ProfileRole.Secondary;
        Assert.False(page.ShowDefaultTakeoverHint);

        var other = page.Profiles.Single(p => p.Id == off.Id);
        other.Role = ProfileRole.Primary;
        page.Selected = other;
        Assert.True(page.ShowDefaultTakeoverHint);

        // Сохранено опорным — пояснение больше не нужно.
        await page.SaveCommand.ExecuteAsync(null);
        Assert.False(page.MessageIsError, page.Message);
        Assert.Equal(RouteTarget.Tunnel(off.Id), store.Settings.DefaultTarget);
        Assert.Equal(ProfileRole.Primary, page.Selected!.Role);
        Assert.False(page.ShowDefaultTakeoverHint);

        // «Остальной интернет» уже через VPN: никуда не переходит, пояснения нет.
        var spareItem = page.Profiles.Single(p => p.Id == spare.Id);
        page.Selected = spareItem;
        spareItem.Role = ProfileRole.Primary;
        Assert.False(page.ShowDefaultTakeoverHint);
    });

    /// <summary>
    /// Пока открыт вопрос «Использовать прежние данные входа?», в другом окне назначили опорным другое подключение:
    /// сохранение теперь понизило бы его без подтверждения. Ничего не сохраняется, пользователь просит повторить.
    /// То же, если опорное сменилось после подтверждённой смены опорного.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public Task CredentialsQuestion_PrimaryChangedElsewhere_NothingSaved(bool hadPrimary) => RunStaAsync(async () =>
    {
        var spare = new ConnectionProfile { Name = "Резерв", Server = "backup.example", UserName = "user", Role = ProfileRole.Secondary };
        var third = new ConnectionProfile { Name = "Третье", Server = "third.example", UserName = "user", Role = ProfileRole.Secondary };
        var work = Work with { Role = hadPrimary ? ProfileRole.Primary : ProfileRole.Secondary };
        var store = new Store { Settings = new AppSettings { Profiles = [work, spare, third], DefaultTarget = RouteTarget.Tunnel(Work.Id) } };
        var asked = new List<string>();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences())
        {
            Confirm = (title, _, _) =>
            {
                asked.Add(title);
                if (title == "Использовать прежние данные входа?")
                {
                    // Другое окно: опорным стало «Третье» (прежнее опорное, если было, — дополнительным).
                    store.Settings = store.Settings with
                    {
                        Profiles = [.. store.Settings.Profiles.Select(p => p.Id == third.Id ? p with { Role = ProfileRole.Primary }
                            : p.Role == ProfileRole.Primary ? p with { Role = ProfileRole.Secondary } : p)],
                    };
                }

                return Task.FromResult(true);
            },
        };
        var page = main.Connections;
        await page.LoadAsync();
        var item = page.Profiles.Single(p => p.Id == spare.Id);
        page.Selected = item;
        item.Role = ProfileRole.Primary;
        item.Server = "new-backup.example";

        await page.SaveCommand.ExecuteAsync(null);

        var expected = hadPrimary ? new[] { "Сменить опорное подключение?", "Использовать прежние данные входа?" } : new[] { "Использовать прежние данные входа?" };
        Assert.Equal(expected, asked);
        Assert.Equal(0, store.ConnectionSaves);
        Assert.True(page.MessageIsError);
        Assert.Contains("Настройки изменились", page.Message, StringComparison.Ordinal);
        Assert.Equal(ProfileRole.Primary, store.Settings.Profile(third.Id)!.Role);
        Assert.Equal("backup.example", store.Settings.Profile(spare.Id)!.Server);
        Assert.True(item.IsDirty);
    });

    /// <summary>
    /// Пока открыт вопрос «Сменить опорное подключение?», в другом окне «Остальной интернет» переключили на
    /// «Блокировать»: теперь сохранение перевело бы его на новое опорное, а этого в подтверждённом тексте не было.
    /// Ничего не сохраняется, пользователь просит повторить; правка остаётся в форме.
    /// </summary>
    [Fact]
    public Task TakeoverQuestion_DefaultChangedElsewhere_NothingSaved() => RunStaAsync(async () =>
    {
        var spare = new ConnectionProfile { Name = "Резерв", Server = "backup.example", UserName = "user", Role = ProfileRole.Secondary };
        var store = new Store { Settings = new AppSettings { Profiles = [Work, spare], DefaultTarget = RouteTarget.Tunnel(Work.Id) } };
        var asked = new List<(string Title, string Text)>();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences())
        {
            Confirm = (title, text, _) =>
            {
                asked.Add((title, text));
                // Другое окно: «Остальной интернет» блокируется — он перешёл бы на новое опорное.
                store.Settings = store.Settings with { DefaultTarget = RouteTarget.Blocked };
                return Task.FromResult(true);
            },
        };
        var page = main.Connections;
        await page.LoadAsync();
        var item = page.Profiles.Single(p => p.Id == spare.Id);
        page.Selected = item;
        item.Role = ProfileRole.Primary;

        await page.SaveCommand.ExecuteAsync(null);

        var (title, text) = Assert.Single(asked);
        Assert.Equal("Сменить опорное подключение?", title);
        Assert.Contains("не меняются", text, StringComparison.Ordinal);
        Assert.Equal(0, store.ConnectionSaves);
        Assert.True(page.MessageIsError);
        Assert.Contains("Настройки изменились, пока было открыто подтверждение", page.Message, StringComparison.Ordinal);
        Assert.Equal(RouteTarget.Blocked, store.Settings.DefaultTarget);
        Assert.Equal(ProfileRole.Primary, store.Settings.Profile(Work.Id)!.Role);
        Assert.Equal(ProfileRole.Primary, item.Role);
        Assert.True(item.IsDirty);
    });

    /// <summary>
    /// Сохранение нового опорного записало настройки, а пароль — нет: основа формы переносится на сохранённый
    /// профиль. Пояснение «через него пойдёт „Остальной интернет“» пересчитывается сразу (оно уже не нужно), а не
    /// при следующей правке.
    /// </summary>
    [Fact]
    public Task FailedSecretAfterTakeover_RebaseRefreshesTakeoverHint() => RunStaAsync(async () =>
    {
        var spare = new ConnectionProfile { Name = "Резерв", Server = "backup.example", UserName = "user", Role = ProfileRole.Secondary };
        var store = new Store { Settings = new AppSettings { Profiles = [spare], DefaultTarget = RouteTarget.Blocked } };
        store.Fail = request => request is SaveConnectionRequest { Password: not null } ? "Не удалось сохранить пароль для «Резерв»." : null;
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();
        var item = page.Profiles.Single();
        page.Selected = item;
        item.Role = ProfileRole.Primary;
        page.Password = "secret";
        Assert.True(page.ShowDefaultTakeoverHint);
        var raised = new List<string?>();
        page.PropertyChanged += (_, e) => raised.Add(e.PropertyName);

        await page.SaveCommand.ExecuteAsync(null);

        Assert.True(page.MessageIsError);
        Assert.Contains(ConnectionsViewModel.SettingsSavedCredentialsNot, page.Message, StringComparison.Ordinal);
        Assert.Equal(RouteTarget.Tunnel(spare.Id), store.Settings.DefaultTarget);
        Assert.Equal(ProfileRole.Primary, item.SavedRole);
        Assert.False(page.ShowDefaultTakeoverHint);
        Assert.Contains(nameof(ConnectionsViewModel.ShowDefaultTakeoverHint), raised);
    });

    /// <summary>Служба недоступна: черновик всё равно открывается (выключенным), без исключения.</summary>
    [Fact]
    public Task HomeAddConnection_ServiceUnavailable_CreatesOffDraft() => RunStaAsync(async () =>
    {
        using var service = new ServiceConnection((_, _) => throw new ServiceUnavailableException("Служба не запущена."));
        using var main = new MainViewModel(service, new UiPreferences());

        await main.Connections.AddOrOpenDraftAsync();

        var draft = Assert.Single(main.Connections.Profiles);
        Assert.Equal(ProfileRole.Off, draft.Role);
        Assert.False(main.Connections.Loaded);
    });

    /// <summary>
    /// Первое (опорное) подключение переводят на AnyConnect и обратно: роль понижается сама и сама же возвращается.
    /// Если роль между этим поменяли руками, выбор пользователя остаётся.
    /// </summary>
    [Fact]
    public void ProtocolRoundTrip_RestoresAutomaticallyLoweredPrimary()
    {
        var item = ProfileItem.From(new ConnectionProfile { Name = "Новое", Role = ProfileRole.Primary });

        item.Security.Protocol = VpnProtocol.AnyConnect;
        Assert.Equal(ProfileRole.Secondary, item.Role);
        item.Security.Protocol = VpnProtocol.Sstp;
        Assert.Equal(ProfileRole.Primary, item.Role);

        item.Security.Protocol = VpnProtocol.AnyConnect;
        item.Role = ProfileRole.Off;
        item.Role = ProfileRole.Secondary;
        item.Security.Protocol = VpnProtocol.Sstp;
        Assert.Equal(ProfileRole.Secondary, item.Role);
    }

    /// <summary>
    /// Сервер сменён, настройки записаны, а пароль нет: повтор «Сохранить» не упирается в «Параметры входа изменились
    /// в другом окне», пароль из формы не теряется, а пользователь знает, что именно не сохранилось.
    /// </summary>
    [Fact]
    public Task EditorRetryAfterSecretFailure_RebasesAndKeepsDraft() => RunStaAsync(async () =>
    {
        var store = new Store { Settings = new AppSettings { Profiles = [Work], DefaultTarget = RouteTarget.Tunnel(Work.Id) } };
        store.Fail = request => request is SaveConnectionRequest { Password: not null } && store.ConnectionSaves == 1
            ? "Не удалось сохранить пароль для «Работа»: не удалось записать файл. Код для поддержки: 0A1B2C3D." : null;
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();
        var item = page.Selected!;
        item.Server = "new.example";
        page.Password = "new-password";

        await page.SaveCommand.ExecuteAsync(null);
        Assert.True(page.MessageIsError);
        Assert.Contains(ConnectionsViewModel.SettingsSavedCredentialsNot, page.Message, StringComparison.Ordinal);
        Assert.Equal("new.example", store.Settings.Profile(Work.Id)!.Server);
        Assert.Equal("new-password", page.Password);
        Assert.True(item.IsDirty);

        await page.SaveCommand.ExecuteAsync(null);
        Assert.False(page.MessageIsError, page.Message);
        Assert.Equal("new-password", store.LastConnection!.Password);
        Assert.Empty(page.Password);
    });

    [Fact]
    public Task EditorPrevalidation_DomainAndIkev2MsChap_NotSent() => RunStaAsync(async () =>
    {
        var store = new Store { Settings = new AppSettings { Profiles = [Work], DefaultTarget = RouteTarget.Tunnel(Work.Id) } };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();
        var item = page.Selected!;

        item.Security.Domain = "corp.example.local";
        await page.SaveCommand.ExecuteAsync(null);
        Assert.Equal(VpnProtocols.DomainTooLong, page.Message);
        Assert.True(item.Security.DetailsExpanded);

        item.Security.Domain = "CORP";
        item.UserName = new string('u', 300);
        var focus = page.UserNameFocusToken;
        await page.SaveCommand.ExecuteAsync(null);
        Assert.StartsWith("Имя пользователя", page.Message, StringComparison.Ordinal);
        Assert.Equal(focus + 1, page.UserNameFocusToken);
        Assert.Equal(0, store.ConnectionSaves);

        Assert.Contains("EAP-MSCHAPv2", VpnProtocols.UnsupportedAuthText(VpnProtocol.Ikev2, AuthMethod.MsChapV2), StringComparison.Ordinal);
        Assert.Null(VpnProtocols.UnsupportedAuthText(VpnProtocol.Ikev2, AuthMethod.EapMsChapV2));
    });

    /// <summary>Адрес шлюза с пробелами по краям проверяется так, как будет сохранён — без них.</summary>
    [Fact]
    public Task EditorServerWithSpaces_IsAccepted() => RunStaAsync(async () =>
    {
        var gateway = new ConnectionProfile { Name = "Шлюз", Server = "gw.example", Protocol = VpnProtocol.AnyConnect, AuthMethod = AuthMethod.GatewayForm, Role = ProfileRole.Off };
        var store = new Store { Settings = new AppSettings { Profiles = [gateway] } };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();
        page.Selected!.Server = "  gw2.example  ";

        await page.SaveCommand.ExecuteAsync(null);

        Assert.False(page.MessageIsError, page.Message);
        Assert.Equal("gw2.example", store.Settings.Profiles[0].Server);
    });

    /// <summary>
    /// Опорное подключение с «Остальным интернетом» и группой переводят на AnyConnect: подтверждение перечисляет, что
    /// пойдёт напрямую и из какой группы оно выйдет; отказ отменяет сохранение, согласие сохраняет допустимые настройки.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public Task EditorSwitchToAnyConnect_MovesForbiddenTargetsAfterConfirmation(bool confirmed) => RunStaAsync(async () =>
    {
        var other = new ConnectionProfile { Name = "Резерв", Server = "backup.example", UserName = "user", Role = ProfileRole.Secondary };
        var group = new TunnelGroupSetting { Name = "Пара", Members = [Work.Id, other.Id] };
        var store = new Store
        {
            Settings = new AppSettings
            {
                Profiles = [Work, other], Groups = [group],
                DefaultTarget = RouteTarget.Tunnel(Work.Id), GeoTarget = RouteTarget.Group(group.Id),
            },
        };
        string? text = null;
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences()) { Confirm = (_, t, _) => { text = t; return Task.FromResult(confirmed); } };
        var page = main.Connections;
        await page.LoadAsync();
        page.Selected = page.Profiles.Single(p => p.Id == Work.Id);
        page.Selected.Server = "gw.example";
        page.Selected.Security.Protocol = VpnProtocol.AnyConnect;

        await page.SaveCommand.ExecuteAsync(null);

        Assert.NotNull(text);
        Assert.Contains("«Остальной интернет»", text, StringComparison.Ordinal);
        Assert.Contains("«Работа» выйдет из группы «Пара»", text, StringComparison.Ordinal);
        if (!confirmed)
        {
            Assert.Equal(0, store.ConnectionSaves);
            return;
        }

        var saved = store.Settings;
        Assert.Equal(VpnProtocol.AnyConnect, saved.Profile(Work.Id)!.Protocol);
        Assert.Equal(ProfileRole.Secondary, saved.Profile(Work.Id)!.Role);
        Assert.Equal(RouteTarget.Direct, saved.DefaultTarget);
        Assert.Equal(new[] { other.Id }, saved.Groups.Single().Members);
        Assert.DoesNotContain(SettingsValidator.Validate(saved).Errors, e => e.Contains("AnyConnect", StringComparison.Ordinal));
    });

    [Fact]
    public void Import_ForcesSafeSecurityValues_AndConfirmationListsTrust()
    {
        var imported = new ConnectionProfile
        {
            Name = "Чужой", Server = "gw.example", Protocol = VpnProtocol.AnyConnect, AuthMethod = AuthMethod.GatewayForm, Role = ProfileRole.Secondary,
            AnyConnect = new AnyConnectSettings { ApplyServerProxy = true, ServerNetworksTarget = RouteTarget.Direct, UserRulesOverrideServerNetworks = false, ClientCertificateThumbprint = new string('A', 40) },
            Eap = new EapSettings { ServerNames = "radius.example", TrustedRootThumbprints = [new string('B', 40)], ClientCertificateThumbprint = new string('C', 40) },
        };

        var result = Assert.Single(ConnectionEdits.PrepareImport([], [imported]));

        Assert.False(result.AnyConnect.ApplyServerProxy);
        Assert.Null(result.AnyConnect.ServerNetworksTarget);
        Assert.True(result.AnyConnect.UserRulesOverrideServerNetworks);
        Assert.Empty(result.AnyConnect.ClientCertificateThumbprint);
        Assert.Empty(result.Eap.ClientCertificateThumbprint);
        Assert.Equal("radius.example", result.Eap.ServerNames);
        var text = ConnectionsViewModel.ImportConfirmation([result]);
        Assert.Contains("radius.example", text, StringComparison.Ordinal);
        Assert.Contains("BBBBBBBB…", text, StringComparison.Ordinal);

        // Выключенный EAP-TLS без сертификата проходит проверку; включить его без сертификата нельзя.
        var tls = new ConnectionProfile { Name = "TLS", Server = "vpn.example", Protocol = VpnProtocol.Ikev2, AuthMethod = AuthMethod.EapTls, Role = ProfileRole.Off,
            Eap = new EapSettings { ServerNames = "vpn.example", TrustedRootThumbprints = [new string('B', 40)] } };
        Assert.True(SettingsValidator.Validate(new AppSettings { Profiles = [tls] }).IsValid);
        Assert.False(SettingsValidator.Validate(new AppSettings { Profiles = [tls with { Role = ProfileRole.Primary }], DefaultTarget = RouteTarget.Tunnel(tls.Id) }).IsValid);
    }

    /// <summary>Включаемое подключение AnyConnect с сетями шлюза «Напрямую» выводит их мимо VPN впервые — это предупреждение.</summary>
    [Fact]
    public void NewlyDirect_CountsGatewayNetworksOfEnabledProfile()
    {
        var gateway = new ConnectionProfile { Name = "Шлюз", Server = "gw.example", Protocol = VpnProtocol.AnyConnect, AuthMethod = AuthMethod.GatewayForm,
            Role = ProfileRole.Off, AnyConnect = new AnyConnectSettings { ServerNetworksTarget = RouteTarget.Direct } };
        var before = new AppSettings { Profiles = [gateway] };
        var after = before with { Profiles = [gateway with { Role = ProfileRole.Secondary }] };

        Assert.Contains("сети шлюза «Шлюз»", ConnectionEdits.NewlyDirect(before, after));
        Assert.Empty(ConnectionEdits.NewlyDirect(after, after));
    }

    [Fact]
    public void RangeString_IsADnsNameForUri_SoTheBoardParsesRangesItself() =>
        Assert.Equal(UriHostNameType.Dns, Uri.CheckHostName("10.0.0.1-10.0.0.9"));

    [Fact]
    public void BoardRange_BecomesMinimalCidrs_WithLimit()
    {
        var range = RoutingViewModel.RangeInput("10.0.0.1-10.0.0.9")!;
        Assert.Null(range.Error);
        Assert.Equal(new[] { "10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/30", "10.0.0.8/31" }, range.Cidrs!.Select(c => c.ToString()));
        Assert.Equal(new[] { "10.0.0.0/24" }, RoutingViewModel.RangeInput("10.0.0.0 - 10.0.0.255")!.Cidrs!.Select(c => c.ToString()));
        Assert.Contains("меньше начала", RoutingViewModel.RangeInput("10.0.0.9-10.0.0.1")!.Error, StringComparison.Ordinal);
        Assert.Equal(14, RoutingViewModel.RangeInput("10.0.0.1-10.0.0.254")!.Cidrs!.Count);
        Assert.Contains("больше 16", RoutingViewModel.RangeInput("10.0.0.1-10.0.255.254")!.Error, StringComparison.Ordinal);
        Assert.Null(RoutingViewModel.RangeInput("my-host.example"));
    }

    [Fact]
    public Task BoardAdd_RangeAndWildcardDomain() => RunStaAsync(async () =>
    {
        var store = new Store();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Routing;
        await page.OnOpenedAsync();
        var column = page.Columns.Single(c => c.Target == RouteTarget.Direct);

        column.NewValue = "192.0.2.1-192.0.2.3";
        column.AddCommand.Execute(null);
        column.NewValue = "*.example.org";
        column.AddCommand.Execute(null);

        var titles = column.Cards.Select(c => c.Title).ToList();
        Assert.Contains("192.0.2.1/32", titles);
        Assert.Contains("192.0.2.2/31", titles);
        Assert.Contains("example.org", titles);
        Assert.DoesNotContain(titles, t => t.StartsWith("192.0.2.1-", StringComparison.Ordinal) || t.StartsWith('*'));
    });

    /// <summary>Служба отложила сохранение до конца дозвона: приложение ждёт и повторяет само, показывая ожидание.</summary>
    [Fact]
    public async Task DialInProgress_IsRetriedWithVisibleWait()
    {
        var attempts = 0;
        Task<IpcResponse> Send(IpcRequest request, CancellationToken token) => Task.FromResult(++attempts < 3
            ? IpcResponse.Failure(IpcErrorCodes.DialInProgress, "Дождитесь завершения дозвона перед изменением настроек.")
            : IpcResponse.Success());
        using var service = new ServiceConnection(Send) { DialRetryDelay = TimeSpan.Zero };
        var waits = new List<bool>();
        service.WaitingForDial += waits.Add;

        var response = await service.CommandAsync(new SaveSettingsRequest(new AppSettings()), TestContext.Current.CancellationToken);

        Assert.True(response.Ok);
        Assert.Equal(3, attempts);
        Assert.Equal(new[] { true, false }, waits);
    }

    [Fact]
    public async Task DialInProgress_GivesUpAfterLimit()
    {
        Task<IpcResponse> Send(IpcRequest request, CancellationToken token) =>
            Task.FromResult(IpcResponse.Failure(IpcErrorCodes.DialInProgress, "Дождитесь завершения дозвона перед изменением настроек."));
        using var service = new ServiceConnection(Send) { DialRetryDelay = TimeSpan.Zero, DialRetryLimit = 2 };

        var error = await Assert.ThrowsAsync<ServiceCommandException>(() => service.CommandAsync(new SaveSettingsRequest(new AppSettings()), TestContext.Current.CancellationToken));

        Assert.Equal(IpcErrorCodes.DialInProgress, error.ErrorCode);
    }

    /// <summary>Подставная служба: настройки в памяти, отказ по выбору теста (<see cref="Fail"/>) — после записи настроек.</summary>
    private sealed class Store
    {
        public AppSettings Settings { get; set; } = new();

        public Func<IpcRequest, string?>? Fail { get; set; }

        public int ConnectionSaves { get; private set; }

        public SaveConnectionRequest? LastConnection { get; private set; }

        public Task<IpcResponse> SendAsync(IpcRequest request, CancellationToken cancellationToken)
        {
            switch (request)
            {
                case GetSettingsRequest:
                    return Task.FromResult(IpcResponse.Success(Settings));
                case GetAdaptersRequest:
                    return Task.FromResult(IpcResponse.Success(new List<AdapterDto>()));
                case GetStatusRequest:
                    return Task.FromResult(IpcResponse.Success(new StatusDto { State = ConnectionState.Error }));
                case SaveSettingsRequest save:
                    Settings = save.Settings;
                    return Task.FromResult(IpcResponse.Success());
                case SaveConnectionRequest save:
                    ConnectionSaves++;
                    Settings = save.Settings;
                    if (Fail?.Invoke(request) is { } failure)
                    {
                        return Task.FromResult(IpcResponse.Failure(IpcErrorCodes.Failed, failure));
                    }

                    LastConnection = save;
                    return Task.FromResult(IpcResponse.Success());
                default:
                    return Task.FromResult(Fail?.Invoke(request) is { } refused
                        ? IpcResponse.Failure(IpcErrorCodes.Failed, refused)
                        : IpcResponse.Success());
            }
        }
    }

    private static Task RunStaAsync(Func<Task> action)
    {
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            var dispatcher = Dispatcher.CurrentDispatcher;
            SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(dispatcher));
            dispatcher.BeginInvoke(new Action(async () =>
            {
                try { await action(); completion.TrySetResult(); }
                catch (Exception ex) { completion.TrySetException(ex); }
                finally { dispatcher.BeginInvokeShutdown(DispatcherPriority.Background); }
            }));
            Dispatcher.Run();
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        return completion.Task.WaitAsync(TimeSpan.FromSeconds(15), TestContext.Current.CancellationToken);
    }
}
