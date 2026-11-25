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
/// Итерация 12: откат мастера после сбоя за сохранением профиля, повтор сохранения после незаписанного секрета,
/// проверка формы до отправки, смена протокола на AnyConnect, импорт, диапазоны на доске, повтор после дозвона.
/// </summary>
public sealed class Iteration12AppTests
{
    private static readonly ConnectionProfile Work = new() { Name = "Работа", Server = "work.example", UserName = "user", Role = ProfileRole.Primary };

    /// <summary>
    /// Профиль мастера сохранён, а загрузка RU-базы не удалась (до подключения): «Отмена» возвращает «Работе» роль
    /// опорного и цели, новое подключение выключается. Правило, добавленное в другом окне между сбоем и отменой, остаётся.
    /// </summary>
    [Fact]
    public Task WizardCancelAfterGeoFailure_RestoresRolesAndTargets_KeepsOtherChanges() => RunStaAsync(async () =>
    {
        var store = new Store { Settings = new AppSettings { Profiles = [Work], DefaultTarget = RouteTarget.Tunnel(Work.Id), GeoTarget = RouteTarget.Tunnel(Work.Id) } };
        store.Fail = request => request is GeoUpdateNowRequest ? "Источник RU-базы недоступен." : null;
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences()) { Confirm = (_, _, _) => Task.FromResult(true) };
        var wizard = new WizardViewModel(main, false)
        {
            Name = "Новое", Server = "vpn.example", UserName = "user", Password = "secret", RussiaDirect = true,
            GeoOption = GeoStartOption.DownloadNow, Step = WizardViewModel.LastStep - 1,
        };

        await wizard.NextCommand.ExecuteAsync(null);
        Assert.Contains("RU-базы", wizard.Error, StringComparison.Ordinal);
        var added = store.Settings.Profiles.Single(p => p.Name == "Новое");
        Assert.Equal(ProfileRole.Primary, added.Role);
        Assert.Equal(RouteTarget.Tunnel(added.Id), store.Settings.DefaultTarget);

        // Пока мастер ждал, в другом окне добавили правило: «Отмена» его не стирает.
        store.Settings = store.Settings with { DomainRules = [new DomainRuleSetting { Suffix = "example.org", Target = RouteTarget.Direct }] };
        await wizard.CancelCommand.ExecuteAsync(null);

        Assert.Null(main.Wizard);
        var restored = store.Settings;
        Assert.Equal(ProfileRole.Primary, restored.Profile(Work.Id)!.Role);
        Assert.Equal(ProfileRole.Off, restored.Profile(added.Id)!.Role);
        Assert.Equal(RouteTarget.Tunnel(Work.Id), restored.DefaultTarget);
        Assert.Equal(RouteTarget.Tunnel(Work.Id), restored.GeoTarget);
        Assert.Single(restored.DomainRules);
    });

    /// <summary>Отказ в подтверждении «станет опорным»: служба ничего не получает, мастер остаётся на последнем шаге ввода.</summary>
    [Fact]
    public Task WizardTakeoverDeclined_SavesNothing() => RunStaAsync(async () =>
    {
        var store = new Store { Settings = new AppSettings { Profiles = [Work], DefaultTarget = RouteTarget.Tunnel(Work.Id) } };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences()) { Confirm = (_, _, _) => Task.FromResult(false) };
        var wizard = new WizardViewModel(main, false) { Name = "Новое", Server = "vpn.example", UserName = "user", Password = "secret", RussiaDirect = false, Step = WizardViewModel.LastStep - 1 };

        await wizard.NextCommand.ExecuteAsync(null);

        Assert.Equal(0, store.ConnectionSaves);
        Assert.Contains("Сохранение отменено", wizard.Error, StringComparison.Ordinal);
        Assert.Equal(wizard.LastInputStep, wizard.Step);
    });

    [Fact]
    public void WizardTakeoverText_NamesDemotedProfileAndMovedTargets()
    {
        var before = new AppSettings { Profiles = [Work], DefaultTarget = RouteTarget.Tunnel(Work.Id), GeoTarget = RouteTarget.Direct };
        var added = new ConnectionProfile { Name = "Новое", Server = "vpn.example", Role = ProfileRole.Primary };
        var after = ConnectionEdits.SaveProfile(before, added) with { DefaultTarget = RouteTarget.Tunnel(added.Id), GeoTarget = RouteTarget.Direct };

        var text = WizardViewModel.TakeoverText(before, after, added.Id)!;

        Assert.Contains("«Работа» станет дополнительным", text, StringComparison.Ordinal);
        Assert.Contains("«Остальной интернет»: сейчас через «Работа», будет через «Новое»", text, StringComparison.Ordinal);
        Assert.DoesNotContain("RU-база", text, StringComparison.Ordinal);
        Assert.Null(WizardViewModel.TakeoverText(new AppSettings(), after, added.Id));
    }

    /// <summary>Откат не трогает поле, которое после мастера поменяли в другом месте.</summary>
    [Fact]
    public void WizardRollback_KeepsFieldChangedElsewhere()
    {
        var before = new AppSettings { Profiles = [Work], DefaultTarget = RouteTarget.Tunnel(Work.Id), GeoTarget = RouteTarget.Tunnel(Work.Id) };
        var added = new ConnectionProfile { Name = "Новое", Server = "vpn.example", Role = ProfileRole.Primary };
        var saved = ConnectionEdits.SaveProfile(before, added) with { DefaultTarget = RouteTarget.Tunnel(added.Id), GeoTarget = RouteTarget.Direct };
        var changedElsewhere = saved with { DefaultTarget = RouteTarget.Blocked };

        var restored = WizardViewModel.Rollback(before, changedElsewhere, added.Id, RouteTarget.Direct)!;

        Assert.Equal(RouteTarget.Blocked, restored.DefaultTarget);
        Assert.Equal(RouteTarget.Tunnel(Work.Id), restored.GeoTarget);
        Assert.Equal(ProfileRole.Primary, restored.Profile(Work.Id)!.Role);
        Assert.Equal(ProfileRole.Off, restored.Profile(added.Id)!.Role);
        Assert.Null(WizardViewModel.Rollback(before, before, added.Id, RouteTarget.Direct));
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
