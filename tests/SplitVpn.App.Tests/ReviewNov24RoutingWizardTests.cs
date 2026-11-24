using System.Windows.Threading;
using SplitVpn.App.Services;
using SplitVpn.App.ViewModels;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;

namespace SplitVpn.App.Tests;

/// <summary>Ревью 24.11: доска маршрутизации (сохранение и перечитывание, конфликт, ввод адресов) и отмена мастера.</summary>
public sealed class ReviewNov24RoutingWizardTests
{
    /// <summary>
    /// «Отменить изменения» во время сохранения: служба ещё отдаёт прежние настройки, но доска не перерисовывается
    /// ими, и следующее сохранение не записывает прежнюю доску поверх первого сохранения.
    /// </summary>
    [Fact]
    public Task ReloadDuringSaveDoesNotRevertTheBoard() => RunStaAsync(async () =>
    {
        var store = new BoardService();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Routing;
        await page.OnOpenedAsync();
        Add(page, RouteTarget.Direct, "203.0.113.0/24");

        store.Hold = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var saving = page.SaveCommand.ExecuteAsync(null);
        await store.SaveArrived.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        Assert.False(page.ReloadCommand.CanExecute(null));

        // Команда вызывается и в обход CanExecute: ответ загрузки во время сохранения всё равно отбрасывается.
        await page.ReloadCommand.ExecuteAsync(null);
        Assert.Contains(page.Columns.Single(c => c.Target == RouteTarget.Direct).Cards, c => c.Title == "203.0.113.0/24");

        store.Hold.SetResult();
        await saving;
        Assert.False(page.Dirty);
        Assert.True(page.ReloadCommand.CanExecute(null));

        Add(page, RouteTarget.Direct, "198.51.100.0/24");
        await page.SaveCommand.ExecuteAsync(null);

        Assert.False(page.MessageIsError, page.Message);
        Assert.Equal(2, store.Saves);
        Assert.Contains(store.LastSaved!.Rules, r => r.Cidr == "203.0.113.0/24");
        Assert.Contains(store.LastSaved.Rules, r => r.Cidr == "198.51.100.0/24");
    });

    /// <summary>
    /// Подключение выключили в другом месте: конфликт пересобирает доску (карточки выключенного подключения уходят
    /// в «Напрямую»), и второе «Сохранить» проходит проверку службы, а правка пользователя сохраняется.
    /// </summary>
    [Fact]
    public Task ConflictRebuildsBoardForDisabledConnection() => RunStaAsync(async () =>
    {
        var profile = new ConnectionProfile { Name = "Второе", Server = "vpn2.example", UserName = "user", Role = ProfileRole.Secondary };
        var store = new BoardService
        {
            Settings = new AppSettings
            {
                Profiles = [profile],
                Rules = [new UserRuleSetting { Cidr = "192.0.2.0/24", Target = RouteTarget.Tunnel(profile.Id) }],
            },
        };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Routing;
        await page.OnOpenedAsync();
        Assert.Contains(page.Columns, c => c.Target == RouteTarget.Tunnel(profile.Id));

        store.Settings = store.Settings with { Profiles = [profile with { Role = ProfileRole.Off }] };
        Add(page, RouteTarget.Direct, "198.51.100.0/24");

        await page.SaveCommand.ExecuteAsync(null);
        Assert.True(page.MessageIsError);
        Assert.Equal(0, store.Saves);
        Assert.DoesNotContain(page.Columns, c => c.Target == RouteTarget.Tunnel(profile.Id));
        Assert.Contains("перенесена в «Напрямую»", page.Message, StringComparison.Ordinal);

        await page.SaveCommand.ExecuteAsync(null);
        Assert.False(page.MessageIsError, page.Message);
        Assert.Equal(1, store.Saves);
        Assert.Contains(store.Settings.Rules, r => r.Cidr == "192.0.2.0/24" && r.Target == RouteTarget.Direct);
        Assert.Contains(store.Settings.Rules, r => r.Cidr == "198.51.100.0/24");
    });

    [Theory]
    [InlineData("https://example.org/path", "example.org", false)]
    [InlineData("http://Example.org:8080/", "example.org", false)]
    [InlineData("vpn.example.org:443", "vpn.example.org", false)]
    [InlineData("203.0.113.5:8080", "203.0.113.5", false)]
    [InlineData("203.0.113.0/24", "203.0.113.0/24", false)]
    [InlineData("example.org", "example.org", false)]
    [InlineData("2001:db8::1", "2001:db8::1", true)]
    [InlineData("2001:db8::/32", "2001:db8::/32", true)]
    [InlineData("[2001:db8::1]", "[2001:db8::1]", true)]
    [InlineData("[2001:db8::1]:443", "[2001:db8::1]:443", true)]
    [InlineData("https://[2001:db8::1]/", "[2001:db8::1]", true)]
    public void BoardInputTakesHostFromUrlAndPort(string input, string expected, bool ipv6)
    {
        Assert.Equal(expected, RoutingViewModel.BoardInput(input, out var isIpv6));
        Assert.Equal(ipv6, isIpv6);
    }

    /// <summary>Вставленная ссылка и «узел:порт» дают карточку домена, а не ложный отказ про IPv6.</summary>
    [Fact]
    public Task PastedUrlAndHostPortBecomeDomainCards() => RunStaAsync(async () =>
    {
        var store = new BoardService();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Routing;
        await page.OnOpenedAsync();

        Add(page, RouteTarget.Direct, "https://example.org/path");
        Assert.False(page.MessageIsError, page.Message);
        Add(page, RouteTarget.Direct, "vpn.example.org:443");
        Assert.False(page.MessageIsError, page.Message);
        var cards = page.Columns.Single(c => c.Target == RouteTarget.Direct).Cards.Select(c => c.Title).ToList();
        Assert.Contains("example.org", cards);
        Assert.Contains("vpn.example.org", cards);

        Add(page, RouteTarget.Direct, "[2001:db8::1]");
        Assert.True(page.MessageIsError);
        Assert.Contains("IPv6", page.Message, StringComparison.Ordinal);
    });

    /// <summary>
    /// «Готово» отправило подключение, но оно не удалось: «Отмена» отключает VPN со снятием защиты, иначе намерение
    /// «подключено» и защита оставили бы трафик заблокированным. Профиль не удаляется.
    /// </summary>
    [Fact]
    public Task WizardCancelAfterFailedConnectRestoresInternet() => RunStaAsync(async () =>
    {
        var store = new BoardService();
        var disconnects = new List<DisconnectRequest>();
        Task<IpcResponse> Send(IpcRequest request, CancellationToken token)
        {
            switch (request)
            {
                case DisconnectRequest disconnect:
                    disconnects.Add(disconnect);
                    return Task.FromResult(IpcResponse.Success());
                case ConnectRequest:
                    return Task.FromResult(IpcResponse.Success());
                case GetStatusRequest:
                    return Task.FromResult(IpcResponse.Success(new StatusDto { State = ConnectionState.Error, Intent = Intent.Connected }));
                default:
                    return store.SendAsync(request, token);
            }
        }

        using var service = new ServiceConnection(Send);
        using var main = new MainViewModel(service, new UiPreferences());
        var wizard = new WizardViewModel(main, false) { Server = "vpn.example", UserName = "user", Password = "draft", RussiaDirect = false, Step = WizardViewModel.LastStep - 1 };
        await wizard.NextCommand.ExecuteAsync(null);
        Assert.Equal(0, wizard.Step);
        Assert.False(wizard.Finished);
        Assert.Empty(disconnects);

        await wizard.CancelCommand.ExecuteAsync(null);

        var sent = Assert.Single(disconnects);
        Assert.False(sent.KeepProtection);
        Assert.Single(store.Settings.Profiles);
    });

    /// <summary>Занятое название выясняется на шаге «Сервер и вход», а после «Готово» возвращает на него.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(WizardViewModel.LastStep - 1)]
    public Task WizardTakenNameKeepsFirstStep(int step) => RunStaAsync(async () =>
    {
        var store = new BoardService
        {
            Settings = new AppSettings { Profiles = [new ConnectionProfile { Name = "Основное", Server = "other.example", UserName = "user" }] },
        };
        var connects = 0;
        Task<IpcResponse> Send(IpcRequest request, CancellationToken token)
        {
            if (request is ConnectRequest) { connects++; return Task.FromResult(IpcResponse.Success()); }
            return store.SendAsync(request, token);
        }

        using var service = new ServiceConnection(Send);
        using var main = new MainViewModel(service, new UiPreferences());
        var wizard = new WizardViewModel(main, false) { Server = "vpn.example", UserName = "user", Password = "draft", RussiaDirect = false, Step = step };
        await wizard.NextCommand.ExecuteAsync(null);

        Assert.Equal(0, wizard.Step);
        Assert.Contains("Название уже занято", wizard.Error, StringComparison.Ordinal);
        Assert.Equal(0, connects);
        Assert.Single(store.Settings.Profiles);

        wizard.Name = "Новое";
        await wizard.NextCommand.ExecuteAsync(null);
        Assert.Equal(1, wizard.Step);
        Assert.Null(wizard.Error);
    });

    private static void Add(RoutingViewModel page, RouteTarget target, string text)
    {
        var column = page.Columns.Single(c => c.Target == target);
        column.NewValue = text;
        column.AddCommand.Execute(null);
    }

    /// <summary>
    /// Подставная служба: сохранение можно задержать (<see cref="Hold"/>) — до его завершения служба отдаёт
    /// прежние настройки. Сохранение с карточками в выключенное или удалённое подключение отклоняется, как валидатором службы.
    /// </summary>
    private sealed class BoardService
    {
        public AppSettings Settings { get; set; } = new();

        public TaskCompletionSource? Hold { get; set; }

        public TaskCompletionSource SaveArrived { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public AppSettings? LastSaved { get; private set; }

        public int Saves { get; private set; }

        public async Task<IpcResponse> SendAsync(IpcRequest request, CancellationToken cancellationToken)
        {
            switch (request)
            {
                case GetSettingsRequest:
                    return IpcResponse.Success(Settings);
                case GetAdaptersRequest:
                    return IpcResponse.Success(new List<AdapterDto>());
                case SaveSettingsRequest save:
                    SaveArrived.TrySetResult();
                    if (Hold is { } hold)
                    {
                        await hold.Task;
                    }

                    if (InvalidTarget(save.Settings) is { } problem)
                    {
                        return IpcResponse.Failure(IpcErrorCodes.InvalidSettings, problem);
                    }

                    Settings = save.Settings;
                    LastSaved = save.Settings;
                    Saves++;
                    return IpcResponse.Success();
                case SaveConnectionRequest save:
                    Settings = save.Settings;
                    return IpcResponse.Success();
                default:
                    return IpcResponse.Failure(IpcErrorCodes.BadRequest, "Неожиданный запрос " + request.GetType().Name);
            }
        }

        private static string? InvalidTarget(AppSettings settings)
        {
            var targets = settings.Rules.Select(r => r.Target).Concat(settings.DomainRules.Select(r => r.Target)).Append(settings.DefaultTarget).Append(settings.GeoTarget);
            foreach (var target in targets)
            {
                if (target.IsTunnel(out var id) && settings.Profile(id) is not { Role: not ProfileRole.Off })
                {
                    return "Правило ведёт в выключенное подключение.";
                }
            }

            return null;
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
