using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows.Threading;
using Microsoft.Web.WebView2.Core;
using SplitVpn.App.Services;
using SplitVpn.App.ViewModels;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;

namespace SplitVpn.App.Tests;

/// <summary>
/// Аудит 27.11: защита браузера окна входа SSO, предел повтора уведомлений о сбоях, разбор замечаний службы при
/// сохранении, пояснение к ключу SSH, неустановленная служба, отказ оболочки при открытии папок и адресов.
/// </summary>
public sealed class AuditNov27AppTests
{
    private static readonly ConnectionProfile Work = new() { Name = "Работа", Server = "work.example", UserName = "user", Role = ProfileRole.Primary };

    // ---------- Браузер окна входа ----------

    [Theory]
    [InlineData("https://idp.example/frame", true)]
    [InlineData("about:blank", true)]
    [InlineData("about:srcdoc", true)]
    // Содержимое, созданное самой HTTPS-страницей (виджеты входа, капчи), из сети не загружается — разрешено.
    [InlineData("data:text/html,<form>", true)]
    [InlineData("DATA:image/svg+xml;base64,PHN2Zz4=", true)]
    [InlineData("blob:https://idp.example/5f0c1e2a-0000-4000-8000-000000000000", true)]
    [InlineData("http://idp.example/frame", false)]
    [InlineData("blob:http://idp.example/5f0c1e2a-0000-4000-8000-000000000000", false)]
    [InlineData("ftp://idp.example/frame", false)]
    [InlineData("ws://idp.example/frame", false)]
    [InlineData("javascript:alert(1)", false)]
    [InlineData("file:///C:/Windows/win.ini", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void FrameNavigation_HttpsOrPageOwnContent(string? uri, bool allowed) =>
        Assert.Equal(allowed, SignInBrowserPolicy.FrameNavigationAllowed(uri));

    [Fact]
    public void FrameBlockedProblem_ExplainsEmptyPart()
    {
        Assert.Contains("не загружена", SignInBrowserPolicy.FrameBlockedProblem, StringComparison.Ordinal);
        Assert.Contains("HTTPS", SignInBrowserPolicy.FrameBlockedProblem, StringComparison.Ordinal);
    }

    [Fact]
    public void MainAndPopupNavigation_KeepPreviousRules()
    {
        Assert.True(SignInBrowserPolicy.MainNavigationAllowed("https://gateway.example/+CSCOE+/saml"));
        Assert.True(SignInBrowserPolicy.MainNavigationAllowed("HTTPS://idp.example/"));
        Assert.False(SignInBrowserPolicy.MainNavigationAllowed("http://gateway.example/"));
        Assert.False(SignInBrowserPolicy.MainNavigationAllowed("about:blank"));
        Assert.False(SignInBrowserPolicy.MainNavigationAllowed(null));

        // Всплывающее окно OAuth сначала открывается пустым, затем переходит на страницу IdP.
        Assert.True(SignInBrowserPolicy.PopupNavigationAllowed("about:blank"));
        Assert.True(SignInBrowserPolicy.PopupNavigationAllowed("https://login.idp.example/authorize?x=1"));
        Assert.False(SignInBrowserPolicy.PopupNavigationAllowed("http://login.idp.example/"));
    }

    [Fact]
    public void CertificateError_IsRecognizedAndNamedForDocumentOnly()
    {
        Assert.True(SignInBrowserPolicy.IsCertificateError("CertificateIsInvalid"));
        Assert.True(SignInBrowserPolicy.IsCertificateError("CertificateCommonNameIsIncorrect"));
        Assert.False(SignInBrowserPolicy.IsCertificateError("HostNameNotResolved"));

        // Сама страница (или фрейм) — пользователю сообщается; картинка или скрипт — только отменяются.
        Assert.True(SignInBrowserPolicy.IsDocumentRequest("https://idp.example/login?a=1", "https://IDP.example/login?a=1#top", null));
        Assert.True(SignInBrowserPolicy.IsDocumentRequest("https://frame.example/", "https://idp.example/", "https://frame.example/"));
        Assert.False(SignInBrowserPolicy.IsDocumentRequest("https://cdn.example/logo.png", "https://idp.example/", null));
        Assert.False(SignInBrowserPolicy.IsDocumentRequest(null, null, null));

        var text = SignInBrowserPolicy.CertificateProblem("https://idp.example/login");
        Assert.Contains("idp.example", text, StringComparison.Ordinal);
        Assert.Contains("продолжить на ней нельзя", text, StringComparison.Ordinal);
    }

    /// <summary>
    /// Ревью 27.11: окно входа только присваивает событиям WebView2 решения политики. Ошибка сертификата — отмена
    /// (не «по умолчанию» и не «разрешить»), загрузки запрещены, инструменты разработчика и сохранение пароля выключены.
    /// </summary>
    [Fact]
    public void BrowserGuards_CancelCertificateErrorsDownloadsAndDevTools()
    {
        Assert.Equal(CoreWebView2ServerCertificateErrorAction.Cancel, SignInBrowserPolicy.CertificateErrorAction);
        Assert.False(SignInBrowserPolicy.DownloadAllowed);
        Assert.False(SignInBrowserPolicy.DevToolsEnabled);
        Assert.False(SignInBrowserPolicy.PasswordAutosaveEnabled);
        Assert.Contains("отменена", SignInBrowserPolicy.DownloadBlockedProblem, StringComparison.Ordinal);
    }

    /// <summary>Любой вид разрешения — в том числе появившийся в новой версии WebView2 — отклоняется.</summary>
    [Fact]
    public void BrowserGuards_DenyEveryPermissionKind()
    {
        var kinds = Enum.GetValues<CoreWebView2PermissionKind>();
        Assert.Contains(CoreWebView2PermissionKind.Camera, kinds);
        Assert.Contains(CoreWebView2PermissionKind.Geolocation, kinds);
        Assert.All(kinds, kind => Assert.Equal(CoreWebView2PermissionState.Deny, SignInBrowserPolicy.PermissionState(kind)));
        // Значение вне перечисления (вид, которого эта сборка ещё не знает) — тоже отказ.
        Assert.Equal(CoreWebView2PermissionState.Deny, SignInBrowserPolicy.PermissionState((CoreWebView2PermissionKind)int.MaxValue));
    }

    // ---------- Уведомления ----------

    /// <summary>
    /// Мигающий Wi-Fi: «Трафик заблокирован» на каждом круге. Показываются «заблокирован → снова подключён →
    /// заблокирован»; дальше «снова подключён» подавлен своим пределом (5 минут), а с ним и повтор блокировки в
    /// течение минуты. После минуты блокировка снова показывается.
    /// </summary>
    [Fact]
    public Task FlappingTrafficBlocked_NotifiesOncePerMinute() => RunStaAsync(async () =>
    {
        var (store, time, service, main, shown) = Setup();
        using (service)
        using (main)
        {
            await Status(store, time, main, ConnectionState.Connected, 0);
            await Status(store, time, main, ConnectionState.TrafficBlocked, 5);
            await Status(store, time, main, ConnectionState.Connected, 10);
            await Status(store, time, main, ConnectionState.TrafficBlocked, 15);
            await Status(store, time, main, ConnectionState.Connected, 20);
            await Status(store, time, main, ConnectionState.TrafficBlocked, 25);
            Assert.Equal(["Трафик заблокирован", "VPN снова подключён", "Трафик заблокирован"], shown);

            await Status(store, time, main, ConnectionState.Connected, 80);
            await Status(store, time, main, ConnectionState.TrafficBlocked, 90);
            Assert.Equal(3, shown.Count(t => t == "Трафик заблокирован"));
        }
    });

    /// <summary>
    /// Ревью 27.11: «заблокирован» → «снова подключён» → через полминуты снова блокировка. Повтор не подавляется:
    /// иначе последним пользователь видел бы «снова подключён» при заблокированном трафике.
    /// </summary>
    [Fact]
    public Task BlockedAgainAfterShownRecovery_IsShown() => RunStaAsync(async () =>
    {
        var (store, time, service, main, shown) = Setup();
        using (service)
        using (main)
        {
            await Status(store, time, main, ConnectionState.Connected, 0);
            await Status(store, time, main, ConnectionState.TrafficBlocked, 5);
            await Status(store, time, main, ConnectionState.Connected, 10);
            await Status(store, time, main, ConnectionState.TrafficBlocked, 40);
            Assert.Equal(["Трафик заблокирован", "VPN снова подключён", "Трафик заблокирован"], shown);
        }
    });

    /// <summary>То же для повторной ошибки и неполного применения: после показанного восстановления — снова видны.</summary>
    [Theory]
    [InlineData(ConnectionState.Error, "Ошибка подключения")]
    [InlineData(ConnectionState.PartiallyApplied, "Неполное применение")]
    public Task SameFailureAfterShownRecovery_IsShown(ConnectionState failure, string title) => RunStaAsync(async () =>
    {
        var (store, time, service, main, shown) = Setup();
        using (service)
        using (main)
        {
            await Status(store, time, main, ConnectionState.Connected, 0);
            await Status(store, time, main, failure, 5);
            await Status(store, time, main, ConnectionState.Connected, 10);
            await Status(store, time, main, failure, 20);
            Assert.Equal([title, "VPN снова подключён", title], shown);
        }
    });

    /// <summary>
    /// Быстрое мигание: 10 кругов «подключено ↔ заблокировано» за минуту — не 10 пар уведомлений. Кончилось
    /// блокировкой — последним показано «заблокирован».
    /// </summary>
    [Fact]
    public Task FastFlapping_DoesNotFloodAndEndsWithBlocked() => RunStaAsync(async () =>
    {
        var (store, time, service, main, shown) = Setup();
        using (service)
        using (main)
        {
            for (var i = 0; i < 10; i++)
            {
                await Status(store, time, main, ConnectionState.Connected, i * 6);
                await Status(store, time, main, ConnectionState.TrafficBlocked, i * 6 + 3);
            }

            Assert.True(shown.Count <= 3, string.Join(", ", shown));
            Assert.Equal("Трафик заблокирован", shown[^1]);
        }
    });

    /// <summary>Вход нужен в разные подключения — это разные действия: оба уведомления показываются сразу.</summary>
    [Fact]
    public Task SignInForDifferentConnections_IsNotSuppressed() => RunStaAsync(async () =>
    {
        var (store, time, service, main, shown) = Setup();
        using (service)
        using (main)
        {
            var first = Guid.NewGuid();
            var second = Guid.NewGuid();
            await Status(store, time, main, ConnectionState.Connected, 0);
            await Status(store, time, main, ConnectionState.PasswordRequired, 5, SignInTunnel(first, "Офис"));
            await Status(store, time, main, ConnectionState.Connected, 10);
            // «Снова подключён» показано — повтор входа в то же подключение снова новость.
            await Status(store, time, main, ConnectionState.PasswordRequired, 15, SignInTunnel(first, "Офис"));
            Assert.Equal(2, shown.Count(t => t == "Требуется вход"));
            // «Снова подключён» теперь подавлено пределом: повтор входа в то же подключение — тоже.
            await Status(store, time, main, ConnectionState.Connected, 18);
            await Status(store, time, main, ConnectionState.PasswordRequired, 19, SignInTunnel(first, "Офис"));
            Assert.Equal(2, shown.Count(t => t == "Требуется вход"));

            await Status(store, time, main, ConnectionState.Connected, 20);
            await Status(store, time, main, ConnectionState.PasswordRequired, 25, SignInTunnel(second, "Склад"));
            Assert.Equal(3, shown.Count(t => t == "Требуется вход"));
        }
    });

    /// <summary>Дополнительный туннель мигает «Подключено» ↔ «Ошибка»: одно уведомление в минуту, а не на каждый переход.</summary>
    [Fact]
    public Task FlappingTunnelError_NotifiesOncePerMinute() => RunStaAsync(async () =>
    {
        var (store, time, service, main, shown) = Setup();
        using (service)
        using (main)
        {
            var id = Guid.NewGuid();
            for (var i = 0; i < 4; i++)
            {
                await Status(store, time, main, ConnectionState.Connected, i * 10, Tunnel(id, ConnectionState.Connected));
                await Status(store, time, main, ConnectionState.Connected, i * 10 + 5, Tunnel(id, ConnectionState.Error));
            }

            Assert.Single(shown, t => t == "Прервалось подключение «Склад»");
        }
    });

    /// <summary>Служба падает по кругу: «Служба недоступна» один раз в минуту, а не на каждом круге.</summary>
    [Fact]
    public Task ServiceCrashingInLoop_NotifiesOncePerMinute() => RunStaAsync(async () =>
    {
        var (store, time, service, main, shown) = Setup();
        using (service)
        using (main)
        {
            for (var i = 0; i < 3; i++)
            {
                store.Unavailable = false;
                await Status(store, time, main, ConnectionState.Connected, i * 10);
                store.Unavailable = true;
                time.Now = DateTimeOffset.UnixEpoch.AddHours(1).AddSeconds(i * 10 + 5);
                await main.RefreshAsync();
            }

            Assert.Single(shown, t => t == "Служба недоступна");
        }
    });

    // ---------- Замечания службы при сохранении ----------

    /// <summary>
    /// Служба другой версии ответила «сохранено» с неразбираемыми замечаниями: это «версии не совпадают», а не
    /// «файл повреждён» и не ложное «данные входа не сохранены» с перечитыванием формы.
    /// </summary>
    [Fact]
    public Task UnreadableSaveWarnings_AreVersionMismatch_NotFailedCredentials() => RunStaAsync(async () =>
    {
        var store = new FakeService { Settings = new AppSettings { Profiles = [Work], DefaultTarget = RouteTarget.Tunnel(Work.Id) }, OddSaveResult = true };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();
        page.Password = "new-password";
        var reads = store.SettingsReads;

        await page.SaveCommand.ExecuteAsync(null);

        Assert.True(page.MessageIsError);
        Assert.DoesNotContain(ConnectionsViewModel.SettingsSavedCredentialsNot, page.Message, StringComparison.Ordinal);
        // Ревью 27.11: честно — сохранено, не распознан только ответ; список перечитан, как после обычного сохранения.
        Assert.StartsWith(ConnectionsViewModel.SavedReplyUnreadable, page.Message, StringComparison.Ordinal);
        Assert.Contains("версии приложения и службы не совпадают", page.Message, StringComparison.Ordinal);
        Assert.Equal(ServiceUnavailableReason.VersionMismatch, service.LastReason);
        // Свежие настройки перед сохранением и перечитывание списка после него.
        Assert.Equal(reads + 2, store.SettingsReads);
        // Пароль ушёл и принят: черновик в форме больше не держится.
        Assert.Empty(page.Password);
    });

    // ---------- Нестрогая запись IPv4 у шлюза AnyConnect ----------

    [Theory]
    [InlineData("010.0.0.1")]
    [InlineData("10.1")]
    public void LooseIpv4Gateway_ExplainsStrictForm(string server)
    {
        Assert.False(VpnProtocols.TryParseServer(server, VpnProtocol.AnyConnect, out _));
        var text = UiText.ServerFieldError(VpnProtocol.AnyConnect, server);
        Assert.Contains("нестрогой", text, StringComparison.Ordinal);
        Assert.Contains("10.0.0.1", text, StringComparison.Ordinal);
        // Обычная ошибка адреса и другие протоколы — прежний текст.
        Assert.DoesNotContain("нестрогой", UiText.ServerFieldError(VpnProtocol.AnyConnect, "https://"), StringComparison.Ordinal);
        Assert.DoesNotContain("нестрогой", UiText.ServerFieldError(VpnProtocol.Sstp, server), StringComparison.Ordinal);
    }

    [Fact]
    public Task LooseIpv4Gateway_InConnectionsForm_IsExplained() => RunStaAsync(async () =>
    {
        var gateway = new ConnectionProfile
        {
            Name = "Шлюз", Server = "010.0.0.1", UserName = "user", Protocol = VpnProtocol.AnyConnect, AuthMethod = AuthMethod.GatewayForm, Role = ProfileRole.Primary,
        };
        var store = new FakeService { Settings = new AppSettings { Profiles = [gateway], DefaultTarget = RouteTarget.Tunnel(gateway.Id) } };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Connections;
        await page.LoadAsync();
        page.Selected = page.Profiles.Single();

        await page.SaveCommand.ExecuteAsync(null);

        Assert.True(page.MessageIsError);
        Assert.Contains("нестрогой", page.Message, StringComparison.Ordinal);
        Assert.Contains("10.0.0.1", page.Message, StringComparison.Ordinal);
    });

    [Fact]
    public Task UnreadableRoutingSaveWarnings_AreVersionMismatch() => RunStaAsync(async () =>
    {
        var store = new FakeService { Settings = new AppSettings { Profiles = [Work], DefaultTarget = RouteTarget.Tunnel(Work.Id) }, OddSaveResult = true };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Routing;
        await page.OnOpenedAsync();
        page.MarkDirty();

        await page.SaveCommand.ExecuteAsync(null);

        Assert.True(page.MessageIsError);
        Assert.Contains("версии приложения и службы не совпадают", page.Message, StringComparison.Ordinal);
    });

    // ---------- Ключ SSH ----------

    [Fact]
    public async Task FailedSshKeyChoice_DoesNotMarkConnectionDirty()
    {
        var item = ProfileItem.From(new ConnectionProfile { Name = "SSH", Server = "ssh.example", UserName = "user", Protocol = VpnProtocol.SshVpn });
        Assert.False(item.IsDirty);

        await item.Security.LoadSshKeyFileAsync(Path.Combine(Path.GetTempPath(), "splitvpn-missing-" + Guid.NewGuid().ToString("N")));

        Assert.Contains("не", item.Security.SshKeyStatus, StringComparison.Ordinal);
        Assert.False(item.IsDirty);
        Assert.Equal(0, item.Edits);
    }

    // ---------- Служба не установлена ----------

    [Fact]
    public Task NotInstalledService_HidesStartAndAdvisesReinstall() => RunStaAsync(async () =>
    {
        var store = new FakeService { Unavailable = true };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        main.ServiceHost.Show(ServiceHostState.Stopped, "1.0.0");
        await main.RefreshAsync();
        Assert.True(main.Diagnostics.CanStartService);
        Assert.Contains("Запустить службу", main.ServiceError, StringComparison.Ordinal);

        // Диспетчер служб сообщил «не установлена» после неудачного опроса: баннер и кнопка следуют за ним.
        var raised = new List<string?>();
        main.Diagnostics.PropertyChanged += (_, e) => raised.Add(e.PropertyName);
        main.ServiceHost.Show(ServiceHostState.NotInstalled, "");

        Assert.False(main.Diagnostics.CanStartService);
        Assert.Contains(nameof(DiagnosticsViewModel.CanStartService), raised);
        Assert.Equal("Служба не установлена", main.ServiceErrorTitle);
        Assert.Contains("Переустановите программу", main.ServiceError, StringComparison.Ordinal);
        Assert.DoesNotContain("Запустить службу", main.ServiceError, StringComparison.Ordinal);

        await main.RefreshAsync();
        Assert.Equal("Служба не установлена", main.ServiceErrorTitle);
    });

    // ---------- Отказ оболочки ----------

    [Fact]
    public Task ShellFailure_IsShownOnPage() => RunStaAsync(async () =>
    {
        var store = new FakeService();
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var diagnostics = main.Diagnostics;
        var folder = Path.Combine(Path.GetTempPath(), "splitvpn-logs-" + Guid.NewGuid().ToString("N"));
        var started = new List<ProcessStartInfo>();
        diagnostics.StartShell = started.Add;
        diagnostics.LogsFolder = folder;

        // Папки ещё нет: проводник не запускается, на странице — что журналов пока нет.
        diagnostics.OpenLogsCommand.Execute(null);
        Assert.Empty(started);
        Assert.False(diagnostics.MessageIsError);
        Assert.Contains("пока нет", diagnostics.Message, StringComparison.Ordinal);

        Directory.CreateDirectory(folder);
        try
        {
            diagnostics.OpenLogsCommand.Execute(null);
            Assert.Single(started);

            // Оболочка отказала: сообщение на странице, а не исключение в общий обработчик.
            diagnostics.StartShell = _ => throw new Win32Exception(1155);
            diagnostics.OpenLogsCommand.Execute(null);
            Assert.True(diagnostics.MessageIsError);
            Assert.Contains(folder, diagnostics.Message, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(folder);
        }

        await Task.CompletedTask;
    });

    // ---------- Вспомогательное ----------

    private static (FakeService Store, ManualTime Time, ServiceConnection Service, MainViewModel Main, List<string> Shown) Setup()
    {
        var store = new FakeService();
        var time = new ManualTime();
        var service = new ServiceConnection(store.SendAsync);
        var main = new MainViewModel(service, new UiPreferences(), time);
        var shown = new List<string>();
        main.Notify += n => shown.Add(n.Title);
        return (store, time, service, main, shown);
    }

    private static async Task Status(FakeService store, ManualTime time, MainViewModel main, ConnectionState state, int seconds, params TunnelStatusDto[] tunnels)
    {
        store.Status = new StatusDto { State = state, Intent = Intent.Connected, ProfileName = "Основное", Tunnels = tunnels };
        time.Now = DateTimeOffset.UnixEpoch.AddHours(1).AddSeconds(seconds);
        await main.RefreshAsync();
    }

    private static TunnelStatusDto SignInTunnel(Guid id, string name) => new()
    {
        ProfileId = id,
        Name = name,
        State = ConnectionState.PasswordRequired,
        SignIn = new SignInPromptDto { RequestId = Guid.NewGuid(), GatewayHost = "gateway.example" },
    };

    private static TunnelStatusDto Tunnel(Guid id, ConnectionState state) => new() { ProfileId = id, Name = "Склад", State = state };

    private sealed class ManualTime : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UnixEpoch;

        public override DateTimeOffset GetUtcNow() => Now;
    }

    /// <summary>Подставная служба: настройки и состояние в памяти; OddSaveResult — ответ на сохранение другой версии.</summary>
    private sealed class FakeService
    {
        public AppSettings Settings { get; set; } = new();

        public StatusDto Status { get; set; } = new() { Intent = Intent.Off };

        public bool Unavailable { get; set; }

        public bool OddSaveResult { get; set; }

        public int SettingsReads { get; private set; }

        public Task<IpcResponse> SendAsync(IpcRequest request, CancellationToken cancellationToken)
        {
            if (Unavailable)
            {
                throw new ServiceUnavailableException("Служба не запущена.");
            }

            if (request is GetSettingsRequest)
            {
                SettingsReads++;
            }

            return Task.FromResult(request switch
            {
                GetSettingsRequest => IpcResponse.Success(Settings),
                GetAdaptersRequest => IpcResponse.Success(new List<AdapterDto>()),
                GetStatusRequest => IpcResponse.Success(Status),
                GetEventsRequest => IpcResponse.Success(new List<ServiceEvent>()),
                SaveSettingsRequest save => Saved(save.Settings),
                SaveConnectionRequest save => Saved(save.Settings),
                _ => IpcResponse.Success(),
            });
        }

        private IpcResponse Saved(AppSettings settings)
        {
            Settings = settings;
            // Замечания служба присылает списком строк; служба другой версии — объектом, который не разбирается.
            return OddSaveResult ? IpcResponse.Success(new { warnings = 1 }) : IpcResponse.Success(new List<string>());
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
