using System.IO;
using System.Text.Json;
using System.Windows.Threading;
using SplitVpn.App.Services;
using SplitVpn.App.ViewModels;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;

namespace SplitVpn.App.Tests;

/// <summary>
/// Отключение во время ожидания дозвона, неразбираемый ответ службы, сбой команды до отправки и запись настроек
/// интерфейса вне потока окна.
/// </summary>
public sealed class CommandDialWaitTests
{
    private const string DialText = "Дождитесь завершения дозвона перед сменой роли подключения.";

    private static StatusDto Connecting => new() { State = ConnectionState.Connecting, Intent = Intent.Connected, ProfileName = "Работа" };

    /// <summary>Прекращение ожидания: следующий повтор не отправляется, возвращается отказ «идёт дозвон».</summary>
    [Fact]
    public async Task StopWaitingForDial_EndsRetriesWithLastRefusal()
    {
        var attempts = 0;
        Task<IpcResponse> Send(IpcRequest request, CancellationToken token)
        {
            attempts++;
            return Task.FromResult(IpcResponse.Failure(IpcErrorCodes.DialInProgress, DialText));
        }

        using var service = new ServiceConnection(Send) { DialRetryDelay = TimeSpan.FromMinutes(5) };
        using var stop = new CancellationTokenSource();
        var waits = new List<bool>();
        service.WaitingForDial += waits.Add;
        var own = new List<bool>();

        var pending = service.SendAsync(new SetProfileRoleRequest(Guid.NewGuid(), ProfileRole.Primary), w =>
        {
            own.Add(w);
            if (w)
            {
                stop.Cancel();
            }
        }, stop.Token, TestContext.Current.CancellationToken);
        var response = await pending.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);

        Assert.Equal(IpcErrorCodes.DialInProgress, response.ErrorCode);
        Assert.Equal(1, attempts);
        Assert.Equal(new[] { true, false }, waits);
        Assert.Equal(new[] { true, false }, own);
    }

    /// <summary>
    /// Смена роли из трея ждёт конца дозвона: «Отключить» доступна, прекращает ожидание и сразу уходит службе.
    /// Отложенная команда больше не повторяется, а пользователь видит, что изменение не сохранено.
    /// </summary>
    [Fact]
    public Task Disconnect_DuringDialWait_CancelsWaitAndRunsAtOnce() => RunStaAsync(async () =>
    {
        var sent = new List<IpcRequest>();
        Task<IpcResponse> Send(IpcRequest request, CancellationToken token)
        {
            sent.Add(request);
            return Task.FromResult(request switch
            {
                SetProfileRoleRequest => IpcResponse.Failure(IpcErrorCodes.DialInProgress, DialText),
                GetStatusRequest => IpcResponse.Success(Connecting),
                DisconnectRequest => IpcResponse.Success(),
                _ => IpcResponse.Failure(IpcErrorCodes.Failed, "нет в тесте"),
            });
        }

        using var service = new ServiceConnection(Send) { DialRetryDelay = TimeSpan.FromMinutes(5) };
        using var main = new MainViewModel(service, new UiPreferences());
        await main.RefreshAsync();
        Assert.True(main.ServiceAvailable);

        var role = main.SetProfileRoleAsync(Guid.NewGuid(), ProfileRole.Primary);
        await WaitUntilAsync(() => main.CommandWaitingForDial);

        Assert.True(main.IsBusy);
        Assert.True(main.CanDisconnect);
        Assert.True(main.DisconnectCommand.CanExecute(null));
        Assert.True(main.DisconnectAndRestoreCommand.CanExecute(null));
        Assert.True(main.ToggleConnectionCommand.CanExecute(null));
        Assert.False(main.ConnectCommand.CanExecute(null));

        await main.DisconnectCommand.ExecuteAsync(null).WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        await role.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);

        Assert.Single(sent.OfType<SetProfileRoleRequest>());
        Assert.Equal(new DisconnectRequest(KeepProtection: true), Assert.Single(sent.OfType<DisconnectRequest>()));
        Assert.False(main.IsBusy);
        Assert.False(main.CommandWaitingForDial);
        Assert.Equal(MainViewModel.DialWaitCancelledText, main.Home.Message);
    });

    /// <summary>Пока идущая команда не ждёт дозвона, отключение по-прежнему не начинается — гонки команд нет.</summary>
    [Fact]
    public Task Disconnect_WhileOtherCommandRuns_IsRefused() => RunStaAsync(async () =>
    {
        var release = new TaskCompletionSource<IpcResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        var sent = new List<IpcRequest>();
        Task<IpcResponse> Send(IpcRequest request, CancellationToken token)
        {
            sent.Add(request);
            return request switch
            {
                ConnectRequest => release.Task,
                GetStatusRequest => Task.FromResult(IpcResponse.Success(Connecting)),
                _ => Task.FromResult(IpcResponse.Failure(IpcErrorCodes.Failed, "нет в тесте")),
            };
        }

        using var service = new ServiceConnection(Send);
        using var main = new MainViewModel(service, new UiPreferences());
        await main.RefreshAsync();

        var connect = main.RunCommandAsync(new ConnectRequest(null, null));
        Assert.False(main.DisconnectCommand.CanExecute(null));
        Assert.False(await main.RunCommandAsync(new DisconnectRequest(KeepProtection: true)));
        Assert.Empty(sent.OfType<DisconnectRequest>());

        release.SetResult(IpcResponse.Success());
        Assert.True(await connect);
    });

    /// <summary>Неразбираемый результат опроса — несовместимая служба: окно показывает это, а не устаревшее состояние.</summary>
    [Fact]
    public Task UnparsableStatus_ShowsVersionMismatch() => RunStaAsync(async () =>
    {
        var garbage = new IpcResponse(true, null, null, JsonSerializer.SerializeToElement("не статус"));
        var good = true;
        using var service = new ServiceConnection((request, _) => Task.FromResult(request is GetStatusRequest
            ? good ? IpcResponse.Success(Connecting) : garbage
            : IpcResponse.Failure(IpcErrorCodes.Failed, "нет в тесте")));
        using var main = new MainViewModel(service, new UiPreferences());
        await main.RefreshAsync();
        Assert.True(main.ServiceAvailable);

        good = false;
        await main.RefreshAsync();

        Assert.False(main.ServiceAvailable);
        Assert.Equal(ServiceUnavailableReason.VersionMismatch, main.UnavailableReason);
        Assert.False(service.IsAvailable);
        Assert.Equal(ServiceUnavailableReason.VersionMismatch, service.LastReason);
        var ex = await Assert.ThrowsAsync<ServiceUnavailableException>(() => service.RequestAsync<StatusDto>(new GetStatusRequest(), TestContext.Current.CancellationToken));
        Assert.Equal(ServiceUnavailableReason.VersionMismatch, ex.Reason);
    });

    /// <summary>Ответ команды не разобран: ошибка видна на странице, занятость снята, статус перечитан.</summary>
    [Fact]
    public Task UnparsableCommandResult_ShowsErrorAndRefreshes() => RunStaAsync(async () =>
    {
        var polls = 0;
        Task<IpcResponse> Send(IpcRequest request, CancellationToken token)
        {
            if (request is GetStatusRequest)
            {
                polls++;
                return Task.FromResult(IpcResponse.Success(Connecting));
            }

            return Task.FromResult(request is ConnectRequest
                ? new IpcResponse(true, null, null, JsonSerializer.SerializeToElement(42))
                : IpcResponse.Failure(IpcErrorCodes.Failed, "нет в тесте"));
        }

        using var service = new ServiceConnection(Send);
        using var main = new MainViewModel(service, new UiPreferences());

        await main.RunCommandAsync(new ConnectRequest(null, null));

        Assert.False(main.IsBusy);
        Assert.True(main.Home.MessageIsError);
        Assert.Contains("не распознан", main.Home.Message, StringComparison.Ordinal);
        Assert.Equal(1, polls);
    });

    /// <summary>Команда не отправлена (слишком большой запрос): ошибка команды, а не необработанное исключение.</summary>
    [Fact]
    public Task CommandNotSent_ShowsErrorAndRefreshes() => RunStaAsync(async () =>
    {
        var polls = 0;
        Task<IpcResponse> Send(IpcRequest request, CancellationToken token)
        {
            if (request is SetProfileRoleRequest)
            {
                throw new ServiceCommandException("Запрос слишком большой для передачи службе.");
            }

            if (request is GetStatusRequest)
            {
                polls++;
                return Task.FromResult(IpcResponse.Success(Connecting));
            }

            return Task.FromResult(IpcResponse.Failure(IpcErrorCodes.Failed, "нет в тесте"));
        }

        using var service = new ServiceConnection(Send);
        using var main = new MainViewModel(service, new UiPreferences());

        await main.SetProfileRoleAsync(Guid.NewGuid(), ProfileRole.Primary);

        Assert.False(main.IsBusy);
        Assert.Contains("слишком большой", main.Home.Message, StringComparison.Ordinal);
        Assert.Equal(1, polls);
    });

    /// <summary>
    /// Запись настроек интерфейса идёт вне потока окна: изменение видно сразу, быстрые повторы записываются по
    /// порядку, и последнее записанное — последнее выбранное.
    /// </summary>
    [Fact]
    public Task PreferencesWrite_RunsOffUiThread_InOrder() => RunStaAsync(async () =>
    {
        using var service = new ServiceConnection((_, _) => Task.FromResult(IpcResponse.Failure(IpcErrorCodes.Failed, "нет в тесте")));
        using var main = new MainViewModel(service, new UiPreferences());
        var ui = Environment.CurrentManagedThreadId;
        var gate = new ManualResetEventSlim();
        var writes = new List<(UiPreferences Desired, UiPreferences Baseline, int Thread)>();
        var themes = new List<ThemeChoice>();
        main.ApplyTheme = themes.Add;
        main.WritePreferences = (desired, baseline) =>
        {
            gate.Wait(TimeSpan.FromSeconds(10));
            lock (writes) { writes.Add((desired, baseline, Environment.CurrentManagedThreadId)); }
            return desired;
        };

        main.SavePreferences(main.Preferences with { Theme = ThemeChoice.Dark });
        Assert.Equal(ThemeChoice.Dark, main.Preferences.Theme);
        main.SavePreferences(main.Preferences with { Notifications = false });
        main.SavePreferences(main.Preferences with { Theme = ThemeChoice.Light });
        Assert.Equal(ThemeChoice.Light, main.Preferences.Theme);
        gate.Set();
        await main.PreferencesWritten.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);

        Assert.Equal(2, writes.Count);
        Assert.All(writes, w => Assert.NotEqual(ui, w.Thread));
        Assert.Equal(ThemeChoice.Dark, writes[0].Desired.Theme);
        Assert.Equal(ThemeChoice.System, writes[0].Baseline.Theme);
        Assert.Equal(new UiPreferences { Theme = ThemeChoice.Light, Notifications = false }, writes[1].Desired);
        Assert.Equal(writes[0].Desired, writes[1].Baseline);
        Assert.Equal(writes[1].Desired, main.Preferences);
        Assert.Equal(ThemeChoice.Light, themes[^1]);
    });

    /// <summary>
    /// Настройки интерфейса прежней версии с полем отказа от мастера первого запуска читаются без ошибки: устаревшее
    /// поле пропускается, остальные настройки пользователя сохраняются, а при записи оно уже не пишется.
    /// </summary>
    [Fact]
    public void OldPreferencesWithObsoleteFieldStillLoad()
    {
        const string old = """{ "theme": "Dark", "notifications": false, "showAdvanced": true, "wizardDismissed": true, "trayHintShown": true }""";

        var loaded = JsonSerializer.Deserialize<UiPreferences>(old, JsonDefaults.Options)!;

        Assert.Equal(new UiPreferences { Theme = ThemeChoice.Dark, Notifications = false, ShowAdvanced = true, TrayHintShown = true }, loaded);
        Assert.DoesNotContain("wizard", JsonSerializer.Serialize(loaded, JsonDefaults.Options), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Файл настроек интерфейса занят: показывается ошибка, и действует последнее записанное.</summary>
    [Fact]
    public Task PreferencesWriteFailure_RevertsAndShowsError() => RunStaAsync(async () =>
    {
        using var service = new ServiceConnection((_, _) => Task.FromResult(IpcResponse.Failure(IpcErrorCodes.Failed, "нет в тесте")));
        var initial = new UiPreferences();
        using var main = new MainViewModel(service, initial);
        main.ApplyTheme = _ => { };
        main.WritePreferences = (_, _) => throw new IOException("занят");

        main.SavePreferences(main.Preferences with { Theme = ThemeChoice.Dark });
        await main.PreferencesWritten.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);

        Assert.Equal(initial, main.Preferences);
        Assert.True(main.CurrentPage.MessageIsError);
        Assert.Contains("настройки интерфейса", main.CurrentPage.Message, StringComparison.Ordinal);
    });

    /// <summary>
    /// Выход ждёт идущую запись настроек в потоке окна без взаимоблокировки (продолжение записи возвращается в этот
    /// поток), а зависшую — не дольше предела.
    /// </summary>
    [Fact]
    public Task PreferencesWait_OnUiThread_CompletesOrTimesOut() => RunStaAsync(async () =>
    {
        using var service = new ServiceConnection((_, _) => Task.FromResult(IpcResponse.Failure(IpcErrorCodes.Failed, "нет в тесте")));
        using var main = new MainViewModel(service, new UiPreferences());
        main.ApplyTheme = _ => { };
        Assert.True(await main.WaitPreferencesWrittenAsync(TimeSpan.Zero));

        var gate = new ManualResetEventSlim();
        main.WritePreferences = (desired, _) => { gate.Wait(TimeSpan.FromSeconds(10)); return desired; };
        main.SavePreferences(main.Preferences with { Theme = ThemeChoice.Dark });
        Assert.False(await main.WaitPreferencesWrittenAsync(TimeSpan.FromMilliseconds(50)));

        gate.Set();
        Assert.True(await main.WaitPreferencesWrittenAsync(TimeSpan.FromSeconds(10)));
        Assert.True(main.PreferencesWritten.IsCompleted);
    });

    /// <summary>
    /// Пока идёт запись, другая копия приложения меняет на диске уведомления, а здесь переключают ещё одну настройку:
    /// повторная запись несёт только правки этой копии, и правка другой не затирается ни на диске, ни в окне.
    /// </summary>
    [Fact]
    public Task PreferencesRewrite_KeepsOtherCopyChange() => RunStaAsync(async () =>
    {
        using var service = new ServiceConnection((_, _) => Task.FromResult(IpcResponse.Failure(IpcErrorCodes.Failed, "нет в тесте")));
        var initial = new UiPreferences();
        using var main = new MainViewModel(service, initial);
        main.ApplyTheme = _ => { };
        var gate = new ManualResetEventSlim();
        var sync = new object();
        var disk = initial;
        main.WritePreferences = (desired, baseline) =>
        {
            gate.Wait(TimeSpan.FromSeconds(10));
            lock (sync) { return disk = desired.ChangesOnto(baseline, disk); }
        };

        main.SavePreferences(main.Preferences with { Theme = ThemeChoice.Dark });
        lock (sync) { disk = disk with { Notifications = false }; }
        main.SavePreferences(main.Preferences with { ShowAdvanced = true });
        gate.Set();
        await main.PreferencesWritten.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);

        var expected = initial with { Theme = ThemeChoice.Dark, Notifications = false, ShowAdvanced = true };
        lock (sync) { Assert.Equal(expected, disk); }
        Assert.Equal(expected, main.Preferences);
    });

    /// <summary>
    /// Неожиданный сбой записи настроек (не занятость файла) — в журнал ошибок, ошибка видна, действует последнее
    /// записанное; следующая запись выполняется.
    /// </summary>
    [Fact]
    public Task PreferencesUnexpectedFailure_RecordsRevertsAndKeepsWriting() => RunStaAsync(async () =>
    {
        using var service = new ServiceConnection((_, _) => Task.FromResult(IpcResponse.Failure(IpcErrorCodes.Failed, "нет в тесте")));
        var initial = new UiPreferences();
        using var main = new MainViewModel(service, initial);
        main.ApplyTheme = _ => { };
        var recorded = new List<Exception>();
        main.RecordError = recorded.Add;
        main.WritePreferences = (_, _) => throw new InvalidOperationException("сбой");

        main.SavePreferences(main.Preferences with { Theme = ThemeChoice.Dark });
        await main.PreferencesWritten.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);

        Assert.Equal(initial, main.Preferences);
        Assert.True(main.CurrentPage.MessageIsError);
        Assert.Contains("настройки интерфейса", main.CurrentPage.Message, StringComparison.Ordinal);
        Assert.IsType<InvalidOperationException>(Assert.Single(recorded));

        UiPreferences? written = null;
        main.WritePreferences = (desired, _) => written = desired;
        main.SavePreferences(main.Preferences with { Notifications = false });
        await main.PreferencesWritten.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);

        Assert.Equal(initial with { Notifications = false }, written);
        Assert.Equal(written, main.Preferences);
    });

    /// <summary>
    /// Выход из Windows ждёт идущую запись настроек на диск блокирующе в потоке окна: самой записи этот поток не нужен,
    /// взаимоблокировки нет. Зависшую запись — не дольше предела.
    /// </summary>
    [Fact]
    public Task PreferencesDiskWait_BlocksUiThreadWithoutDeadlock() => RunStaAsync(async () =>
    {
        using var service = new ServiceConnection((_, _) => Task.FromResult(IpcResponse.Failure(IpcErrorCodes.Failed, "нет в тесте")));
        using var main = new MainViewModel(service, new UiPreferences());
        main.ApplyTheme = _ => { };
        Assert.True(main.WaitPreferencesDiskWrite(TimeSpan.Zero));

        var gate = new ManualResetEventSlim();
        main.WritePreferences = (desired, _) => { gate.Wait(TimeSpan.FromSeconds(10)); return desired; };
        main.SavePreferences(main.Preferences with { Theme = ThemeChoice.Dark });
        Assert.False(main.WaitPreferencesDiskWrite(TimeSpan.FromMilliseconds(50)));

        _ = Task.Run(async () => { await Task.Delay(50); gate.Set(); }, TestContext.Current.CancellationToken);
        Assert.True(main.WaitPreferencesDiskWrite(TimeSpan.FromSeconds(10)));
        await main.PreferencesWritten.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
    });

    /// <summary>
    /// Пока команда ждёт дозвона, другая копия отключила VPN: главная команда «Отключить» становится недоступной, и
    /// об этом сообщается. Опрос с тем же намерением лишних уведомлений не даёт.
    /// </summary>
    [Fact]
    public Task StatusIntentChange_DuringDialWait_NotifiesToggleCommand() => RunStaAsync(async () =>
    {
        var status = Connecting;
        Task<IpcResponse> Send(IpcRequest request, CancellationToken token) => Task.FromResult(request switch
        {
            SetProfileRoleRequest => IpcResponse.Failure(IpcErrorCodes.DialInProgress, DialText),
            GetStatusRequest => IpcResponse.Success(status),
            DisconnectRequest => IpcResponse.Success(),
            _ => IpcResponse.Failure(IpcErrorCodes.Failed, "нет в тесте"),
        });

        using var service = new ServiceConnection(Send) { DialRetryDelay = TimeSpan.FromMinutes(5) };
        using var main = new MainViewModel(service, new UiPreferences());
        await main.RefreshAsync();
        var role = main.SetProfileRoleAsync(Guid.NewGuid(), ProfileRole.Primary);
        await WaitUntilAsync(() => main.CommandWaitingForDial);
        Assert.True(main.ToggleConnectionCommand.CanExecute(null));

        var changes = 0;
        main.ToggleConnectionCommand.CanExecuteChanged += (_, _) => changes++;
        await main.RefreshAsync();
        Assert.Equal(0, changes);

        status = Connecting with { State = ConnectionState.Disconnected, Intent = Intent.Protected };
        await main.RefreshAsync();
        Assert.Equal(1, changes);
        Assert.False(main.ToggleConnectionCommand.CanExecute(null));

        await main.DisconnectCommand.ExecuteAsync(null).WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        await role.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
    });

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, "условие не выполнилось за 10 с");
            await Task.Delay(10, TestContext.Current.CancellationToken);
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
        return completion.Task.WaitAsync(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken);
    }
}
