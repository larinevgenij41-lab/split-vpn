using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Native;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.Operations;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Ревью 2026-11-16: сеанс, умерший до присоединения, идёт по паузе повторов, а живой при временном сбое снимка сети
/// присоединяется повтором без паузы; ожидание сервера включает обрыв без завершения сеанса, но не отключение пользователем; нечитаемые
/// ключ IPsec и пароль не держат очередь подъёма и не отключают автоподключение.
/// </summary>
public sealed partial class CoordinatorTests
{
    /// <summary>
    /// Дозвон прошёл, но сеанс умер, пока результат ждал очереди: остаток разрывается, попытка считается неудачной,
    /// и следующий дозвон ждёт паузы, а не идёт на ближайшем тике с «попыткой 1».
    /// </summary>
    [Fact]
    public async Task DialSucceeded_SessionDeadBeforeAttach_HangsUpAndBacksOff()
    {
        var ras = new DeadSessionRas(_world.Ras) { ProjectionFailures = 1 };
        var coordinator = await StartWithAsync(d => d with { Ras = ras });
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];

        Assert.Equal(1, _world.Ras.Dials);
        Assert.Null(tunnel.Connection);
        Assert.True(_world.Ras.HangUps > 0, Dump(coordinator));
        Assert.False(_world.Ras.Connected);
        Assert.Equal(1, tunnel.DialAttempt);
        Assert.Equal(ErrorCategory.Other, tunnel.LastErrorCategory);
        Assert.Equal(ErrorCategory.None, tunnel.BlockingError);
        Assert.True(tunnel.NextDialAt > _world.Time.GetUtcNow());

        // До срока паузы новых дозвонов нет.
        await TickAsync(coordinator);
        Assert.Equal(1, _world.Ras.Dials);

        _world.Time.Advance(tunnel.NextDialAt - _world.Time.GetUtcNow() + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);

        Assert.Equal(2, _world.Ras.Dials);
        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("попытка 2", StringComparison.Ordinal));
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    /// <summary>Соединение, умершее между перечислением и подхватом при запуске, не срывает сверку: его остаток отпускается, туннель дозванивается.</summary>
    [Fact]
    public async Task Startup_AdoptedConnectionDeadBeforeAttach_IsReleasedAndRedialed()
    {
        new ServiceStores(_world.Paths).SaveState(new ServiceStateFile { Intent = Intent.Connected });
        _world.Ras.SaveEntry(Coordinator.EntryNameFor(_profile), _profile, []);
        await _world.Ras.DialAsync(Coordinator.EntryNameFor(_profile), "user", "secret".AsMemory(), null, CancellationToken.None);
        var dials = _world.Ras.Dials;
        var ras = new DeadSessionRas(_world.Ras) { ProjectionFailures = 1 };

        var coordinator = await StartWithAsync(d => d with { Ras = ras });
        await TickAsync(coordinator);

        Assert.True(_world.Ras.HangUps > 0, Dump(coordinator));
        Assert.Equal(dials + 1, _world.Ras.Dials);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    /// <summary>
    /// Дозвон прошёл, сеанс жив, но снимок сети при присоединении временно не читается: присоединение повторяется
    /// сразу и проходит. Сеанс не разрывается, попытка не наказывается паузой, нового дозвона нет.
    /// </summary>
    [Fact]
    public async Task DialSucceeded_TransientInventoryFailureOnAttach_RetriesAndKeepsSession()
    {
        var ras = new DeadSessionRas(_world.Ras);
        var inventory = new FlakyInventory(_world.Inventory);
        var coordinator = await StartWithAsync(d => d with { Ras = ras, Inventory = inventory });
        // Снимок сразу после запроса сведений о сеансе не читается у всех попыток, кроме последней.
        ras.OnProjection = () =>
        {
            ras.OnProjection = null;
            inventory.Failures = Coordinator.AttachAttempts - 1;
        };

        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];

        Assert.Equal(1, _world.Ras.Dials);
        Assert.Equal(0, _world.Ras.HangUps);
        Assert.True(_world.Ras.Connected);
        Assert.NotNull(tunnel.Connection);
        Assert.Equal(0, tunnel.DialAttempt);
        Assert.DoesNotContain(_world.Journal.Since(0), e => e.Text.Contains("разорвано сразу после подключения", StringComparison.Ordinal));
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    /// <summary>
    /// Дозвон прошёл, но присоединение не удаётся ни с одной попытки: сеанс разрывается, попытка считается неудачной
    /// и следующий дозвон ждёт обычной паузы повторов.
    /// </summary>
    [Fact]
    public async Task DialSucceeded_PersistentAttachFailure_HangsUpAndBacksOff()
    {
        var ras = new DeadSessionRas(_world.Ras);
        var inventory = new FlakyInventory(_world.Inventory);
        var coordinator = await StartWithAsync(d => d with { Ras = ras, Inventory = inventory });
        ras.OnProjection = () =>
        {
            ras.OnProjection = null;
            inventory.Failures = Coordinator.AttachAttempts;
        };

        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];

        Assert.Equal(1, _world.Ras.Dials);
        Assert.Null(tunnel.Connection);
        Assert.True(_world.Ras.HangUps > 0, Dump(coordinator));
        Assert.False(_world.Ras.Connected);
        Assert.Equal(1, tunnel.DialAttempt);
        Assert.True(tunnel.NextDialAt > _world.Time.GetUtcNow());
        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("разорвано сразу после подключения", StringComparison.Ordinal));

        await TickAsync(coordinator);
        Assert.Equal(1, _world.Ras.Dials);

        _world.Time.Advance(tunnel.NextDialAt - _world.Time.GetUtcNow() + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);

        Assert.Equal(2, _world.Ras.Dials);
        Assert.NotNull(tunnel.Connection);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    /// <summary>
    /// Соединение пережило перезапуск службы, а снимок сети при подхвате временно не читается: подхват повторяется
    /// сразу, сеанс подхватывается без разрыва и без нового дозвона.
    /// </summary>
    [Fact]
    public async Task Startup_AdoptTransientInventoryFailure_AdoptsWithoutRedial()
    {
        new ServiceStores(_world.Paths).SaveState(new ServiceStateFile { Intent = Intent.Connected });
        _world.Ras.SaveEntry(Coordinator.EntryNameFor(_profile), _profile, []);
        await _world.Ras.DialAsync(Coordinator.EntryNameFor(_profile), "user", "secret".AsMemory(), null, CancellationToken.None);
        var dials = _world.Ras.Dials;
        var ras = new DeadSessionRas(_world.Ras);
        var inventory = new FlakyInventory(_world.Inventory);
        ras.OnProjection = () =>
        {
            ras.OnProjection = null;
            inventory.Failures = Coordinator.AttachAttempts - 1;
        };

        var coordinator = await StartWithAsync(d => d with { Ras = ras, Inventory = inventory });
        await TickAsync(coordinator);

        Assert.Equal(0, _world.Ras.HangUps);
        Assert.Equal(dials, _world.Ras.Dials);
        Assert.NotNull(coordinator.Facts.Tunnels[_profile.Id].Connection);
        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("Подхвачено существующее соединение", StringComparison.Ordinal));
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    /// <summary>
    /// Соединение пережило перезапуск службы, но подхват не удаётся ни с одной попытки: сеанс отпускается, сверка
    /// не срывается, туннель поднимается обычным дозвоном.
    /// </summary>
    [Fact]
    public async Task Startup_AdoptPersistentAttachFailure_ReleasesAndRedials()
    {
        new ServiceStores(_world.Paths).SaveState(new ServiceStateFile { Intent = Intent.Connected });
        _world.Ras.SaveEntry(Coordinator.EntryNameFor(_profile), _profile, []);
        await _world.Ras.DialAsync(Coordinator.EntryNameFor(_profile), "user", "secret".AsMemory(), null, CancellationToken.None);
        var dials = _world.Ras.Dials;
        var ras = new DeadSessionRas(_world.Ras);
        var inventory = new FlakyInventory(_world.Inventory);
        ras.OnProjection = () =>
        {
            ras.OnProjection = null;
            inventory.Failures = Coordinator.AttachAttempts;
        };

        var coordinator = await StartWithAsync(d => d with { Ras = ras, Inventory = inventory });
        await TickAsync(coordinator);

        Assert.True(_world.Ras.HangUps > 0, Dump(coordinator));
        Assert.Equal(dials + 1, _world.Ras.Dials);
        Assert.NotNull(coordinator.Facts.Tunnels[_profile.Id].Connection);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    /// <summary>
    /// Интерфейс PPP пропал (сброс Wi-Fi или драйвера), и служба разорвала сеанс RAS: завершение до сервера не
    /// дошло, он ещё держит прежний сеанс - окно «сервер держит прежний сеанс» открывается.
    /// </summary>
    [Fact]
    public async Task OwnHangUpForMissingAdapter_StartsServerHoldWindow()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        Assert.True(tunnel.Verified);

        _world.Inventory.HideTunnel(0);
        await TickAsync(coordinator);
        // Отсчёт срока начинается со сверки, которая уже не нашла интерфейс.
        _world.Time.Advance(TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);
        _world.Time.Advance(Coordinator.AdapterMissingTimeout);
        await TickAsync(coordinator);

        Assert.True(_world.Ras.HangUps > 0);
        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("интерфейс VPN не найден", StringComparison.Ordinal));
        Assert.NotNull(tunnel.UncleanDropUtc);
    }

    /// <summary>
    /// Код 631 записан нашим же RasHangUp мёртвого соединения, а не пользователем: это обрыв, о котором сервер мог
    /// не узнать, - окно ожидания сервера открывается и при включённом автоподключении.
    /// </summary>
    [Fact]
    public async Task OwnHangUp631WithAutoConnect_StartsServerHoldWindow()
    {
        var stores = new ServiceStores(_world.Paths);
        stores.SaveSettings(stores.LoadSettings(out _) with { AutoConnect = true });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        tunnel.LastOwnHangUpUtc = _world.Time.GetUtcNow();

        _world.TerminationReason = 631;
        _world.TerminationTimeUtc = _world.Time.GetUtcNow().AddSeconds(1);
        _world.Ras.Drop();
        await TickAsync(coordinator);

        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("Обрыв", StringComparison.Ordinal));
        Assert.NotNull(tunnel.UncleanDropUtc);
    }

    /// <summary>Пользователь отключил VPN в Windows при включённом автоподключении: сервер получил завершение, окно ожидания сервера не открывается.</summary>
    [Fact]
    public async Task UserDisconnectWithAutoConnect_DoesNotStartServerHoldWindow()
    {
        var stores = new ServiceStores(_world.Paths);
        stores.SaveSettings(stores.LoadSettings(out _) with { AutoConnect = true });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];

        _world.TerminationReason = 631;
        _world.Ras.Drop();
        await TickAsync(coordinator);

        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("Обрыв", StringComparison.Ordinal));
        Assert.Null(tunnel.UncleanDropUtc);
    }

    /// <summary>
    /// При загрузке Windows сохранённый пароль ещё не расшифровывается (DPAPI не готов): автоподключение всё равно
    /// включается, туннель не просит пароль, а повторяет по паузе и подключается, когда пароль читается.
    /// </summary>
    [Fact]
    public async Task AutoConnect_PasswordStoredButUnreadableAtBoot_ConnectsWhenReadable()
    {
        var stores = new ServiceStores(_world.Paths);
        stores.SaveSettings(stores.LoadSettings(out _) with { AutoConnect = true });
        _world.Uptime = TimeSpan.FromMinutes(1);
        _world.Secrets.Unreadable.Add(_profile.Id);

        var coordinator = await StartAsync();
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];

        Assert.Equal(Intent.Connected, coordinator.State.Intent);
        Assert.Equal(0, _world.Ras.Dials);
        Assert.False(tunnel.PasswordRequired);
        Assert.True(tunnel.DialSettled);
        Assert.Equal(ErrorCategory.None, tunnel.BlockingError);
        Assert.True(tunnel.NextDialAt > _world.Time.GetUtcNow());

        _world.Secrets.Unreadable.Clear();
        _world.Time.Advance(tunnel.NextDialAt - _world.Time.GetUtcNow() + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);

        Assert.Equal(1, _world.Ras.Dials);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    /// <summary>Пароля нет совсем: это по-прежнему «нужен пароль», а не повтор по паузе.</summary>
    [Fact]
    public async Task Connect_PasswordNotStored_StillRequiresPassword()
    {
        _world.Secrets.Delete(_profile.Id);
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        Assert.True(tunnel.PasswordRequired);
        Assert.Equal(0, _world.Ras.Dials);
    }

    /// <summary>
    /// Подъём по очереди: у первого L2TP сохранённый ключ IPsec сейчас не читается. Он повторяет по своей паузе,
    /// а следующие туннели его не ждут.
    /// </summary>
    [Fact]
    public async Task SequentialDial_UnreadablePresharedKey_DoesNotHoldQueue()
    {
        var l2tp = _profile with { Protocol = VpnProtocol.L2tpIpsec, Server = "203.0.113.10", AuthMethod = AuthMethod.EapMsChapV2 };
        var second = SecondProfile();
        SaveSettings(Settings() with { Profiles = [l2tp, second], SequentialDial = true, DefaultTarget = RouteTarget.Tunnel(second.Id) });
        _world.Secrets.Keys[l2tp.Id] = "psk";
        _world.Secrets.Unreadable.Add(l2tp.Id);
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        await TickAsync(coordinator);

        var first = coordinator.Facts.Tunnels[l2tp.Id];
        Assert.True(first.DialSettled);
        Assert.Equal(ErrorCategory.None, first.BlockingError);
        Assert.DoesNotContain(Coordinator.EntryNameFor(l2tp), _world.Ras.DialOrder);
        Assert.Contains(Coordinator.EntryNameFor(second), _world.Ras.DialOrder);
        Assert.True(coordinator.Facts.Tunnels[second.Id].IsUp, Dump(coordinator));
    }
}

/// <summary>
/// Сеанс RAS умирает до того, как служба прочла его сведения: RasGetProjectionInfoEx отвечает ошибкой, и дальше для
/// разорванного соединения тоже.
/// </summary>
internal sealed class DeadSessionRas(FakeRas inner) : IRasOps
{
    /// <summary>Сколько следующих запросов сведений о сеансе закончатся ошибкой.</summary>
    public int ProjectionFailures { get; set; }

    public void SaveEntry(string entryName, ConnectionProfile profile, ReadOnlySpan<char> preSharedKey) => inner.SaveEntry(entryName, profile, preSharedKey);

    public void DeleteEntry(string entryName) => inner.DeleteEntry(entryName);

    public IReadOnlyList<string> EntryNames() => inner.EntryNames();

    public Task<RasDialResult> DialAsync(string entryName, string userName, ReadOnlyMemory<char> password, string? domain, CancellationToken cancellationToken) =>
        inner.DialAsync(entryName, userName, password, domain, cancellationToken);

    public Task HangUpAsync(RasConnectionHandle handle, CancellationToken cancellationToken) => inner.HangUpAsync(handle, cancellationToken);

    public RasConnectionStatus GetStatus(RasConnectionHandle handle) => inner.GetStatus(handle);

    public IReadOnlyList<RasActiveConnection> FindOwnConnections() => inner.FindOwnConnections();

    /// <summary>Вызывается при каждом запросе сведений о сеансе, пока не снят: так тест ломает снимок сети, который читается следом.</summary>
    public Action? OnProjection { get; set; }

    public RasProjection GetProjection(RasConnectionHandle handle)
    {
        OnProjection?.Invoke();
        if (ProjectionFailures > 0)
        {
            ProjectionFailures--;
            // ERROR_INVALID_HANDLE: соединения уже нет - и RAS сообщает о нём «разорвано».
            inner.Drop();
            throw new NativeCallException("RasGetProjectionInfoEx", 6);
        }

        if (inner.GetStatus(handle) == RasConnectionStatus.Gone)
        {
            // Повторный запрос сведений о разорванном соединении тоже не проходит, как у настоящего RAS.
            throw new NativeCallException("RasGetProjectionInfoEx", 6);
        }

        return inner.GetProjection(handle);
    }

    public RasStatistics? GetStatistics(RasConnectionHandle handle) => inner.GetStatistics(handle);
}

/// <summary>Снимок сети временно не читается (GetIfTable2 во время смены интерфейсов сразу после дозвона).</summary>
internal sealed class FlakyInventory(INetInventory inner) : INetInventory
{
    /// <summary>Сколько следующих снимков закончатся ошибкой.</summary>
    public int Failures { get; set; }

    public NetSnapshot Capture()
    {
        if (Failures > 0)
        {
            Failures--;
            // ERROR_NOT_ENOUGH_MEMORY: таблица интерфейсов поменялась во время чтения.
            throw new NativeCallException("GetIfTable2", 8);
        }

        return inner.Capture();
    }

    public IReadOnlyList<uint> DhcpDnsServers(Guid interfaceGuid) => inner.DhcpDnsServers(interfaceGuid);
}
