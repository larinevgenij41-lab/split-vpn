using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using SplitVpn.Service.Coordination;

namespace SplitVpn.Service.Tests;

/// <summary>
/// 0.17.10: после подключения Wi-Fi новые туннели ждут, пока Windows не закончит возможное восстановление адаптера,
/// а служба ведёт запись подключения (разбор 21.11.2026: перезапуск адаптера на 32-й секунде после загрузки).
/// </summary>
public sealed partial class CoordinatorTests
{
    private WifiEvent Wifi(WifiEventKind kind, string detail = "") =>
        new(kind, kind == WifiEventKind.Recovery ? null : FakeWorld.WiFiGuid, _world.Time.GetUtcNow(), detail);

    [Fact]
    public async Task WifiJustConnected_DialWaitsForSettleDelay()
    {
        var coordinator = await StartAsync();
        coordinator.OnWifiEvent(Wifi(WifiEventKind.Connected));

        await ConnectAsync(coordinator);
        _world.Time.Advance(Coordinator.WifiSettleDelay - TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);
        Assert.Equal(0, _world.Ras.Dials);
        // Защита и DNS адаптера включаются сразу: откладывается только подъём туннеля.
        Assert.Equal("127.0.0.1", _world.Dns.NameServers[FakeWorld.WiFiGuid]);

        _world.Time.Advance(TimeSpan.FromSeconds(2));
        await TickAsync(coordinator);
        Assert.True(_world.Ras.Dials > 0, Dump(coordinator));
        Assert.True(_world.Ras.Connected, Dump(coordinator));
    }

    /// <summary>
    /// Запись 21.11.2026: событие 8001 приходит службе с опозданием, а сверка по уведомлению о смене сети уже выбрала
    /// адаптер и начала подъём туннеля. Ожидание ставит сама сверка, когда Wi-Fi появляется при работающей службе.
    /// </summary>
    [Fact]
    public async Task WifiAppearsWhileServiceRuns_DialWaitsWithoutAnyEvent()
    {
        _world.Inventory.WiFiUp = false;
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.Equal(0, _world.Ras.Dials);

        _world.Inventory.WiFiUp = true;
        await TickAsync(coordinator);
        _world.Time.Advance(Coordinator.WifiSettleDelay - TimeSpan.FromSeconds(2));
        await TickAsync(coordinator);
        Assert.Equal(0, _world.Ras.Dials);

        // Опоздавшее событие 8001 отсчёт не сдвигает.
        coordinator.OnWifiEvent(new WifiEvent(WifiEventKind.Connected, FakeWorld.WiFiGuid, _world.Time.GetUtcNow() - Coordinator.WifiSettleDelay, ""));
        _world.Time.Advance(TimeSpan.FromSeconds(3));
        await TickAsync(coordinator);
        Assert.True(_world.Ras.Connected, Dump(coordinator));
    }

    [Fact]
    public void WifiEventWatcher_SecurityEventCarriesDeviceGuid()
    {
        const string xml = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><EventData><Data Name='Adapter'>Wi-Fi</Data>" +
            "<Data Name='DeviceGuid'>{0d660c99-2010-41fd-a16e-387926f18b06}</Data><Data Name='ConnectionId'>0x1</Data></EventData></Event>";

        var parsed = WifiEventWatcher.Parse(11005, null, xml);

        Assert.Equal(WifiEventKind.SecuritySucceeded, parsed!.Kind);
        Assert.Equal(Guid.Parse("0d660c99-2010-41fd-a16e-387926f18b06"), parsed.InterfaceGuid);
    }

    [Fact]
    public async Task WifiConnectedLongAgo_DialIsNotDelayed()
    {
        var coordinator = await StartAsync();
        coordinator.OnWifiEvent(Wifi(WifiEventKind.Connected));
        _world.Time.Advance(TimeSpan.FromMinutes(10));

        await ConnectAsync(coordinator);

        Assert.True(_world.Ras.Connected, Dump(coordinator));
    }

    [Fact]
    public async Task SecondSecurityCheck_ExtendsHold_AndWritesRecord()
    {
        var coordinator = await StartAsync();
        coordinator.OnWifiEvent(Wifi(WifiEventKind.Connected));
        await ConnectAsync(coordinator);

        // 16-я секунда: Windows повторяет проверку безопасности - первый шаг восстановления.
        _world.Time.Advance(TimeSpan.FromSeconds(16));
        coordinator.OnWifiEvent(Wifi(WifiEventKind.SecurityStopped));
        coordinator.OnWifiEvent(Wifi(WifiEventKind.SecuritySucceeded));
        _world.Time.Advance(TimeSpan.FromSeconds(10));
        await TickAsync(coordinator);

        // 26-я секунда: обычное ожидание (20 с) вышло, но туннель не поднимается - ждём перезапуска адаптера.
        Assert.Equal(0, _world.Ras.Dials);
        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("перепроверяет подключение Wi-Fi", StringComparison.Ordinal));
        var file = coordinator.WifiRecorder!.LastFile;
        Assert.NotNull(file);
        var text = File.ReadAllText(file);
        Assert.Contains("повторная проверка безопасности через 16 с", text, StringComparison.Ordinal);
        Assert.Contains("Основной адаптер: Беспроводная сеть.", text, StringComparison.Ordinal);

        // Перезапуска не случилось: по истечении ожидания туннель поднимается.
        _world.Time.Advance(Coordinator.WifiMarkerHold);
        await TickAsync(coordinator);
        Assert.True(_world.Ras.Connected, Dump(coordinator));
    }

    [Fact]
    public async Task AfterRecovery_ReconnectHoldsLonger_ButNotBeyondLimit()
    {
        var coordinator = await StartAsync();
        coordinator.OnWifiEvent(Wifi(WifiEventKind.Connected));
        await ConnectAsync(coordinator);
        _world.Time.Advance(TimeSpan.FromSeconds(32));
        coordinator.OnWifiEvent(Wifi(WifiEventKind.Recovery, "Event=4, ChangeReason=1"));
        coordinator.OnWifiEvent(Wifi(WifiEventKind.Disconnected));
        _world.Time.Advance(TimeSpan.FromSeconds(4));
        coordinator.OnWifiEvent(Wifi(WifiEventKind.Connected));

        // Через 30 с после возврата Wi-Fi туннель ещё ждёт: на 65-й секунде Windows отключает Wi-Fi на минуту.
        _world.Time.Advance(TimeSpan.FromSeconds(30));
        await TickAsync(coordinator);
        Assert.Equal(0, _world.Ras.Dials);
        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("перезапускает адаптер", StringComparison.Ordinal));

        _world.Time.Advance(Coordinator.WifiAfterRecoveryHold);
        await TickAsync(coordinator);
        Assert.True(_world.Ras.Connected, Dump(coordinator));

        // Цепочка восстановлений идёт дольше предела: следующее подключение ждёт не дольше предела от начала цепочки.
        _world.Time.Advance(Coordinator.WifiHoldLimit);
        coordinator.OnWifiEvent(Wifi(WifiEventKind.Connected));
        await TickAsync(coordinator);
        Assert.True(_world.Ras.Connected, Dump(coordinator));
    }

    [Fact]
    public async Task HourlyRekey_IsNotARecoverySign()
    {
        var coordinator = await StartAsync();
        coordinator.OnWifiEvent(Wifi(WifiEventKind.Connected));
        _world.Time.Advance(TimeSpan.FromHours(1));

        coordinator.OnWifiEvent(Wifi(WifiEventKind.SecurityStopped));
        coordinator.OnWifiEvent(Wifi(WifiEventKind.SecuritySucceeded));
        await ConnectAsync(coordinator);

        Assert.Null(coordinator.WifiRecorder!.LastFile);
        Assert.True(_world.Ras.Connected, Dump(coordinator));
    }

    [Fact]
    public void Recorder_KeepsRecentLines_AndAppendsAfterTrigger()
    {
        var folder = Directory.CreateTempSubdirectory("splitvpn-wifi-").FullName;
        try
        {
            var time = new FakeTimeProvider(new DateTimeOffset(2026, 11, 21, 12, 0, 0, TimeSpan.Zero));
            var recorder = new WifiIncidentRecorder(folder, time, NullLogger.Instance);
            recorder.Note("старое");
            time.Advance(WifiIncidentRecorder.History + TimeSpan.FromSeconds(1));
            recorder.Note("перед признаком");
            recorder.Trigger("причина");
            recorder.Note("после признака");
            time.Advance(WifiIncidentRecorder.Follow + TimeSpan.FromSeconds(1));
            recorder.Note("слишком поздно");

            var text = File.ReadAllText(recorder.LastFile!);
            Assert.DoesNotContain("старое", text, StringComparison.Ordinal);
            Assert.Contains("перед признаком", text, StringComparison.Ordinal);
            Assert.Contains("Признак: причина", text, StringComparison.Ordinal);
            Assert.Contains("после признака", text, StringComparison.Ordinal);
            Assert.DoesNotContain("слишком поздно", text, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    [Fact]
    public void WifiEventWatcher_ParsesInterfaceAndReason()
    {
        const string xml = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>8003</EventID></System>" +
            "<EventData><Data Name='InterfaceGuid'>{0D660C99-2010-41FD-A16E-387926F18B06}</Data><Data Name='SSID'>Home</Data><Data Name='Reason'>запрос на временное отключение</Data></EventData></Event>";

        var parsed = WifiEventWatcher.Parse(8003, new DateTime(2026, 11, 21, 8, 56, 38, DateTimeKind.Local), xml);

        Assert.NotNull(parsed);
        Assert.Equal(WifiEventKind.Disconnected, parsed.Kind);
        Assert.Equal(Guid.Parse("0d660c99-2010-41fd-a16e-387926f18b06"), parsed.InterfaceGuid);
        Assert.Contains("временное отключение", parsed.Detail, StringComparison.Ordinal);
        // Имя сети в запись не попадает.
        Assert.DoesNotContain("Home", parsed.Detail, StringComparison.Ordinal);
        Assert.Null(WifiEventWatcher.Parse(8000, null, xml));
    }
}
