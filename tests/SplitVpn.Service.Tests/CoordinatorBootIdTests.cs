using SplitVpn.Core.Ipc;
using SplitVpn.Core.State;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Автоподключение один раз за загрузку Windows: загрузку узнаёт идентификатор, не зависящий от настенных часов.
/// Поправка часов, пришедшая, пока служба не работала, не делает тот же сеанс новой загрузкой.
/// </summary>
public sealed partial class CoordinatorTests
{
    [Theory]
    [InlineData("41", false)]
    [InlineData("42", true)]
    public async Task AutoConnect_BootId_DecidesWhenClockWasCorrectedWhileServiceStopped(string bootIdAfterRestart, bool newBoot)
    {
        var stores = new ServiceStores(_world.Paths);
        stores.SaveSettings(stores.LoadSettings(out _) with { AutoConnect = true });
        _world.Uptime = TimeSpan.FromMinutes(1);
        _world.BootId = "41";
        var clock = new ShiftedTimeProvider(_world.Time);
        var first = await StartWithClockAsync(clock);
        Assert.Equal(Intent.Connected, first.State.Intent);
        Assert.Equal("41", stores.LoadState().AutoConnectBootId);
        await first.HandleRequestAsync(new DisconnectRequest(KeepProtection: false), CancellationToken.None);
        await TickAsync(first);
        Assert.Equal(Intent.Off, stores.LoadState().Intent);

        // Служба остановлена; тем временем Windows перевела часы назад на 3 ч. По времени загрузки это другая загрузка.
        _world.Uptime = TimeSpan.FromMinutes(3);
        clock.Offset = -TimeSpan.FromHours(3);
        _world.BootId = bootIdAfterRestart;
        var restarted = await StartWithClockAsync(clock);

        Assert.Equal(newBoot ? Intent.Connected : Intent.Off, restarted.State.Intent);
    }

    [Fact]
    public async Task AutoConnect_StaleBootId_FallsBackToBootTime()
    {
        var stores = new ServiceStores(_world.Paths);
        stores.SaveSettings(stores.LoadSettings(out _) with { AutoConnect = true });
        _world.Uptime = TimeSpan.FromMinutes(1);
        var boot = _world.Time.GetUtcNow() - _world.Uptime;
        boot = new DateTimeOffset(boot.UtcDateTime.AddTicks(-(boot.UtcDateTime.Ticks % TimeSpan.TicksPerMinute)), TimeSpan.Zero);
        // Отметку этой загрузки переписали без идентификатора: прежний идентификатор относится к другой отметке.
        stores.SaveState(new ServiceStateFile
        {
            Intent = Intent.Off,
            AutoConnectBootUtc = boot,
            AutoConnectBootId = "7",
            AutoConnectBootIdUtc = boot - TimeSpan.FromDays(1),
        });
        _world.BootId = "8";

        var coordinator = await StartAsync();

        Assert.Equal(Intent.Off, coordinator.State.Intent);
    }
}
