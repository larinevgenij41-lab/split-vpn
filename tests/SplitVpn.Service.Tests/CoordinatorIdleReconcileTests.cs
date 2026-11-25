using SplitVpn.Core.Net;
using SplitVpn.Service.Coordination;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Тик не гоняет полную сверку каждые 2 с, пока ей нечего сделать: подготовка адаптера SSH ещё идёт или проба
/// неподнятого туннеля не может стартовать без основного адаптера. Контроль SSH при «моргающей» сети всё же
/// набирает неудачи и перезапускает мёртвый сеанс.
/// </summary>
public sealed partial class CoordinatorTests
{
    /// <summary>Сколько из <paramref name="ticks"/> тиков по <paramref name="step"/> провели полную сверку.</summary>
    private async Task<int> CountReconcilingTicksAsync(Coordinator coordinator, int ticks, TimeSpan step)
    {
        var count = 0;
        for (var i = 0; i < ticks; i++)
        {
            _world.Time.Advance(step);
            var before = coordinator.Facts.LastFullReconcile;
            await TickAsync(coordinator);
            if (coordinator.Facts.LastFullReconcile != before)
            {
                count++;
            }
        }

        return count;
    }

    [Fact]
    public async Task Ssh_InterfacePreparationPending_DoesNotReconcileEveryTick()
    {
        var coordinator = await StartWithSshAsync();
        var released = new TaskCompletionSource();
        _world.SshTunnel.InterfacePreparation = released.Task;
        await ConnectAsync(coordinator);
        await TickAsync(coordinator);
        Assert.Empty(_world.SshTunnel.Sessions);

        var reconciles = await CountReconcilingTicksAsync(coordinator, 5, TimeSpan.FromSeconds(2));

        Assert.True(reconciles <= 1, $"сверок: {reconciles}; {Dump(coordinator)}");
        Assert.Equal(1, _world.SshTunnel.PreparationCalls);

        // Завершение подготовки само ставит сверку в очередь: движок запускается, не дожидаясь тика.
        released.SetResult();
        await WaitAsync(coordinator, () => _world.SshTunnel.Sessions.Count == 1);
        Assert.Equal(1, _world.SshTunnel.PreparationCalls);
    }

    [Fact]
    public async Task Ssh_UnverifiedTunnelWithoutPrimary_DoesNotReconcileEveryTick()
    {
        var coordinator = await StartWithSshAsync();
        _world.SshTunnel.Alive = false;
        await RaiseSshAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_ssh.Id];
        Assert.NotNull(tunnel.Luid);
        Assert.False(tunnel.Verified);

        _world.Inventory.WiFiUp = false;
        _world.Time.Advance(TimeSpan.FromSeconds(2));
        await TickAsync(coordinator);
        Assert.Null(coordinator.Facts.Primary);

        var reconciles = await CountReconcilingTicksAsync(coordinator, 5, TimeSpan.FromSeconds(2));

        // Допустим повтор после неполного применения (2 -> 4 -> 8 с), но не сверка на каждом тике.
        Assert.True(reconciles <= 2, $"сверок: {reconciles}; {Dump(coordinator)}");
    }

    /// <summary>
    /// Мёртвое соединение SSH при «моргающей» сети: уведомления о смене пути приходят чаще, чем две пробы подряд,
    /// но счёт неудач ими не обнуляется, и сеанс перезапускается.
    /// </summary>
    [Fact]
    public async Task Ssh_DeadTransportWithFlappingNetwork_RestartsSession()
    {
        var coordinator = await StartWithSshAsync();
        var session = await RaiseSshAsync(coordinator);
        Assert.True(coordinator.Facts.Tunnels[_ssh.Id].Verified);

        _world.SshTunnel.Alive = false;
        session.EstablishedTransport = false;
        for (var i = 0; i < 6 && !session.Disposed; i++)
        {
            _world.Inventory.WiFiAddress = Ipv4.Parse("192.168.1.100") + (uint)(i % 2 == 0 ? 50 : 0);
            _world.Time.Advance(TimeSpan.FromSeconds(5));
            await TickAsync(coordinator);
        }

        Assert.True(session.Disposed, Dump(coordinator));
    }
}
