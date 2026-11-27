using System.Diagnostics;
using SplitVpn.Core.Net;
using SplitVpn.Core.OpenConnect;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Net;

namespace SplitVpn.Service.Tests;

/// <summary>Остановка службы и прощание AnyConnect со шлюзом; повторы очистки «пустой» службы.</summary>
public sealed partial class CoordinatorTests
{
    /// <summary>
    /// Выключение Windows: помощник получает Stop (BYE на шлюзе) сразу, политика не применяется - ни фильтры, ни маршруты
    /// не трогаются (после загрузки служба применит защиту заново).
    /// </summary>
    [Fact]
    public async Task AnyConnect_SystemShutdown_SendsStopWithoutApplyingPolicy()
    {
        var coordinator = await StartWithAnyConnectAsync();
        var session = await EstablishAsync(coordinator);
        var transactions = _world.Wfp.Transactions;
        var routes = _world.Routes.Current.ToHashSet();
        Assert.NotEmpty(_world.Routes.On(FakeInventory.TunnelLuid(AnyConnectSlot)));

        coordinator.OnSystemShutdown();
        var exited = coordinator.ShutdownAnyConnect(coordinator.SystemShuttingDown);

        Assert.IsType<StopCommand>(session.Commands[^1]);
        Assert.True(session.Disposed);
        Assert.Equal(transactions, _world.Wfp.Transactions);
        Assert.True(routes.SetEquals(_world.Routes.Current));
        session.ExitSource.SetResult();
        await exited.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// Обычная остановка, применение политики зависло (WFP): Stop уходит по истечении срока, а применение доходит в фоне -
    /// маршруты через туннель снимаются после того, как WFP ответил.
    /// </summary>
    [Fact]
    public async Task AnyConnect_ServiceStop_SlowApply_StopSentAfterBudget()
    {
        var coordinator = await StartWithAnyConnectAsync();
        var session = await EstablishAsync(coordinator);
        using var entered = new ManualResetEventSlim();
        using var gate = new ManualResetEventSlim();
        _world.Wfp.BeforeReplace = () =>
        {
            entered.Set();
            gate.Wait(TimeSpan.FromSeconds(30));
        };

        var watch = Stopwatch.StartNew();
        var exited = coordinator.ShutdownAnyConnect(systemShutdown: false, TimeSpan.FromMilliseconds(300));
        watch.Stop();

        Assert.True(entered.Wait(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken), "применение политики не началось");
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(10), $"Stop ждал применения {watch.Elapsed}");
        Assert.IsType<StopCommand>(session.Commands[^1]);
        Assert.True(session.Disposed);

        gate.Set();
        for (var i = 0; i < 500 && _world.Routes.On(FakeInventory.TunnelLuid(AnyConnectSlot)).Any(); i++)
        {
            await Task.Delay(10, TestContext.Current.CancellationToken);
        }

        Assert.Empty(_world.Routes.On(FakeInventory.TunnelLuid(AnyConnectSlot)));
        session.ExitSource.SetResult();
        await exited.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// Применение зависло дольше срока: Stop уходит вовремя, но факты туннелей (ссылка на помощника, запись журнала,
    /// остановка SSH) меняются только после конца фонового применения — оно читает их без синхронизации.
    /// </summary>
    [Fact]
    public async Task AnyConnect_ServiceStop_SlowApply_FactsChangeOnlyAfterApply()
    {
        var coordinator = await StartWithAnyConnectAsync();
        var session = await EstablishAsync(coordinator);
        using var entered = new ManualResetEventSlim();
        using var gate = new ManualResetEventSlim();
        var linkAtApplyEnd = (object?)null;
        var calls = 0;
        _world.Wfp.BeforeReplace = () =>
        {
            if (Interlocked.Increment(ref calls) != 1)
            {
                return;
            }

            entered.Set();
            gate.Wait(TimeSpan.FromSeconds(30));
            linkAtApplyEnd = coordinator.Facts.Tunnels[_anyConnect.Id].AnyConnect;
        };
        var journal = _world.Journal.Since(0)[^1].Id;

        var exited = coordinator.ShutdownAnyConnect(systemShutdown: false, TimeSpan.FromMilliseconds(300));
        var ssh = coordinator.ShutdownSshTunnels();

        Assert.True(entered.Wait(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken), "применение политики не началось");
        Assert.IsType<StopCommand>(session.Commands[^1]);
        Assert.True(session.Disposed);
        Assert.NotNull(coordinator.Facts.Tunnels[_anyConnect.Id].AnyConnect);
        Assert.False(ssh.IsCompleted, "остановка SSH не ждёт фонового применения");
        Assert.DoesNotContain(_world.Journal.Since(journal), e => e.Text.Contains("сеансы AnyConnect завершены", StringComparison.Ordinal));

        gate.Set();
        session.ExitSource.SetResult();
        await exited.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        await ssh.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);

        Assert.NotNull(linkAtApplyEnd);
        Assert.Null(coordinator.Facts.Tunnels[_anyConnect.Id].AnyConnect);
        Assert.Single(session.Commands.OfType<StopCommand>());
        Assert.Contains(_world.Journal.Since(journal), e => e.Text.Contains("сеансы AnyConnect завершены", StringComparison.Ordinal));
    }

    /// <summary>
    /// «Пустая» служба после загрузки: первая очистка не удалась (маршруты не удалились), повтор через срок её завершает, и в
    /// журнале - итог повтора.
    /// </summary>
    [Fact]
    public async Task Emergency_InertStart_RetriesHealUntilClean()
    {
        _world.Routes.Current.Add(new RouteKey(Ipv4Cidr.Parse("10.0.0.0/8"), FakeWorld.Gateway, FakeWorld.WiFiLuid));
        _world.Routes.FailNext = 2;

        var coordinator = await StartInertAsync();
        Assert.NotEmpty(_world.Routes.Current);

        await AdvanceHealRetryAsync(coordinator, () => _world.Routes.FailNext == 0);
        Assert.NotEmpty(_world.Routes.Current);
        await AdvanceHealRetryAsync(coordinator, () => _world.Routes.Current.Count == 0);

        Assert.Empty(_world.Routes.Current);
        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("выполнена при повторе 2", StringComparison.Ordinal));
    }

    /// <summary>Повторов не больше <see cref="Coordinator.EmergencyHealRetries"/>: дальше - запись в журнал, а не цикл.</summary>
    [Fact]
    public async Task Emergency_InertStart_HealRetriesAreBounded()
    {
        _world.Routes.Current.Add(new RouteKey(Ipv4Cidr.Parse("10.0.0.0/8"), FakeWorld.Gateway, FakeWorld.WiFiLuid));
        _world.Routes.FailNext = 100;

        var coordinator = await StartInertAsync();
        for (var attempt = 1; attempt <= Coordinator.EmergencyHealRetries; attempt++)
        {
            var expected = 100 - 1 - attempt;
            await AdvanceHealRetryAsync(coordinator, () => _world.Routes.FailNext == expected);
        }

        for (var i = 0; i < 3; i++)
        {
            _world.Time.Advance(Coordinator.EmergencyHealRetryDelay);
            await coordinator.DrainAsync();
        }

        Assert.Equal(100 - 1 - Coordinator.EmergencyHealRetries, _world.Routes.FailNext);
        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains($"после {Coordinator.EmergencyHealRetries} повторов", StringComparison.Ordinal));
    }

    private async Task AdvanceHealRetryAsync(Coordinator coordinator, Func<bool> done)
    {
        _world.Time.Advance(Coordinator.EmergencyHealRetryDelay);
        for (var i = 0; i < 500 && !done(); i++)
        {
            await coordinator.DrainAsync();
            if (!done())
            {
                await Task.Delay(5, TestContext.Current.CancellationToken);
            }
        }

        Assert.True(done(), "повтор очистки не выполнен");
    }
}
