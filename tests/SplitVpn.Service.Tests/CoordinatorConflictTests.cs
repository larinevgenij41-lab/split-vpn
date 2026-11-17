using SplitVpn.Core.Ipc;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Diagnostics;

namespace SplitVpn.Service.Tests;

/// <summary>Детектор конфликтов: когда служба разрывает чужое подключение и что бывает с зависшей проверкой.</summary>
public sealed partial class CoordinatorTests
{
    /// <summary>Поднятое службой подключение: чужое подключение Windows к тому же серверу разрывается.</summary>
    [Fact]
    public async Task ConflictServers_TunnelUp_HangsUpForeign()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        Assert.True(Assert.Single(coordinator.ConflictServers()).HangUpForeign);
    }

    /// <summary>
    /// Служба не дозванивается сама (ошибка входа, ждёт пароля или входа, отключено в меню сети Windows, туннеля
    /// нет): к серверу можно подключиться средствами Windows, служба такое подключение не разрывает.
    /// </summary>
    [Theory]
    [InlineData("blocking")]
    [InlineData("password")]
    [InlineData("external")]
    [InlineData("sign-in")]
    [InlineData("paused")]
    [InlineData("no-tunnel")]
    public async Task ConflictServers_ServiceDoesNotHoldConnection_DoesNotHangUpForeign(string state)
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];

        switch (state)
        {
            case "blocking":
                tunnel.BlockingError = ErrorCategory.Authentication;
                break;
            case "password":
                tunnel.PasswordRequired = true;
                break;
            case "external":
                tunnel.ExternallyDisconnected = true;
                break;
            case "sign-in":
                tunnel.SignIn = new SignInPromptDto();
                break;
            case "paused":
                tunnel.Paused = true;
                break;
            default:
                coordinator.Facts.Tunnels.Remove(_profile.Id);
                break;
        }

        Assert.False(Assert.Single(coordinator.ConflictServers()).HangUpForeign);
    }

    /// <summary>
    /// Детектор завис (открытие чужой телефонной книги ждёт снятия oplock): через предел проверка бросается, но
    /// новая не запускается, пока брошенная не завершится, - иначе каждая занимала бы ещё один поток пула. Поздний
    /// результат брошенной проверки отбрасывается, после её завершения проверки идут снова.
    /// </summary>
    [Fact]
    public async Task ConflictCheck_HungDetector_IsAbandoned_NoNewRunUntilItCompletes()
    {
        using var gate = new ManualResetEventSlim();
        var calls = 0;
        var lateReturned = 0;
        var stale = new StatusWarning("foreign-vpn", "Результат брошенной проверки", null);
        var coordinator = new Coordinator(_world.Dependencies() with
        {
            DetectConflicts = _ =>
            {
                if (Interlocked.Increment(ref calls) == 1)
                {
                    gate.Wait(TimeSpan.FromSeconds(30));
                    Volatile.Write(ref lateReturned, 1);
                    return [stale];
                }

                return [];
            },
        });
        try
        {
            await coordinator.StartupAsync(CancellationToken.None);
            await coordinator.DrainAsync();

            await coordinator.TickAsync(CancellationToken.None);
            await coordinator.DrainAsync();
            await WaitForAsync(() => Volatile.Read(ref calls) >= 1);
            Assert.True(coordinator.Facts.ConflictCheckRunning);

            // До предела проверка считается идущей.
            _world.Time.Advance(Coordinator.ConflictCheckTimeout - TimeSpan.FromSeconds(10));
            await coordinator.TickAsync(CancellationToken.None);
            await coordinator.DrainAsync();
            Assert.True(coordinator.Facts.ConflictCheckRunning);

            // После предела - брошена.
            _world.Time.Advance(TimeSpan.FromSeconds(20));
            await coordinator.TickAsync(CancellationToken.None);
            await coordinator.DrainAsync();
            Assert.False(coordinator.Facts.ConflictCheckRunning);

            // Срок следующей проверки настал, но брошенная ещё висит: новый поток детектору не отдаётся.
            _world.Time.Advance(TimeSpan.FromMinutes(5));
            await coordinator.TickAsync(CancellationToken.None);
            await coordinator.DrainAsync();
            await Task.Delay(50, TestContext.Current.CancellationToken);
            Assert.Equal(1, Volatile.Read(ref calls));
            Assert.False(coordinator.Facts.ConflictCheckRunning);

            gate.Set();
            await WaitForAsync(() => Volatile.Read(ref lateReturned) == 1);
            for (var i = 0; i < 20; i++)
            {
                await Task.Delay(10, TestContext.Current.CancellationToken);
                await coordinator.DrainAsync();
            }

            Assert.DoesNotContain(coordinator.Facts.ConflictWarnings, w => w.Text == stale.Text);
            Assert.False(coordinator.Facts.ConflictCheckRunning);

            // Брошенная проверка завершилась: следующая идёт в свой срок.
            for (var i = 0; i < 20 && Volatile.Read(ref calls) < 2; i++)
            {
                _world.Time.Advance(TimeSpan.FromMinutes(5));
                await coordinator.TickAsync(CancellationToken.None);
                await coordinator.DrainAsync();
                await Task.Delay(10, TestContext.Current.CancellationToken);
            }

            await WaitForQuietConflictsAsync(coordinator);
            Assert.Equal(2, Volatile.Read(ref calls));
            Assert.False(coordinator.Facts.ConflictCheckRunning);
            Assert.Empty(coordinator.Facts.ConflictWarnings);
        }
        finally
        {
            gate.Set();
        }
    }

    /// <summary>
    /// Проверка, начатая при поднятом VPN, разрывает чужое подключение только пока она актуальна: после «Отключить»
    /// её снимок «служба держит подключение» устарел, и разрывать по нему нельзя.
    /// </summary>
    [Fact]
    public async Task ConflictCheck_RunBeforeDisconnect_MayNotHangUpAfterIt()
    {
        ConflictInputs? last = null;
        var coordinator = await StartWithAsync(d => d with
        {
            DetectConflicts = inputs =>
            {
                Volatile.Write(ref last, inputs);
                return [];
            },
        });
        await ConnectAsync(coordinator);
        _world.Time.Advance(TimeSpan.FromMinutes(5));
        await TickAsync(coordinator);
        await WaitForAsync(() => Volatile.Read(ref last) is { } seen && seen.Servers.Count == 1 && seen.Servers[0].HangUpForeign);
        var run = Volatile.Read(ref last)!;
        Assert.True(run.StillCurrent!());

        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: true), CancellationToken.None);
        await CompleteDialAsync(coordinator);

        Assert.False(run.StillCurrent!());
    }

    /// <summary>Брошенная по пределу проверка больше не актуальна: висящий детектор не разорвёт чужое подключение, когда очнётся.</summary>
    [Fact]
    public async Task ConflictCheck_AbandonedRun_MayNotHangUp()
    {
        using var gate = new ManualResetEventSlim();
        var hold = 0;
        ConflictInputs? hung = null;
        var coordinator = await StartWithAsync(d => d with
        {
            DetectConflicts = inputs =>
            {
                if (Volatile.Read(ref hold) == 1 && Interlocked.CompareExchange(ref hung, inputs, null) is null)
                {
                    gate.Wait(TimeSpan.FromSeconds(30));
                }

                return [];
            },
        });
        try
        {
            await ConnectAsync(coordinator);
            Volatile.Write(ref hold, 1);
            _world.Time.Advance(TimeSpan.FromMinutes(5));
            await coordinator.TickAsync(CancellationToken.None);
            await coordinator.DrainAsync();
            await WaitForAsync(() => Volatile.Read(ref hung) is not null);
            var run = Volatile.Read(ref hung)!;
            Assert.True(run.StillCurrent!());

            _world.Time.Advance(Coordinator.ConflictCheckTimeout);
            await coordinator.TickAsync(CancellationToken.None);
            await coordinator.DrainAsync();

            Assert.False(coordinator.Facts.ConflictCheckRunning);
            Assert.False(run.StillCurrent!());
        }
        finally
        {
            gate.Set();
        }
    }

    private static async Task WaitForAsync(Func<bool> condition)
    {
        for (var i = 0; i < 400 && !condition(); i++)
        {
            await Task.Delay(5, TestContext.Current.CancellationToken);
        }

        Assert.True(condition());
    }

    private static async Task WaitForQuietConflictsAsync(Coordinator coordinator)
    {
        for (var i = 0; i < 400 && (coordinator.QueuedCount > 0 || coordinator.Facts.ConflictCheckRunning); i++)
        {
            await coordinator.DrainAsync();
            await Task.Delay(5, TestContext.Current.CancellationToken);
        }

        await coordinator.DrainAsync();
    }
}
