using SplitVpn.Core.Ipc;
using SplitVpn.Core.State;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Поведение при неудачной проверке готовности туннеля: пауза между повторами растёт, счётчик снимает только
/// успешная проверка, а недоступность российской цели туннель не разрывает. Проверяет исправление цикла
/// переподключений (см. docs\WINDOWS-AUDIT.md, раздел 2.1).
/// </summary>
public sealed partial class CoordinatorTests
{
    [Fact]
    public async Task VerificationFailure_GrowsRetryDelay_AndDoesNotResetOnRedial()
    {
        _world.Probes.TunnelWorks = false;
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        Assert.Equal(1, tunnel.VerifyFailures);
        var firstGap = tunnel.NextDialAt - _world.Time.GetUtcNow();

        // Дожидаемся паузы и повторяем — дозвон снова успешен, проверка снова нет: счётчик не сбрасывается.
        _world.Time.Advance(firstGap + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);

        Assert.Equal(2, tunnel.VerifyFailures);
        var secondGap = tunnel.NextDialAt - _world.Time.GetUtcNow();
        Assert.True(secondGap > firstGap, $"пауза не выросла: {firstGap} → {secondGap}");
        Assert.NotEqual(ConnectionState.Connected, coordinator.DeriveState());
    }

    [Fact]
    public async Task SuccessfulVerification_ResetsRetryCounters()
    {
        _world.Probes.TunnelWorks = false;
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        Assert.True(tunnel.VerifyFailures > 0);

        _world.Probes.TunnelWorks = true;
        _world.Time.Advance(tunnel.NextDialAt - _world.Time.GetUtcNow() + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);

        Assert.Equal(0, tunnel.VerifyFailures);
        Assert.Equal(0, tunnel.DialAttempt);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    [Fact]
    public async Task RussianTargetUnreachable_KeepsTunnel_AndWarns()
    {
        _world.Probes.RussianWorks = false;
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        // Иностранная цель доступна через туннель — подключение считается рабочим, туннель не разрывается.
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
        Assert.True(_world.Ras.Connected);
        Assert.Contains(coordinator.BuildStatus().Warnings, w => w.Code == "russian-target-direct");
    }
}
