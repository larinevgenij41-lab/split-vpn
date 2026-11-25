using SplitVpn.Core.Ipc;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Итерация 13: повтор после открытия адресов проверки отзыва для обоих кодов (0x80092013 и 0x80092012) и
/// автоматические повторы после отказа 734, который бывает и при обрыве ненадёжного канала.
/// </summary>
public sealed partial class CoordinatorTests
{
    /// <summary>
    /// Первое подключение SSTP без кеша серверов: дозвон отклонён с 0x80092012 раньше, чем проба узнала адреса
    /// списка отзыва. Отказ блокирующий, но как только проба открыла адреса, повтор назначается сам —
    /// иначе пользователь остался бы без сети за защитой, хотя подсказка обещает переподключение.
    /// </summary>
    [Theory]
    [InlineData(ConnectionErrorGuide.NoRevocationCheck)]
    [InlineData(ConnectionErrorGuide.RevocationOffline)]
    public async Task RevocationFailure_BeforeProbe_RetriesAfterAddressesOpen(int code)
    {
        var probe = new TaskCompletionSource<ServerCertificateFacts?>(TaskCreationOptions.RunContinuationsAsynchronously);
        _world.Probes.CertificateResult = probe;
        _world.Ras.Results.Enqueue(Failed(code));
        var coordinator = await StartAsync();
        try
        {
            await coordinator.HandleRequestAsync(new ConnectRequest(null, null), CancellationToken.None);
            var tunnel = coordinator.Facts.Tunnels[_profile.Id];
            await WaitUntilAsync(coordinator, () => tunnel.BlockingError == ErrorCategory.Certificate && !tunnel.Dialing);
            Assert.Empty(tunnel.RevocationHosts);

            probe.SetResult(ServerCertificate(_world.Time.GetUtcNow().AddDays(6)));
            await WaitUntilAsync(coordinator, () => !tunnel.CertificateProbeRunning && tunnel.RevocationHosts.Count > 0);
            await CompleteDialAsync(coordinator);

            // Отказ снят, повтор назначен сразу: он может пройти уже в этой сверке.
            Assert.Equal(ErrorCategory.None, tunnel.BlockingError);
            if (!_world.Ras.Connected)
            {
                _world.Time.Advance(TimeSpan.FromSeconds(1) + (tunnel.NextDialAt > _world.Time.GetUtcNow() ? tunnel.NextDialAt - _world.Time.GetUtcNow() : TimeSpan.Zero));
                await TickAsync(coordinator);
            }

            Assert.True(_world.Ras.Connected);
            Assert.Equal(2, _world.Ras.Dials);
        }
        finally
        {
            probe.TrySetResult(null);
            await CompleteDialAsync(coordinator);
        }
    }

    [Fact]
    public void RevocationCheckFailure_CoversBothCodes()
    {
        Assert.True(ConnectionErrorGuide.IsRevocationCheckFailure(ConnectionErrorGuide.RevocationOffline));
        Assert.True(ConnectionErrorGuide.IsRevocationCheckFailure(ConnectionErrorGuide.NoRevocationCheck));
        Assert.False(ConnectionErrorGuide.IsRevocationCheckFailure(ConnectionErrorGuide.CertificateRevoked));
        Assert.False(ConnectionErrorGuide.IsRevocationCheckFailure(null));
    }

    /// <summary>Отказ 734 дважды повторяется сам; третий подряд останавливает повторы до действия пользователя.</summary>
    [Fact]
    public async Task LcpTerminated_RetriesTwice_ThenBlocks()
    {
        for (var i = 0; i < 3; i++)
        {
            _world.Ras.Results.Enqueue(new RasDialResult(false, null, 734, "Согласование PPP прервано"));
        }

        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];

        for (var attempt = 1; attempt <= Coordinator.LcpTerminatedAutoRetries; attempt++)
        {
            Assert.Equal(ErrorCategory.None, tunnel.BlockingError);
            Assert.Equal(attempt, tunnel.LcpTerminatedRetries);
            _world.Time.Advance(tunnel.NextDialAt - _world.Time.GetUtcNow() + TimeSpan.FromSeconds(1));
            await TickAsync(coordinator);
        }

        Assert.Equal(3, _world.Ras.Dials);
        Assert.Equal(ErrorCategory.Authentication, tunnel.BlockingError);
        Assert.False(_world.Ras.Connected);
    }

    /// <summary>Успешное подключение сбрасывает счётчик: следующий обрыв с 734 снова получает два повтора.</summary>
    [Fact]
    public async Task LcpTerminated_CounterResetsAfterSuccessfulConnect()
    {
        _world.Ras.Results.Enqueue(new RasDialResult(false, null, 734, "Согласование PPP прервано"));

        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        Assert.Equal(1, tunnel.LcpTerminatedRetries);

        _world.Time.Advance(tunnel.NextDialAt - _world.Time.GetUtcNow() + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);

        Assert.True(_world.Ras.Connected);
        Assert.True(tunnel.Verified);
        Assert.Equal(0, tunnel.LcpTerminatedRetries);
    }
}
