using SplitVpn.Core.Ipc;
using SplitVpn.Core.Policy;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Native;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Отказ по сертификату сервера. Разбирается случай 21.09: Windows не смогла получить список отзыва
/// (0x80092013), потому что его адрес закрыт защитой, — исправный сертификат при этом отклоняется.
/// </summary>
public sealed partial class CoordinatorTests
{
    private const string RevocationHost = "ye1.c.lencr.org";

    private static ServerCertificateFacts ServerCertificate(DateTimeOffset notAfter) => new()
    {
        Subject = "vpn.example.org",
        Issuer = "Let's Encrypt",
        Names = ["vpn.example.org"],
        NotBefore = notAfter.AddDays(-7),
        NotAfter = notAfter,
        Thumbprint = "AABB",
        RevocationUrls = ["http://" + RevocationHost + "/112.crl"],
        RevocationHosts = [RevocationHost],
    };

    private static RasDialResult Failed(int code) =>
        new(false, null, unchecked((uint)code), "проверка отзыва недоступна");

    [Fact]
    public async Task ChangedServer_IgnoresOutstandingCertificateProbe()
    {
        var result = new TaskCompletionSource<ServerCertificateFacts?>(TaskCreationOptions.RunContinuationsAsynchronously);
        _world.Probes.CertificateResult = result;
        var coordinator = await StartAsync();
        try
        {
            await coordinator.HandleRequestAsync(new ConnectRequest(null, null), CancellationToken.None);
            var tunnel = coordinator.Facts.Tunnels[_profile.Id];
            for (var i = 0; i < 600 && (!tunnel.Verified || _world.Probes.ServerCertificateCalls == 0); i++)
            {
                await coordinator.DrainAsync();
                await Task.Delay(5, TestContext.Current.CancellationToken);
            }

            Assert.True(tunnel.Verified);
            Assert.True(tunnel.CertificateProbeRunning);
            await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: true), CancellationToken.None);
            var changed = coordinator.Settings with { Profiles = [_profile with { Server = "new.example:4443" }] };
            Assert.True((await coordinator.HandleRequestAsync(new SaveSettingsRequest(changed), CancellationToken.None)).Ok);

            result.SetResult(ServerCertificate(_world.Time.GetUtcNow().AddDays(6)));
            for (var i = 0; i < 600 && coordinator.QueuedCount == 0; i++)
            {
                await Task.Delay(5, TestContext.Current.CancellationToken);
            }

            Assert.True(coordinator.QueuedCount > 0);
            await coordinator.DrainAsync();
            Assert.Null(tunnel.ServerCertificate);
            Assert.Empty(tunnel.RevocationHosts);
            Assert.False(tunnel.CertificateProbeRunning);
        }
        finally
        {
            result.TrySetResult(null);
            await CompleteDialAsync(coordinator);
        }
    }

    [Fact]
    public async Task RevocationFailure_OpensRevocationAddress_AndConnectsOnRetry()
    {
        _world.Probes.ServerCertificate = ServerCertificate(_world.Time.GetUtcNow().AddDays(6));
        _world.Ras.Results.Enqueue(Failed(ConnectionErrorGuide.RevocationOffline));

        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        Assert.Contains(RevocationHost, tunnel.RevocationHosts);
        Assert.Equal(TimeSpan.FromHours(1), _world.Proxy.PinLifetimes[RevocationHost]);
        // Адрес проверки отзыва разрешается напрямую: полученный адрес закрепляется и получает разрешение.
        Assert.Contains(_world.Proxy.Configuration.DomainRoutes, d => d.Suffix == RevocationHost && d.Target.Kind == TargetKind.Direct);
        // Причина отказа устранена самой программой: повторы не остановлены, назначен повтор.
        Assert.Equal(ErrorCategory.None, tunnel.BlockingError);

        _world.Time.Advance(tunnel.NextDialAt - _world.Time.GetUtcNow() + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);

        Assert.True(_world.Ras.Connected);
        Assert.Equal(2, _world.Ras.Dials);
    }

    [Fact]
    public async Task RevocationHosts_SurviveServiceRestart()
    {
        _world.Probes.ServerCertificate = ServerCertificate(_world.Time.GetUtcNow().AddDays(6));
        _world.Ras.Results.Enqueue(Failed(ConnectionErrorGuide.RevocationOffline));
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.Contains(RevocationHost, coordinator.State.Servers.Single().RevocationHosts!);

        var restarted = await StartAsync();

        Assert.Contains(RevocationHost, restarted.Facts.Tunnels[_profile.Id].RevocationHosts);
        Assert.Contains(restarted.BuildStatus().Tunnels, t => t.ProfileId == _profile.Id);
    }

    [Fact]
    public async Task KnownRevocationHost_IsOpenedBeforeFirstDial()
    {
        _world.Probes.ServerCertificate = ServerCertificate(_world.Time.GetUtcNow().AddDays(6));

        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        // Проба идёт вместе с первым дозвоном: к следующему подключению адрес уже открыт.
        Assert.Equal(1, _world.Ras.Dials);
        Assert.Contains(_world.Proxy.Configuration.DomainRoutes, d => d.Suffix == RevocationHost);
    }

    [Fact]
    public async Task ExpiredServerCertificate_IsWarnedAbout()
    {
        _world.Probes.ServerCertificate = ServerCertificate(_world.Time.GetUtcNow().AddHours(-1));

        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        Assert.Contains(coordinator.BuildStatus().Warnings, w => w.Code == "server-certificate-expired");
    }

    [Fact]
    public async Task BlockingFailure_IsExplainedWithStepsInStatus()
    {
        _world.Ras.Results.Enqueue(new RasDialResult(false, null, 691, "Отказано в доступе"));

        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var status = coordinator.BuildStatus();
        var help = Assert.IsType<ConnectionErrorHelp>(status.ErrorHelp);
        Assert.Equal("Код 691 (RAS)", help.CodeText);
        Assert.NotEmpty(help.Steps);
        Assert.Equal(help.Summary, status.Tunnels.Single().ErrorHelp!.Summary);
    }

    /// <summary>
    /// Коды RAS расшифровывает RAS: у системного FormatMessage 668 — «Произошла ошибка подтверждения»,
    /// и именно этот чужой текст показывался вместо причины отказа подключения.
    /// </summary>
    [Fact]
    public void RasErrorCodes_AreDescribedByRas()
    {
        var text = NativeCallException.Describe(668);

        Assert.NotEmpty(text);
        Assert.DoesNotContain("подтверждения", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("assertion", text, StringComparison.OrdinalIgnoreCase);
    }
}
