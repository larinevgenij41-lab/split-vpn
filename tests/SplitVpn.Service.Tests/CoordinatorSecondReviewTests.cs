using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

/// <summary>Второй круг исправлений по код-ревью 0.9.6: DNS адаптеров, кеш адресов отзыва, неполная цепочка, настройки.</summary>
public sealed partial class CoordinatorTests
{
    private const string IssuerHost = "r11.i.lencr.org";

    [Fact]
    public async Task DnsFailureOnOneAdapter_OthersAndProxyStillConfigured()
    {
        _world.Dns.FailLoopback.Add(FakeWorld.WiFiGuid);

        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        // Сбой на Wi-Fi не оставляет туннель без посредника, а посредник — без настроек.
        Assert.Equal("127.0.0.1", _world.Dns.NameServers[FakeWorld.TunnelGuid]);
        Assert.Equal(DnsProxyMode.Online, _world.Proxy.Configuration.Mode);
        Assert.NotNull(coordinator.Facts.PartialError);
    }

    [Fact]
    public async Task CachedRevocationHostsWithoutTrustMark_AreIgnored()
    {
        // Кеш версий до 0.9.6: узлы выучены из сертификата любого ответившего.
        new ServiceStores(_world.Paths).SaveState(new ServiceStateFile
        {
            Intent = Intent.Protected,
            Servers = [new ServerCacheEntry(_profile.Id, [Ipv4.Format(FakeWorld.Server)], _world.Time.GetUtcNow(), null, [RevocationHost])],
        });

        var coordinator = await StartAsync();

        Assert.Empty(coordinator.Facts.Tunnels[_profile.Id].RevocationHosts);
        Assert.DoesNotContain(_world.Proxy.Configuration.DomainRoutes, d => d.Suffix == RevocationHost);
    }

    [Fact]
    public async Task UntrustedProbe_ClearsKnownRevocationHosts()
    {
        _world.Probes.ServerCertificate = ServerCertificate(_world.Time.GetUtcNow().AddDays(6));
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        Assert.Contains(RevocationHost, tunnel.RevocationHosts);
        Assert.True(coordinator.State.Servers.Single().RevocationHostsTrusted);

        var forged = ServerCertificate(_world.Time.GetUtcNow().AddDays(6)) with { ChainProblem = "корневой сертификат издателя не установлен" };
        await coordinator.OnCertificateProbedAsync(_profile.Id, tunnel.CertificateProbeGeneration, forged, "тест", CancellationToken.None);

        Assert.Empty(tunnel.RevocationHosts);
        Assert.Empty(coordinator.State.Servers.Single().RevocationHosts ?? []);
        Assert.DoesNotContain(_world.Proxy.Configuration.DomainRoutes, d => d.Suffix == RevocationHost);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task MissingIntermediate_OpensOnlyIssuerHost(bool nameMatches)
    {
        var named = _profile with { Server = "vpn.example.org:4443" };
        SaveSettings(Settings() with { Profiles = [named] });
        _world.Probes.ServerCertificate = ServerCertificate(_world.Time.GetUtcNow().AddDays(6)) with
        {
            ChainProblem = "цепочка неполная: сервер не прислал промежуточный сертификат",
            MissingIntermediateOnly = true,
            NameMatches = nameMatches,
            RevocationHosts = [RevocationHost, IssuerHost],
            IssuerHosts = [IssuerHost],
        };
        _world.Ras.Results.Enqueue(Failed(ConnectionErrorGuide.RevocationOffline));

        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var tunnel = coordinator.Facts.Tunnels[named.Id];
        Assert.DoesNotContain(RevocationHost, tunnel.RevocationHosts);
        Assert.DoesNotContain(_world.Proxy.Configuration.DomainRoutes, d => d.Suffix == RevocationHost);
        if (nameMatches)
        {
            Assert.Equal([IssuerHost], tunnel.RevocationHosts);
            Assert.Contains(_world.Proxy.Configuration.DomainRoutes, d => d.Suffix == IssuerHost && d.Target.Kind == TargetKind.Direct && d.ExactName);
            Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("промежуточный сертификат", StringComparison.Ordinal));
        }
        else
        {
            Assert.Empty(tunnel.RevocationHosts);
        }
    }

    [Fact]
    public async Task ProbeOfPreviousServerName_IsDiscarded()
    {
        var named = _profile with { Server = "vpn.example.org:4443" };
        SaveSettings(Settings() with { Profiles = [named] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[named.Id];
        var facts = ServerCertificate(_world.Time.GetUtcNow().AddDays(6)) with { NameMatches = true };

        // Имя совпало с тем, к которому шла проба, но это прежний сервер профиля.
        await coordinator.OnCertificateProbedAsync(named.Id, tunnel.CertificateProbeGeneration, facts with { ProbedHost = "old.example.org" }, "тест", CancellationToken.None);
        Assert.Null(tunnel.ServerCertificate);
        Assert.Empty(tunnel.RevocationHosts);

        await coordinator.OnCertificateProbedAsync(named.Id, tunnel.CertificateProbeGeneration, facts with { ProbedHost = "vpn.example.org" }, "тест", CancellationToken.None);
        Assert.Contains(RevocationHost, tunnel.RevocationHosts);
    }

    [Fact]
    public async Task ClientCancellation_SchedulesReconcileWithoutError()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var before = _world.Journal.Since(0).Count;

        coordinator.MarkInterruptedApply("DisconnectRequest", new OperationCanceledException(), canceledByClient: true);

        Assert.Null(coordinator.Facts.PartialError);
        Assert.True(coordinator.Facts.ReconcilePending);
        Assert.DoesNotContain(_world.Journal.Since(0).Skip(before), e => e.Level == "Ошибка");

        await TickAsync(coordinator);
        Assert.False(coordinator.Facts.ReconcilePending);
        Assert.Null(coordinator.Facts.PartialError);
    }

    [Fact]
    public async Task ResetConnection_ClearsConnectingTicks()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        tunnel.ConnectingTicks = 2;

        tunnel.ResetConnection(_world.Time.GetUtcNow());

        Assert.Equal(0, tunnel.ConnectingTicks);
    }

    [Fact]
    public async Task UnparsedUpstreamDnsAndRules_AreSkippedAndReportedOnce()
    {
        const string LeadingZeros = "008.008.008.008";
        Assert.False(Ipv4.TryParse(LeadingZeros, out _));
        SaveSettings(Settings() with
        {
            UpstreamDns = [LeadingZeros, "9.9.9.9"],
            Rules = [new UserRuleSetting { Cidr = "10.0.0.1/8", Target = RouteTarget.Direct }],
        });

        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        _world.Time.Advance(Coordinator.FullReconcileInterval);
        await TickAsync(coordinator);

        Assert.Null(coordinator.Facts.PartialError);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
        Assert.Equal(Ipv4.ToAddress(Ipv4.Parse("9.9.9.9")), Assert.Single(_world.Proxy.Configuration.Tunnel!.Servers).Address);
        var skipped = coordinator.BuildStatus().Warnings.Where(w => w.Code == "settings-skipped").ToList();
        Assert.Equal(2, skipped.Count);
        Assert.Single(_world.Journal.Since(0), e => e.Text.Contains(LeadingZeros, StringComparison.Ordinal));
        Assert.Single(_world.Journal.Since(0), e => e.Text.Contains("10.0.0.1/8", StringComparison.Ordinal));
    }
}
