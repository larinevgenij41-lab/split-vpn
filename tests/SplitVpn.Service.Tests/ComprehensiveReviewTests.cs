using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;
using SplitVpn.Core.Policy;
using SplitVpn.Core.State;
using SplitVpn.Core.Update;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;
using SplitVpn.Core.Net;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.Operations;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests
{
    [Fact]
    public async Task Review_MirrorEtagMustNotBeSentToPrimary()
    {
        SaveSettings(Settings() with { AppUpdate = new AppUpdateSettings { AutoDownload = false, ManifestMirrors = ["https://mirror.example/update.json"] } });
        var primaryRecovered = false;
        var source = new UpdateSource(Manifest(expires: "2027-01-01T00:00:00Z"));
        source.Override = request =>
        {
            if (!request.RequestUri!.AbsoluteUri.EndsWith("update.json", StringComparison.Ordinal)) { return null; }
            if (request.RequestUri.Host != "mirror.example" && !primaryRecovered)
            { return new HttpResponseMessage(System.Net.HttpStatusCode.ServiceUnavailable); }
            var response = new HttpResponseMessage(primaryRecovered && request.Headers.IfNoneMatch.Count > 0
                ? System.Net.HttpStatusCode.NotModified : System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(Manifest(primaryRecovered ? "0.9.1" : "0.9.0", expires: "2027-01-01T00:00:00Z")),
            };
            response.Headers.ETag = new System.Net.Http.Headers.EntityTagHeaderValue("\"same-opaque-tag\"");
            return response;
        };
        var coordinator = await UpdatingAsync(source);
        await TickAsync(coordinator);
        await PumpAsync(coordinator);
        Assert.Equal("0.9.0", Status(coordinator).AvailableVersion);
        primaryRecovered = true;
        _world.Time.Advance(TimeSpan.FromDays(2));
        await TickAsync(coordinator);
        await PumpAsync(coordinator);
        Assert.Equal("0.9.1", Status(coordinator).AvailableVersion);
    }

    [Fact]
    public async Task Review_PskHangupFailureMustRetryReconnect()
    {
        SaveSettings(Settings() with { Profiles = [_profile with { Protocol = VpnProtocol.L2tpIpsec }] });
        _world.Secrets.Save(_profile.Id, "old-key", SecretKind.PreSharedKey);
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var dials = _world.Ras.Dials;
        _world.Ras.HangUpFailure = new IOException("review: hangup failed");
        await Assert.ThrowsAsync<IOException>(() => coordinator.HandleRequestAsync(new SetPreSharedKeyRequest(_profile.Id, "new-key"), CancellationToken.None));
        _world.Ras.HangUpFailure = null;
        _world.Time.Advance(TimeSpan.FromMinutes(2));
        await TickAsync(coordinator);
        Assert.True(_world.Ras.Dials > dials);
        Assert.Equal("new-key", _world.Ras.SavedKey);
    }

    [Fact]
    public async Task Review_DhcpDnsChangeMustTriggerImmediateReconcile()
    {
        SaveSettings(Settings() with { LocalDnsSuffixes = ["office.example"] });
        var inventory = new ReviewInventory(_world.Inventory);
        var coordinator = new Coordinator(_world.Dependencies() with { Inventory = inventory });
        await coordinator.StartupAsync(CancellationToken.None);
        await CompleteDialAsync(coordinator);
        await ConnectAsync(coordinator);
        await TickAsync(coordinator);
        inventory.Changed = true;
        _world.Time.Advance(TimeSpan.FromSeconds(2));
        await TickAsync(coordinator);
        Assert.Contains(_world.Proxy.Configuration.Local!.Servers, s => s.Address.ToString() == "192.168.1.53");
    }

    private sealed class ReviewInventory(INetInventory inner) : INetInventory
    {
        public bool Changed { get; set; }
        public NetSnapshot Capture()
        {
            var snapshot = inner.Capture();
            return snapshot with
            {
                Adapters = snapshot.Adapters.Select(a => a.Luid == FakeWorld.WiFiLuid
                    // После настройки посредника Capture видит loopback, а сменившийся DHCP DNS - только реестр.
                    ? a with { DnsServers = [Ipv4.Parse("127.0.0.1")] } : a).ToList(),
            };
        }
        public IReadOnlyList<uint> DhcpDnsServers(Guid interfaceGuid) => Changed && interfaceGuid == FakeWorld.WiFiGuid
            ? [Ipv4.Parse("192.168.1.53")] : inner.DhcpDnsServers(interfaceGuid);
    }

    [Fact]
    public async Task Review_DisablingAutoDownloadDuringCheckMustBeRespected()
    {
        var source = new UpdateSource(Manifest());
        var coordinator = await UpdatingAsync(source);
        using var gate = new ManualResetEventSlim();
        source.Override = HoldManifest(gate);
        await coordinator.TickAsync(CancellationToken.None);
        await coordinator.HandleRequestAsync(new SaveSettingsRequest(coordinator.Settings with
        {
            AppUpdate = coordinator.Settings.AppUpdate with { AutoDownload = false },
        }), CancellationToken.None);
        gate.Set();
        await PumpAsync(coordinator);
        Assert.Equal(0, source.PackageCalls);
    }

    [Fact]
    public async Task Review_FullManifestMustNotResetDownloadRetryCounter()
    {
        var source = new UpdateSource(Manifest())
        {
            Override = request => request.RequestUri!.AbsoluteUri.EndsWith(".msi", StringComparison.Ordinal)
                ? new HttpResponseMessage(System.Net.HttpStatusCode.ServiceUnavailable) : null,
        };
        var coordinator = await UpdatingAsync(source);
        await TickAsync(coordinator);
        await PumpAsync(coordinator);
        var store = new UpdateStore(_world.Paths.Update);
        Assert.Equal(1, store.LoadState().DownloadAttempts);
        _world.Time.Advance(TimeSpan.FromDays(2));
        await TickAsync(coordinator);
        await PumpAsync(coordinator);
        Assert.Equal(2, store.LoadState().DownloadAttempts);
    }

    [Fact]
    public async Task Review_IncompleteDnsRestoreMustReportPartialFailure()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        _world.Dns.FailIpv6Restore.Add(FakeWorld.WiFiGuid);
        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: false), CancellationToken.None);
        Assert.Equal(ConnectionState.PartiallyApplied, coordinator.DeriveState());
    }

    [Fact]
    public async Task Review_ExplicitLocalDnsMustPrecedeProvider()
    {
        SaveSettings(Settings() with { LocalDnsServer = "10.2.0.53", LocalDnsSuffixes = ["office.example"] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.Equal("10.2.0.53", _world.Proxy.Configuration.Local!.Servers[0].Address.ToString());
    }

    [Theory]
    [InlineData("block")]
    [InlineData("direct")]
    [InlineData("tunnel")]
    public async Task Review_GatewayMustNotBypassParentRule(string kind)
    {
        var target = kind switch
        {
            "block" => RouteTarget.Blocked,
            "direct" => RouteTarget.Direct,
            _ => RouteTarget.Tunnel(_profile.Id),
        };
        var coordinator = await StartWithAnyConnectAsync(Settings() with
        {
            Profiles = [_profile, _anyConnect],
            DomainRules = [new DomainRuleSetting { Suffix = "example.org", Target = target }],
        });
        await EstablishAsync(coordinator);
        var route = DnsProxyServer.MatchDomain(_world.Proxy.Configuration, "host.office.example.org");
        Assert.Equal(target, route!.Target);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1602)]
    [InlineData(null)]
    public async Task Review_OldInstallerExitMustNotCompleteNewAttempt(int? exitCode)
    {
        _world.HttpHandler = new UpdateSource(Manifest());
        var old = new TaskCompletionSource<int?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var current = new TaskCompletionSource<int?>();
        var coordinator = new Coordinator(_world.Dependencies() with
        {
            WaitForProcessAsync = (id, _) => id == 101 ? old.Task : current.Task,
        });
        await coordinator.StartupAsync(CancellationToken.None);
        await CompleteDialAsync(coordinator);
        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: false), CancellationToken.None);
        await TickAsync(coordinator);
        await PumpAsync(coordinator);
        var first = coordinator.HandleRequestAsync(new InstallUpdateRequest("0.9.0"), CancellationToken.None);
        await PumpAsync(coordinator, first);
        await coordinator.HandleRequestAsync(new UpdateStartedRequest(101), CancellationToken.None);
        _world.Time.Advance(TimeSpan.FromMinutes(16));
        await TickAsync(coordinator);
        var second = coordinator.HandleRequestAsync(new InstallUpdateRequest("0.9.0"), CancellationToken.None);
        await PumpAsync(coordinator, second);
        Assert.True((await second).Ok);
        await coordinator.HandleRequestAsync(new UpdateStartedRequest(202), CancellationToken.None);
        old.SetResult(exitCode);
        for (var i = 0; i < 20; i++) { await Task.Delay(5, TestContext.Current.CancellationToken); await coordinator.DrainAsync(); }
        Assert.Equal(UpdatePhase.Installing, Status(coordinator).Phase);
    }
}
