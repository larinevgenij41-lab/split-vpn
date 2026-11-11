using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.Operations;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests
{
    [Theory]
    [InlineData("unused", false)]
    [InlineData("folder", false)]
    [InlineData("default", true)]
    [InlineData("domain", true)]
    [InlineData("cidr", true)]
    [InlineData("geo", true)]
    [InlineData("bypass-empty", false)]
    public async Task UncleanDrop_OnlyUsedGroupCanOpenFallback(string assignment, bool useGroup)
    {
        var second = SecondProfile();
        var group = new TunnelGroupSetting { Name = "Резервная", Members = [_profile.Id, second.Id], Mode = BalanceMode.Failover };
        SaveSettings(Settings() with
        {
            Profiles = [_profile, second], Groups = [group],
            DefaultTarget = assignment == "default" ? RouteTarget.Group(group.Id) : RouteTarget.Tunnel(_profile.Id),
            GeoTarget = assignment == "geo" ? RouteTarget.Group(group.Id) : RouteTarget.Direct,
            BypassTarget = assignment == "bypass-empty" ? RouteTarget.Group(group.Id) : null,
            DomainRules = assignment == "domain" ? [new DomainRuleSetting { Suffix = "example.org", Target = RouteTarget.Group(group.Id) }] : [],
            Rules = assignment == "cidr" ? [new UserRuleSetting { Cidr = "93.184.216.0/24", Target = RouteTarget.Group(group.Id) }] : [],
            RoutingFolders = assignment == "folder" ? [new RoutingFolderSetting { Name = "Пустая папка", Target = RouteTarget.Group(group.Id) }] : [],
        });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.True(coordinator.Facts.Tunnels[second.Id].Verified);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        _world.Probes.TunnelWorks = false;
        _world.Ras.Drop(Coordinator.EntryNameFor(_profile));
        await TickAsync(coordinator);
        Assert.NotNull(tunnel.UncleanDropUtc);
        _world.Time.Advance(tunnel.NextDialAt - _world.Time.GetUtcNow() + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);
        Assert.True(tunnel.IsUp);
        for (var i = 0; i < Coordinator.VerifyProbeAttempts && tunnel.VerifyFailures == 0; i++)
        {
            _world.Time.Advance(Coordinator.VerifyProbeInterval + TimeSpan.FromMilliseconds(1));
            await TickAsync(coordinator);
        }

        Assert.Equal(useGroup ? 1 : 0, tunnel.VerifyFailures);
    }

    [Fact]
    public async Task ConnectivityCheck_ChangingPrimaryRefreshesPinsAndFreesCapacity()
    {
        var inventory = new TwoPhysicalAdapters(_world.Inventory);
        SaveSettings(Settings() with { Profiles = [Pinned(FakeWorld.WiFiGuid, null)] });
        var coordinator = new Coordinator(_world.Dependencies() with { Inventory = inventory });
        await coordinator.StartupAsync(CancellationToken.None);
        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: true), CancellationToken.None);
        await CompleteDialAsync(coordinator);
        var network = coordinator.Facts.NetworkFingerprint;
        Assert.Equal(FakeWorld.WiFiLuid, coordinator.Facts.Primary!.Luid);
        var oldContext = coordinator.ConnectivityPinContext;
        await coordinator.OnConnectivityCheckResolvedAsync(oldContext,
            Enumerable.Range(1, 4).Select(i => Ipv4.Parse($"23.215.0.{i}")).ToArray());
        _world.Resolver.Answers[Coordinator.ConnectivityCheckWebHost] = [Ipv4.Parse("23.215.0.136")];
        _world.Time.Advance(TimeSpan.FromSeconds(31));

        var changed = coordinator.Settings with { Profiles = [Pinned(TwoPhysicalAdapters.EthernetGuid, null)] };
        Assert.True((await coordinator.HandleRequestAsync(new SaveSettingsRequest(changed), CancellationToken.None)).Ok);
        await CompleteDialAsync(coordinator);
        Assert.Equal(TwoPhysicalAdapters.EthernetLuid, coordinator.Facts.Primary!.Luid);
        Assert.Equal(network, coordinator.Facts.NetworkFingerprint);
        Assert.NotEqual(oldContext, coordinator.ConnectivityPinContext);
        await WaitForConnectivityResolutionAsync(coordinator);
        Assert.True(await ObserveConnectivityCheckAsync(coordinator, [Ipv4.Parse("23.215.0.136")]));
        Assert.Equal("Проверка интернета Windows 23.215.0.136:80", Assert.Single(ConnectivityFilters()).Name);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConnectivityCheck_OldPrimaryLookupIsRejectedAfterSwitch(bool returnToWifi)
    {
        var inventory = new TwoPhysicalAdapters(_world.Inventory);
        SaveSettings(Settings() with { Profiles = [Pinned(FakeWorld.WiFiGuid, null)] });
        var coordinator = new Coordinator(_world.Dependencies() with { Inventory = inventory });
        await coordinator.StartupAsync(CancellationToken.None);
        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: true), CancellationToken.None);
        await CompleteDialAsync(coordinator);
        var oldContext = coordinator.ConnectivityPinContext;
        Assert.True((await coordinator.HandleRequestAsync(new SaveSettingsRequest(coordinator.Settings with
        {
            Profiles = [Pinned(TwoPhysicalAdapters.EthernetGuid, null)],
        }), CancellationToken.None)).Ok);
        Assert.Equal(TwoPhysicalAdapters.EthernetLuid, coordinator.Facts.Primary!.Luid);
        if (returnToWifi)
        {
            Assert.True((await coordinator.HandleRequestAsync(new SaveSettingsRequest(coordinator.Settings with
            {
                Profiles = [Pinned(FakeWorld.WiFiGuid, null)],
            }), CancellationToken.None)).Ok);
        }

        Assert.NotEqual(oldContext, coordinator.ConnectivityPinContext);

        // Отложенный ответ разрешения, начатого через Wi-Fi до выбора Ethernet.
        await coordinator.OnConnectivityCheckResolvedAsync(oldContext, [Ipv4.Parse("23.215.0.1")]);
        Assert.DoesNotContain(ConnectivityFilters(), f => f.Name == "Проверка интернета Windows 23.215.0.1:80");
    }

    [Fact]
    public async Task ConnectivityCheck_DnsChangeInvalidatesOldContextAndPreservesOtherOwners()
    {
        SaveSettings(Settings() with { DomainRules = [new DomainRuleSetting { Suffix = "other.example", Target = RouteTarget.Direct }] });
        var coordinator = await StartProtectedForConnectivityCheckAsync();
        var oldContext = coordinator.ConnectivityPinContext;
        var address = Ipv4.Parse("23.215.0.1");
        await coordinator.OnConnectivityCheckResolvedAsync(oldContext, [address]);
        var pin = coordinator.ObservePinnedAsync(new SplitVpn.Windows.Dns.PinnedRouteNotice("other.example", "other.example",
            RouteTarget.Direct, [address], TimeSpan.FromMinutes(30)), CancellationToken.None);
        await coordinator.DrainAsync();
        Assert.True(await pin);

        Assert.True((await coordinator.HandleRequestAsync(new SaveSettingsRequest(coordinator.Settings with
        {
            LocalDnsServer = "9.9.9.9",
        }), CancellationToken.None)).Ok);

        Assert.NotEqual(oldContext, coordinator.ConnectivityPinContext);
        Assert.Equal(RouteTarget.Direct, coordinator.Facts.Pinned[address].Target);
        await coordinator.OnConnectivityCheckResolvedAsync(oldContext, [Ipv4.Parse("23.215.0.2")]);
        Assert.Empty(ConnectivityFilters());
    }

    [Fact]
    public async Task ConnectivityCheck_OffThenOnRejectsPreviousLookup()
    {
        var coordinator = await StartProtectedForConnectivityCheckAsync();
        var oldContext = coordinator.ConnectivityPinContext;
        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: false), CancellationToken.None);
        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: true), CancellationToken.None);
        Assert.NotEqual(oldContext, coordinator.ConnectivityPinContext);
        await coordinator.OnConnectivityCheckResolvedAsync(oldContext, [Ipv4.Parse("23.215.0.1")]);
        Assert.Empty(ConnectivityFilters());
    }

    [Fact]
    public async Task ConnectivityCheck_RemovingExplicitDirectRuleDiscardsItsUnboundedPins()
    {
        SaveSettings(Settings() with { DomainRules = [new DomainRuleSetting { Suffix = Coordinator.ConnectivityCheckWebHost, Target = RouteTarget.Direct }] });
        var coordinator = await StartProtectedForConnectivityCheckAsync();
        Assert.True(await ObserveConnectivityCheckAsync(coordinator,
            Enumerable.Range(1, 5).Select(i => Ipv4.Parse($"23.215.0.{i}")).ToArray()));

        Assert.True((await coordinator.HandleRequestAsync(new SaveSettingsRequest(coordinator.Settings with { DomainRules = [] }), CancellationToken.None)).Ok);
        Assert.Empty(coordinator.Facts.Pinned);
        Assert.Empty(ConnectivityFilters());
        Assert.True(await ObserveConnectivityCheckAsync(coordinator, [Ipv4.Parse("23.215.0.136")]));
        Assert.Single(ConnectivityFilters());
    }

    private sealed class TwoPhysicalAdapters(FakeInventory inner) : INetInventory
    {
        internal static readonly Guid EthernetGuid = Guid.NewGuid();
        internal const ulong EthernetLuid = 88;

        public NetSnapshot Capture()
        {
            var original = inner.Capture();
            var ethernet = new AdapterCandidate
            {
                InterfaceGuid = EthernetGuid, Luid = EthernetLuid, InterfaceIndex = 88,
                Name = "Ethernet", Description = "Проводной адаптер", IsHardware = true, IsUp = true, IfType = 6,
                DefaultGateway = Ipv4.Parse("10.20.30.1"), DefaultRouteMetric = 45,
                Addresses = [Ipv4.Parse("10.20.30.2")], DnsServers = [Ipv4.Parse("10.20.30.1")],
                OnLinkPrefixes = [Ipv4Cidr.Parse("10.20.30.0/24")],
            };
            return new NetSnapshot(original.Adapters.Append(ethernet).ToList(), []);
        }

        public IReadOnlyList<uint> DhcpDnsServers(Guid interfaceGuid) =>
            interfaceGuid == EthernetGuid ? [Ipv4.Parse("10.20.30.1")] : inner.DhcpDnsServers(interfaceGuid);
    }
}
