using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Protection;

/// <summary>«VPN поверх SSH»: процессу движка открыт только свой сервер, в туннеле нет UDP.</summary>
public partial class FilterPlanTests
{
    private const string EngineExe = @"C:\Program Files\SplitVpn\sing-box.exe";
    private const ushort SshPort = 2222;

    /// <summary>Основной туннель - «VPN поверх SSH»; второй (AnyConnect) поднят рядом, как корпоративный.</summary>
    private static ProtectionInputs SshInputs(ulong? tunnel, bool session = true, string engine = EngineExe)
    {
        var baseline = Inputs(tunnel, SecondTunnel);
        return baseline with
        {
            SshEngineExecutablePath = engine,
            Tunnels =
            [
                .. baseline.Tunnels.Select(t => t.ServesDefault
                    ? t with { Protocol = VpnProtocol.SshVpn, ServerPort = SshPort, EngineServerAddress = session ? Server : null }
                    : t with { Protocol = VpnProtocol.AnyConnect }),
            ],
        };
    }

    private static Packet Engine(uint remote, byte protocol, ushort port, ulong luid) =>
        Packet.V4(remote, protocol, port, luid) with { AppPath = EngineExe };

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void SshEngine_ReachesOnlyItsServerOverTcpOnPrimaryAdapter(bool tunnelUp)
    {
        var filters = All(SshInputs(tunnelUp ? Tunnel : null));

        Assert.Equal(FilterAction.Permit, Evaluate(filters, Engine(Server, FilterPlanBuilder.ProtocolTcp, SshPort, WiFi)));

        // Другой порт, другой протокол, другой адаптер - даже к своему серверу.
        Assert.Equal(FilterAction.Block, Evaluate(filters, Engine(Server, FilterPlanBuilder.ProtocolTcp, 443, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Engine(Server, FilterPlanBuilder.ProtocolUdp, SshPort, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Engine(Server, FilterPlanBuilder.ProtocolTcp, SshPort, Radmin)));

        // Собственный адаптер: движок не замкнётся сам на себя, даже если маршрут до сервера пропал.
        Assert.Equal(FilterAction.Block, Evaluate(filters, Engine(Server, FilterPlanBuilder.ProtocolTcp, SshPort, Tunnel)));

        // То, что другим программам открыто напрямую, движку закрыто: адрес из RU-базы и сервер соседнего туннеля.
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Yandex, 443, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Engine(Yandex, FilterPlanBuilder.ProtocolTcp, 443, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Engine(Yandex, FilterPlanBuilder.ProtocolTcp, SshPort, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Engine(SecondServer, FilterPlanBuilder.ProtocolTcp, 443, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Engine(SecondServer, FilterPlanBuilder.ProtocolUdp, 443, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Engine(RouterDns, FilterPlanBuilder.ProtocolUdp, 53, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Packet.V6("2606:4700:4700::1111", FilterPlanBuilder.ProtocolTcp, 443, WiFi) with { AppPath = EngineExe }));
    }

    [Fact]
    public void SshEngine_DomainPinDoesNotOpenAnythingForTheEngine()
    {
        var pinned = Cloudflare;
        var baseline = SshInputs(Tunnel);
        var inputs = baseline with
        {
            Policy = Inputs(Tunnel, SecondTunnel, pins: [new SplitVpn.Core.Policy.PinnedHost(pinned, SplitVpn.Core.Policy.RouteTarget.Direct)]).Policy,
        };
        var filters = All(inputs);

        // Доменное правило «напрямую» (вес 14) действует для программ, но не для движка.
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(pinned, 443, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Engine(pinned, FilterPlanBuilder.ProtocolTcp, 443, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Engine(pinned, FilterPlanBuilder.ProtocolTcp, SshPort, WiFi)));
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public void SshEngine_WithoutSessionOrPrimaryAdapter_IsBlockedCompletely(bool session, bool primary)
    {
        var inputs = SshInputs(null, session);
        var filters = All(primary ? inputs : inputs with { PrimaryLuid = null });

        Assert.Equal(FilterAction.Block, Evaluate(filters, Engine(Server, FilterPlanBuilder.ProtocolTcp, SshPort, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Engine(Yandex, FilterPlanBuilder.ProtocolTcp, 443, WiFi)));
        Assert.Single(FilterPlanBuilder.BuildRuntime(primary ? inputs : inputs with { PrimaryLuid = null }), f => f.Conditions.OfType<AppIdCondition>().Any(a => a.ExecutablePath == EngineExe));
    }

    /// <summary>Файла движка нет: WFP не выдаёт идентификатор отсутствующего файла, и фильтр с ним сорвал бы применение всей группы.</summary>
    [Fact]
    public void SshEngine_MissingExecutable_BuildsNoAppFilters()
    {
        var runtime = FilterPlanBuilder.BuildRuntime(SshInputs(Tunnel, engine: ""));
        Assert.DoesNotContain(runtime, f => f.Conditions.OfType<AppIdCondition>().Any(a => a.ExecutablePath != ServiceExe));
        Assert.Contains(runtime, f => f.Name.Contains("без UDP", StringComparison.Ordinal));
    }

    [Fact]
    public void SshEngine_FiltersLiveInRuntimeGroup_AndUseSingleAddressCondition()
    {
        var engine = FilterPlanBuilder.BuildRuntime(SshInputs(Tunnel))
            .Where(f => f.Conditions.OfType<AppIdCondition>().Any(a => a.ExecutablePath == EngineExe)).ToList();

        Assert.Equal(5, engine.Count);
        Assert.All(engine, f =>
        {
            Assert.Equal(FilterGroup.Runtime, f.Group);
            Assert.Equal(FilterAction.Block, f.Action);
            Assert.Equal(FilterPlanBuilder.WeightEngineGuard, f.Weight);
        });

        // Одно условие «адрес не равен» на весь набор: два таких условия WFP объединил бы через «или».
        Assert.Single(engine.SelectMany(f => f.Conditions).OfType<RemoteAddressNotV4>());

        // Условие IPv4-адреса стоит только в фильтре IPv4: на слое IPv6 оно сорвало бы транзакцию.
        Assert.All(engine.Where(f => f.Conditions.Any(c => c is RemoteAddressNotV4)), f => Assert.Equal(FilterFamily.V4, f.Family));
        Assert.Contains(engine, f => f.Family == FilterFamily.V6 && f.Conditions.Count == 1);
    }

    [Fact]
    public void SshTunnel_BlocksUdpInsideTunnel_ButNotTcpAndNotNeighbourTunnel()
    {
        var filters = All(SshInputs(Tunnel));

        // QUIC и любой другой UDP в туннеле SSH получают отказ сразу; TCP идёт.
        Assert.Equal(FilterAction.Block, Evaluate(filters, Udp(Cloudflare, 443, Tunnel)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Udp(Cloudflare, 3478, Tunnel)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Cloudflare, 443, Tunnel)));

        // Соседний туннель (AnyConnect) свой UDP сохраняет.
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Udp(SecondNetwork, 443, SecondTunnel)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(SecondNetwork, 443, SecondTunnel)));
    }

    [Fact]
    public void SshTunnel_DomainPinnedToTunnel_StillHasNoUdp()
    {
        var pinned = SplitVpn.Core.Net.Ipv4.Parse("77.88.55.60");
        var policy = Inputs(Tunnel, SecondTunnel, pins: [new SplitVpn.Core.Policy.PinnedHost(pinned, SplitVpn.Core.Policy.RouteTarget.Tunnel(TunnelA))]).Policy;
        var filters = All(SshInputs(Tunnel) with { Policy = policy });

        // Доменное разрешение (вес 14) пропускает любой протокол; запрет UDP стоит выше.
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(pinned, 443, Tunnel)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Udp(pinned, 443, Tunnel)));
    }

    [Fact]
    public void SshTunnel_ServiceDnsOverTcpPassesThroughTunnel()
    {
        var inputs = SshInputs(Tunnel);
        var filters = All(inputs with
        {
            Tunnels = [.. inputs.Tunnels.Select(t => t.Protocol == VpnProtocol.SshVpn ? t with { DnsAddresses = [Cloudflare] } : t)],
        });
        var query = Tcp(Cloudflare, 53, Tunnel) with { AppPath = ServiceExe, IsSystem = true };

        Assert.Equal(FilterAction.Permit, Evaluate(filters, query));
        Assert.Equal(FilterAction.Block, Evaluate(filters, query with { Protocol = FilterPlanBuilder.ProtocolUdp }));
    }
}
