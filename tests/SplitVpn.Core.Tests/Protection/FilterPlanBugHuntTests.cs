using System.Net;
using System.Net.Http.Headers;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Protection;

/// <summary>Поиск ошибок 2026-11-09: участник группы «остального интернета», DNS адаптера, Retry-After.</summary>
public partial class FilterPlanTests
{
    private static readonly uint PublicAdapterDns = Ipv4.Parse("8.8.8.8");

    /// <summary>
    /// «Остальной интернет» за группой {A, B}, сеть 13.107.0.0/16 правилом назначена B. B лежит, A работает:
    /// назначенное B не должно уйти в туннель A (раньше блокировались только частные адреса B).
    /// </summary>
    [Fact]
    public void GroupCarrier_DownMember_ItsRuleNetworksDoNotGoIntoOtherMember()
    {
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            // Служба передаёт в группе только поднятых участников.
            Groups = [new TunnelGroup(GroupAb, [TunnelA])],
            DefaultTarget = RouteTarget.Group(GroupAb),
            Rules = [new UserRule(Ipv4Cidr.Parse("13.107.0.0/16"), RouteTarget.Tunnel(TunnelB))],
            ServerAddresses = [Server],
            ServiceDnsAddresses = [RouterDns],
            OnLinePrefixes = [Ipv4Cidr.Parse("192.168.1.0/24")],
        });
        var inputs = new ProtectionInputs
        {
            Policy = policy,
            PrimaryLuid = WiFi,
            Tunnels =
            [
                new TunnelInput { Id = TunnelA, Name = "Основной", Luid = Tunnel, ServerAddresses = [Server], ServesDefault = true },
                new TunnelInput { Id = TunnelB, Name = "Второй", ServerAddresses = [SecondServer], ServesDefault = true },
                new TunnelInput { Id = GroupAb, Name = "Группа", ServesDefault = true },
            ],
            ServiceDnsAddresses = [RouterDns],
            ServiceExecutablePath = ServiceExe,
            OnLinkPrefixes = [Ipv4Cidr.Parse("192.168.1.0/24")],
        };

        var filters = All(inputs);

        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(SecondNetwork, 443, Tunnel)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Tcp(SecondNetwork, 443, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(Cloudflare, 443, Tunnel)));
        Assert.False(FilterPlanBuilder.IsOutage(inputs));
    }

    /// <summary>Публичный DNS адаптера при прямом «остальном интернете»: программам открыт, кроме обычного DNS.</summary>
    [Fact]
    public void PublicAdapterDns_UnderDirectDefault_StaysOpenToApps()
    {
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            DefaultTarget = RouteTarget.Direct,
            ServerAddresses = [Server],
            ServiceDnsAddresses = [PublicAdapterDns],
            OnLinePrefixes = [Ipv4Cidr.Parse("192.168.1.0/24")],
        });
        var inputs = new ProtectionInputs
        {
            Policy = policy,
            PrimaryLuid = WiFi,
            Tunnels = [new TunnelInput { Id = TunnelA, Name = "Основной", Luid = Tunnel, ServerAddresses = [Server] }],
            ServiceDnsAddresses = [PublicAdapterDns],
            ServiceExecutablePath = ServiceExe,
            OnLinkPrefixes = [Ipv4Cidr.Parse("192.168.1.0/24")],
        };

        var filters = All(inputs);

        Assert.True(policy.DirectRanges.Contains(PublicAdapterDns));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Tcp(PublicAdapterDns, 443, WiFi)));
        Assert.Equal(FilterAction.Block, Evaluate(filters, Udp(PublicAdapterDns, 53, WiFi)));
        Assert.Equal(FilterAction.Permit, Evaluate(filters, Udp(PublicAdapterDns, 53, WiFi, ServiceExe, system: true)));
    }

    /// <summary>Под туннелем DNS адаптера по-прежнему остаётся за службой: в туннельные диапазоны он не попадает.</summary>
    [Fact]
    public void PublicAdapterDns_UnderVpnDefault_StaysServiceOnly()
    {
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            DefaultTarget = RouteTarget.Tunnel(TunnelA),
            ServerAddresses = [Server],
            ServiceDnsAddresses = [PublicAdapterDns],
        });

        Assert.False(policy.RangesFor(TunnelA).Contains(PublicAdapterDns));
        Assert.False(policy.DirectRanges.Contains(PublicAdapterDns));
    }

    [Theory]
    [InlineData(int.MaxValue, 24 * 60 * 60)]
    [InlineData(1800, 1800)]
    public void RetryAfter_IsCappedAtOneDay(int seconds, int expected)
    {
        using var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
        response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(seconds));

        Assert.Equal(TimeSpan.FromSeconds(expected), HttpFailureClassifier.RetryAfterOf(response));
    }

    [Fact]
    public void RetryAfter_FarFutureOrPastDate_DoesNotOverflow()
    {
        using var far = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
        far.Headers.RetryAfter = new RetryConditionHeaderValue(new DateTimeOffset(9999, 12, 31, 23, 59, 59, TimeSpan.Zero));
        using var past = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
        past.Headers.RetryAfter = new RetryConditionHeaderValue(DateTimeOffset.UtcNow.AddHours(-1));

        Assert.Equal(HttpFailureClassifier.MaxRetryAfter, HttpFailureClassifier.RetryAfterOf(far));
        Assert.Null(HttpFailureClassifier.RetryAfterOf(past));
    }
}
