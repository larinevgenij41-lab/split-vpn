using System.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

public sealed class DnsRouteSelectionTests
{
    private static readonly DnsRoute Local = new([new IPEndPoint(IPAddress.Loopback, 5301)], null);
    private static readonly DnsRoute Corporate = new([new IPEndPoint(IPAddress.Loopback, 5302)], null);
    private static readonly DnsRoute Default = new([new IPEndPoint(IPAddress.Loopback, 5303)], null);

    [Theory]
    [InlineData("corp.example", "corp.example", true)]
    [InlineData("host.corp.example", "corp.example", true)]
    [InlineData("host.corp.example", ".CORP.Example.", true)]
    [InlineData("notcorp.example", "corp.example", false)]
    [InlineData("corp.example.evil", "corp.example", false)]
    [InlineData("example", "corp.example", false)]
    [InlineData("host.example", "...", false)]
    [InlineData("host.example", "", false)]
    public void DomainMatch_RespectsLabelBoundaries(string name, string suffix, bool matches)
    {
        var rule = new DomainRoute(suffix, RouteTarget.Direct, Corporate);
        var configuration = new DnsProxyConfiguration { DomainRoutes = [rule] };

        Assert.Equal(matches ? rule : null, DnsProxyServer.MatchDomain(configuration, name));
    }

    [Fact]
    public void DomainMatch_UsesLongestSuffixAndFirstEqualRule()
    {
        var first = new DomainRoute("corp.example", RouteTarget.Direct, Corporate);
        var configuration = new DnsProxyConfiguration
        {
            DomainRoutes = [new("example", RouteTarget.Direct, Default), first, first with { Route = Local }],
        };

        Assert.Same(first, DnsProxyServer.MatchDomain(configuration, "host.corp.example"));
    }

    [Theory]
    [InlineData("example", false)]
    [InlineData("corp.example", false)]
    [InlineData("host.corp.example", true)]
    public void Selection_PrefersLocalOnlyWhenMoreSpecific(string localSuffix, bool localWins)
    {
        var configuration = new DnsProxyConfiguration
        {
            Mode = DnsProxyMode.Online,
            Tunnel = Default,
            Local = Local,
            LocalSuffixes = ["irrelevant", localSuffix],
            DomainRoutes = [new("corp.example", RouteTarget.Direct, Corporate)],
        };

        var choice = DnsProxyServer.SelectRoute(configuration, "host.corp.example");

        Assert.Same(localWins ? Local : Corporate, choice.Route);
        Assert.False(choice.Unavailable);
    }

    [Fact]
    public void Selection_UnavailableSpecificRuleDoesNotUseBroaderUpstream()
    {
        var configuration = new DnsProxyConfiguration
        {
            Mode = DnsProxyMode.Online,
            Tunnel = Default,
            Local = Local,
            LocalSuffixes = ["example"],
            DomainRoutes = [new("corp.example", RouteTarget.Direct, null, Unavailable: true)],
        };

        var choice = DnsProxyServer.SelectRoute(configuration, "host.corp.example");

        Assert.Null(choice.Route);
        Assert.True(choice.Unavailable);
    }
}
