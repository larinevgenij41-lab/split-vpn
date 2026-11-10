using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConnectivityCheck_RotatedAnswerAtCapacity_IsRejectedWithoutLosingIssuedAddresses(bool prewarm)
    {
        var coordinator = await StartProtectedForConnectivityCheckAsync();
        var old = Enumerable.Range(1, 4).Select(i => Ipv4.Parse($"23.215.0.{i}")).ToArray();
        if (prewarm)
        {
            await coordinator.OnConnectivityCheckResolvedAsync(coordinator.ConnectivityPinContext, old);
        }
        else
        {
            Assert.True(await ObserveConnectivityCheckAsync(coordinator, old));
        }

        var next = Ipv4.Parse("23.215.0.136");
        Assert.False(await ObserveConnectivityCheckAsync(coordinator, [old[0], next]));
        Assert.False(coordinator.Facts.RevocationPins.ContainsKey(next));
        Assert.Equal(4, ConnectivityFilters().Count);
        foreach (var address in old)
        {
            Assert.Contains(ConnectivityFilters(), f => f.Name == $"Проверка интернета Windows {Ipv4.Format(address)}:80");
        }

        // Отказ не продлевает старый набор: после TTL появляется место для нового ответа.
        _world.Time.Advance(TimeSpan.FromMinutes(prewarm ? 60 : 5) + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);
        Assert.True(await ObserveConnectivityCheckAsync(coordinator, [next]));
        Assert.Equal("Проверка интернета Windows 23.215.0.136:80", Assert.Single(ConnectivityFilters()).Name);
    }

    [Theory]
    [InlineData(5, false)]
    [InlineData(1, true)]
    public async Task ConnectivityCheck_InvalidDnsAnswer_IsRejectedAtomically(int count, bool privateAddress)
    {
        var coordinator = await StartProtectedForConnectivityCheckAsync();
        var addresses = Enumerable.Range(1, count).Select(i => Ipv4.Parse($"23.215.0.{i}")).ToList();
        if (privateAddress)
        {
            addresses.Add(Ipv4.Parse("10.1.2.3"));
        }

        Assert.False(await ObserveConnectivityCheckAsync(coordinator, addresses));
        Assert.Empty(ConnectivityFilters());
        Assert.Empty(coordinator.Facts.RevocationPins);
    }

    [Fact]
    public async Task ConnectivityCheck_DuplicateAddresses_DoNotConsumeCapacity()
    {
        var coordinator = await StartProtectedForConnectivityCheckAsync();
        var addresses = Enumerable.Range(1, 4).Select(i => Ipv4.Parse($"23.215.0.{i}")).ToArray();
        Assert.True(await ObserveConnectivityCheckAsync(coordinator, addresses.Concat(addresses).ToArray()));
        Assert.True(await ObserveConnectivityCheckAsync(coordinator, addresses));
        Assert.Equal(4, ConnectivityFilters().Count);
    }

    [Fact]
    public async Task ConnectivityCheck_ConcurrentAnswers_ReserveCapacityBeforeApplication()
    {
        var coordinator = await StartProtectedForConnectivityCheckAsync();
        var first = ObserveConnectivityCheckWithoutDrain(coordinator,
            Enumerable.Range(1, 3).Select(i => Ipv4.Parse($"23.215.0.{i}")).ToArray());
        var second = ObserveConnectivityCheckWithoutDrain(coordinator, [Ipv4.Parse("23.215.0.4"), Ipv4.Parse("23.215.0.5")]);
        await coordinator.DrainAsync();

        Assert.True(await first);
        Assert.False(await second);
        Assert.Equal(3, ConnectivityFilters().Count);
    }

    [Fact]
    public async Task ConnectivityCheck_RepeatedPrewarm_DoesNotEvictIssuedAddressesOrExceedLimit()
    {
        var coordinator = await StartProtectedForConnectivityCheckAsync();
        var old = Enumerable.Range(1, 4).Select(i => Ipv4.Parse($"23.215.0.{i}")).ToArray();
        Assert.True(await ObserveConnectivityCheckAsync(coordinator, old));
        await coordinator.OnConnectivityCheckResolvedAsync(coordinator.ConnectivityPinContext, [Ipv4.Parse("23.215.0.136")]);
        Assert.Equal(4, ConnectivityFilters().Count);
        Assert.DoesNotContain(ConnectivityFilters(), f => f.Name.Contains("23.215.0.136", StringComparison.Ordinal));
        Assert.True(await ObserveConnectivityCheckAsync(coordinator, old));
    }

    [Theory]
    [InlineData(56)]
    [InlineData(61)]
    public async Task ConnectivityCheck_PrewarmRenewsBeforeExpiry_AndRecoversAfterExpiry(int minutes)
    {
        var coordinator = await StartProtectedForConnectivityCheckAsync();
        var address = Ipv4.Parse("23.215.0.136");
        await coordinator.OnConnectivityCheckResolvedAsync(coordinator.ConnectivityPinContext, [address]);
        Assert.Single(ConnectivityFilters());
        _world.Resolver.Answers[Coordinator.ConnectivityCheckWebHost] = [address];

        _world.Time.Advance(TimeSpan.FromMinutes(minutes));
        await TickAsync(coordinator);
        await WaitForConnectivityResolutionAsync(coordinator);
        _world.Time.Advance(TimeSpan.FromMinutes(6));
        await TickAsync(coordinator);
        Assert.Equal("Проверка интернета Windows 23.215.0.136:80", Assert.Single(ConnectivityFilters()).Name);
    }

    [Fact]
    public async Task ConnectivityCheck_RefreshDnsFailure_KeepsOldPermissionAndRetries()
    {
        var coordinator = await StartProtectedForConnectivityCheckAsync();
        var address = Ipv4.Parse("23.215.0.136");
        await coordinator.OnConnectivityCheckResolvedAsync(coordinator.ConnectivityPinContext, [address]);
        _world.Time.Advance(TimeSpan.FromMinutes(56));
        await TickAsync(coordinator);
        await CompleteDialAsync(coordinator);
        Assert.Single(ConnectivityFilters());

        _world.Resolver.Answers[Coordinator.ConnectivityCheckWebHost] = [address];
        _world.Time.Advance(TimeSpan.FromMinutes(1));
        await TickAsync(coordinator);
        await WaitForConnectivityResolutionAsync(coordinator);
        _world.Time.Advance(TimeSpan.FromMinutes(5));
        await TickAsync(coordinator);
        Assert.Single(ConnectivityFilters());
    }

    [Fact]
    public async Task ConnectivityCheck_ExplicitDirectRule_IsNotSubjectToServiceAddressLimit()
    {
        SaveSettings(Settings() with { DomainRules = [new DomainRuleSetting { Suffix = Coordinator.ConnectivityCheckWebHost, Target = RouteTarget.Direct }] });
        var coordinator = await StartProtectedForConnectivityCheckAsync();
        var addresses = Enumerable.Range(1, 5).Select(i => Ipv4.Parse($"23.215.0.{i}")).ToArray();
        Assert.True(await ObserveConnectivityCheckAsync(coordinator, addresses));
        Assert.All(addresses, address => Assert.True(coordinator.Facts.Pinned.ContainsKey(address)));
    }

    private async Task<Coordinator> StartProtectedForConnectivityCheckAsync()
    {
        var coordinator = await StartAsync();
        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: true), CancellationToken.None);
        await CompleteDialAsync(coordinator);
        return coordinator;
    }

    private List<FilterSpec> ConnectivityFilters() => _world.Wfp.Group(FilterGroup.Dynamic)
        .Where(f => f.Name.StartsWith("Проверка интернета Windows", StringComparison.Ordinal)).ToList();

    private static ValueTask<bool> ObserveConnectivityCheckWithoutDrain(Coordinator coordinator, IReadOnlyList<uint> addresses) =>
        coordinator.ObservePinnedAsync(new PinnedRouteNotice(Coordinator.ConnectivityCheckWebHost, Coordinator.ConnectivityCheckWebHost,
            RouteTarget.Direct, addresses, TimeSpan.FromMinutes(5), coordinator.ConnectivityPinContext), CancellationToken.None);

    private static async Task<bool> ObserveConnectivityCheckAsync(Coordinator coordinator, IReadOnlyList<uint> addresses)
    {
        var result = ObserveConnectivityCheckWithoutDrain(coordinator, addresses);
        await coordinator.DrainAsync();
        return await result;
    }

    private async Task WaitForConnectivityResolutionAsync(Coordinator coordinator)
    {
        for (var i = 0; i < 200 && _world.Resolver.Calls == 0; i++)
        {
            await Task.Delay(10, TestContext.Current.CancellationToken);
            await coordinator.DrainAsync();
        }

        Assert.True(_world.Resolver.Calls > 0);
        await CompleteDialAsync(coordinator);
    }
}
