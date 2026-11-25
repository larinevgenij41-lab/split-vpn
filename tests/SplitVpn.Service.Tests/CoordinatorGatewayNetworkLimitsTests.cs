using System.Globalization;
using SplitVpn.Core.Net;
using SplitVpn.Core.OpenConnect;
using SplitVpn.Core.Policy;
using SplitVpn.Service.Coordination;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Слой сетей шлюза сверх <see cref="GatewayNetworkLimits"/> отбрасывается целиком: журнал называет причину,
/// а не сообщает ложно, что шлюз сетей не прислал.
/// </summary>
public sealed partial class CoordinatorTests
{
    /// <summary>Вход через SSO и сеанс с заданными сетями шлюза.</summary>
    private async Task EstablishWithIncludesAsync(Coordinator coordinator, IReadOnlyList<string> includes)
    {
        await ConnectAsync(coordinator);
        var session = _world.AnyConnect.Last!;
        var request = Guid.NewGuid();
        session.Emit(new SsoOpenEvent(request, "https://" + Gateway + "/+CSCOE+/saml/sp/login", Gateway));
        await CompleteDialAsync(coordinator);
        session.Emit(new SsoResultEvent(request, true, null));
        _world.Inventory.AddTunnel(AnyConnectSlot);
        session.Emit(new EstablishedEvent(FakeInventory.TunnelLuid(AnyConnectSlot), "SplitVpn AC", GatewaySession() with { SplitIncludes = includes }));
        await CompleteDialAsync(coordinator);
    }

    [Fact]
    public async Task AnyConnect_RejectedGatewayLayer_JournalsReasonInsteadOfNoNetworks()
    {
        // 17 сетей /8 — каждая в поштучном пределе, но вместе больше 1/16 IPv4.
        var includes = Enumerable.Range(11, 17).Select(i => string.Create(CultureInfo.InvariantCulture, $"{i}.0.0.0/8")).ToList();
        var coordinator = await StartWithAnyConnectAsync();
        await EstablishWithIncludesAsync(coordinator, includes);

        var journal = _world.Journal.Since(0).ToList();
        Assert.Contains(journal, e => e.Level == "Предупреждение"
            && e.Text.Contains("сети шлюза отброшены целиком", StringComparison.Ordinal)
            && e.Text.Contains("покрывают", StringComparison.Ordinal));
        Assert.DoesNotContain(journal, e => e.Text.Contains("шлюз не прислал сетей", StringComparison.Ordinal));
        Assert.DoesNotContain(_world.Routes.On(FakeInventory.TunnelLuid(AnyConnectSlot)), r => r.Contains(Ipv4.Parse("11.1.2.3")));
        Assert.NotEqual(DecisionSource.ServerNetwork, coordinator.Facts.Policy!.Classify(Ipv4.Parse("11.1.2.3")).Source);
        // Не только журнал: предупреждение видно на главной.
        Assert.Contains(coordinator.BuildStatus().Warnings, w => w.Code == "gateway-networks-rejected"
            && w.Text.Contains("отброшены целиком", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnyConnect_NoGatewayNetworks_JournalsNoNetworks()
    {
        var coordinator = await StartWithAnyConnectAsync();
        await EstablishWithIncludesAsync(coordinator, []);

        var journal = _world.Journal.Since(0).ToList();
        Assert.Contains(journal, e => e.Level == "Предупреждение" && e.Text.Contains("шлюз не прислал сетей", StringComparison.Ordinal));
        Assert.DoesNotContain(journal, e => e.Text.Contains("отброшены целиком", StringComparison.Ordinal));
        Assert.DoesNotContain(coordinator.BuildStatus().Warnings, w => w.Code == "gateway-networks-rejected");
    }
}
