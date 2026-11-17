using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests
{
    /// <summary>
    /// Длина свёртки вне допустимых в файле настроек раньше роняла сборку политики на каждой сверке:
    /// теперь служба берёт длину по умолчанию и строит политику.
    /// </summary>
    [Fact]
    public async Task OutOfRangeBypassPrefixInFile_PolicyIsStillBuilt()
    {
        SeedBypass("8.8.8.8/32", "8.8.8.200/32", "77.88.8.8/32");
        SaveSettings(Settings() with
        {
            GeoTarget = RouteTarget.Direct,
            BypassTarget = RouteTarget.Tunnel(_profile.Id),
            BypassAggregatePrefix = 8,
        });

        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        Assert.Equal(BypassAggregation.DefaultPrefix, coordinator.Settings.BypassAggregatePrefix);
        Assert.NotNull(coordinator.Facts.Policy);
        // Свёртка до /18 по умолчанию забирает соседа из той же подсети.
        Assert.Equal(DecisionSource.Bypass, coordinator.Facts.Policy.Classify(Ipv4.Parse("8.8.8.50")).Source);
    }
}
