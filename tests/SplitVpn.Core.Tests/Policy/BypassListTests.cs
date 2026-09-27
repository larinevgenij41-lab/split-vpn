using SplitVpn.Core.Geo;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Policy;

/// <summary>
/// Список обхода блокировок: слой поверх RU-базы и ниже правил пользователя. Заблокированный ресурс
/// на российском адресе должен уходить в туннель, иначе он так и останется недоступен.
/// </summary>
public class BypassListTests
{
    private static readonly Guid TunnelId = new("aaaaaaaa-0000-0000-0000-000000000001");
    private static readonly RouteTarget ToTunnel = RouteTarget.Tunnel(TunnelId);

    private static readonly uint BlockedInsideRussia = Ipv4.Parse("77.88.8.8");
    private static readonly uint RussianAddress = Ipv4.Parse("77.88.55.242");

    [Fact]
    public void BypassOverridesGeo_ButNotUserRule()
    {
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            DefaultTarget = ToTunnel,
            GeoTarget = RouteTarget.Direct,
            Geo = Set("77.88.0.0/16"),
            BypassTarget = ToTunnel,
            Bypass = Set("77.88.8.0/24"),
            Rules = [new UserRule(Ipv4Cidr.Parse("77.88.8.8/32"), RouteTarget.Direct)],
        });

        // Российский адрес вне списка обхода идёт напрямую.
        Assert.Equal(Decision.Direct, policy.Classify(RussianAddress).Decision);
        Assert.Equal(DecisionSource.Geo, policy.Classify(RussianAddress).Source);

        // Адрес из списка обхода — в туннель, но ручное правило на него важнее обоих списков.
        Assert.Equal(Decision.Direct, policy.Classify(BlockedInsideRussia).Decision);
        Assert.Equal(DecisionSource.UserRule, policy.Classify(BlockedInsideRussia).Source);
        Assert.Equal(Decision.Vpn, policy.Classify(Ipv4.Parse("77.88.8.9")).Decision);
        Assert.Equal(DecisionSource.Bypass, policy.Classify(Ipv4.Parse("77.88.8.9")).Source);
    }

    /// <summary>
    /// Цель списка совпадает с «остальным интернетом» — и слой всё равно нужен: он вытаскивает
    /// заблокированный адрес из RU-базы, которая увела бы его напрямую.
    /// </summary>
    [Fact]
    public void BypassWithDefaultTarget_StillRescuesAddressFromGeo()
    {
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            DefaultTarget = ToTunnel,
            GeoTarget = RouteTarget.Direct,
            Geo = Set("77.88.0.0/16"),
            BypassTarget = ToTunnel,
            Bypass = Set("77.88.8.0/24"),
        });

        Assert.Equal(Decision.Vpn, policy.Classify(BlockedInsideRussia).Decision);
        Assert.Equal(TunnelId, policy.Classify(BlockedInsideRussia).Tunnel);
        Assert.Equal(Decision.Direct, policy.Classify(RussianAddress).Decision);
    }

    /// <summary>Пустой список ничего не меняет: до первой загрузки маршрутизация прежняя.</summary>
    [Fact]
    public void EmptyBypassList_ChangesNothing()
    {
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            DefaultTarget = ToTunnel,
            GeoTarget = RouteTarget.Direct,
            Geo = Set("77.88.0.0/16"),
            BypassTarget = ToTunnel,
        });

        Assert.Equal(DecisionSource.Geo, policy.Classify(BlockedInsideRussia).Source);
    }

    [Fact]
    public void BypassList_HasItsOwnValidationFloor()
    {
        Assert.Equal(1000, GeoValidationOptions.For(GeoListKind.Geo).MinV4Count);
        Assert.Equal(100, GeoValidationOptions.For(GeoListKind.Bypass).MinV4Count);
    }

    [Fact]
    public void BypassSettings_DefaultToReFilterAndNoTarget()
    {
        var settings = SettingsSerializer.Normalize(new AppSettings());

        Assert.Null(settings.BypassTarget);
        Assert.Equal(GeoSourceKind.ReFilter, settings.BypassUpdate.Source);
        Assert.True(settings.BypassUpdate.AutoUpdate);
        Assert.All(new ReFilterSource().Urls, url => Assert.Equal(Uri.UriSchemeHttps, url.Scheme));
    }

    /// <summary>RU-базу нельзя подсунуть в слой обхода: её сети перекрыли бы саму RU-базу.</summary>
    [Fact]
    public void BypassSource_CannotBeTheRussianBase()
    {
        var settings = SettingsSerializer.Normalize(new AppSettings
        {
            BypassUpdate = new GeoUpdateSettings { Source = GeoSourceKind.Loyalsoldier },
        });

        Assert.Equal(GeoSourceKind.ReFilter, settings.BypassUpdate.Source);
    }

    [Fact]
    public void BypassTarget_FallsBackWhenTunnelIsGone()
    {
        var settings = ConnectionEdits.Retarget(new AppSettings
        {
            Profiles = [],
            BypassTarget = ToTunnel,
        });

        Assert.Equal(RouteTarget.Direct, settings.BypassTarget);
    }

    /// <summary>
    /// Реальные объёмы: RU-база около 13 тысяч сетей, список обхода блокировок — около 21 тысячи
    /// диапазонов после слияния (живой ipsum.lst). Два слоя вместе не должны ронять скорость сверки.
    /// </summary>
    [Fact]
    public void FullSizeGeoAndBypass_CompileQuickly()
    {
        var random = new Random(13);
        var geo = RangeSet.From(Enumerable.Range(0, 13_000)
            .Select(_ => new Ipv4Cidr((uint)random.NextInt64(0x01000000, 0xDF000000) & Ipv4Cidr.MaskOf(24), 24)));
        var bypass = RangeSet.From(Enumerable.Range(0, 21_000)
            .Select(_ => new Ipv4Cidr((uint)random.NextInt64(0x01000000, 0xDF000000), 32)));
        var input = new PolicyInput
        {
            DefaultTarget = ToTunnel,
            GeoTarget = RouteTarget.Direct,
            Geo = geo,
            BypassTarget = ToTunnel,
            Bypass = bypass,
        };

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var policy = PolicyCompiler.Compile(input);
        stopwatch.Stop();

        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(3), $"Компиляция заняла {stopwatch.Elapsed}");
        Assert.True(policy.SegmentCount > 0);
    }

    private static RangeSet Set(params string[] cidrs) =>
        RangeSet.From(cidrs.Select(c => Ipv4Cidr.Parse(c).ToRange()));
}
