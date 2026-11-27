using SplitVpn.Core.Ipc;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Путь в сеть для загрузки списков и обновлений: при «остальной интернет напрямую» он открыт и без проверенного
/// опорного туннеля, а при «остальной интернет через VPN» - только через проверенный туннель.
/// </summary>
public sealed partial class CoordinatorTests
{
    /// <summary>Опорный туннель не поднимается, а остальной интернет идёт напрямую: база обновляется, команда не отвечает Busy.</summary>
    [Fact]
    public async Task NetworkPath_DefaultDirect_OpenWhileAnchorTunnelDown()
    {
        SaveSettings(Settings() with
        {
            DefaultTarget = RouteTarget.Direct,
            GeoUpdate = new GeoUpdateSettings { Source = GeoSourceKind.CustomUrl, CustomUrl = GeoUrlA, AutoUpdate = false },
            BypassUpdate = new GeoUpdateSettings { AutoUpdate = false },
            AppUpdate = new AppUpdateSettings { AutoCheck = false },
        });
        _world.HttpHandler = new GeoHttpSource();
        for (var i = 0; i < 10; i++)
        {
            _world.Ras.Results.Enqueue(new RasDialResult(false, null, 809, "Нет ответа"));
        }

        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];

        Assert.Equal(Intent.Connected, coordinator.State.Intent);
        Assert.False(tunnel.Verified);
        Assert.True(coordinator.NetworkPathAllowed);

        var request = coordinator.SubmitAsync(new GeoUpdateNowRequest(), CancellationToken.None);
        await PumpAsync(coordinator, request);
        var response = await request;
        Assert.NotEqual(IpcErrorCodes.Busy, response.ErrorCode);
        Assert.True(response.Ok, response.ErrorMessage);
    }

    /// <summary>Остальной интернет назначен туннелю, а он лежит: путь закрыт, запрос мимо VPN не уходит.</summary>
    [Fact]
    public async Task NetworkPath_DefaultTunnelDown_Closed()
    {
        SaveSettings(Settings() with
        {
            GeoUpdate = new GeoUpdateSettings { Source = GeoSourceKind.CustomUrl, CustomUrl = GeoUrlA, AutoUpdate = false },
            BypassUpdate = new GeoUpdateSettings { AutoUpdate = false },
            AppUpdate = new AppUpdateSettings { AutoCheck = false },
        });
        _world.HttpHandler = new GeoHttpSource();
        for (var i = 0; i < 10; i++)
        {
            _world.Ras.Results.Enqueue(new RasDialResult(false, null, 809, "Нет ответа"));
        }

        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        Assert.Equal(RouteTarget.Tunnel(_profile.Id), coordinator.Settings.DefaultTarget);
        Assert.False(coordinator.Facts.Tunnels[_profile.Id].Verified);
        Assert.False(coordinator.NetworkPathAllowed);
        var request = coordinator.SubmitAsync(new GeoUpdateNowRequest(), CancellationToken.None);
        await PumpAsync(coordinator, request);
        Assert.Equal(IpcErrorCodes.Busy, (await request).ErrorCode);
    }

    /// <summary>Остальной интернет напрямую, но основного адаптера нет: идти в сеть не через что.</summary>
    [Fact]
    public async Task NetworkPath_DefaultDirect_NoPrimaryAdapter_Closed()
    {
        SaveSettings(Settings() with
        {
            DefaultTarget = RouteTarget.Direct,
            GeoUpdate = new GeoUpdateSettings { AutoUpdate = false },
            BypassUpdate = new GeoUpdateSettings { AutoUpdate = false },
            AppUpdate = new AppUpdateSettings { AutoCheck = false },
        });
        for (var i = 0; i < 10; i++)
        {
            _world.Ras.Results.Enqueue(new RasDialResult(false, null, 809, "Нет ответа"));
        }

        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.True(coordinator.NetworkPathAllowed);
        coordinator.Facts.Primary = null;

        Assert.False(coordinator.Facts.Tunnels[_profile.Id].Verified);
        Assert.False(coordinator.NetworkPathAllowed);
    }
}
