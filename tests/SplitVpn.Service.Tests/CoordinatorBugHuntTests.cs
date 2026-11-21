using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Operations;

namespace SplitVpn.Service.Tests;

/// <summary>Поиск ошибок 2026-11-09: сбой RAS при отключении, DNS подхваченного туннеля, полная сверка, посредник.</summary>
public sealed partial class CoordinatorTests
{
    /// <summary>Перечисление RAS-соединений упало: отключение всё равно снимает фильтры, маршруты и DNS.</summary>
    [Fact]
    public async Task Off_RasEnumerationFailure_StillRemovesProtection()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        _world.Ras.FailFind = true;

        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: false), CancellationToken.None);

        Assert.NotNull(coordinator.Facts.PartialError);
        Assert.Empty(_world.Wfp.Groups);
        Assert.Empty(_world.Routes.Current);
        Assert.Equal("", _world.Dns.NameServers[FakeWorld.WiFiGuid]);
    }

    /// <summary>
    /// Служба перезапустилась (обновление) и подхватила живое соединение: на адаптере туннеля уже наш 127.0.0.1,
    /// но DNS, выданный сервером, берётся из файла состояния, а не заменяется запасными публичными.
    /// </summary>
    [Fact]
    public async Task Restart_AdoptedTunnel_KeepsServerPushedDns()
    {
        var first = await StartAsync();
        await ConnectAsync(first);
        Assert.Equal("127.0.0.1", _world.Dns.NameServers[FakeWorld.TunnelGuid]);
        Assert.Contains(Ipv4.Parse("198.51.100.50"), TunnelDnsServers());

        var restarted = await StartAsync();
        await TickAsync(restarted);

        Assert.Equal(ConnectionState.Connected, restarted.DeriveState());
        Assert.Contains(Ipv4.Parse("198.51.100.50"), TunnelDnsServers());
    }

    /// <summary>Обычные сверки каждые 10 с не отменяют полную раз в минуту: изменённое извне восстанавливается.</summary>
    [Fact]
    public async Task FrequentReconciles_DoNotPostponeForcedReconcile()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var baseCount = _world.Wfp.Groups[FilterGroup.Base].Count;
        _world.Wfp.RemoveOne(FilterGroup.Base);

        for (var i = 0; i < 7; i++)
        {
            _world.Time.Advance(TimeSpan.FromSeconds(10));
            coordinator.Facts.ReconcilePending = true;
            await TickAsync(coordinator);
        }

        Assert.Equal(baseCount, _world.Wfp.Groups[FilterGroup.Base].Count);
    }

    /// <summary>Настройки, заданные посреднику до запуска (порт 53 был занят), не теряются.</summary>
    [Fact]
    public void SystemDnsProxy_KeepsConfigurationSetBeforeStart()
    {
        var proxy = new SystemDnsProxy();
        var configuration = new DnsProxyConfiguration { Mode = DnsProxyMode.DirectAllowed };

        proxy.Configuration = configuration;

        Assert.False(proxy.IsRunning);
        Assert.Same(configuration, proxy.Configuration);
    }

    /// <summary>Профиль выключили и сразу включили: имя его сервера снова закреплено в посреднике, без часа ожидания.</summary>
    [Fact]
    public async Task ReenabledProfile_ServerNameIsPinnedAgain()
    {
        const string host = "backup.example.net";
        _world.Resolver.Answers[host] = [FakeWorld.SecondServer];
        var second = SecondProfile() with { Server = host };
        SaveSettings(Settings() with { Profiles = [_profile, second] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        await TickAsync(coordinator);
        Assert.True(_world.Proxy.Pinned.ContainsKey(host));

        await coordinator.HandleRequestAsync(new SetProfileRoleRequest(second.Id, ProfileRole.Off), CancellationToken.None);
        Assert.False(_world.Proxy.Pinned.ContainsKey(host));

        await coordinator.HandleRequestAsync(new SetProfileRoleRequest(second.Id, ProfileRole.Secondary), CancellationToken.None);
        Assert.True(_world.Proxy.Pinned.ContainsKey(host));
    }

    /// <summary>Сменили сервер и пароль, а пароль не записался: соединение со старым сервером всё равно разрывается.</summary>
    [Fact]
    public async Task SaveConnection_PasswordStoreFailure_StillDropsOldServer()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        _world.Secrets.FailSave = true;
        var moved = _profile with { Server = "203.0.113.11:4443", SavePassword = true };

        var response = await coordinator.HandleRequestAsync(
            new SaveConnectionRequest(coordinator.Settings with { Profiles = [moved] }, moved.Id, "new-password", null), CancellationToken.None);

        // Ошибка пароля показана, но соединение со старым сервером разорвано: дальше служба ждёт пароль к новому.
        Assert.False(response.Ok);
        Assert.False(_world.Ras.Connected);
        Assert.False(coordinator.Facts.Tunnels[moved.Id].ReconnectRequired);
    }

    private List<uint> TunnelDnsServers() =>
        _world.Proxy.Configuration.Tunnel?.Servers.Select(s => Ipv4.ToUInt(s.Address)).ToList() ?? [];
}
