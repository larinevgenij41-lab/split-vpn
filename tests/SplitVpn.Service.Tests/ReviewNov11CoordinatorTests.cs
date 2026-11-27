using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.OpenConnect;
using SplitVpn.Core.Settings;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Operations;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests
{
    [Fact]
    public async Task Nov11_StaleCancelMustNotCancelNewSignInWaitingForHelperExit()
    {
        var coordinator = await StartWithAnyConnectAsync();
        var session = await EstablishAsync(coordinator);
        await DropAsync(coordinator, session);
        await coordinator.HandleRequestAsync(new BeginSignInRequest(_anyConnect.Id), CancellationToken.None);
        await CompleteDialAsync(coordinator);
        Assert.Single(_world.AnyConnect.Sessions);
        await coordinator.HandleRequestAsync(new CancelSignInRequest(_anyConnect.Id, Guid.NewGuid()), CancellationToken.None);
        session.ExitSource.SetResult();
        await CompleteDialAsync(coordinator);
        await TickAsync(coordinator);
        Assert.Equal(2, _world.AnyConnect.Sessions.Count);
    }

    [Theory]
    [InlineData("profile")]
    [InlineData("geo")]
    [InlineData("address")]
    public async Task Nov11_IncompatibleOffQueueRequestMustBeRejected(string kind)
    {
        var coordinator = await StartAsync();
        IpcRequest request = kind switch
        {
            "profile" => new TestProfileRequest(_profile.Id),
            "geo" => new GeoUpdateNowRequest(),
            _ => new CheckAddressRequest("203.0.113.7")
        };
        var response = coordinator.SubmitAsync(request with { ContractVersion = IpcNames.ContractVersion - 1 }, CancellationToken.None);
        await PumpAsync(coordinator, response);
        Assert.Equal(IpcErrorCodes.BadRequest, (await response).ErrorCode);
    }

    [Fact]
    public async Task Nov11_RotatingDnsMustNotBypassGatewayAddressLimit()
    {
        var coordinator = await StartWithAnyConnectAsync();
        await ConnectAsync(coordinator);
        var session = _world.AnyConnect.Last!;
        for (var i = 0; i < 12; i++)
        {
            _world.Resolver.Answers["node.example.org"] = [Ipv4.Parse("198.51.100.30") + (uint)i];
            session.Emit(new ResolveHostEvent("node.example.org"));
            await CompleteDialAsync(coordinator);
        }
        Assert.InRange(coordinator.Facts.Tunnels[_anyConnect.Id].AnyConnect!.ResolvedAddresses.Count, 0, 8);
    }

    [Fact]
    public async Task Nov11_PartialSecretWriteMustNotLeaveOldSession()
    {
        SaveSettings(Settings() with { Profiles = [_profile with { Protocol = VpnProtocol.L2tpIpsec, Server = "203.0.113.10" }] });
        _world.Secrets.Save(_profile.Id, "old-key", SecretKind.PreSharedKey);
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.True(coordinator.Facts.Tunnels[_profile.Id].HasSession);
        _world.Secrets.FailSave = true;
        var response = await coordinator.HandleRequestAsync(new SaveConnectionRequest(coordinator.Settings, _profile.Id, "new-password", ""), CancellationToken.None);
        Assert.False(response.Ok);
        Assert.False(_world.Secrets.Contains(_profile.Id, SecretKind.PreSharedKey), response.ErrorMessage);
        Assert.False(coordinator.Facts.Tunnels[_profile.Id].HasSession,
            $"HangUps={_world.Ras.HangUps}, Dials={_world.Ras.Dials}, Error={response.ErrorMessage}, Protocol={coordinator.Settings.Profile(_profile.Id)!.Protocol}");
    }
}
