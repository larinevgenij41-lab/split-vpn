using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Settings;

public sealed class AnyConnectSettingsTests
{
    private static readonly ConnectionProfile Primary = new() { Name = "Германия", Server = "vpn.example.org", UserName = "user", Role = ProfileRole.Primary };

    private static ConnectionProfile AnyConnect(ProfileRole role = ProfileRole.Secondary) => new()
    {
        Name = "Офис",
        Server = "avpn.example.org",
        Protocol = VpnProtocol.AnyConnect,
        AuthMethod = AuthMethod.GatewayForm,
        Role = role,
    };

    private static AppSettings With(ConnectionProfile anyConnect) => new()
    {
        Profiles = [Primary, anyConnect],
        DefaultTarget = RouteTarget.Tunnel(Primary.Id),
    };

    [Theory]
    [InlineData("avpn.example.org", "avpn.example.org", 443, "")]
    [InlineData("avpn.example.org:8443", "avpn.example.org", 8443, "")]
    [InlineData("avpn.example.org/staff", "avpn.example.org", 443, "staff")]
    [InlineData("https://avpn.example.org/staff/", "avpn.example.org", 443, "staff")]
    [InlineData("198.51.100.10", "198.51.100.10", 443, "")]
    public void Gateway_Parses(string text, string host, int port, string path)
    {
        Assert.True(AnyConnectGateway.TryParse(text, out var gateway));
        Assert.Equal(host, gateway.Host);
        Assert.Equal(port, gateway.Port);
        Assert.Equal(path, gateway.Path);
    }

    [Theory]
    [InlineData("")]
    [InlineData("http://avpn.example.org")]
    [InlineData("https://user:pass@avpn.example.org")]
    [InlineData("avpn.example.org/?x=1")]
    [InlineData("avpn example.org")]
    [InlineData("[::1]")]
    public void Gateway_RejectsUnsafeOrForeign(string text)
    {
        Assert.False(AnyConnectGateway.TryParse(text, out _));
    }

    [Fact]
    public void Gateway_Url_OmitsDefaultPort()
    {
        Assert.Equal("https://avpn.example.org/", new AnyConnectGateway("avpn.example.org", 443, "").Url);
        Assert.Equal("https://avpn.example.org:8443/staff", new AnyConnectGateway("avpn.example.org", 8443, "staff").Url);
    }

    [Fact]
    public void Protocol_AcceptsOnlyGatewayForm()
    {
        Assert.True(VpnProtocols.Supports(VpnProtocol.AnyConnect, AuthMethod.GatewayForm));
        Assert.False(VpnProtocols.Supports(VpnProtocol.AnyConnect, AuthMethod.MsChapV2));
        Assert.False(VpnProtocols.Supports(VpnProtocol.Sstp, AuthMethod.GatewayForm));
        Assert.False(VpnProtocols.NeedsPassword(AuthMethod.GatewayForm));
        Assert.False(VpnProtocols.UsesRas(VpnProtocol.AnyConnect));
        Assert.True(VpnProtocols.UsesRas(VpnProtocol.Ikev2));
        Assert.True(VpnProtocols.TryParseServer("avpn.example.org/staff", VpnProtocol.AnyConnect, out var address));
        Assert.Equal("avpn.example.org", address.Host);
    }

    [Fact]
    public void SecondaryAnyConnect_WithOwnNetworks_IsValid()
    {
        var result = SettingsValidator.Validate(With(AnyConnect()));

        Assert.True(result.IsValid, string.Join("; ", result.Errors));
        Assert.DoesNotContain(result.Warnings, w => w.Contains("Офис", StringComparison.Ordinal));
    }

    [Fact]
    public void AnyConnect_CannotBePrimaryGroupMemberOrCarryDefaultAndGeo()
    {
        var profile = AnyConnect(ProfileRole.Primary);
        var settings = new AppSettings
        {
            Profiles = [profile],
            DefaultTarget = RouteTarget.Tunnel(profile.Id),
            GeoTarget = RouteTarget.Tunnel(profile.Id),
            Groups = [new TunnelGroupSetting { Name = "Группа", Members = [profile.Id] }],
        };

        var errors = SettingsValidator.Validate(settings).Errors;

        Assert.Contains(errors, e => e.Contains("не может быть опорным", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.Contains("не может входить в группу", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.Contains("«Остальной интернет»", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.Contains("«Россия (RU-база)»", StringComparison.Ordinal));
    }

    [Fact]
    public void ServerNetworks_CannotTargetGroupOrDisabledTunnel()
    {
        var disabled = new ConnectionProfile { Name = "Выкл", Server = "vpn2.example.org", UserName = "u", Role = ProfileRole.Off };
        var toGroup = AnyConnect() with { AnyConnect = new AnyConnectSettings { ServerNetworksTarget = RouteTarget.Group(Guid.NewGuid()) } };
        var toDisabled = AnyConnect() with { Name = "Офис2", Server = "avpn2.example.org", AnyConnect = new AnyConnectSettings { ServerNetworksTarget = RouteTarget.Tunnel(disabled.Id) } };
        var settings = new AppSettings { Profiles = [Primary, disabled, toGroup, toDisabled], DefaultTarget = RouteTarget.Tunnel(Primary.Id) };

        var errors = SettingsValidator.Validate(settings).Errors;

        Assert.Contains(errors, e => e.Contains("нельзя направить в группу", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.Contains("сети шлюза «Офис2»", StringComparison.Ordinal) && e.Contains("выключено", StringComparison.Ordinal));
    }

    [Fact]
    public void InvalidThumbprintAndUserAgent_AreRejected()
    {
        var profile = AnyConnect() with { AnyConnect = new AnyConnectSettings { ClientCertificateThumbprint = "12AB", UserAgent = "" } };

        var errors = VpnProtocols.ValidateAuthentication(profile);

        Assert.Equal(2, errors.Count);
    }

    [Fact]
    public void ConnectionKey_ChangesWithGatewaySettings()
    {
        var profile = AnyConnect();

        Assert.NotEqual(VpnProtocols.ConnectionKey(profile), VpnProtocols.ConnectionKey(profile with { AnyConnect = new AnyConnectSettings { Group = "staff" } }));
    }

    [Fact]
    public void SettingsWithAnyConnect_RoundTripInCurrentSchema()
    {
        var profile = AnyConnect() with { AnyConnect = new AnyConnectSettings { Group = "Офис_SSO", UseDtls = false, ServerNetworksTarget = RouteTarget.Direct } };
        var settings = With(profile);

        var loaded = SettingsSerializer.Deserialize(SettingsSerializer.Serialize(settings));

        Assert.True(loaded.IsSuccess, loaded.Error);
        var restored = loaded.Settings!.Profile(profile.Id)!;
        Assert.Equal(VpnProtocol.AnyConnect, restored.Protocol);
        Assert.Equal(AuthMethod.GatewayForm, restored.AuthMethod);
        Assert.Equal(profile.AnyConnect, restored.AnyConnect);
        Assert.Equal(AppSettings.CurrentSchemaVersion, loaded.Settings.SchemaVersion);
    }

    [Fact]
    public void OldProfileWithoutAnyConnectBlock_GetsDefaults()
    {
        var json = SettingsSerializer.Serialize(new AppSettings { Profiles = [Primary], DefaultTarget = RouteTarget.Tunnel(Primary.Id) })
            .Replace("\"anyConnect\"", "\"ignoredOldField\"", StringComparison.Ordinal);

        var loaded = SettingsSerializer.Deserialize(json);

        Assert.True(loaded.IsSuccess, loaded.Error);
        Assert.Equal(new AnyConnectSettings(), loaded.Settings!.Profiles[0].AnyConnect);
    }
}
