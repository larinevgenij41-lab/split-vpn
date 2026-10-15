using System.Text;
using System.Text.Json;
using SplitVpn.Core.Ipc;

using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Settings;

public sealed class VpnProtocolTests
{
    [Theory]
    [InlineData(VpnProtocol.Ikev2, AuthMethod.MsChapV2, false)]
    [InlineData(VpnProtocol.Ikev2, AuthMethod.EapMsChapV2, true)]
    [InlineData(VpnProtocol.Ikev2, AuthMethod.MachineCertificate, true)]
    [InlineData(VpnProtocol.Pptp, AuthMethod.Pap, false)]
    [InlineData(VpnProtocol.Pptp, AuthMethod.Chap, false)]
    [InlineData(VpnProtocol.Pptp, AuthMethod.PeapMsChapV2, true)]
    [InlineData(VpnProtocol.L2tpIpsec, AuthMethod.Pap, true)]
    [InlineData(VpnProtocol.Sstp, AuthMethod.MachineCertificate, false)]
    [InlineData((VpnProtocol)99, AuthMethod.MsChapV2, false)]
    public void AuthenticationMatrix(VpnProtocol protocol, AuthMethod method, bool allowed) => Assert.Equal(allowed, VpnProtocols.Supports(protocol, method));

    [Theory]
    [InlineData(VpnProtocol.Sstp, "vpn.example.org:4443", true)]
    [InlineData(VpnProtocol.L2tpIpsec, "vpn.example.org:1701", false)]
    [InlineData(VpnProtocol.Ikev2, "vpn.example.org:500", false)]
    [InlineData(VpnProtocol.Pptp, "vpn.example.org", true)]
    public void ServerSyntaxMatchesTransport(VpnProtocol protocol, string server, bool valid) => Assert.Equal(valid, VpnProtocols.TryParseServer(server, protocol, out _));

    [Fact]
    public void LegacySettingsMigrateToSstpAndCurrentSchema()
    {
        var loaded = SettingsSerializer.Deserialize("""{"schemaVersion":1,"profiles":[{"name":"Old","server":"vpn.example.org","userName":"user"}]}""");
        Assert.True(loaded.IsSuccess);
        Assert.Equal(AppSettings.CurrentSchemaVersion, loaded.Settings!.SchemaVersion);
        Assert.Equal(VpnProtocol.Sstp, loaded.Settings.Profiles[0].Protocol);
        Assert.Equal(AuthMethod.MsChapV2, loaded.Settings.Profiles[0].AuthMethod);
    }

    [Fact]
    public void CertificateAuthenticationNeedsTrustButDoesNotNeedPassword()
    {
        var profile = new ConnectionProfile { Name = "TLS", Server = "vpn.example.org", Protocol = VpnProtocol.Ikev2, AuthMethod = AuthMethod.EapTls,
            Eap = new() { ServerNames = "radius.example.org", TrustedRootThumbprints = [new string('A', 40)], ClientCertificateThumbprint = new string('B', 40) } };
        Assert.False(VpnProtocols.NeedsPassword(profile.AuthMethod));
        Assert.True(SettingsValidator.Validate(new AppSettings { Profiles = [profile with { Role = ProfileRole.Primary }], DefaultTarget = Core.Policy.RouteTarget.Tunnel(profile.Id) }).IsValid);
        Assert.NotEmpty(VpnProtocols.ValidateAuthentication(profile with { Eap = new() }));
    }

    [Fact]
    public void SecretRequestsAreRedactedAndVersioned()
    {
        IpcRequest request = new SaveConnectionRequest(new AppSettings(), Guid.NewGuid(), "secret-password", "secret-psk");
        Assert.True(request.ContainsSecret);
        Assert.DoesNotContain("secret-password", request.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("secret-psk", request.ToString(), StringComparison.Ordinal);
        Assert.Equal(IpcNames.ContractVersion, IpcSerializer.TryDeserializeRequest(IpcSerializer.SerializeRequest(request))!.ContractVersion);
        Assert.Equal(1, IpcSerializer.TryDeserializeRequest(Encoding.UTF8.GetBytes("""{"type":"getStatus"}"""))!.ContractVersion);
    }

    [Fact]
    public void ExportedProfileContainsNoSecretFields()
    {
        var json = JsonSerializer.Serialize(new ConnectionProfile { Protocol = VpnProtocol.L2tpIpsec }, JsonDefaults.Options);
        using var document = JsonDocument.Parse(json);
        Assert.False(document.RootElement.TryGetProperty("password", out _));
        Assert.False(document.RootElement.TryGetProperty("preSharedKey", out _));
    }
}
