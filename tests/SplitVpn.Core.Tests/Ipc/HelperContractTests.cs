using System.Text;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.OpenConnect;

namespace SplitVpn.Core.Tests.Ipc;

public sealed class HelperContractTests
{
    private const string Secret = "acSamlv2Token-secret-7f3c9";

    [Fact]
    public async Task CommandsAndEvents_RoundTripThroughFrames()
    {
        HelperCommand[] commands =
        [
            new StartCommand("https://avpn.example.org/", "Офис_SSO", "AnyConnect Windows 4.10.06090", true, null, "SplitVpn AC 1", null, null),
            new WebviewLoadCommand(Guid.NewGuid(), "https://avpn.example.org/+CSCOE+/saml_ac_login.html", [new SsoCookie("acSamlv2Token", Secret)]),
            new WebviewClosedCommand(Guid.NewGuid()),
            new FormReplyCommand(Guid.NewGuid(), new Dictionary<string, string> { ["group_list"] = "Офис_SSO" }, false),
            new ResolveReplyCommand("avpn.example.org", "198.51.100.10"),
            new StopCommand(),
        ];

        using var stream = new MemoryStream();
        foreach (var command in commands)
        {
            await FrameCodec.WriteAsync(stream, HelperContract.Serialize(command), TestContext.Current.CancellationToken);
        }

        stream.Position = 0;
        foreach (var expected in commands)
        {
            var payload = await FrameCodec.ReadAsync(stream, TestContext.Current.CancellationToken);
            var actual = HelperContract.TryDeserializeCommand(payload!);
            Assert.NotNull(actual);
            Assert.Equal(expected.GetType(), actual.GetType());
            Assert.Equal(HelperContract.Serialize(expected), HelperContract.Serialize(actual));
        }
    }

    [Fact]
    public void Events_RoundTrip()
    {
        var session = new SessionInfo
        {
            Address = "10.0.7.190",
            Netmask = "255.255.255.0",
            Mtu = 1230,
            Dns = ["10.0.16.21"],
            SplitDns = ["example.net", "local", "example.org", "office.example.org"],
            SplitIncludes = ["10.0.0.0/255.0.0.0", "213.180.193.247/255.255.255.255"],
            ProxyPac = "https://nexus.example.net/repository/repo/proxy.pac",
            SessionTimeoutSeconds = 36000,
            DtlsActive = true,
        };
        HelperEvent[] events =
        [
            new HelloEvent(HelperContract.Version, "v9.21"),
            new SsoOpenEvent(Guid.NewGuid(), "https://sso.example/adfs", "avpn.example.org"),
            new SsoResultEvent(Guid.NewGuid(), true, null),
            new AuthFormEvent(Guid.NewGuid(), null, "Please complete the authentication process", null,
                [new AuthFieldDto("group_list", "GROUP:", AuthFieldKind.Select, [new AuthChoiceDto("Офис_SSO", "Офис_SSO")], null)]),
            new ResolveHostEvent("avpn.example.org"),
            new EstablishedEvent(14918723521478656, "SplitVpn AC 1", session),
            new IpInfoChangedEvent(session),
            new StatsEvent(15290, 16714, true),
            new ReconnectingEvent("DPD"),
            new LogEvent("info", "CSTP connected"),
            new TerminatedEvent(TerminationKind.AuthRejected, "401"),
        ];

        foreach (var expected in events)
        {
            var actual = HelperContract.TryDeserializeEvent(HelperContract.Serialize(expected));
            Assert.NotNull(actual);
            Assert.Equal(Encoding.UTF8.GetString(HelperContract.Serialize(expected)), Encoding.UTF8.GetString(HelperContract.Serialize(actual)));
        }
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("{\"type\":\"runShell\"}")]
    [InlineData("[]")]
    public void UnknownOrBrokenPayload_IsNull(string json)
    {
        Assert.Null(HelperContract.TryDeserializeCommand(Encoding.UTF8.GetBytes(json)));
        Assert.Null(HelperContract.TryDeserializeEvent(Encoding.UTF8.GetBytes(json)));
    }

    [Fact]
    public void SecretCommands_DoNotExposeSecretsInToString()
    {
        Assert.DoesNotContain(Secret, new WebviewLoadCommand(Guid.NewGuid(), "https://x/", [new SsoCookie("acSamlv2Token", Secret)]).ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, new StartCommand("https://x/", "", "ua", true, null, "if", "user", Secret).ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, new FormReplyCommand(Guid.NewGuid(), new Dictionary<string, string> { ["password"] = Secret }, false).ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, new SsoNavigationRequest(Guid.NewGuid(), Guid.NewGuid(), "https://x/", [new SsoCookie("t", Secret)]).ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Secret, new SubmitAuthFormRequest(Guid.NewGuid(), Guid.NewGuid(), new Dictionary<string, string> { ["password"] = Secret }, false).ToString(), StringComparison.Ordinal);
        Assert.True(new SsoNavigationRequest(Guid.NewGuid(), Guid.NewGuid(), "https://x/", []).ContainsSecret);
    }

    [Theory]
    [InlineData("10.0.0.0/255.0.0.0", "10.0.0.0/8")]
    [InlineData("213.180.193.247/255.255.255.255", "213.180.193.247/32")]
    [InlineData("89.249.23.128/28", "89.249.23.128/28")]
    [InlineData("10.1.2.3/255.255.0.0", "10.1.0.0/16")]
    [InlineData("10.0.16.21", "10.0.16.21/32")]
    public void Routes_ParseFromLibraryFormat(string route, string expected)
    {
        Assert.Equal(Ipv4Cidr.Parse(expected), SessionInfo.ParseRoute(route));
    }

    [Theory]
    [InlineData("")]
    [InlineData("10.0.0.0/255.0.255.0")]
    [InlineData("10.0.0.0/33")]
    [InlineData("fd00::/8")]
    [InlineData("10.0.0.0/8/1")]
    public void Routes_RejectInvalid(string route)
    {
        Assert.Null(SessionInfo.ParseRoute(route));
    }

    [Fact]
    public void IncludeCidrs_SkipsGarbageAndDuplicates()
    {
        var session = new SessionInfo { SplitIncludes = ["10.0.0.0/255.0.0.0", "bogus", "10.0.0.0/8"], Dns = ["10.0.16.21", "x"] };

        Assert.Equal([Ipv4Cidr.Parse("10.0.0.0/8")], session.IncludeCidrs());
        Assert.Equal([Ipv4.Parse("10.0.16.21")], session.DnsAddresses());
    }

    [Fact]
    public void TunnelStatus_CarriesSignInAndServerNetworks()
    {
        var status = new StatusDto
        {
            Tunnels =
            [
                new TunnelStatusDto
                {
                    Name = "Офис",
                    SignIn = new SignInPromptDto { Kind = SignInKind.Browser, Uri = "https://sso", GatewayHost = "avpn.example.org" },
                    ServerNetworks = new ServerNetworksDto { Networks = ["10.0.0.0/8"], Dns = ["10.0.16.21"], Mtu = 1230 },
                },
            ],
        };

        var restored = IpcSerializer.DeserializeResponse(IpcSerializer.SerializeResponse(IpcResponse.Success(status))).ResultAs<StatusDto>()!;

        Assert.Equal(SignInKind.Browser, restored.Tunnels[0].SignIn!.Kind);
        Assert.Equal(1230, restored.Tunnels[0].ServerNetworks!.Mtu);
    }
}
