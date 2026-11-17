using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using SplitVpn.Core.Net;
using SplitVpn.Core.Settings;
using SplitVpn.Core.SshTunnel;

namespace SplitVpn.Core.Tests.Settings;

public sealed class SshVpnTests
{
    private static readonly Lazy<System.Security.Cryptography.ECPoint> s_testPoint = new(() =>
    {
        using var key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        return key.ExportParameters(false).Q;
    });

    /// <summary>Ключ сервера нужного вида с произвольным содержимым: настоящих ключей в тестах нет.</summary>
    internal static string HostKey(string type = "ssh-ed25519", byte fill = 7)
    {
        var name = Encoding.ASCII.GetBytes(type);
        if (type != "ssh-ed25519")
        {
            using var fields = new MemoryStream();
            WriteString(fields, name);
            if (type == "ssh-rsa")
            {
                WriteString(fields, [1, 0, 1]);
                WriteString(fields, Enumerable.Repeat(fill, 256).ToArray());
            }
            else
            {
                WriteString(fields, "nistp256"u8.ToArray());
                WriteString(fields, [4, .. s_testPoint.Value.X!, .. s_testPoint.Value.Y!]);
            }

            return type + " " + Convert.ToBase64String(fields.ToArray());
        }

        var blob = new byte[4 + name.Length + 4 + 32];
        BinaryPrimitives.WriteUInt32BigEndian(blob, (uint)name.Length);
        name.CopyTo(blob, 4);
        BinaryPrimitives.WriteUInt32BigEndian(blob.AsSpan(4 + name.Length), 32);
        blob.AsSpan(8 + name.Length).Fill(fill);
        return type + " " + Convert.ToBase64String(blob);
    }

    /// <summary>
    /// Контейнер закрытого ключа OpenSSH со случайным содержимым. Собирается в тесте: в репозитории нет ни одного
    /// блока закрытого ключа, даже вымышленного.
    /// </summary>
    internal static string PrivateKeyFile(string cipher = "none")
    {
        using var stream = new MemoryStream();
        stream.Write("openssh-key-v1\0"u8);
        WriteString(stream, Encoding.ASCII.GetBytes(cipher));
        WriteString(stream, "none"u8.ToArray());
        WriteString(stream, []);
        stream.Write([0, 0, 0, 1]);
        WriteString(stream, System.Security.Cryptography.RandomNumberGenerator.GetBytes(51));
        var privatePart = System.Security.Cryptography.RandomNumberGenerator.GetBytes(136);
        privatePart.AsSpan(0, 4).CopyTo(privatePart.AsSpan(4));
        WriteString(stream, privatePart);
        var body = Convert.ToBase64String(stream.ToArray(), Base64FormattingOptions.InsertLineBreaks);
        return "-----BEGIN OPENSSH " + "PRIVATE KEY-----\n" + body + "\n-----END OPENSSH " + "PRIVATE KEY-----\n";
    }

    private static void WriteString(Stream stream, byte[] value)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, (uint)value.Length);
        stream.Write(length);
        stream.Write(value);
    }

    private static ConnectionProfile Profile() => new()
    {
        Name = "SSH", Server = "192.0.2.10:2222", Protocol = VpnProtocol.SshVpn, AuthMethod = AuthMethod.SshKey,
        UserName = "tunnel", Role = ProfileRole.Primary, SshVpn = new SshVpnSettings { HostKey = HostKey() },
    };

    [Fact]
    public void SshVpn_IsNotRas_AndNeedsKeyInsteadOfPassword()
    {
        Assert.False(VpnProtocols.UsesRas(VpnProtocol.SshVpn));
        Assert.False(VpnProtocols.UsesRas(VpnProtocol.AnyConnect));
        Assert.All([VpnProtocol.Sstp, VpnProtocol.L2tpIpsec, VpnProtocol.Ikev2, VpnProtocol.Pptp], p => Assert.True(VpnProtocols.UsesRas(p)));
        Assert.False(VpnProtocols.NeedsPassword(AuthMethod.SshKey));
        Assert.True(VpnProtocols.NeedsSshKey(Profile()));
        Assert.False(VpnProtocols.NeedsSshKey(Profile() with { Protocol = VpnProtocol.Sstp }));
    }

    [Theory]
    [InlineData(VpnProtocol.SshVpn, AuthMethod.SshKey, true)]
    [InlineData(VpnProtocol.SshVpn, AuthMethod.MsChapV2, false)]
    [InlineData(VpnProtocol.SshVpn, AuthMethod.GatewayForm, false)]
    [InlineData(VpnProtocol.Sstp, AuthMethod.SshKey, false)]
    [InlineData(VpnProtocol.L2tpIpsec, AuthMethod.SshKey, false)]
    [InlineData(VpnProtocol.Ikev2, AuthMethod.SshKey, false)]
    [InlineData(VpnProtocol.Pptp, AuthMethod.SshKey, false)]
    [InlineData(VpnProtocol.AnyConnect, AuthMethod.SshKey, false)]
    public void SshKey_IsOnlyForSshVpn(VpnProtocol protocol, AuthMethod method, bool allowed) =>
        Assert.Equal(allowed, VpnProtocols.Supports(protocol, method));

    [Theory]
    [InlineData("vpn.example.org", 22)]
    [InlineData("vpn.example.org:2222", 2222)]
    [InlineData("192.0.2.10:443", 443)]
    public void Server_DefaultsToPort22(string server, int port)
    {
        Assert.True(VpnProtocols.TryParseServer(server, VpnProtocol.SshVpn, out var address));
        Assert.Equal(port, address.Port);
        Assert.Equal(22, VpnProtocols.DefaultPort(VpnProtocol.SshVpn));
        Assert.Equal(443, VpnProtocols.DefaultPort(VpnProtocol.Sstp));
    }

    [Fact]
    public void Validation_RequiresPinnedHostKeyAndUser()
    {
        Assert.Empty(VpnProtocols.ValidateAuthentication(Profile()));
        Assert.Contains(VpnProtocols.ValidateAuthentication(Profile() with { SshVpn = new SshVpnSettings() }), e => e.Contains("ключ сервера", StringComparison.Ordinal));
        Assert.Contains(VpnProtocols.ValidateAuthentication(Profile() with { SshVpn = new SshVpnSettings { HostKey = "ssh-ed25519 не-ключ" } }), e => e.Contains("не распознан", StringComparison.Ordinal));
        Assert.Contains(VpnProtocols.ValidateAuthentication(Profile() with { UserName = "" }), e => e.Contains("имя пользователя", StringComparison.Ordinal));
        Assert.Contains(VpnProtocols.ValidateAuthentication(Profile() with { UserName = "two words" }), e => e.Contains("имя пользователя", StringComparison.Ordinal));
    }

    [Fact]
    public void Settings_AllowPrimaryRole_ButOnlyOneActiveAndNoGroups()
    {
        var first = Profile();
        var settings = new AppSettings { Profiles = [first], DefaultTarget = SplitVpn.Core.Policy.RouteTarget.Tunnel(first.Id) };
        Assert.Empty(SettingsValidator.Validate(settings).Errors);
        Assert.Contains(SettingsValidator.Validate(settings with { UpstreamDns = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"] }).Warnings,
            error => error.Contains("первые четыре", StringComparison.Ordinal));
        // Весь остальной интернет в туннеле без UDP - не ошибка, но предупреждение при сохранении.
        Assert.Contains(SettingsValidator.Validate(settings).Warnings, w => w.Contains("только TCP", StringComparison.Ordinal));
        Assert.DoesNotContain(SettingsValidator.Validate(settings with { DefaultTarget = SplitVpn.Core.Policy.RouteTarget.Direct }).Warnings, w => w.Contains("только TCP", StringComparison.Ordinal));

        var second = Profile() with { Id = Guid.NewGuid(), Name = "SSH 2", Role = ProfileRole.Secondary };
        Assert.Contains(SettingsValidator.Validate(settings with { Profiles = [first, second] }).Errors, e => e.Contains("только одно подключение", StringComparison.Ordinal));
        Assert.DoesNotContain(SettingsValidator.Validate(settings with { Profiles = [first, second with { Role = ProfileRole.Off }] }).Errors, e => e.Contains("только одно подключение", StringComparison.Ordinal));

        var group = new TunnelGroupSetting { Name = "Группа", Members = [first.Id] };
        Assert.Contains(SettingsValidator.Validate(settings with { Groups = [group] }).Errors, e => e.Contains("не может входить в группу", StringComparison.Ordinal));
    }

    [Fact]
    public void ConnectionKey_ChangesWithSshFields_AndIgnoresThemForOtherProtocols()
    {
        var ssh = Profile();
        var key = VpnProtocols.ConnectionKey(ssh);
        Assert.NotEqual(key, VpnProtocols.ConnectionKey(ssh with { SshVpn = new SshVpnSettings { HostKey = HostKey(fill: 9) } }));
        Assert.NotEqual(key, VpnProtocols.ConnectionKey(ssh with { UserName = "other" }));
        Assert.NotEqual(key, VpnProtocols.ConnectionKey(ssh with { Server = "192.0.2.10:22" }));

        // Прежние типы: появление раздела SSH в профиле не меняет ключ, иначе обновление разорвало бы их сеансы.
        var sstp = new ConnectionProfile { Name = "SSTP", Server = "vpn.example.org", UserName = "user" };
        Assert.Equal(VpnProtocols.ConnectionKey(sstp), VpnProtocols.ConnectionKey(sstp with { SshVpn = new SshVpnSettings { HostKey = HostKey() } }));
    }

    [Fact]
    public void Profile_RoundTripsThroughSettingsFile_WithoutSecrets()
    {
        var settings = new AppSettings { Profiles = [Profile()] };
        var text = SettingsSerializer.Serialize(settings);
        Assert.Contains("\"sshVpn\"", text, StringComparison.Ordinal);
        Assert.DoesNotContain("PRIVATE KEY", text, StringComparison.Ordinal);
        var loaded = SettingsSerializer.Deserialize(text);
        Assert.True(loaded.IsSuccess);
        Assert.Equal(VpnProtocol.SshVpn, loaded.Settings!.Profiles[0].Protocol);
        Assert.Equal(Profile().SshVpn.HostKey, loaded.Settings.Profiles[0].SshVpn.HostKey);
    }

    [Theory]
    [InlineData("ssh-ed25519", "ssh-ed25519")]
    [InlineData("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256")]
    [InlineData("ssh-rsa", "rsa-sha2-512,rsa-sha2-256")]
    public void HostKey_ParsesKnownTypes_AndOffersMatchingAlgorithms(string type, string algorithms)
    {
        Assert.True(SshHostKey.TryParse("  " + HostKey(type) + "  comment@host ", out var key));
        Assert.Equal(type, key.Type);
        Assert.Equal(HostKey(type), key.Text);
        Assert.Equal(algorithms, string.Join(',', key.Algorithms));
    }

    [Theory]
    [InlineData("")]
    [InlineData("ssh-ed25519")]
    [InlineData("ssh-dss AAAAB3NzaC1kc3M=")]
    [InlineData("ssh-ed25519 ###")]
    public void HostKey_RejectsGarbage(string text) => Assert.False(SshHostKey.TryParse(text, out _));

    [Fact]
    public void HeaderOnlyHostKeyIsRejected()
    {
        using var fields = new MemoryStream();
        WriteString(fields, "ssh-ed25519"u8.ToArray());
        Assert.False(SshHostKey.TryParse("ssh-ed25519 " + Convert.ToBase64String(fields.ToArray()), out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(SshPrivateKey.MaxChars + 1)]
    public void KeyFileRejectsEmptyAndOversizedInput(int length)
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, new string('a', length));
            Assert.Throws<InvalidDataException>(() => SshPrivateKey.ReadFile(path));
            Assert.True(File.Exists(path));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void KeyCommentDoesNotChangeConnectionIdentity()
    {
        var profile = Profile();
        Assert.Equal(VpnProtocols.ConnectionKey(profile), VpnProtocols.ConnectionKey(profile with
        {
            SshVpn = profile.SshVpn with { HostKey = profile.SshVpn.HostKey + " comment" },
        }));
    }

    [Fact]
    public void HostKey_RejectsTypeMismatchInsideBlob() =>
        Assert.False(SshHostKey.TryParse("ssh-rsa " + HostKey().Split(' ')[1], out _));

    [Fact]
    public void PrivateKey_AcceptsOnlyUnencryptedOpenSshContainer()
    {
        Assert.Equal(SshPrivateKeyCheck.Ok, SshPrivateKey.Check(PrivateKeyFile()));
        Assert.Equal(SshPrivateKeyCheck.Ok, SshPrivateKey.Check(PrivateKeyFile().Replace("\n", "\r\n", StringComparison.Ordinal)));
        Assert.Equal(SshPrivateKeyCheck.Encrypted, SshPrivateKey.Check(PrivateKeyFile("aes256-ctr")));
        Assert.Equal(SshPrivateKeyCheck.NotOpenSsh, SshPrivateKey.Check("-----BEGIN RSA " + "PRIVATE KEY-----\nAAAA\n-----END RSA " + "PRIVATE KEY-----"));
        Assert.Equal(SshPrivateKeyCheck.NotOpenSsh, SshPrivateKey.Check("ssh-ed25519 AAAA"));
        Assert.Equal(SshPrivateKeyCheck.WrongSize, SshPrivateKey.Check(""));
        Assert.Equal(SshPrivateKeyCheck.WrongSize, SshPrivateKey.Check(new string('A', SshPrivateKey.MaxChars + 1)));
        Assert.All(Enum.GetValues<SshPrivateKeyCheck>().Where(c => c != SshPrivateKeyCheck.Ok), c => Assert.NotEqual("", SshPrivateKey.Describe(c)));
    }

    [Fact]
    public void EngineConfig_HasSingleSshOutbound_NoRoutesOfItsOwn_AndNoListeners()
    {
        var privateKey = PrivateKeyFile();
        Assert.True(SshHostKey.TryParse(HostKey(), out var hostKey));
        var parameters = new SingBoxParameters
        {
            InterfaceName = SshTunnelDefaults.InterfaceName(Guid.Parse("0123456789abcdef0123456789abcdef")),
            Server = Ipv4.Parse("192.0.2.10"), Port = 2222, User = "tunnel", HostKey = hostKey,
        };
        var buffer = new byte[SingBoxConfig.BufferSize(privateKey.Length)];
        var length = SingBoxConfig.Write(buffer, parameters, privateKey);
        using var json = JsonDocument.Parse(buffer.AsMemory(0, length));
        var root = json.RootElement;

        Assert.Equal("warn", root.GetProperty("log").GetProperty("level").GetString());

        var inbound = Assert.Single(root.GetProperty("inbounds").EnumerateArray());
        Assert.Equal("tun", inbound.GetProperty("type").GetString());
        Assert.Equal("SplitVpn SSH 01234567", inbound.GetProperty("interface_name").GetString());
        Assert.False(inbound.GetProperty("auto_route").GetBoolean());
        Assert.False(inbound.TryGetProperty("strict_route", out _));
        Assert.Equal("gvisor", inbound.GetProperty("stack").GetString());
        Assert.Equal("198.19.255.1/32", Assert.Single(inbound.GetProperty("address").EnumerateArray()).GetString());

        // Единственный выход - SSH: прямого выхода нет, значит мимо сервера движок отправить ничего не может.
        var outbound = Assert.Single(root.GetProperty("outbounds").EnumerateArray());
        Assert.Equal("ssh", outbound.GetProperty("type").GetString());
        Assert.Equal("192.0.2.10", outbound.GetProperty("server").GetString());
        Assert.Equal(2222, outbound.GetProperty("server_port").GetInt32());
        Assert.Equal("tunnel", outbound.GetProperty("user").GetString());
        Assert.Equal(privateKey, outbound.GetProperty("private_key").GetString());
        Assert.Equal(hostKey.Text, Assert.Single(outbound.GetProperty("host_key").EnumerateArray()).GetString());
        Assert.Equal("ssh-ed25519", Assert.Single(outbound.GetProperty("host_key_algorithms").EnumerateArray()).GetString());

        var dnsConfig = new byte[SingBoxConfig.BufferSize(privateKey.Length)];
        var dnsLength = SingBoxConfig.Write(dnsConfig, parameters with { DnsServers = [Ipv4.Parse("192.0.2.53")] }, privateKey);
        using var withDns = JsonDocument.Parse(dnsConfig.AsMemory(0, dnsLength));
        var dnsRule = withDns.RootElement.GetProperty("route").GetProperty("rules")[0];
        Assert.Equal("tcp", dnsRule.GetProperty("network").GetString());
        Assert.Equal(53, dnsRule.GetProperty("port").GetInt32());
        Assert.Equal("ssh", dnsRule.GetProperty("outbound").GetString());
        Assert.Equal("reject", withDns.RootElement.GetProperty("route").GetProperty("rules")[1].GetProperty("action").GetString());

        var rule = Assert.Single(root.GetProperty("route").GetProperty("rules").EnumerateArray());
        Assert.Equal("udp", rule.GetProperty("network").GetString());
        Assert.Equal("reject", rule.GetProperty("action").GetString());
        Assert.True(rule.GetProperty("no_drop").GetBoolean());
        Assert.Equal("ssh", root.GetProperty("route").GetProperty("final").GetString());

        // Локальных слушателей и собственного DNS нет: фильтр защиты блокирует движку всё, кроме сервера.
        Assert.False(root.TryGetProperty("dns", out _));
        Assert.False(root.TryGetProperty("experimental", out _));
        Assert.False(root.GetProperty("route").TryGetProperty("auto_detect_interface", out _));
    }

    [Fact]
    public void EngineConfig_FailsInsteadOfGrowing_WhenBufferIsTooSmall()
    {
        Assert.True(SshHostKey.TryParse(HostKey(), out var hostKey));
        var parameters = new SingBoxParameters { InterfaceName = "x", Server = Ipv4.Parse("192.0.2.10"), Port = 22, User = "u", HostKey = hostKey };
        Assert.Throws<InvalidOperationException>(() => SingBoxConfig.Write(new byte[64], parameters, PrivateKeyFile()));
    }
}
