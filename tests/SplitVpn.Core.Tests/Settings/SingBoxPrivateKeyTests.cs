using System.Text;
using System.Text.Json;
using SplitVpn.Core.Net;
using SplitVpn.Core.SshTunnel;

namespace SplitVpn.Core.Tests.Settings;

/// <summary>
/// Ключ SSH в настройках движка экранируется собственным кодом (копия не остаётся в ArrayPool), и результат
/// остаётся корректным JSON с тем же ключом.
/// </summary>
public sealed class SingBoxPrivateKeyTests
{
    [Theory]
    [InlineData("-----BEGIN OPENSSH PRIVATE KEY-----\r\nb3BlbnNzaC1rZXktdjE=\r\n-----END OPENSSH PRIVATE KEY-----\r\n")]
    [InlineData("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA+/==\n-----END OPENSSH PRIVATE KEY-----\n")]
    [InlineData("кавычка \" обратная \\ косая\tтаб\b\f\u0001\u001f\u007f </script> 😀 \u2028")]
    [InlineData("")]
    public void PrivateKey_RoundTripsThroughJson(string privateKey)
    {
        Assert.True(SshHostKey.TryParse(SshVpnTests.HostKey(), out var hostKey));
        var parameters = new SingBoxParameters
        {
            InterfaceName = "x", Server = Ipv4.Parse("192.0.2.10"), Port = 22, User = "u", HostKey = hostKey,
        };
        var buffer = new byte[SingBoxConfig.BufferSize(privateKey.Length)];

        var length = SingBoxConfig.Write(buffer, parameters, privateKey);

        using var json = JsonDocument.Parse(buffer.AsMemory(0, length));
        var outbound = Assert.Single(json.RootElement.GetProperty("outbounds").EnumerateArray());
        Assert.Equal(privateKey, outbound.GetProperty("private_key").GetString());
        Assert.Equal("u", outbound.GetProperty("user").GetString());
    }

    [Fact]
    public void Escape_MatchesComputedLength()
    {
        const string value = "a\"\\\r\n\u0000я😀";
        var destination = new byte[SingBoxConfig.EscapedLength(value)];

        SingBoxConfig.Escape(value, destination);

        Assert.Equal(value, JsonSerializer.Deserialize<string>(destination));
        Assert.Equal("\"a\\\"\\\\\\r\\n\\u0000\\u044f\\ud83d\\ude00\"", Encoding.ASCII.GetString(destination));
    }
}
