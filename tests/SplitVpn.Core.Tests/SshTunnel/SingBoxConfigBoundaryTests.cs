using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using System.Text.Json;
using SplitVpn.Core.Net;
using SplitVpn.Core.SshTunnel;
using SplitVpn.Core.Tests.Settings;

namespace SplitVpn.Core.Tests.SshTunnel;

/// <summary>
/// Настройки sing-box пишутся в массив размера <see cref="SingBoxConfig.BufferSize"/> без роста. Контракт: всё, что
/// пропускают проверки подключения (имя до 64 знаков без пробелов, ключ сервера до 4096 знаков base64, ключ
/// устройства до <see cref="SshPrivateKey.MaxChars"/>), помещается, а результат - корректный JSON с теми же значениями.
/// </summary>
public sealed class SingBoxConfigBoundaryTests
{
    private static SingBoxParameters Parameters(string user = "tunnel", SshHostKey? hostKey = null) => new()
    {
        InterfaceName = SshTunnelDefaults.InterfaceName(Guid.Parse("0123456789abcdef0123456789abcdef")),
        Server = Ipv4.Parse("192.0.2.10"),
        Port = 22,
        User = user,
        HostKey = hostKey ?? HostKey(SshVpnTests.HostKey()),
    };

    private static SshHostKey HostKey(string text)
    {
        Assert.True(SshHostKey.TryParse(text, out var key), text);
        return key;
    }

    /// <summary>
    /// Ключ сервера ssh-rsa с модулем заданной длины в байтах: содержимое произвольное, разбор его принимает.
    /// Заполнитель 0xFB даёт в base64 знаки «+» и «/».
    /// </summary>
    private static string RsaHostKey(int modulusBytes, byte fill = 0x5A)
    {
        using var blob = new MemoryStream();
        void Field(byte[] value)
        {
            Span<byte> length = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(length, (uint)value.Length);
            blob.Write(length);
            blob.Write(value);
        }

        Field("ssh-rsa"u8.ToArray());
        Field([1, 0, 1]);
        var modulus = Enumerable.Repeat(fill, modulusBytes).ToArray();
        modulus[0] = 0x5A; // старший байт модуля меньше 128: иначе число отрицательное, и разбор отказывает
        Field(modulus);
        return "ssh-rsa " + Convert.ToBase64String(blob.ToArray());
    }

    private static JsonElement Write(SingBoxParameters parameters, string privateKey, out int length)
    {
        var buffer = new byte[SingBoxConfig.BufferSize(privateKey.Length)];
        length = SingBoxConfig.Write(buffer, parameters, privateKey);
        return JsonDocument.Parse(buffer.AsMemory(0, length)).RootElement.Clone();
    }

    private static JsonElement Outbound(JsonElement root) => Assert.Single(root.GetProperty("outbounds").EnumerateArray());

    [Theory]
    [InlineData("u")]
    [InlineData("tunnel.user-01_x")]
    [InlineData("пользователь")]
    [InlineData("user@example.org")]
    [InlineData("a\"b\\c")]
    [InlineData("</script>&<!--")]
    [InlineData("😀emoji")]
    public void UnusualButValidUserNames_RoundTrip(string user)
    {
        var root = Write(Parameters(user), SshVpnTests.PrivateKeyFile(), out _);

        Assert.Equal(user, Outbound(root).GetProperty("user").GetString());
    }

    [Fact]
    public void MaximumUserName_64Chars_OfWorstCaseEscaping_Fits()
    {
        // 64 кавычки: каждая экранируется в два байта; 64 знака кириллицы - по два байта UTF-8.
        foreach (var user in new[] { new string('"', 64), new string('я', 64), string.Concat(Enumerable.Repeat("😀", 32)) })
        {
            var root = Write(Parameters(user), SshVpnTests.PrivateKeyFile(), out _);
            Assert.Equal(user, Outbound(root).GetProperty("user").GetString());
        }
    }

    /// <summary>Пустой ключ - минимальный буфер (4096 байт): постоянная часть настроек должна в него помещаться.</summary>
    [Fact]
    public void EmptyPrivateKey_WithMaximumDnsServers_FitsMinimalBuffer()
    {
        var parameters = Parameters() with { DnsServers = [.. Enumerable.Range(1, 4).Select(i => Ipv4.Parse($"255.255.255.{250 + i}"))], VerboseLog = true };

        var root = Write(parameters, "", out var length);

        Assert.True(length < SingBoxConfig.BufferSize(0));
        Assert.Equal("", Outbound(root).GetProperty("private_key").GetString());
        Assert.Equal("debug", root.GetProperty("log").GetProperty("level").GetString());
    }

    [Theory]
    [InlineData(5)]
    [InlineData(64)]
    public void MoreThanFourDnsServers_OnlyFirstFourAreRouted(int count)
    {
        var servers = Enumerable.Range(1, count).Select(i => Ipv4.Parse($"192.0.2.{i}")).ToList();

        var rules = Write(Parameters() with { DnsServers = servers }, SshVpnTests.PrivateKeyFile(), out _).GetProperty("route").GetProperty("rules");

        // 4 правила подмены адреса, отказ на прочие служебные адреса и отказ UDP.
        Assert.Equal(SshTunnelDefaults.MaxDnsServers + 2, rules.GetArrayLength());
        var overrides = rules.EnumerateArray().Where(r => r.TryGetProperty("override_address", out _)).Select(r => r.GetProperty("override_address").GetString()).ToList();
        Assert.Equal(["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"], overrides);
        var rejected = rules[SshTunnelDefaults.MaxDnsServers].GetProperty("ip_cidr").EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.Equal(["198.19.255.2/32", "198.19.255.3/32", "198.19.255.4/32", "198.19.255.5/32"], rejected);
    }

    [Theory]
    [InlineData(0u, 1)]
    [InlineData(uint.MaxValue, ushort.MaxValue)]
    public void ExtremeAddressesAndPorts_AreFormattedExactly(uint server, int port)
    {
        var outbound = Outbound(Write(Parameters() with { Server = server, Port = (ushort)port }, "k", out _));

        Assert.Equal(Ipv4.Format(server), outbound.GetProperty("server").GetString());
        Assert.Equal(port, outbound.GetProperty("server_port").GetInt32());
    }

    [Fact]
    public void Output_IsIdenticalUnderAnyCulture()
    {
        var privateKey = SshVpnTests.PrivateKeyFile();
        var parameters = Parameters() with { DnsServers = [Ipv4.Parse("10.0.0.1")], Mtu = 1400 };

        TestCulture.AssertSameUnderAll(() =>
        {
            var buffer = new byte[SingBoxConfig.BufferSize(privateKey.Length)];
            return Convert.ToHexString(buffer, 0, SingBoxConfig.Write(buffer, parameters, privateKey));
        });
    }

    /// <summary>Ключ устройства у предела разбора, целиком из символов с самым длинным экранированием (\uXXXX).</summary>
    [Fact]
    public void PrivateKey_AtMaxChars_WorstCaseEscaping_Fits()
    {
        var privateKey = new string('\u0001', SshPrivateKey.MaxChars);

        var outbound = Outbound(Write(Parameters(hostKey: HostKey(RsaHostKey(512))), privateKey, out _));

        Assert.Equal(privateKey, outbound.GetProperty("private_key").GetString());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(5)]
    public void EscapedLength_IsExactForMixedInput(int repeat)
    {
        var value = string.Concat(Enumerable.Repeat("a\"\\\n\r\t\b\f\u0000\u001f \u007f~я😀", repeat));
        var destination = new byte[SingBoxConfig.EscapedLength(value)];

        SingBoxConfig.Escape(value, destination);

        Assert.Equal((byte)'"', destination[^1]);
        Assert.Equal(value, JsonSerializer.Deserialize<string>(destination));
        Assert.True(Ascii.IsValid(destination));
    }

    /// <summary>Ключ сервера RSA обычных размеров: 2048-8192 бит.</summary>
    [Theory]
    [InlineData(256)]
    [InlineData(512)]
    [InlineData(1024)]
    public void RsaHostKey_UsualSizes_FitAndRoundTrip(int modulusBytes)
    {
        var hostKey = HostKey(RsaHostKey(modulusBytes));

        var outbound = Outbound(Write(Parameters(hostKey: hostKey), SshVpnTests.PrivateKeyFile(), out _));

        Assert.Equal(hostKey.Text, Assert.Single(outbound.GetProperty("host_key").EnumerateArray()).GetString());
        Assert.Equal(["rsa-sha2-512", "rsa-sha2-256"], outbound.GetProperty("host_key_algorithms").EnumerateArray().Select(e => e.GetString()));
    }

    /// <summary>
    /// Ключ сервера, который проверка подключения принимает (до 4096 знаков base64: RSA до ~24000 бит, OpenSSH
    /// создаёт до 16384), должен помещаться в буфер. Utf8JsonWriter резервирует под строку втрое больше её длины
    /// (худший случай перекодирования UTF-16 в UTF-8), а запас буфера при обычном ключе ed25519 - около 6 КБ.
    /// </summary>
    [Theory]
    [InlineData(1536, 0x5A)]
    [InlineData(2048, 0x5A)]
    [InlineData(3000, 0x5A)]
    [InlineData(3000, 0xFB)]
    public void RsaHostKey_LargestAcceptedSizes_Fit(int modulusBytes, byte fill)
    {
        var hostKey = HostKey(RsaHostKey(modulusBytes, fill));

        // Самый длинный ключ сервера вместе с самым длинным именем и ключом устройства у предела разбора.
        foreach (var (user, privateKey) in new[] { ("tunnel", SshVpnTests.PrivateKeyFile()), (new string('"', 64), new string('\u0001', SshPrivateKey.MaxChars)) })
        {
            var outbound = Outbound(Write(Parameters(user, hostKey), privateKey, out _));

            Assert.Equal(hostKey.Text, Assert.Single(outbound.GetProperty("host_key").EnumerateArray()).GetString());
            Assert.Equal(privateKey, outbound.GetProperty("private_key").GetString());
        }
    }

    /// <summary>Ключ, собранный в обход разбора и длиннее его предела, - чистый отказ, а не порча буфера или обрезанный JSON.</summary>
    [Fact]
    public void HostKey_BeyondParseLimit_FailsCleanly()
    {
        var hostKey = new SshHostKey("ssh-rsa", new string('A', 64 * 1024));
        var privateKey = SshVpnTests.PrivateKeyFile();
        var buffer = new byte[SingBoxConfig.BufferSize(privateKey.Length)];

        var error = Assert.Throws<InvalidOperationException>(() => SingBoxConfig.Write(buffer, Parameters(hostKey: hostKey), privateKey));

        Assert.Contains(buffer.Length.ToString(CultureInfo.InvariantCulture), error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void HostKeyParse_AcceptsBlobUpTo4096Chars_AndRejectsLonger()
    {
        // Модуль 3000 байт - blob 3022 байта, 4032 знака base64; модуль 3100 байт - 4164 знака, длиннее предела.
        var accepted = RsaHostKey(3000);
        Assert.True(accepted.Split(' ')[1].Length <= 4096);
        Assert.True(SshHostKey.TryParse(accepted, out _));
        var rejected = RsaHostKey(3100);
        Assert.True(rejected.Split(' ')[1].Length > 4096);
        Assert.False(SshHostKey.TryParse(rejected, out _));
    }

    [Theory]
    [InlineData(int.MaxValue / 6 + 1)]
    [InlineData(int.MaxValue)]
    public void BufferSize_OverflowIsAnError_NotANegativeOrSmallSize(int chars) =>
        Assert.Throws<OverflowException>(() => SingBoxConfig.BufferSize(chars));

    [Fact]
    public void BufferSize_AtMaxPrivateKeyChars_IsPositive() =>
        Assert.True(SingBoxConfig.BufferSize(SshPrivateKey.MaxChars) > SshPrivateKey.MaxChars * 6);

    [Fact]
    public void Write_RejectsNullArguments()
    {
        Assert.Throws<ArgumentNullException>(() => SingBoxConfig.Write(null!, Parameters(), "k"));
        Assert.Throws<ArgumentNullException>(() => SingBoxConfig.Write(new byte[8192], null!, "k"));
    }

    [Fact]
    public void Write_UsesPrefixOfLargerBuffer_AndLeavesRestUntouched()
    {
        var buffer = Enumerable.Repeat((byte)0xCC, 65536).ToArray();

        var length = SingBoxConfig.Write(buffer, Parameters(), "key");

        using var json = JsonDocument.Parse(buffer.AsMemory(0, length));
        Assert.All(buffer.Skip(length), b => Assert.Equal(0xCC, b));
        Assert.True(Encoding.UTF8.GetString(buffer, 0, length).EndsWith('}'));
    }
}
