using SplitVpn.Core.SshTunnel;

namespace SplitVpn.Core.Tests.SshTunnel;

/// <summary>
/// Разбор вывода sing-box. Служба по нему останавливает повторы (отказ аутентификации, чужой ключ сервера,
/// несовместимые алгоритмы) и решает, писать ли строку в обычный журнал. Строки ниже - в том виде, в каком их
/// печатает sing-box без файла журнала: «УРОВЕНЬ[секунды] текст». Цвет служба выключает ключом --disable-color
/// (в JSON-настройках такого поля нет), но раскрашенный ANSI уровень разбор всё равно понимает.
/// </summary>
public sealed class SshEngineLogTests
{
    private const string Esc = "\u001b";

    private const string AuthFailed =
        "ERROR[0003] connection: open outbound connection: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain";

    private const string HostKeyMismatch =
        "ERROR[0001] connection: open outbound connection: ssh: handshake failed: host key mismatch, server send ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    private const string AlgorithmMismatch =
        "ERROR[0001] connection: open outbound connection: ssh: handshake failed: ssh: no common algorithm for host key; client offered: [ssh-ed25519], server offered: [rsa-sha2-512 rsa-sha2-256]";

    [Theory]
    [InlineData(AuthFailed, SshEngineFailure.Authentication)]
    [InlineData("ERROR[0003] ssh: handshake failed: ssh: unable to authenticate, attempted methods [none], no supported methods remain", SshEngineFailure.Authentication)]
    [InlineData("ERROR[0003] ssh: no supported methods remain", SshEngineFailure.Authentication)]
    [InlineData(HostKeyMismatch, SshEngineFailure.HostKeyMismatch)]
    [InlineData(AlgorithmMismatch, SshEngineFailure.AlgorithmMismatch)]
    [InlineData("ERROR[0005] connection: open outbound connection: dial tcp 192.0.2.10:22: i/o timeout", SshEngineFailure.None)]
    [InlineData("ERROR[0005] dial tcp 192.0.2.10:22: connectex: No connection could be made because the target machine actively refused it.", SshEngineFailure.None)]
    [InlineData("WARN[0010] ssh: handshake failed: EOF", SshEngineFailure.None)]
    [InlineData("WARN[0010] ssh: handshake failed: read tcp 198.19.255.1:50000->192.0.2.10:22: wsarecv: An existing connection was forcibly closed by the remote host.", SshEngineFailure.None)]
    [InlineData("FATAL[0000] start service: initialize inbound/tun[tun-in]: configure tun interface: Access is denied.", SshEngineFailure.None)]
    public void Classify_RealisticEngineLines(string line, SshEngineFailure expected) =>
        Assert.Equal(expected, SshEngineLog.Classify(line));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("\r\n")]
    [InlineData("\0")]
    public void Classify_EmptyOrBlank_IsNone(string? line) => Assert.Equal(SshEngineFailure.None, SshEngineLog.Classify(line));

    /// <summary>Регистр, раскраска, перевод строки внутри и обрамляющий мусор признак не прячут.</summary>
    [Theory]
    [InlineData("UNABLE TO AUTHENTICATE", SshEngineFailure.Authentication)]
    [InlineData("Host Key Mismatch", SshEngineFailure.HostKeyMismatch)]
    [InlineData("No Common Algorithm For Host Key", SshEngineFailure.AlgorithmMismatch)]
    [InlineData(Esc + "[31mERROR" + Esc + "[0m[0003] ssh: unable to authenticate, attempted methods [none publickey]", SshEngineFailure.Authentication)]
    [InlineData(Esc + "[31mERROR" + Esc + "[0m[0001] ssh: handshake failed: host key mismatch, server send ssh-rsa AAAA", SshEngineFailure.HostKeyMismatch)]
    [InlineData("ERROR[0003] ssh: handshake failed:\r\nssh: unable to authenticate", SshEngineFailure.Authentication)]
    [InlineData("\uFEFFERROR[0003] host key mismatch", SshEngineFailure.HostKeyMismatch)]
    public void Classify_IgnoresCaseColorAndFraming(string line, SshEngineFailure expected) =>
        Assert.Equal(expected, SshEngineLog.Classify(line));

    /// <summary>Признак, разорванный переводом строки или лишним пробелом, - уже не признак: так и должно быть, без догадок.</summary>
    [Theory]
    [InlineData("unable to\nauthenticate")]
    [InlineData("host  key mismatch")]
    [InlineData("host-key mismatch")]
    [InlineData("no common algorithm")]
    [InlineData("authentication succeeded (publickey)")]
    public void Classify_NearMisses_AreNone(string line) => Assert.Equal(SshEngineFailure.None, SshEngineLog.Classify(line));

    /// <summary>
    /// Несовместимость обмена ключами, шифра, MAC или сжатия (сервер знает только устаревшие алгоритмы) повтором не
    /// лечится: отказ блокирующий, со своим текстом. Формулировки golang.org/x/crypto/ssh - старая («client offered»)
    /// и новая («we offered»).
    /// </summary>
    [Theory]
    [InlineData("ERROR[0001] connection: open outbound connection: ssh: handshake failed: ssh: no common algorithm for key exchange; client offered: [curve25519-sha256 curve25519-sha256@libssh.org ecdh-sha2-nistp256 ext-info-c kex-strict-c-v00@openssh.com], server offered: [diffie-hellman-group1-sha1]")]
    [InlineData("ERROR[0001] connection: open outbound connection: ssh: handshake failed: ssh: no common algorithm for client to server cipher; client offered: [aes128-gcm@openssh.com chacha20-poly1305@openssh.com aes128-ctr], server offered: [3des-cbc]")]
    [InlineData("ERROR[0001] ssh: handshake failed: ssh: no common algorithm for server to client MAC; client offered: [hmac-sha2-256-etm@openssh.com hmac-sha2-256], server offered: [hmac-md5]")]
    [InlineData("ERROR[0001] ssh: handshake failed: ssh: no common algorithm for key exchange; we offered: [curve25519-sha256], peer offered: [diffie-hellman-group1-sha1]")]
    [InlineData("\u001b[31mERROR\u001b[0m[0001] ssh: handshake failed: ssh: no common algorithm for client to server compression; client offered: [none], server offered: [zlib]")]
    public void Classify_NegotiationMismatch_IsBlocking(string line)
    {
        var failure = SshEngineLog.Classify(line);

        Assert.Equal(SshEngineFailure.NegotiationMismatch, failure);
        Assert.Contains("алгоритм", SshEngineLog.Describe(failure), StringComparison.Ordinal);
    }

    /// <summary>Строка с несколькими признаками: несовместимость алгоритма важнее несовпадения ключа, оно - важнее отказа входа.</summary>
    [Theory]
    [InlineData("host key mismatch; unable to authenticate", SshEngineFailure.HostKeyMismatch)]
    [InlineData("unable to authenticate; host key mismatch", SshEngineFailure.HostKeyMismatch)]
    [InlineData("unable to authenticate; no common algorithm for host key", SshEngineFailure.AlgorithmMismatch)]
    [InlineData("host key mismatch; no common algorithm for host key", SshEngineFailure.AlgorithmMismatch)]
    public void Classify_SeveralMarkers_UsesFixedPriority(string line, SshEngineFailure expected) =>
        Assert.Equal(expected, SshEngineLog.Classify(line));

    [Theory]
    [InlineData(0, SshEngineFailure.Authentication)]
    [InlineData(1, SshEngineFailure.Authentication)]
    public void Classify_VeryLongLine_FindsMarkerAtEitherEnd(int markerAtEnd, SshEngineFailure expected)
    {
        var filler = new string('x', 1 << 20);
        var line = markerAtEnd == 1 ? filler + " unable to authenticate" : "unable to authenticate " + filler;

        Assert.Equal(expected, SshEngineLog.Classify(line));
        Assert.Equal(SshEngineFailure.None, SshEngineLog.Classify(filler));
    }

    [Theory]
    [InlineData("DEBUG[0000] router: match[0] => route(ssh)", true)]
    [InlineData("TRACE[0000] something", true)]
    [InlineData("INFO[0000] inbound/tun[tun-in]: started at SplitVpn SSH 01234567", true)]
    [InlineData("info[0000] lower-case level", true)]
    [InlineData("WARN[0010] ssh: handshake failed: EOF", false)]
    [InlineData("ERROR[0003] " + "ssh: unable to authenticate", false)]
    [InlineData("FATAL[0000] start service", false)]
    [InlineData("PANIC[0000] runtime error", false)]
    [InlineData("", false)]
    [InlineData("panic: runtime error: index out of range", false)]
    [InlineData("goroutine 1 [running]:", false)]
    public void IsDetailed_PlainLevelPrefixes(string line, bool expected) => Assert.Equal(expected, SshEngineLog.IsDetailed(line));

    /// <summary>
    /// Раскрашенный уровень (sing-box без --disable-color) начинается с ESC[..m: без разбора подробная строка
    /// (DEBUG/INFO) уходила бы в обычный журнал службы уровнем Warning даже без подробного режима.
    /// </summary>
    [Theory]
    [InlineData(Esc + "[37mDEBUG" + Esc + "[0m[0000] router: match[0] => route(ssh)", true)]
    [InlineData(Esc + "[36mINFO" + Esc + "[0m[0000] inbound/tun[tun-in]: started", true)]
    [InlineData(Esc + "[1;37mTRACE" + Esc + "[0m[0000] something", true)]
    [InlineData(Esc + "[33mWARN" + Esc + "[0m[0010] ssh: handshake failed: EOF", false)]
    [InlineData(Esc + "[31mERROR" + Esc + "[0m[0003] ssh: unable to authenticate", false)]
    public void IsDetailed_AnsiColoredLevel(string line, bool expected) => Assert.Equal(expected, SshEngineLog.IsDetailed(line));

    /// <summary>Текст для журнала службы - без ESC-последовательностей; прочее содержимое строки не трогается.</summary>
    [Theory]
    [InlineData(Esc + "[33mWARN" + Esc + "[0m[0010] ssh: handshake failed: EOF", "WARN[0010] ssh: handshake failed: EOF")]
    [InlineData(Esc + "[1;31mERROR" + Esc + "[0m[0003] x", "ERROR[0003] x")]
    [InlineData("WARN[0010] plain [0m text", "WARN[0010] plain [0m text")]
    [InlineData("tail " + Esc, "tail " + Esc)]
    [InlineData(Esc + "[12", Esc + "[12")]
    [InlineData("", "")]
    public void Plain_RemovesAnsiSequencesOnly(string line, string expected) => Assert.Equal(expected, SshEngineLog.Plain(line));

    [Fact]
    public void Plain_NullIsEmpty() => Assert.Equal("", SshEngineLog.Plain(null));

    /// <summary>Строка, которую служба дописывает точкой: текст без завершающей точки и не пустой для каждого отказа.</summary>
    [Theory]
    [InlineData(SshEngineFailure.Authentication)]
    [InlineData(SshEngineFailure.HostKeyMismatch)]
    [InlineData(SshEngineFailure.AlgorithmMismatch)]
    [InlineData(SshEngineFailure.NegotiationMismatch)]
    public void Describe_EveryFailureHasSentenceWithoutTrailingPeriod(SshEngineFailure failure)
    {
        var text = SshEngineLog.Describe(failure);

        Assert.False(string.IsNullOrWhiteSpace(text));
        Assert.False(text.EndsWith('.'), text);
        Assert.Equal(text.Trim(), text);
    }

    [Fact]
    public void Describe_CoversEveryEnumValue_AndUndefinedIsEmpty()
    {
        Assert.All(Enum.GetValues<SshEngineFailure>().Where(f => f != SshEngineFailure.None), f => Assert.NotEqual("", SshEngineLog.Describe(f)));
        Assert.Equal("", SshEngineLog.Describe(SshEngineFailure.None));
        Assert.Equal("", SshEngineLog.Describe((SshEngineFailure)42));
        Assert.Equal(4, Enum.GetValues<SshEngineFailure>().Distinct().Select(SshEngineLog.Describe).Where(t => t.Length > 0).Distinct().Count());
    }

    [Fact]
    public void Classify_IsCultureIndependent() =>
        TestCulture.AssertSameUnderAll(() => string.Join(',',
            new[] { "UNABLE TO AUTHENTICATE", "HOST KEY MISMATCH", "NO COMMON ALGORITHM FOR HOST KEY", "INFO" }
                .Select(l => SshEngineLog.Classify(l) + ":" + SshEngineLog.IsDetailed(l))));
}
