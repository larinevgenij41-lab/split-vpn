using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Settings;

/// <summary>
/// Разбор поля «Сервер» AnyConnect. Контракт: только https, хост - DNS-имя (в виде IDNA) или IPv4 в строгой
/// записи; порт 1-65535, по умолчанию 443; путь - group-url без ведущей косой; учётные данные, запрос, фрагмент,
/// пробелы и IPv6 - отказ; не длиннее 512 знаков.
/// </summary>
public sealed class AnyConnectGatewayBoundaryTests
{
    [Theory]
    [InlineData("HTTPS://avpn.example.org", "avpn.example.org", 443, "")]
    [InlineData("AVPN.Example.ORG", "avpn.example.org", 443, "")]
    [InlineData("avpn.example.org:443", "avpn.example.org", 443, "")]
    [InlineData("avpn.example.org:1", "avpn.example.org", 1, "")]
    [InlineData("avpn.example.org:65535", "avpn.example.org", 65535, "")]
    [InlineData("avpn.example.org:08443", "avpn.example.org", 8443, "")]
    [InlineData("avpn.example.org/a/b", "avpn.example.org", 443, "a/b")]
    [InlineData("avpn.example.org/", "avpn.example.org", 443, "")]
    [InlineData("avpn.example.org/группа", "avpn.example.org", 443, "%D0%B3%D1%80%D1%83%D0%BF%D0%BF%D0%B0")]
    [InlineData("255.255.255.255", "255.255.255.255", 443, "")]
    [InlineData("localhost", "localhost", 443, "")]
    public void Parses(string text, string host, int port, string path)
    {
        Assert.True(AnyConnectGateway.TryParse(text, out var gateway));
        Assert.Equal((host, port, path), (gateway.Host, (int)gateway.Port, gateway.Path));
    }

    /// <summary>Хост IDN уходит в openconnect в виде IDNA (только ASCII), как его разрешает DNS.</summary>
    [Theory]
    [InlineData("впн.пример.рф")]
    [InlineData("ВПН.Пример.РФ")]
    [InlineData("https://впн.пример.рф:8443/staff")]
    public void IdnHost_IsPunycode(string text)
    {
        Assert.True(AnyConnectGateway.TryParse(text, out var gateway));

        Assert.Equal(new System.Globalization.IdnMapping().GetAscii("впн.пример.рф"), gateway.Host);
        Assert.True(System.Text.Ascii.IsValid(gateway.Url));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("   ")]
    [InlineData("\t")]
    [InlineData("avpn.example.org\t")]
    [InlineData(" avpn.example.org")]
    [InlineData("avpn.example.org\u00A0")]
    [InlineData("avpn.example.org\u3000")]
    [InlineData("avpn.example.org\n/staff")]
    [InlineData("avpn.example.org:0")]
    [InlineData("avpn.example.org:65536")]
    [InlineData("avpn.example.org:-1")]
    [InlineData("avpn.example.org:abc")]
    [InlineData("avpn.example.org#frag")]
    [InlineData("avpn.example.org/staff#frag")]
    [InlineData("avpn.example.org?x")]
    [InlineData("user@avpn.example.org")]
    [InlineData("https://:pass@avpn.example.org")]
    [InlineData("ftp://avpn.example.org")]
    [InlineData("wss://avpn.example.org")]
    [InlineData("file://avpn.example.org/x")]
    [InlineData("[2001:db8::1]")]
    [InlineData("https://[2001:db8::1]:443/")]
    [InlineData("https://")]
    [InlineData("://avpn.example.org")]
    public void Rejects(string? text) => Assert.False(AnyConnectGateway.TryParse(text, out _));

    [Fact]
    public void Length_512IsAccepted_513IsRejected()
    {
        // Хост из меток по 63 знака: длина имени DNS не больше 253, остальное добирается путём.
        var host = string.Join('.', Enumerable.Repeat(new string('a', 60), 4)) + ".org";
        var at512 = host + "/" + new string('p', 512 - host.Length - 1);
        Assert.Equal(512, at512.Length);

        Assert.True(AnyConnectGateway.TryParse(at512, out var gateway));
        Assert.Equal(512 - host.Length - 1, gateway.Path.Length);
        Assert.False(AnyConnectGateway.TryParse(at512 + "p", out _));
    }

    [Fact]
    public void FailedParse_LeavesDefault()
    {
        Assert.False(AnyConnectGateway.TryParse("ftp://x", out var gateway));
        Assert.Equal(default, gateway);
    }

    /// <summary>Разбор и обратная сборка ссылки сходятся: Url снова разбирается в тот же шлюз.</summary>
    [Theory]
    [InlineData("avpn.example.org")]
    [InlineData("avpn.example.org:8443/staff")]
    [InlineData("https://avpn.example.org/a/b/")]
    [InlineData("впн.пример.рф:444/группа")]
    [InlineData("198.51.100.10:1")]
    public void Url_RoundTrips(string text)
    {
        Assert.True(AnyConnectGateway.TryParse(text, out var gateway));

        Assert.True(AnyConnectGateway.TryParse(gateway.Url, out var again));
        Assert.Equal(gateway, again);
    }

    [Fact]
    public void Url_IsCultureInvariant()
    {
        var gateway = new AnyConnectGateway("avpn.example.org", 65535, "staff");

        TestCulture.AssertSameUnderAll(() => gateway.Url);
        Assert.Equal("https://avpn.example.org:65535/staff", gateway.Url);
    }

    /// <summary>
    /// Остальная программа принимает IPv4 только в строгой записи (Ipv4.TryParse: «010» был бы восьмеричным, «10.1»
    /// - сокращённой формой). System.Uri же понимает «10.1» как 10.0.0.1, «010.0.0.1» как 8.0.0.1, «0x7f.1» как
    /// 127.0.0.1 и одно число как адрес целиком - шлюз молча оказывается другим адресом.
    /// </summary>
    [Theory]
    [InlineData("10.1")]
    [InlineData("10.1.2")]
    [InlineData("010.0.0.1")]
    [InlineData("0x7f.0.0.1")]
    [InlineData("3232235777")]
    [InlineData("https://0300.0250.0.1/")]
    [InlineData("10.1:8443/staff")]
    [InlineData("HTTPS://010.0.0.1:443")]
    public void LooseIpv4Notations_AreRejected(string text)
    {
        Assert.False(AnyConnectGateway.TryParse(text, out var gateway));
        Assert.Equal(default, gateway);
        // Отказ узнаваем: служба и проверка настроек говорят «исправьте адрес», а не общее «неверный адрес».
        Assert.True(AnyConnectGateway.IsLooseIpv4(text));
    }

    /// <summary>Строгий IPv4 - с портом, путём и в полной ссылке - по-прежнему принимается и не считается нестрогим.</summary>
    [Theory]
    [InlineData("10.0.0.1", "10.0.0.1", 443, "")]
    [InlineData("0.0.0.0:8443", "0.0.0.0", 8443, "")]
    [InlineData("https://198.51.100.10:444/staff", "198.51.100.10", 444, "staff")]
    [InlineData("192.168.1.1/a/b", "192.168.1.1", 443, "a/b")]
    public void StrictIpv4_IsAccepted(string text, string host, int port, string path)
    {
        Assert.True(AnyConnectGateway.TryParse(text, out var gateway));
        Assert.Equal((host, port, path), (gateway.Host, (int)gateway.Port, gateway.Path));
        Assert.False(AnyConnectGateway.IsLooseIpv4(text));
    }

    /// <summary>Прочие отказы и имена DNS к нестрогому IPv4 не относятся.</summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("ftp://10.1")]
    [InlineData("user@10.1")]
    [InlineData("[2001:db8::1]")]
    [InlineData("avpn.example.org")]
    [InlineData("10.0.0.1")]
    public void IsLooseIpv4_OnlyForLooseIpv4Hosts(string? text) => Assert.False(AnyConnectGateway.IsLooseIpv4(text));
}
