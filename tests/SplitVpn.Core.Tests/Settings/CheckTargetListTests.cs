using System.Globalization;
using SplitVpn.Core.Net;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Settings;

/// <summary>
/// Список контрольных целей «IPv4:порт». Контракт: разделители - запятая, точка с запятой, пробел, табуляция;
/// пустые элементы выпадают; цель - строгий IPv4 и порт 1-65535 из десятичных цифр ASCII; MapItems меняет только
/// элементы, разделители оставляет как были.
/// </summary>
public sealed class CheckTargetListTests
{
    [Theory]
    [InlineData(null, new string[0])]
    [InlineData("", new string[0])]
    [InlineData(" ,;\t ", new string[0])]
    [InlineData("1.1.1.1:443", new[] { "1.1.1.1:443" })]
    [InlineData("1.1.1.1:443,1.0.0.1:80", new[] { "1.1.1.1:443", "1.0.0.1:80" })]
    [InlineData(" 1.1.1.1:443 ;; 1.0.0.1:80\t8.8.8.8:53 ,", new[] { "1.1.1.1:443", "1.0.0.1:80", "8.8.8.8:53" })]
    [InlineData("1.1.1.1:443\n1.0.0.1:80", new[] { "1.1.1.1:443\n1.0.0.1:80" })]
    public void Split_SeparatorsAndEmptyItems(string? text, string[] expected) => Assert.Equal(expected, CheckTargetList.Split(text));

    [Theory]
    [InlineData("1.1.1.1:443", "1.1.1.1", 443)]
    [InlineData("0.0.0.0:1", "0.0.0.0", 1)]
    [InlineData("255.255.255.255:65535", "255.255.255.255", 65535)]
    [InlineData("1.1.1.1:0443", "1.1.1.1", 443)]
    public void TryParse_Accepts(string item, string address, int port)
    {
        Assert.True(CheckTargetList.TryParse(item, out var parsed, out var parsedPort));
        Assert.Equal(Ipv4.Parse(address), parsed);
        Assert.Equal(port, parsedPort);
    }

    [Theory]
    [InlineData("")]
    [InlineData(":")]
    [InlineData("1.1.1.1")]
    [InlineData("1.1.1.1:")]
    [InlineData(":443")]
    [InlineData("1.1.1.1:0")]
    [InlineData("1.1.1.1:00")]
    [InlineData("1.1.1.1:65536")]
    [InlineData("1.1.1.1:99999999999")]
    [InlineData("1.1.1.1:-1")]
    [InlineData("1.1.1.1:+443")]
    [InlineData("1.1.1.1:443 ")]
    [InlineData("1.1.1.1:4 43")]
    [InlineData("1.1.1.1:0x1BB")]
    [InlineData("1.1.1.1:1e3")]
    [InlineData("1.1.1.1:443:80")]
    [InlineData("1.1.1.1::443")]
    [InlineData("010.1.1.1:443")]
    [InlineData("1.1.1:443")]
    [InlineData("1.1.1.256:443")]
    [InlineData("one.one.one.one:443")]
    [InlineData("[::1]:443")]
    [InlineData("::1:443")]
    [InlineData("1.1.1.1:٤٤٣")]
    [InlineData("1.1.1.1:４４３")]
    [InlineData("١.1.1.1:443")]
    public void TryParse_Rejects(string item) => Assert.False(CheckTargetList.TryParse(item, out _, out _));

    [Fact]
    public void TryParse_DoesNotDependOnCulture() =>
        TestCulture.AssertSameUnderAll(() => string.Join(',',
            new[] { "1.1.1.1:443", "1.1.1.1:1 000", "1.1.1.1:1,000", "1.1.1.1:1.000", "1.1.1.1:٤٤٣" }
                .Select(i => CheckTargetList.TryParse(i, out _, out var p) + p.ToString(CultureInfo.InvariantCulture))));

    [Theory]
    [InlineData("", "")]
    [InlineData(",", ",")]
    [InlineData("a", "[a]")]
    [InlineData("a,b", "[a],[b]")]
    [InlineData(" a ;; b\t", " [a] ;; [b]\t")]
    [InlineData(",,a,,", ",,[a],,")]
    [InlineData("a\nb", "[a\nb]")]
    public void MapItems_KeepsSeparatorsExactly(string text, string expected) =>
        Assert.Equal(expected, CheckTargetList.MapItems(text, item => "[" + item + "]"));

    /// <summary>Тождественное отображение ничего не меняет - на этом держится «настройки не изменились».</summary>
    [Theory]
    [InlineData("1.1.1.1:443, 1.0.0.1:80")]
    [InlineData(" ;\t,")]
    [InlineData("x")]
    public void MapItems_IdentityIsNoOp(string text) => Assert.Equal(text, CheckTargetList.MapItems(text, s => s));

    [Fact]
    public void MapItems_CalledOncePerItem()
    {
        var seen = new List<string>();

        CheckTargetList.MapItems("a, b;c\td", s => { seen.Add(s); return s; });

        Assert.Equal(["a", "b", "c", "d"], seen);
    }

    /// <summary>Разбор списка и проверка элементов согласованы: каждый элемент Split при MapItems видится тем же.</summary>
    [Theory]
    [InlineData("1.1.1.1:443, 1.0.0.1:80;;8.8.8.8:53")]
    [InlineData("  ")]
    public void MapItems_SeesSameItemsAsSplit(string text)
    {
        var seen = new List<string>();
        CheckTargetList.MapItems(text, s => { seen.Add(s); return s; });

        Assert.Equal(CheckTargetList.Split(text), seen);
    }
}
