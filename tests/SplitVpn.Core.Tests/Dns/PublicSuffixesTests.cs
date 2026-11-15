using SplitVpn.Core.Dns;

namespace SplitVpn.Core.Tests.Dns;

public sealed class PublicSuffixesTests
{
    [Theory]
    [InlineData("corp.example.org", true)]
    [InlineData("office.example.org", true)]
    [InlineData("corp.com.ru", true)]
    [InlineData("Corp.Example.Org.", true)]
    [InlineData("пример.рф", true)]
    [InlineData("ru", false)]
    [InlineData("local", false)]
    [InlineData("com.ru", false)]
    [InlineData("CO.UK", false)]
    [InlineData("msk.ru", false)]
    [InlineData("", false)]
    [InlineData("bad_name..ru", false)]
    public void IsSearchListSuffix_RejectsTopLevelAndPublicZones(string suffix, bool expected)
    {
        Assert.Equal(expected, PublicSuffixes.IsSearchListSuffix(suffix));
    }
}
