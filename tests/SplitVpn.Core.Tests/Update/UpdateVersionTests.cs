using SplitVpn.Core.Update;

namespace SplitVpn.Core.Tests.Update;

public class UpdateVersionTests
{
    [Theory]
    [InlineData("0.8.1", 0, 8, 1)]
    [InlineData("1.0.0", 1, 0, 0)]
    [InlineData("0.10.0", 0, 10, 0)]
    public void Valid_IsParsed(string text, int major, int minor, int patch)
    {
        Assert.True(UpdateVersion.TryParse(text, out var version));
        Assert.Equal(new Version(major, minor, patch), version);
        Assert.Equal(text, UpdateVersion.Text(version));
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("abc")]
    [InlineData("1.2")]
    [InlineData("1.2.3.4")]
    [InlineData("1.2.3.4.5")]
    [InlineData("v1.2.3")]
    [InlineData("1.2.-3")]
    [InlineData("1. 2.3")]
    [InlineData("1.2.+3")]
    [InlineData("1.2.99999")]
    public void Invalid_IsRejected(string? text) => Assert.False(UpdateVersion.TryParse(text, out _));

    /// <summary>Сравнение числовое, а не строковое: «0.10.0» новее «0.9.9».</summary>
    [Theory]
    [InlineData("0.7.3", "0.8.0")]
    [InlineData("0.9.9", "0.10.0")]
    [InlineData("0.99.99", "1.0.0")]
    [InlineData("0.8.0", "0.8.1")]
    public void Newer_IsGreater(string older, string newer)
    {
        Assert.True(UpdateVersion.TryParse(older, out var left));
        Assert.True(UpdateVersion.TryParse(newer, out var right));

        Assert.True(right > left);
        Assert.False(left >= right);
    }

    /// <summary>
    /// Версия программы всегда трёхсоставная: у Version четвёртая часть тогда равна −1, и такие
    /// значения сравнимы между собой. Смешивать их с четырёхсоставными нельзя — «0.8.0» оказался бы
    /// меньше «0.8.0.0», поэтому обе стороны сравнения проходят через UpdateVersion.
    /// </summary>
    [Fact]
    public void Current_IsThreePartAndComparable()
    {
        Assert.True(UpdateVersion.Current.Build >= 0);
        Assert.Equal(-1, UpdateVersion.Current.Revision);
        Assert.Equal(UpdateVersion.Current, new Version(UpdateVersion.Text(UpdateVersion.Current)));

        Assert.True(UpdateVersion.TryParse(UpdateVersion.Text(UpdateVersion.Current), out var parsed));
        Assert.Equal(UpdateVersion.Current, parsed);
    }
}
