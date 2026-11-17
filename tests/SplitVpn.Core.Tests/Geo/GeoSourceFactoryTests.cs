using SplitVpn.Core.Geo;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Geo;

public sealed class GeoSourceFactoryTests
{
    /// <summary>Неверный адрес зеркала из файла настроек пропускается, а не роняет плановое обновление списка.</summary>
    [Fact]
    public void InvalidMirror_IsSkipped()
    {
        var source = GeoSourceFactory.Create(new GeoUpdateSettings { Mirrors = ["не адрес", "https://mirror.example.org/geo.txt"] });

        Assert.Contains(source.Urls, u => u.AbsoluteUri == "https://mirror.example.org/geo.txt");
        Assert.DoesNotContain(source.Urls, u => u.OriginalString == "не адрес");
    }
}
