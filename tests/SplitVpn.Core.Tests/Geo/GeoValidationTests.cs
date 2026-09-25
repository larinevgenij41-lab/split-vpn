using System.Text;
using SplitVpn.Core.Geo;
using SplitVpn.Core.Net;

namespace SplitVpn.Core.Tests.Geo;

public class GeoValidationTests
{
    private static readonly GeoValidationOptions Small = new() { MinV4Count = 2 };

    [Fact]
    public void Parser_ReadsV4V6AndComments()
    {
        var parsed = GeoListParser.Parse("# RU\n2.16.20.0/23\r\n\n// comment\n2a00:1450::/32\n5.8.8.8\n");

        Assert.Equal(2, parsed.V4.Count);
        Assert.Single(parsed.V6);
        Assert.Equal(0, parsed.ErrorCount);
    }

    [Fact]
    public void Validator_RejectsHtml()
    {
        var result = GeoValidator.Validate(GeoListParser.Parse("<!DOCTYPE html><html><body>rate limited</body></html>"), Small);

        Assert.False(result.IsValid);
        Assert.Contains("HTML", result.Problems[0], StringComparison.Ordinal);
    }

    [Fact]
    public void Validator_RejectsHostBitsAndGarbage()
    {
        var result = GeoValidator.Validate(GeoListParser.Parse("2.16.20.0/23\n2.16.20.1/23\nnot-a-subnet\n5.8.0.0/16"), Small);

        Assert.False(result.IsValid);
        Assert.Contains("Неверных строк: 2", result.Problems[0], StringComparison.Ordinal);
        Assert.Contains("биты хоста", result.Problems[0], StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("0.0.0.0/0\n5.8.0.0/16\n2.16.0.0/16")]
    [InlineData("::/0\n5.8.0.0/16\n2.16.0.0/16")]
    public void Validator_RejectsWholeInternet(string text)
    {
        Assert.False(GeoValidator.Validate(GeoListParser.Parse(text), Small).IsValid);
    }

    [Fact]
    public void Validator_RejectsEmptyAndTooSmall()
    {
        Assert.False(GeoValidator.Validate(GeoListParser.Parse("2a00:1450::/32\n"), Small).IsValid);
        Assert.False(GeoValidator.Validate(GeoListParser.Parse("5.8.0.0/16"), new GeoValidationOptions()).IsValid);
    }

    [Fact]
    public void Validator_RemovesFewNonPublicEntries_WithWarning()
    {
        var lines = Enumerable.Range(0, 200).Select(i => $"5.{i}.0.0/16").Append("10.0.0.0/8");
        var result = GeoValidator.Validate(GeoListParser.Parse(string.Join('\n', lines)), Small);

        Assert.True(result.IsValid);
        Assert.Contains(result.Warnings, w => w.Contains("Удалены", StringComparison.Ordinal));
        Assert.False(result.V4.Contains(Ipv4.Parse("10.1.1.1")));
    }

    [Fact]
    public void Validator_RejectsManyNonPublicEntries()
    {
        var result = GeoValidator.Validate(GeoListParser.Parse("5.8.0.0/16\n10.0.0.0/8\n192.168.0.0/16"), Small);

        Assert.False(result.IsValid);
    }

    [Fact]
    public void Validator_ReportsMergedDuplicates()
    {
        var result = GeoValidator.Validate(GeoListParser.Parse("5.8.0.0/16\n5.8.0.0/16\n5.8.1.0/24"), Small);

        Assert.True(result.IsValid);
        Assert.Contains(result.Warnings, w => w.Contains("Объединено", StringComparison.Ordinal));
        Assert.Single(result.V4);
    }

    [Fact]
    public void Diff_FlagsAnomalies_ButNotFirstBase()
    {
        var oldSet = RangeSet.From(Enumerable.Range(0, 100).Select(i => Ipv4Cidr.Parse($"5.{i}.0.0/16")));
        var similar = RangeSet.From(Enumerable.Range(0, 102).Select(i => Ipv4Cidr.Parse($"5.{i}.0.0/16")));
        var halved = RangeSet.From(Enumerable.Range(0, 50).Select(i => Ipv4Cidr.Parse($"5.{i * 2}.0.0/16")));
        var thresholds = new GeoAnomalyThresholds();

        Assert.False(GeoDiff.IsAnomalous(GeoDiff.Compare(oldSet, similar), thresholds));
        Assert.True(GeoDiff.IsAnomalous(GeoDiff.Compare(oldSet, halved), thresholds));
        Assert.False(GeoDiff.IsAnomalous(GeoDiff.Compare(RangeSet.Empty, halved), thresholds));
    }

    [Fact]
    public void IpverseSource_ConvertsJsonToCidrText()
    {
        var json = "{\"countryCode\":\"RU\",\"prefixes\":{\"ipv4\":[\"2.56.24.0/22\",\"5.8.0.0/16\"],\"ipv6\":[\"2a00:1450::/32\"]}}";
        var text = new IpverseSource().ToCidrText(Encoding.UTF8.GetBytes(json));
        var parsed = GeoListParser.Parse(text);

        Assert.Equal(2, parsed.V4.Count);
        Assert.Single(parsed.V6);
    }

    [Fact]
    public void IpverseSource_UnknownFormat_FailsValidation()
    {
        var text = new IpverseSource().ToCidrText(Encoding.UTF8.GetBytes("{\"subnets\":{}}"));

        Assert.False(GeoValidator.Validate(GeoListParser.Parse(text), Small).IsValid);
    }

    [Fact]
    public void Validator_RejectsHalfInternetHiddenAmongFillers_EvenOnManualImport()
    {
        var fillers = Enumerable.Range(0, 998).Select(i => $"5.{i / 250}.{i % 250}.0/24");
        var text = string.Join('\n', fillers.Append("0.0.0.0/1").Append("128.0.0.0/1"));
        var evaluation = GeoUpdateEvaluator.Evaluate(Encoding.UTF8.GetBytes(text), new LoyalsoldierSource(), new GeoStoreState(), RangeSet.Empty,
            new GeoRevisionInfo(null, DateTimeOffset.UnixEpoch, null, null), isManual: true);

        Assert.Equal(GeoEvaluationOutcome.Rejected, evaluation.Outcome);
        Assert.Contains("крупнее /8", evaluation.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validator_RejectsCoverageBeyondAbsoluteLimit()
    {
        // 32 сети /8 — 1/8 адресного пространства: каждая сеть допустима, но вместе слишком много.
        var text = string.Join('\n', Enumerable.Range(0, 32).Select(i => $"{64 + i}.0.0.0/8"));

        var result = GeoValidator.Validate(GeoListParser.Parse(text), Small);

        Assert.False(result.IsValid);
        Assert.Contains(result.Problems, p => p.Contains("адресного пространства", StringComparison.Ordinal));
    }
}
