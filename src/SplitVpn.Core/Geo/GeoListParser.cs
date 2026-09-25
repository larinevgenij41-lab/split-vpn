using System.Net;
using System.Net.Sockets;
using SplitVpn.Core.Net;

namespace SplitVpn.Core.Geo;

public sealed record GeoParseError(int LineNumber, string Text, string Reason);

public sealed record GeoParseResult(
    IReadOnlyList<Ipv4Cidr> V4,
    IReadOnlyList<IPNetwork> V6,
    IReadOnlyList<GeoParseError> Errors,
    int ErrorCount,
    bool LooksLikeHtml);

/// <summary>Разбор текстового списка CIDR: одна подсеть на строку, комментарии «#» и «//».</summary>
public static class GeoListParser
{
    private const int MaxReportedErrors = 20;

    public static GeoParseResult Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (LooksLikeHtml(text))
        {
            return new GeoParseResult([], [], [], 0, true);
        }

        var v4 = new List<Ipv4Cidr>();
        var v6 = new List<IPNetwork>();
        var errors = new List<GeoParseError>();
        var errorCount = 0;
        var lineNumber = 0;
        foreach (var rawLine in text.Split('\n'))
        {
            lineNumber++;
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith("//", StringComparison.Ordinal))
            {
                continue;
            }

            var reason = ParseLine(line, v4, v6);
            if (reason is null)
            {
                continue;
            }

            errorCount++;
            if (errors.Count < MaxReportedErrors)
            {
                errors.Add(new GeoParseError(lineNumber, line.Length > 80 ? line[..80] : line, reason));
            }
        }

        return new GeoParseResult(v4, v6, errors, errorCount, false);
    }

    private static string? ParseLine(string line, List<Ipv4Cidr> v4, List<IPNetwork> v6)
    {
        if (Ipv4Cidr.TryParse(line, out var cidr))
        {
            v4.Add(cidr);
            return null;
        }

        if (IPNetwork.TryParse(line, out var network) && network.BaseAddress.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (!IsCanonicalV6(line, network))
            {
                return "у подсети установлены биты хоста";
            }

            v6.Add(network);
            return null;
        }

        return Ipv4Cidr.HasHostBits(line) ? "у подсети установлены биты хоста" : "неверная запись подсети";
    }

    private static bool IsCanonicalV6(string line, IPNetwork network)
    {
        var slash = line.IndexOf('/', StringComparison.Ordinal);
        var addressText = slash < 0 ? line : line[..slash];
        return IPAddress.TryParse(addressText, out var address) && address.Equals(network.BaseAddress);
    }

    private static bool LooksLikeHtml(string text)
    {
        var head = text.AsSpan(0, Math.Min(text.Length, 1024)).TrimStart();
        return head.StartsWith("<", StringComparison.Ordinal)
            || head.Contains("<html", StringComparison.OrdinalIgnoreCase);
    }
}
