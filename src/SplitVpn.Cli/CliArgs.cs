using System.Globalization;

namespace SplitVpn.Cli;

internal sealed class CliArgs(string[] values)
{
    public string? Option(string name)
    {
        var index = Array.FindIndex(values, v => string.Equals(v, name, StringComparison.OrdinalIgnoreCase));
        return index >= 0 && index + 1 < values.Length ? values[index + 1] : null;
    }

    /// <summary>Все значения повторяющейся опции.</summary>
    public IReadOnlyList<string> Values(string name) =>
        values.Select((v, i) => (v, i)).Where(p => string.Equals(p.v, name, StringComparison.OrdinalIgnoreCase) && p.i + 1 < values.Length)
            .Select(p => values[p.i + 1]).ToList();

    public int IntOption(string name, int fallback) =>
        int.TryParse(Option(name), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? value : fallback;

    public bool Flag(string name) => values.Any(v => string.Equals(v, name, StringComparison.OrdinalIgnoreCase));

    /// <summary>Позиционный аргумент (не начинающийся с «--» и не являющийся значением опции).</summary>
    public string? Positional(int index)
    {
        var positional = new List<string>();
        for (var i = 0; i < values.Length; i++)
        {
            if (values[i].StartsWith("--", StringComparison.Ordinal))
            {
                i += i + 1 < values.Length && !values[i + 1].StartsWith("--", StringComparison.Ordinal) ? 1 : 0;
                continue;
            }

            positional.Add(values[i]);
        }

        return index < positional.Count ? positional[index] : null;
    }
}

internal static class Text
{
    public static string Inv(FormattableString value) => value.ToString(CultureInfo.InvariantCulture);
}
