using System.Globalization;

namespace SplitVpn.Cli;

internal sealed class CliArgs(string[] values)
{
    public string? Option(string name) => TryOption(name, out var value)
        ? value : throw new ArgumentException("Требуется значение параметра " + name);

    public bool TryOption(string name, out string? value)
    {
        var index = Array.FindIndex(values, v => string.Equals(v, name, StringComparison.OrdinalIgnoreCase));
        value = index < 0 ? null : ValueAt(index);
        return index < 0 || value is not null;
    }

    private string? ValueAt(int index) =>
        index + 1 < values.Length && !values[index + 1].StartsWith("--", StringComparison.Ordinal) ? values[index + 1] : null;

    /// <summary>Все значения повторяющейся опции.</summary>
    public IReadOnlyList<string> Values(string name) =>
        values.Select((v, i) => (v, i)).Where(p => string.Equals(p.v, name, StringComparison.OrdinalIgnoreCase))
            .Select(p => ValueAt(p.i) ?? throw new ArgumentException("Требуется значение параметра " + name)).ToList();

    public int IntOption(string name, int fallback) =>
        int.TryParse(Option(name), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? value : fallback;

    public bool OnlyFlags(params string[] allowed) => values.All(v => allowed.Contains(v, StringComparer.OrdinalIgnoreCase));

    public bool Flag(string name) => values.Any(v => string.Equals(v, name, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Флаги без значения. Позиционный аргумент после такого флага остаётся позиционным: иначе
    /// «report --no-mask out.txt» потерял бы имя файла, приняв его за значение флага.
    /// </summary>
    private static readonly HashSet<string> s_flags = new(StringComparer.OrdinalIgnoreCase)
    {
        "--json", "--keep-protection", "--no-mask", "--no-save-password", "--save-password", "--from-dev-creds", "--hangup", "--with-routes",
    };

    /// <summary>Позиционный аргумент (не начинающийся с «--» и не являющийся значением опции).</summary>
    public string? Positional(int index)
    {
        var positional = new List<string>();
        for (var i = 0; i < values.Length; i++)
        {
            if (values[i].StartsWith("--", StringComparison.Ordinal))
            {
                i += !s_flags.Contains(values[i]) && i + 1 < values.Length && !values[i + 1].StartsWith("--", StringComparison.Ordinal) ? 1 : 0;
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
