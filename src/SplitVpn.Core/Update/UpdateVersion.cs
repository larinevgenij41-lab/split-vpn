using System.Globalization;

namespace SplitVpn.Core.Update;

/// <summary>
/// Версия программы «major.minor.patch». Разбор строгий: ровно три числа без знаков и пробелов —
/// манифест приходит из сети, и «1.2.3.4», «v1.2.3» или «1.2.-3» должны отклоняться, а не толковаться.
/// </summary>
public static class UpdateVersion
{
    public static Version Empty { get; } = new(0, 0, 0);

    /// <summary>Версия этой сборки: выводится из Directory.Build.props и одинакова у службы, интерфейса и ядра.</summary>
    public static Version Current { get; } = Normalize(typeof(UpdateVersion).Assembly.GetName().Version);

    public static string Text(Version? version) => version is null ? "" : version.ToString(3);

    public static bool TryParse(string? text, out Version version)
    {
        version = Empty;
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        var parts = text.Split('.');
        if (parts.Length != 3)
        {
            return false;
        }

        var numbers = new int[3];
        for (var i = 0; i < parts.Length; i++)
        {
            // NumberStyles.None: ни знака, ни пробелов, ни разделителей разрядов.
            if (!int.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out numbers[i]) || numbers[i] > 65534)
            {
                return false;
            }
        }

        version = new Version(numbers[0], numbers[1], numbers[2]);
        return true;
    }

    /// <summary>Версия сборки к трём частям: Revision всегда 0, отсутствующий Build — тоже.</summary>
    private static Version Normalize(Version? version) =>
        version is null ? Empty : new Version(version.Major, version.Minor, Math.Max(0, version.Build));
}
