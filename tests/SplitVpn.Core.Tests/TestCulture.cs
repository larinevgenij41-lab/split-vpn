using System.Globalization;

namespace SplitVpn.Core.Tests;

/// <summary>Выполняет код под заданной культурой потока и возвращает прежнюю: русская и турецкая Windows - частые источники ошибок форматирования.</summary>
internal static class TestCulture
{
    public static readonly string[] Sensitive = ["ru-RU", "tr-TR", "ar-SA", "de-DE"];

    public static T Run<T>(CultureInfo culture, Func<T> action)
    {
        var culture0 = CultureInfo.CurrentCulture;
        var ui0 = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentCulture = culture;
            CultureInfo.CurrentUICulture = culture;
            return action();
        }
        finally
        {
            CultureInfo.CurrentCulture = culture0;
            CultureInfo.CurrentUICulture = ui0;
        }
    }

    /// <summary>Результат одинаков под инвариантной и под каждой «чувствительной» культурой.</summary>
    public static void AssertSameUnderAll<T>(Func<T> action)
    {
        var expected = Run(CultureInfo.InvariantCulture, action);
        foreach (var name in Sensitive)
        {
            Assert.Equal(expected, Run(CultureInfo.GetCultureInfo(name), action));
        }
    }
}
