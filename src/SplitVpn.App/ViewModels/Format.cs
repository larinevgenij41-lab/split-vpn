using System.Globalization;

namespace SplitVpn.App.ViewModels;

public static class Format
{
    private static readonly CultureInfo Ru = CultureInfo.GetCultureInfo("ru-RU");

    public static string Bytes(double value)
    {
        string[] units = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return value.ToString(unit == 0 ? "0" : "0.0", Ru) + " " + units[unit];
    }

    public static string Duration(TimeSpan span) =>
        span.TotalHours >= 1
            ? string.Create(Ru, $"{(int)span.TotalHours} ч {span.Minutes:00} мин")
            : string.Create(Ru, $"{span.Minutes} мин {span.Seconds:00} с");

    public static string Local(DateTimeOffset? time) =>
        time is { } t ? t.ToLocalTime().ToString("dd.MM.yyyy HH:mm", Ru) : "—";

    /// <summary>Время дня («20:21») для срока, который наступит сегодня; иначе с датой.</summary>
    public static string Time(DateTimeOffset time)
    {
        var local = time.ToLocalTime();
        return local.Date == DateTimeOffset.Now.Date ? local.ToString("HH:mm", Ru) : local.ToString("dd.MM HH:mm", Ru);
    }

    public static string Number(int value) => value.ToString("N0", Ru);

    /// <summary>Число со словом в нужной форме: 1 подключение, 2 подключения, 5 подключений.</summary>
    public static string Count(int value, string one, string few, string many)
    {
        var tens = Math.Abs(value) % 100;
        var units = tens % 10;
        var word = tens is >= 11 and <= 14 ? many : units == 1 ? one : units is >= 2 and <= 4 ? few : many;
        return value.ToString(Ru) + " " + word;
    }
}
