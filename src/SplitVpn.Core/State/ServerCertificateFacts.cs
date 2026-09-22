using System.Globalization;

namespace SplitVpn.Core.State;

/// <summary>
/// Что сервер предъявил при TLS-пробе. Нужно для двух вещей: объяснить пользователю отказ по сертификату
/// словами (кто выдал, до какого числа действует) и узнать адреса проверки отзыва, которые защита обязана
/// пропустить, — иначе Windows не сможет получить список отзыва и отклонит исправный сертификат.
/// </summary>
public sealed record ServerCertificateFacts
{
    /// <summary>Кому выдан; у сертификатов с пустым субъектом — первое имя из списка SAN.</summary>
    public string Subject { get; init; } = "";

    public string Issuer { get; init; } = "";

    public IReadOnlyList<string> Names { get; init; } = [];

    public DateTimeOffset NotBefore { get; init; }

    public DateTimeOffset NotAfter { get; init; }

    public string Thumbprint { get; init; } = "";

    /// <summary>Адреса списков отзыва (CRL) и OCSP из всей цепочки.</summary>
    public IReadOnlyList<string> RevocationUrls { get; init; } = [];

    /// <summary>Имена узлов из этих адресов: по ним ставятся правила для доменов и разрешения защиты.</summary>
    public IReadOnlyList<string> RevocationHosts { get; init; } = [];

    /// <summary>Что сказала сборка цепочки без проверки отзыва; null — цепочка в порядке.</summary>
    public string? ChainProblem { get; init; }

    public DateTimeOffset ProbedUtc { get; init; }

    public bool Expired(DateTimeOffset now) => now >= NotAfter;

    public bool NotYetValid(DateTimeOffset now) => now < NotBefore;

    /// <summary>Сертификат словами: кому выдан, кем и до какого числа. Для текста ошибки и «Диагностики».</summary>
    public string Describe(DateTimeOffset now)
    {
        var name = Subject.Length > 0 ? Subject : Names.Count > 0 ? Names[0] : "без имени";
        var issuer = Issuer.Length > 0 ? Issuer : "неизвестный издатель";
        var validity = Expired(now)
            ? $"срок истёк {Format(NotAfter)}"
            : NotYetValid(now)
                ? $"начнёт действовать {Format(NotBefore)}"
                : $"действует до {Format(NotAfter)} (осталось {Left(NotAfter - now)})";
        return string.Create(CultureInfo.InvariantCulture, $"Сертификат сервера: {name}, выдал {issuer}, {validity}.");
    }

    private static string Format(DateTimeOffset moment) =>
        moment.ToLocalTime().ToString("dd.MM.yyyy HH:mm", CultureInfo.GetCultureInfo("ru-RU"));

    private static string Left(TimeSpan span)
    {
        if (span.TotalDays >= 1)
        {
            var days = (int)span.TotalDays;
            return days + " " + Plural(days, "день", "дня", "дней");
        }

        var hours = Math.Max(1, (int)span.TotalHours);
        return hours + " " + Plural(hours, "час", "часа", "часов");
    }

    private static string Plural(int count, string one, string few, string many)
    {
        var tail = count % 100;
        if (tail is >= 11 and <= 14)
        {
            return many;
        }

        return (count % 10) switch
        {
            1 => one,
            2 or 3 or 4 => few,
            _ => many,
        };
    }
}
