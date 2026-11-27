using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Dns;

/// <summary>
/// Общедоступные суффиксы из двух меток, под которыми регистрируют чужие домены («com.ru», «co.uk»). Небольшой
/// встроенный список самых частых зон, не полный Public Suffix List: он нужен, чтобы суффикс, присланный шлюзом,
/// не превратил короткое имя в запрос к чужой публичной зоне.
/// </summary>
public static class PublicSuffixes
{
    /// <summary>Зоны открытой регистрации: в них регистрирует домены кто угодно («com.ru», «co.uk»).</summary>
    private static readonly HashSet<string> OpenRegistration = new(StringComparer.OrdinalIgnoreCase)
    {
        // Россия и СНГ.
        "com.ru", "net.ru", "org.ru", "pp.ru", "msk.ru", "spb.ru",
        "msk.su", "spb.su", "com.su", "net.su", "org.su", "ru.net", "com.by", "net.by", "org.by",
        "com.kz", "org.kz", "net.kz", "com.ua", "net.ua", "org.ua",
        "in.ua", "kiev.ua", "com.kg", "net.kg", "org.kg", "com.uz", "co.uz", "org.uz", "com.tj", "com.am",
        "com.az", "net.az", "org.az", "com.ge", "org.ge", "com.md",

        // Остальной мир.
        "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
        "com.au", "net.au", "org.au", "co.nz", "org.nz", "net.nz",
        "co.jp", "ne.jp", "or.jp", "co.kr", "or.kr", "ne.kr",
        "com.cn", "net.cn", "org.cn", "com.hk", "com.tw", "com.sg", "com.my",
        "co.in", "net.in", "org.in", "co.id", "or.id", "co.th", "in.th", "com.vn", "com.ph", "com.pk",
        "co.il", "org.il", "com.tr", "com.sa", "com.eg", "co.za", "com.ng", "co.ke",
        "com.br", "net.br", "org.br", "com.ar", "com.mx", "com.co", "com.pe", "com.ve", "com.uy", "com.ec",
        "com.pl", "net.pl", "org.pl", "com.es", "com.pt", "com.gr", "com.cy", "com.mt", "co.at", "or.at",
    };

    /// <summary>
    /// Ведомственные зоны: государственные, военные, научные и учебные («gov.ru», «ac.uk»). Сторонние домены в них не
    /// регистрируют, поэтому правило домена на зону целиком («gov.ru → напрямую») осмысленно. Для списка поиска DNS они
    /// такие же публичные зоны, как и остальные.
    /// </summary>
    private static readonly HashSet<string> Institutional = new(StringComparer.OrdinalIgnoreCase)
    {
        "ac.ru", "edu.ru", "gov.ru", "int.ru", "mil.ru", "gov.by", "gov.kz", "edu.kz", "gov.ua", "edu.ua",
        "ac.uk", "gov.uk", "sch.uk", "edu.au", "gov.au", "ac.jp", "go.jp", "gov.cn", "edu.cn", "gov.in",
        "ac.il", "gov.tr", "gov.br",
    };

    /// <summary>Все известные общедоступные зоны из двух меток.</summary>
    private static readonly HashSet<string> TwoLabel = new(OpenRegistration.Concat(Institutional), StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Частые домены верхнего уровня из одной метки помимо двухбуквенных (все двухбуквенные — коды стран). Не полный
    /// список: нужен для предупреждения о локальном DNS-суффиксе, под который попала бы публичная зона целиком.
    /// </summary>
    private static readonly HashSet<string> TopLevel = new(StringComparer.OrdinalIgnoreCase)
    {
        "com", "net", "org", "info", "biz", "name", "pro", "edu", "gov", "mil", "int", "arpa", "mobi", "aero", "asia",
        "app", "dev", "xyz", "online", "site", "top", "shop", "store", "tech", "cloud", "club", "live", "blog", "page",
        "space", "website", "link", "click", "group", "company", "network", "systems", "email", "news",
        // рф, рус, москва, онлайн, сайт — в виде IDNA, как их хранит NormalizeSuffix.
        "xn--p1ai", "xn--p1acf", "xn--80adxhks", "xn--80asehdb", "xn--80aswg",
    };

    /// <summary>Общедоступная зона из двух меток («com.ru», «co.uk»); имя — после <see cref="SettingsSerializer.NormalizeSuffix"/>.</summary>
    public static bool IsPublicZone(string normalized) => TwoLabel.Contains(normalized);

    /// <summary>
    /// Зона открытой регистрации из двух меток («com.ru», «co.uk»): правило домена на неё целиком охватило бы чужие домены.
    /// Имя — после <see cref="SettingsSerializer.NormalizeSuffix"/>.
    /// </summary>
    public static bool IsOpenRegistrationZone(string normalized) => OpenRegistration.Contains(normalized);

    /// <summary>Ведомственная зона из двух меток («gov.ru», «ac.uk»); имя — после <see cref="SettingsSerializer.NormalizeSuffix"/>.</summary>
    public static bool IsInstitutionalZone(string normalized) => Institutional.Contains(normalized);

    /// <summary>
    /// Домен верхнего уровня («com», «ru», «рф»); имя — после <see cref="SettingsSerializer.NormalizeSuffix"/>. Двухбуквенная
    /// метка из латинских букв считается кодом страны: такие метки зарезервированы за ними.
    /// </summary>
    public static bool IsTopLevelDomain(string normalized) =>
        !normalized.Contains('.', StringComparison.Ordinal)
        && (TopLevel.Contains(normalized) || (normalized.Length == 2 && normalized.All(char.IsAsciiLetter)));

    /// <summary>
    /// Суффикс годится в список поиска DNS адаптера: допустимое имя не меньше чем из двух меток, не зона
    /// верхнего уровня («ru») и не общедоступная зона из двух меток («com.ru»). Иначе Windows дополняла бы
    /// короткие имена до запросов в чужие публичные зоны.
    /// </summary>
    public static bool IsSearchListSuffix(string suffix)
    {
        var normalized = SettingsSerializer.NormalizeSuffix(suffix);
        return SettingsSerializer.IsValidDomainSuffix(normalized) && !TwoLabel.Contains(normalized);
    }
}
