using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Dns;

/// <summary>
/// Общедоступные суффиксы из двух меток, под которыми регистрируют чужие домены («com.ru», «co.uk»). Небольшой
/// встроенный список самых частых зон, не полный Public Suffix List: он нужен, чтобы суффикс, присланный шлюзом,
/// не превратил короткое имя в запрос к чужой публичной зоне.
/// </summary>
public static class PublicSuffixes
{
    private static readonly HashSet<string> TwoLabel = new(StringComparer.OrdinalIgnoreCase)
    {
        // Россия и СНГ.
        "com.ru", "net.ru", "org.ru", "pp.ru", "msk.ru", "spb.ru", "ac.ru", "edu.ru", "gov.ru", "int.ru", "mil.ru",
        "msk.su", "spb.su", "com.su", "net.su", "org.su", "ru.net", "com.by", "net.by", "org.by", "gov.by",
        "com.kz", "org.kz", "net.kz", "gov.kz", "edu.kz", "com.ua", "net.ua", "org.ua", "gov.ua", "edu.ua",
        "in.ua", "kiev.ua", "com.kg", "net.kg", "org.kg", "com.uz", "co.uz", "org.uz", "com.tj", "com.am",
        "com.az", "net.az", "org.az", "com.ge", "org.ge", "com.md",

        // Остальной мир.
        "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "net.nz",
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "co.kr", "or.kr", "ne.kr",
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "com.hk", "com.tw", "com.sg", "com.my",
        "co.in", "net.in", "org.in", "gov.in", "co.id", "or.id", "co.th", "in.th", "com.vn", "com.ph", "com.pk",
        "co.il", "org.il", "ac.il", "com.tr", "gov.tr", "com.sa", "com.eg", "co.za", "com.ng", "co.ke",
        "com.br", "net.br", "org.br", "gov.br", "com.ar", "com.mx", "com.co", "com.pe", "com.ve", "com.uy", "com.ec",
        "com.pl", "net.pl", "org.pl", "com.es", "com.pt", "com.gr", "com.cy", "com.mt", "co.at", "or.at",
    };

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
