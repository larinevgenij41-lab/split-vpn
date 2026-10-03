namespace SplitVpn.Core.Update;

/// <summary>
/// Откуда берутся манифест и установщик.
///
/// Манифест забирается с устойчивого адреса последнего релиза, а не через api.github.com: у API есть
/// предел в 60 запросов в час на адрес (за общим NAT провайдера он исчерпывается чужими клиентами),
/// своя схема ответа и обязательные заголовки. Наш манифест — килобайт, подписан и не зависит от
/// изменений чужого API.
///
/// Запасные пути к манифесту — jsDelivr и raw.githubusercontent: они раздают файлы из дерева
/// репозитория, куда манифест кладётся при публикации снимка. Установщик так раздать нельзя
/// (в дереве его нет, и предел jsDelivr — 20 МБ), поэтому у пакета остаются только активы релиза
/// и зеркала, заданные пользователем. Доверия к зеркалу не требуется: SHA-256 берётся из
/// подписанного манифеста.
/// </summary>
public static class UpdateSources
{
    public const string Repository = "larinevgenij41-lab/split-vpn";

    public const string ManifestFileName = "update.json";

    /// <summary>Файл манифеста в дереве опубликованного снимка: отсюда его раздают зеркала.</summary>
    public const string ManifestRepositoryPath = "release/" + ManifestFileName;

    public static Uri LatestRelease { get; } = new($"https://github.com/{Repository}/releases/latest/download/{ManifestFileName}");

    public static Uri JsDelivrMirror { get; } = new($"https://cdn.jsdelivr.net/gh/{Repository}@main/{ManifestRepositoryPath}");

    public static Uri RawMirror { get; } = new($"https://raw.githubusercontent.com/{Repository}/main/{ManifestRepositoryPath}");

    /// <summary>Адреса манифеста по порядку: основной, два зеркала и адреса из настроек.</summary>
    public static IReadOnlyList<Uri> ManifestUrls(IEnumerable<string>? mirrors)
    {
        var urls = new List<Uri> { LatestRelease, JsDelivrMirror, RawMirror };
        Append(urls, mirrors, null);
        return urls;
    }

    /// <summary>
    /// Адреса установщика: сначала из манифеста, затем зеркала пользователя — к каждому дописывается
    /// имя файла из манифеста, если адрес указан каталогом.
    /// </summary>
    public static IReadOnlyList<Uri> PackageUrls(ReleaseInfo release, IEnumerable<string>? mirrors)
    {
        ArgumentNullException.ThrowIfNull(release);
        var urls = new List<Uri>(release.PackageUrls);
        Append(urls, mirrors, release.Manifest.Package.FileName);
        return urls;
    }

    private static void Append(List<Uri> urls, IEnumerable<string>? mirrors, string? fileName)
    {
        foreach (var text in mirrors ?? [])
        {
            var value = text.Trim();
            if (value.Length == 0)
            {
                continue;
            }

            if (fileName is not null && value.EndsWith('/'))
            {
                value += fileName;
            }

            if (Uri.TryCreate(value, UriKind.Absolute, out var url) && url.Scheme == Uri.UriSchemeHttps && !urls.Contains(url))
            {
                urls.Add(url);
            }
        }
    }
}
