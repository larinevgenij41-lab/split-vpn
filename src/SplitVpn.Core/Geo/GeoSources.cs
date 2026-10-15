using System.Text;
using System.Text.Json;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Geo;

public enum GeoBasis
{
    /// <summary>Страна расположения IP по геолокации.</summary>
    Geolocation,

    /// <summary>Страна регистрации (делегирования) сети.</summary>
    Registration,

    Custom,
}

public interface IGeoSource
{
    string Id { get; }

    string DisplayName { get; }

    GeoBasis Basis { get; }

    /// <summary>Основной адрес и зеркала той же базы.</summary>
    IReadOnlyList<Uri> Urls { get; }

    /// <summary>Преобразует ответ источника в текст CIDR (одна подсеть на строку).</summary>
    string ToCidrText(byte[] content);
}

public sealed class LoyalsoldierSource : IGeoSource
{
    public const string SourceId = "loyalsoldier-ru";

    public static readonly Uri Primary = new("https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/ru.txt");

    public static readonly Uri JsDelivrMirror = new("https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/text/ru.txt");

    public LoyalsoldierSource(IEnumerable<Uri>? extraMirrors = null)
    {
        Urls = [Primary, JsDelivrMirror, .. extraMirrors ?? []];
    }

    public string Id => SourceId;

    public string DisplayName => "GeoIP — Loyalsoldier/geoip (рекомендуется)";

    public GeoBasis Basis => GeoBasis.Geolocation;

    public IReadOnlyList<Uri> Urls { get; }

    public string ToCidrText(byte[] content) => Encoding.UTF8.GetString(content);
}

public sealed class IpverseSource : IGeoSource
{
    public const string SourceId = "ipverse-ru";

    public static readonly Uri Primary = new("https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country/ru/aggregated.json");

    public IpverseSource(IEnumerable<Uri>? extraMirrors = null)
    {
        Urls = [Primary, .. extraMirrors ?? []];
    }

    public string Id => SourceId;

    public string DisplayName => "Страна регистрации — ipverse/country-ip-blocks";

    public GeoBasis Basis => GeoBasis.Registration;

    public IReadOnlyList<Uri> Urls { get; }

    public string ToCidrText(byte[] content)
    {
        try
        {
            using var document = JsonDocument.Parse(content);
            if (!document.RootElement.TryGetProperty("prefixes", out var prefixes))
            {
                return "# неизвестный формат ipverse: нет поля prefixes\ninvalid";
            }

            var builder = new StringBuilder();
            AppendArray(prefixes, "ipv4", builder);
            AppendArray(prefixes, "ipv6", builder);
            return builder.ToString();
        }
        catch (JsonException)
        {
            // Пусть валидатор отклонит содержимое как неверное.
            return Encoding.UTF8.GetString(content);
        }
    }

    private static void AppendArray(JsonElement prefixes, string name, StringBuilder builder)
    {
        if (!prefixes.TryGetProperty(name, out var array) || array.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var item in array.EnumerateArray())
        {
            builder.Append(item.GetString()).Append('\n');
        }
    }
}

/// <summary>
/// Список обхода блокировок: подсети ресурсов, заблокированных в России, и ресурсов, которые сами
/// закрывают доступ из России. Обновляется ежедневно, формат — CIDR построчно.
/// </summary>
public sealed class ReFilterSource : IGeoSource
{
    public const string SourceId = "refilter-bypass";

    public static readonly Uri Primary = new("https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/ipsum.lst");

    public static readonly Uri JsDelivrMirror = new("https://cdn.jsdelivr.net/gh/1andrevich/Re-filter-lists@main/ipsum.lst");

    public ReFilterSource(IEnumerable<Uri>? extraMirrors = null)
    {
        Urls = [Primary, JsDelivrMirror, .. extraMirrors ?? []];
    }

    public string Id => SourceId;

    public string DisplayName => "Обход блокировок — 1andrevich/Re-filter-lists";

    public GeoBasis Basis => GeoBasis.Custom;

    public IReadOnlyList<Uri> Urls { get; }

    public string ToCidrText(byte[] content) => Encoding.UTF8.GetString(content);
}

public sealed class CustomUrlSource : IGeoSource
{
    public const string SourceId = "custom-url";

    public CustomUrlSource(Uri url, IEnumerable<Uri>? extraMirrors = null)
    {
        Urls = [url, .. extraMirrors ?? []];
    }

    public string Id => SourceId;

    public string DisplayName => "Собственный HTTPS-источник";

    public GeoBasis Basis => GeoBasis.Custom;

    public IReadOnlyList<Uri> Urls { get; }

    public string ToCidrText(byte[] content) => Encoding.UTF8.GetString(content);
}

public static class GeoSourceFactory
{
    public static IGeoSource Create(GeoUpdateSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var mirrors = settings.Mirrors.Select(m => new Uri(m)).ToList();
        return settings.Source switch
        {
            GeoSourceKind.Ipverse => new IpverseSource(mirrors),
            GeoSourceKind.ReFilter => new ReFilterSource(mirrors),
            GeoSourceKind.CustomUrl => new CustomUrlSource(new Uri(settings.CustomUrl ?? throw new InvalidOperationException("Не задан адрес собственного источника.")), mirrors),
            _ => new LoyalsoldierSource(mirrors),
        };
    }

    public static IGeoSource ForImport() => new CustomUrlSource(new Uri("file:///import"));
}
