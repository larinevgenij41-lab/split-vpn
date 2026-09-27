using System.Globalization;
using System.Text.Json;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Update;

public sealed record ManifestParseResult(ReleaseInfo? Release, string? Error)
{
    public static ManifestParseResult Failed(string error) => new(null, error);
}

/// <summary>
/// Разбор манифеста релиза. Содержимое пришло из сети, поэтому проверяется каждое поле, а любая
/// неожиданность превращается в текст отказа — исключений наружу не бывает.
/// </summary>
public static class UpdateManifestParser
{
    /// <summary>Больше этого манифест не бывает: отсекается до разбора, чтобы не читать чужой большой ответ.</summary>
    public const long MaxManifestBytes = 64 * 1024;

    public const int SupportedSchema = 1;

    public const string ProductId = "SplitVpn";

    /// <summary>Верхний предел размера установщика: больше этого MSI проекта не бывает.</summary>
    public const long MaxPackageBytes = 256L * 1024 * 1024;

    /// <summary>Последняя версия, манифест которой выложен без срока годности: у более новых срок обязателен.</summary>
    public static Version LastVersionWithoutExpiry { get; } = new(0, 9, 5);

    /// <summary>
    /// Срок годности манифеста к моменту проверки. Отдельно от разбора: разбор не зависит от часов, а срок
    /// проверяется и при подписи выпуска, и в службе. Просроченный манифест означает не ошибку, а «обновлений
    /// нет»: новый выпуск выкладывается со свежим сроком.
    ///
    /// <paramref name="installed"/> — версия, которая проверяет манифест (у службы — своя). Установленной
    /// версии новее <see cref="LastVersionWithoutExpiry"/> манифест без срока годности не нужен: такие
    /// выкладывались только до неё, а повтор подписанного старого манифеста без срока иначе выдавал бы
    /// «установлена последняя версия» бессрочно и прятал настоящие выпуски. Поэтому он устарел, как просроченный.
    /// </summary>
    public static string? ExpiryProblem(ReleaseInfo release, DateTimeOffset now, Version? installed = null)
    {
        ArgumentNullException.ThrowIfNull(release);
        if (release.Manifest.ExpiresUtc is not { } expires)
        {
            return installed is not null && installed > LastVersionWithoutExpiry
                ? "Список выпусков устарел (без срока годности): новых версий не найдено."
                : null;
        }

        return now > expires
            ? string.Create(CultureInfo.InvariantCulture,
                $"Список выпусков устарел (действителен до {expires.UtcDateTime:yyyy-MM-dd}): новых версий не найдено.")
            : null;
    }

    /// <summary>Идентификатор ключа подписи — читается отдельно и до проверки подписи, по неразобранным байтам.</summary>
    public static string? ReadKeyId(byte[] utf8)
    {
        ArgumentNullException.ThrowIfNull(utf8);
        try
        {
            using var document = JsonDocument.Parse(utf8);
            return document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty("kid", out var kid) && kid.ValueKind == JsonValueKind.String
                ? kid.GetString()
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static ManifestParseResult Parse(byte[] utf8)
    {
        ArgumentNullException.ThrowIfNull(utf8);
        if (utf8.Length == 0)
        {
            return ManifestParseResult.Failed("Манифест обновления пуст.");
        }

        if (utf8.Length > MaxManifestBytes)
        {
            return ManifestParseResult.Failed("Манифест обновления превышает допустимый размер.");
        }

        UpdateManifest? manifest;
        try
        {
            manifest = JsonSerializer.Deserialize<UpdateManifest>(utf8, JsonDefaults.Options);
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException)
        {
            return ManifestParseResult.Failed("Манифест обновления повреждён: " + ex.Message);
        }

        return manifest is null ? ManifestParseResult.Failed("Манифест обновления пуст.") : Validate(manifest);
    }

    private static ManifestParseResult Validate(UpdateManifest manifest)
    {
        if (manifest.Schema != SupportedSchema)
        {
            return ManifestParseResult.Failed(string.Create(CultureInfo.InvariantCulture,
                $"Манифест обновления новее этой версии программы (схема {manifest.Schema}): обновите программу вручную."));
        }

        if (!string.Equals(manifest.Product, ProductId, StringComparison.Ordinal))
        {
            return ManifestParseResult.Failed("Манифест обновления относится к другой программе.");
        }

        if (!UpdateVersion.TryParse(manifest.Version, out var version))
        {
            return ManifestParseResult.Failed("Манифест обновления: неверная версия.");
        }

        if (manifest.ExpiresUtc is null && version > LastVersionWithoutExpiry)
        {
            return ManifestParseResult.Failed("Манифест обновления: не указан срок годности.");
        }

        Version? minUpgradable = null;
        if (!string.IsNullOrEmpty(manifest.MinUpgradableVersion))
        {
            if (!UpdateVersion.TryParse(manifest.MinUpgradableVersion, out var parsed))
            {
                return ManifestParseResult.Failed("Манифест обновления: неверная минимальная версия.");
            }

            minUpgradable = parsed;
        }

        var package = manifest.Package;
        if (!IsSha256(package.Sha256))
        {
            return ManifestParseResult.Failed("Манифест обновления: неверная контрольная сумма установщика.");
        }

        if (package.Size <= 0 || package.Size > MaxPackageBytes)
        {
            return ManifestParseResult.Failed("Манифест обновления: недопустимый размер установщика.");
        }

        if (!IsSafeFileName(package.FileName))
        {
            return ManifestParseResult.Failed("Манифест обновления: недопустимое имя файла установщика.");
        }

        var urls = new List<Uri>();
        foreach (var text in package.Urls)
        {
            if (!Uri.TryCreate(text, UriKind.Absolute, out var url) || url.Scheme != Uri.UriSchemeHttps)
            {
                return ManifestParseResult.Failed($"Манифест обновления: адрес установщика должен быть HTTPS-ссылкой ({text}).");
            }

            urls.Add(url);
        }

        if (urls.Count == 0)
        {
            return ManifestParseResult.Failed("Манифест обновления: не указан адрес установщика.");
        }

        return new ManifestParseResult(new ReleaseInfo(manifest, version, minUpgradable, urls), null);
    }

    /// <summary>Ровно 64 шестнадцатеричных знака в нижнем регистре.</summary>
    private static bool IsSha256(string? value)
    {
        if (value is not { Length: 64 })
        {
            return false;
        }

        foreach (var c in value)
        {
            if (c is not ((>= '0' and <= '9') or (>= 'a' and <= 'f')))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Имя файла без пути: манифест не должен уводить запись за пределы каталога обновлений. Проверка
    /// строгая — только буквы, цифры, точка, дефис и подчёркивание, и обязательное расширение «.msi».
    /// </summary>
    private static bool IsSafeFileName(string? value)
    {
        if (value is not { Length: > 4 and <= 128 } || value.StartsWith('.'))
        {
            return false;
        }

        foreach (var c in value)
        {
            if (c is not ((>= '0' and <= '9') or (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or '.' or '-' or '_'))
            {
                return false;
            }
        }

        return value.EndsWith(".msi", StringComparison.Ordinal);
    }
}
