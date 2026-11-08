namespace SplitVpn.Core.Update;

/// <summary>Установщик, который предлагает манифест: имя, размер, контрольная сумма и адреса.</summary>
public sealed record UpdatePackageInfo
{
    public string FileName { get; init; } = "";

    public long Size { get; init; }

    /// <summary>SHA-256 файла в нижнем регистре: то же представление, что у идентификатора ревизии списка адресов.</summary>
    public string Sha256 { get; init; } = "";

    public IReadOnlyList<string> Urls { get; init; } = [];
}

/// <summary>
/// Манифест релиза: что выложено и где это взять. Подписан ключом проекта, поэтому разбирается только
/// после проверки подписи и никогда не пересериализуется — подпись считается по точным байтам файла.
/// </summary>
public sealed record UpdateManifest
{
    public int Schema { get; init; }

    public string Product { get; init; } = "";

    public string Version { get; init; } = "";

    public string Tag { get; init; } = "";

    public DateTimeOffset? ReleasedUtc { get; init; }

    /// <summary>
    /// Срок годности манифеста: позже него манифест не принимается. Без срока перехватчик мог бы бесконечно
    /// отдавать старый верно подписанный манифест и скрывать новые версии. Необязателен только у версий
    /// до 0.9.5 включительно: их манифесты выложены без этого поля.
    /// </summary>
    public DateTimeOffset? ExpiresUtc { get; init; }

    /// <summary>Ниже этой версии обновляться поверх нельзя: нужна промежуточная. Пусто — ограничения нет.</summary>
    public string? MinUpgradableVersion { get; init; }

    public UpdatePackageInfo Package { get; init; } = new();

    /// <summary>Что нового: несколько строк для карточки «О программе».</summary>
    public string? Notes { get; init; }

    public string? NotesUrl { get; init; }

    /// <summary>Каким ключом подписан манифест: нужен, чтобы ключ выпуска можно было сменить.</summary>
    public string? Kid { get; init; }
}

/// <summary>Проверенный манифест с разобранными значениями: второй раз разбирать строки не нужно.</summary>
public sealed record ReleaseInfo(UpdateManifest Manifest, Version Version, Version? MinUpgradable, IReadOnlyList<Uri> PackageUrls)
{
    public string VersionText => UpdateVersion.Text(Version);
}
