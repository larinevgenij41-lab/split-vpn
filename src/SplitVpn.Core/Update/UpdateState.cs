namespace SplitVpn.Core.Update;

/// <summary>Что сейчас происходит с обновлением программы.</summary>
public enum UpdatePhase
{
    /// <summary>Установлена последняя известная версия.</summary>
    Idle,

    /// <summary>Новая версия найдена, установщик ещё не скачан.</summary>
    Available,

    /// <summary>Установщик скачивается.</summary>
    Downloading,

    /// <summary>Установщик скачан и проверен: можно ставить.</summary>
    Ready,

    /// <summary>Установка запущена, интерфейс закрывается.</summary>
    Installing,

    /// <summary>Последняя попытка не удалась; установщик сохранён для повтора.</summary>
    Failed,
}

/// <summary>
/// Состояние обновления между запусками службы. Лежит в %ProgramData%\SplitVpn\update\state.json
/// рядом со скачанным установщиком.
/// </summary>
public sealed record UpdateState
{
    public DateTimeOffset? LastCheckUtc { get; init; }

    public DateTimeOffset? NextCheckUtc { get; init; }

    public string? LastResult { get; init; }

    /// <summary>ETag манифеста: повторная проверка не качает то же самое.</summary>
    public string? LastETag { get; init; }

    public UpdatePhase Phase { get; init; }

    public string? AvailableVersion { get; init; }

    public DateTimeOffset? ReleasedUtc { get; init; }

    public string? Notes { get; init; }

    public string? NotesUrl { get; init; }

    public string? PackageFileName { get; init; }

    public string? PackageSha256 { get; init; }

    public long PackageSize { get; init; }

    public long DownloadedBytes { get; init; }

    /// <summary>Неудачные попытки подряд: после трёх недокачанный файл выбрасывается и загрузка идёт с нуля.</summary>
    public int DownloadAttempts { get; init; }

    public IReadOnlyList<string> PackageUrls { get; init; } = [];

    /// <summary>Версия, которую пользователь просил больше не предлагать.</summary>
    public string? SkippedVersion { get; init; }

    /// <summary>
    /// Самая новая версия, которую когда-либо предлагал проверенный манифест. Манифест с версией ниже
    /// отклоняется: иначе подмена ответа старым, но верно подписанным манифестом откатила бы программу.
    /// </summary>
    public string? HighestSeenVersion { get; init; }

    public string? InstallVersion { get; init; }

    public DateTimeOffset? InstallStartedUtc { get; init; }

    public string? InstallLogPath { get; init; }

    public string? LastInstallResult { get; init; }
}
