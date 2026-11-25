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

    /// <summary>ETag действителен только для того URL, который его выдал.</summary>
    public string? LastETagUrl { get; init; }

    /// <summary>
    /// Срок годности проверенного манифеста, с которым получен <see cref="LastETag"/>. После него ETag не
    /// отправляется: ответ 304 иначе продлевал бы уже просроченный манифест, не показывая нового.
    /// </summary>
    public DateTimeOffset? LastETagExpiresUtc { get; init; }

    /// <summary>
    /// Версия программы, при которой получен <see cref="LastETag"/>. Ответ манифеста оценивался для неё:
    /// после ручной установки или отката другой версии ответ "не изменилось" скрыл бы подходящий выпуск,
    /// поэтому ETag отправляется только при той же версии. null (файл прежней версии) - ETag не отправляется.
    /// </summary>
    public string? LastETagProductVersion { get; init; }

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

    /// <summary>
    /// Сколько раз подряд скачанный установщик предлагаемого выпуска не совпал по SHA-256 с подписанным манифестом.
    /// Повтор откладывается всё дольше, после трёх автозагрузка этого выпуска останавливается до смены выпуска
    /// в манифесте или загрузки по команде пользователя. Сбрасывается новым выпуском и удачной загрузкой.
    /// </summary>
    public int HashMismatches { get; init; }

    /// <summary>
    /// SHA-256 последнего верно подписанного манифеста с версией ниже уже известной: такой манифест - «обновлений нет»,
    /// и запись в журнал о нём делается один раз, а не при каждой проверке.
    /// </summary>
    public string? IgnoredOlderManifestSha256 { get; init; }

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

    /// <summary>Номер процесса msiexec, о котором сообщил интерфейс; null — запуск ещё не подтверждён.</summary>
    public int? InstallerProcessId { get; init; }

    public string? InstallLogPath { get; init; }

    public string? LastInstallResult { get; init; }
}
