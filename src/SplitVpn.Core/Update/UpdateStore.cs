using System.Globalization;
using System.Text.Json;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Update;

/// <summary>
/// Каталог обновлений: состояние, скачанный установщик и журналы установки. Лежит внутри каталога
/// данных службы и наследует его права — писать туда могут только SYSTEM и администраторы, поэтому
/// проверенный установщик нельзя подменить между проверкой и запуском.
/// </summary>
public sealed class UpdateStore
{
    /// <summary>Журналы установки старше этого срока удаляются.</summary>
    private static readonly TimeSpan KeepLogs = TimeSpan.FromDays(30);

    private readonly string _root;

    public UpdateStore(string root)
    {
        _root = root;
        Directory.CreateDirectory(_root);
    }

    /// <summary>Куда сообщать о повреждённых файлах: журнал событий и предупреждение в статусе.</summary>
    public Action<CorruptFile>? OnCorrupt { get; init; }

    private string StatePath => Path.Combine(_root, "state.json");

    public string PackagePath(string fileName) => Path.Combine(_root, fileName);

    public string PartialPath(string fileName) => Path.Combine(_root, fileName + ".part");

    public string InstallLogPath(string version, DateTimeOffset now) => Path.Combine(_root,
        string.Create(CultureInfo.InvariantCulture, $"install-{version}-{now.ToLocalTime():yyyyMMdd-HHmmss}.log"));

    public UpdateState LoadState() => SafeFile.Load(
        StatePath,
        text => JsonSerializer.Deserialize<UpdateState>(text, JsonDefaults.Options),
        () => new UpdateState(),
        "Состояние обновления программы было повреждено и заменено значениями по умолчанию",
        OnCorrupt);

    /// <summary>Каталог перенаправлен (см. <see cref="RedirectionProblem"/>) — состояние не пишется: оно остаётся в памяти службы.</summary>
    public void SaveState(UpdateState state)
    {
        if (RedirectionProblem() is null)
        {
            AtomicFile.WriteAllText(StatePath, JsonSerializer.Serialize(state, JsonDefaults.Options));
        }
    }

    /// <summary>
    /// Каталог обновлений или каталог данных над ним оказался ссылкой (junction, символическая ссылка):
    /// служба от SYSTEM писала бы и удаляла файлы по чужому пути, а проверенный установщик можно было бы
    /// подменить между проверкой и запуском. Возвращает причину отказа; null — каталоги настоящие.
    /// </summary>
    public string? RedirectionProblem()
    {
        var update = Path.GetFullPath(_root);
        foreach (var directory in new[] { update, Path.GetDirectoryName(update) })
        {
            if (directory is null)
            {
                continue;
            }

            try
            {
                var info = new DirectoryInfo(directory);
                if (info.Exists && info.Attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    return $"Каталог {directory} подменён ссылкой на другой путь: работа с обновлениями остановлена.";
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return $"Каталог {directory} не проверить: {ex.Message}";
            }
        }

        return null;
    }

    /// <summary>
    /// Убирает всё лишнее: установщики и недокачанные файлы, которых нет в состоянии, и журналы
    /// установки старше месяца. Состояние — единственный источник истины о нужном файле: установщик
    /// прошлой версии занимает десятки мегабайт и после установки или пропуска версии не нужен.
    /// Ошибки доступа молча пропускаются: уборка не должна мешать обновлению.
    /// </summary>
    public void Cleanup(UpdateState state, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (RedirectionProblem() is not null)
        {
            return;
        }

        var keep = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (state.PackageFileName is { Length: > 0 } name)
        {
            keep.Add(name);
            keep.Add(name + ".part");
        }

        foreach (var path in SafeList())
        {
            var file = Path.GetFileName(path);
            if (keep.Contains(file))
            {
                continue;
            }

            var installer = file.EndsWith(".msi", StringComparison.OrdinalIgnoreCase)
                || file.EndsWith(".part", StringComparison.OrdinalIgnoreCase);
            var expendable = installer
                || (file.EndsWith(".log", StringComparison.OrdinalIgnoreCase) && now - Age(path) > KeepLogs);
            if (expendable)
            {
                TryDelete(path);
            }
        }
    }

    private string[] SafeList()
    {
        try
        {
            return Directory.GetFiles(_root);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    private static DateTimeOffset Age(string path)
    {
        try
        {
            return File.GetLastWriteTimeUtc(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return DateTimeOffset.UtcNow;
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Файл занят установщиком или антивирусом: уйдёт при следующей уборке.
        }
    }
}
