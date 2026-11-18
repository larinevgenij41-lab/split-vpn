using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using SplitVpn.Core.Settings;
using SplitVpn.Core.Diagnostics;
using SplitVpn.Windows.Security;

namespace SplitVpn.Service.Diagnostics;

/// <summary>Часть архива: путь внутри zip и текст, который строится во время сбора.</summary>
public sealed record DiagnosticsPart(string Path, Func<string> Content);

/// <summary>Каталог профиля пользователя Windows: имя для архива и путь.</summary>
public sealed record UserProfileFolder(string Name, string Path);

/// <summary>
/// Часть архива для разбора, которую собирает служба: её журналы, служебные файлы, снимки, журналы
/// интерфейса всех пользователей. Каждый пункт собирается отдельно — сбой одного попадает в список
/// проблем и не срывает остальное. Пароли не попадают сюда никогда: secrets.bin в архив не берётся,
/// в настройках паролей нет.
/// </summary>
public sealed class DiagnosticsCollector(ServicePaths paths, TimeProvider time, Func<IEnumerable<DiagnosticsPart>> systemParts, Func<IReadOnlyList<UserProfileFolder>> profiles)
{
    private static readonly DiagnosticsFileReader UserReader = new(2);
    /// <summary>Основной журнал службы — за столько дней и не больше этого объёма, новые первыми.</summary>
    public static readonly TimeSpan ServiceLogAge = TimeSpan.FromDays(7);
    public const long MaxServiceLogBytes = 60_000_000;

    /// <summary>Пределы на файлы из профиля пользователя: размер файла, число по шаблону, объём на профиль, время открытия.</summary>
    public const long MaxUserFileBytes = 20_000_000;
    public const int MaxUserFilesPerPattern = 4;
    public const long MaxUserBytes = 50_000_000;
    public static readonly TimeSpan UserFileTimeout = TimeSpan.FromSeconds(10);

    /// <summary>Журналы установщика: последние несколько.</summary>
    private const int InstallLogs = 3;

    /// <summary>Файлы интерфейса в профиле пользователя, которые нужны для разбора.</summary>
    private static readonly string[] UserFilePatterns = ["ui-*.log", "ui-*.log.1", "ui.json", "proxy-backup.json"];

    public IReadOnlyList<string> Write(Stream destination, IEnumerable<DiagnosticsPart> serviceParts) => Write(destination, serviceParts, CancellationToken.None);

    public IReadOnlyList<string> Write(Stream destination, IEnumerable<DiagnosticsPart> serviceParts, CancellationToken cancellationToken, bool serviceDirectoryPrefix = false)
    {
        var problems = new List<string>();
        var entries = new List<string>();
        using (var archive = new ZipArchive(destination, ZipArchiveMode.Create, leaveOpen: true, Encoding.UTF8))
        {
            var zip = new ArchiveWriter(archive, serviceDirectoryPrefix ? "service/" : "", cancellationToken);
            foreach (var part in serviceParts.Concat(Safe(systemParts, problems)))
            {
                cancellationToken.ThrowIfCancellationRequested();
                Add(zip, entries, problems, part.Path, () => part.Content());
            }

            AddLogs(zip, entries, problems, cancellationToken);
            AddFile(zip, entries, problems, "files/state.json", paths.State);
            AddFile(zip, entries, problems, "files/dns-backup.json", paths.DnsBackup);
            AddFile(zip, entries, problems, "files/splitvpn.pbk", paths.Phonebook, LogText.StripPhonebookSecrets);
            // В состоянии лежат адреса пакета и зеркал пользователя: токены из userinfo и query в архив не попадают.
            AddFile(zip, entries, problems, "files/update/state.json", Path.Combine(paths.Update, "state.json"), LogText.StripUrls);
            foreach (var log in Newest(paths.Update, "*.log", problems, cancellationToken).Take(InstallLogs))
            {
                AddFile(zip, entries, problems, "files/update/" + log.Name, log.FullName);
            }

            AddUserFiles(zip, entries, problems, cancellationToken);
            var manifest = JsonSerializer.Serialize(new { generatedUtc = time.GetUtcNow(), entries, problems }, JsonDefaults.Options);
            Add(zip, entries, problems, "service-manifest.json", () => manifest);
        }

        return problems;
    }

    private sealed record ArchiveWriter(ZipArchive Archive, string Prefix, CancellationToken Token)
    {
        public ZipArchiveEntry CreateEntry(string path) => Archive.CreateEntry(Prefix + path, CompressionLevel.Optimal);
    }

    private void AddLogs(ArchiveWriter zip, List<string> entries, List<string> problems, CancellationToken cancellationToken)
    {
        var limit = time.GetUtcNow().UtcDateTime - ServiceLogAge;
        long total = 0;
        var truncated = false;
        foreach (var log in Newest(paths.Logs, "service-*.log", problems, cancellationToken).Where(f => f.LastWriteTimeUtc >= limit))
        {
            if (total + log.Length > MaxServiceLogBytes)
            {
                if (!truncated) { problems.Add("logs: часть журналов пропущена из-за ограничения размера"); }
                truncated = true;
                continue;
            }

            cancellationToken.ThrowIfCancellationRequested();
            total += log.Length;
            AddFile(zip, entries, problems, "logs/" + log.Name, log.FullName);
        }

        foreach (var pattern in VerboseMode.FilePatterns)
        {
            foreach (var log in Newest(paths.Logs, pattern, problems, cancellationToken))
            {
                cancellationToken.ThrowIfCancellationRequested();
                AddFile(zip, entries, problems, "logs/" + log.Name, log.FullName);
            }
        }
    }

    /// <summary>
    /// Каталог программы в профиле распоряжается пользователь: пределы на число, размер файлов и время чтения
    /// не дают ему растянуть сбор на часы или заполнить диск службы. Файлы интерфейса — до 10 МБ плюс «.1».
    /// </summary>
    private void AddUserFiles(ArchiveWriter zip, List<string> entries, List<string> problems, CancellationToken cancellationToken)
    {
        foreach (var profile in Safe(profiles, problems))
        {
            var folder = Path.Combine(profile.Path, "AppData", "Local", "SplitVpn");
            long budget = MaxUserBytes;
            var candidates = Newest(folder, "*", problems, cancellationToken, limit: 1024);
            foreach (var file in UserFilePatterns.SelectMany(pattern => candidates.Where(file =>
                System.IO.Enumeration.FileSystemName.MatchesSimpleExpression(pattern, file.Name, ignoreCase: true)).Take(MaxUserFilesPerPattern)))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var path = "users/" + profile.Name + "/" + file.Name;
                budget -= AddUserFile(zip, entries, problems, path, file.FullName, folder, Math.Min(MaxUserFileBytes, budget));
            }
        }
    }

    private static List<T> Safe<T>(Func<IEnumerable<T>> source, List<string> problems)
    {
        try
        {
            return source().ToList();
        }
        catch (Exception ex)
        {
            problems.Add("источник частей: " + ex.GetType().Name + ": " + ex.Message);
            return [];
        }
    }

    private static List<FileInfo> Newest(string directory, string pattern, List<string> problems, CancellationToken cancellationToken, int limit = int.MaxValue)
    {
        try
        {
            var files = new List<FileInfo>();
            foreach (var file in new DirectoryInfo(directory).EnumerateFiles(pattern))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (files.Count == limit)
                {
                    problems.Add(directory + ": достигнут предел просмотра файлов " + limit);
                    break;
                }
                files.Add(file);
            }
            return files.OrderByDescending(f => f.LastWriteTimeUtc).ToList();
        }
        catch (DirectoryNotFoundException) { return []; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            problems.Add(directory + ": " + ex.Message);
            return [];
        }
    }

    private static void Add(ArchiveWriter zip, List<string> entries, List<string> problems, string path, Func<string> content)
    {
        try
        {
            var text = content();
            var entry = zip.CreateEntry(path);
            using var writer = new StreamWriter(entry.Open(), new UTF8Encoding(false));
            writer.Write(text);
            entries.Add(path);
        }
        catch (Exception ex)
        {
            problems.Add(path + ": " + ex.GetType().Name + ": " + ex.Message);
        }
    }

    /// <summary>
    /// Файл из профиля пользователя: служба читает его правами SYSTEM, поэтому ссылка за пределы профиля
    /// или файл с несколькими именами (подложенные пользователем) пропускаются — см. <see cref="ConfinedFile"/>.
    /// </summary>
    private static long AddUserFile(ArchiveWriter zip, List<string> entries, List<string> problems, string path, string source, string root, long limit)
    {
        var file = UserReader.Read(token => ReadConfined(source, root, limit, token), UserFileTimeout, out var problem);
        if (file is null)
        {
            problems.Add(path + ": пропущен — " + (problem ?? "ссылка за пределы каталога программы, файл с несколькими именами или сверх предела"));
            return 0;
        }

        var entry = zip.CreateEntry(path);
        ArchiveTime.Set(entry, file.LastWriteTime, problems);
        using var output = entry.Open();
        // Адрес PAC в копии прокси пользователя может нести логин и токен — как и в настройках, он режется до пути.
        var data = path.EndsWith("proxy-backup.json", StringComparison.OrdinalIgnoreCase)
            ? new UTF8Encoding(false).GetBytes(LogText.StripUrls(Encoding.UTF8.GetString(file.Data)))
            : file.Data;
        output.Write(data);
        entries.Add(path);
        return file.Data.Length;
    }

    /// <summary>Содержимое файла внутри корня и не больше предела; null — отвергнут.</summary>
    private static CollectedFile? ReadConfined(string source, string root, long limit, CancellationToken cancellationToken)
    {
        using var input = ConfinedFile.OpenRead(source, root);
        if (input is null || input.Length > limit)
        {
            return null;
        }

        var modified = File.GetLastWriteTime(input.SafeFileHandle);
        var data = DiagnosticsFileReader.ReadBounded(input, limit, cancellationToken);
        return data is null ? null : new CollectedFile(data, modified);
    }

    /// <summary>Файл, открытый журналом или другим процессом, читается с общим доступом; нет файла — не проблема.</summary>
    private static void AddFile(ArchiveWriter zip, List<string> entries, List<string> problems, string path, string source, Func<string, string>? sanitize = null)
    {
        try
        {
            using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var entry = zip.CreateEntry(path);
            ArchiveTime.Set(entry, File.GetLastWriteTime(input.SafeFileHandle), problems);
            using var output = entry.Open();
            if (sanitize is null)
            {
                input.CopyToAsync(output, zip.Token).GetAwaiter().GetResult();
            }
            else
            {
                using var reader = new StreamReader(input, new UTF8Encoding(false), true, leaveOpen: true);
                using var writer = new StreamWriter(output, new UTF8Encoding(false), leaveOpen: true);
                writer.Write(sanitize(reader.ReadToEndAsync(zip.Token).GetAwaiter().GetResult()));
            }

            entries.Add(path);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            // Файла нет (не было обновлений, нет резервной копии DNS) — это не ошибка сбора.
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            problems.Add(path + ": " + ex.GetType().Name + ": " + ex.Message);
        }
    }
}
