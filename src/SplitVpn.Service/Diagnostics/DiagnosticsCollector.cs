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

    /// <summary>Записи подключения Wi-Fi в архиве: несколько файлов по пределу самописца, а не все двадцать.</summary>
    public const long MaxWifiIncidentBytes = 8_000_000;

    /// <summary>Пределы на файлы из профиля пользователя: размер файла, число по шаблону, объём на профиль, время открытия.</summary>
    public const long MaxUserFileBytes = 20_000_000;
    public const int MaxUserFilesPerPattern = 4;
    public const long MaxUserBytes = 50_000_000;
    public static readonly TimeSpan UserFileTimeout = TimeSpan.FromSeconds(10);

    /// <summary>Журналы установщика: последние несколько.</summary>
    private const int InstallLogs = 3;

    /// <summary>
    /// Срок одной части архива. Системные части (снимок WFP через BFE, инвентаризация сети, сеансы WTS, журнал
    /// событий) обращаются к службам Windows, которые на «больной» системе могут не отвечать вовсе: часть, не
    /// уложившаяся в срок, пропускается, а не держит сбор (и запрет повторного сбора) до перезапуска службы.
    /// </summary>
    public static readonly TimeSpan DefaultPartTimeout = TimeSpan.FromSeconds(20);

    /// <summary>Сколько потоков зависших частей может жить одновременно; дальше части пропускаются сразу.</summary>
    public const int DefaultMaxStuckParts = 2;

    /// <summary>Запас под манифест и центральный каталог ZIP сверх их оценки: архив должен закрыться при любой квоте.</summary>
    internal const long ArchiveReserveBytes = 256 * 1024;

    /// <summary>Сколько пропущенных по размеру файлов перечисляется в списке проблем поимённо; остальные — числом.</summary>
    private const int MaxListedSkips = 20;

    private readonly DiagnosticsPartRunner _parts = new();

    internal TimeSpan PartTimeout { get; init; } = DefaultPartTimeout;

    internal int MaxStuckParts { get; init; } = DefaultMaxStuckParts;

    /// <summary>Файлы интерфейса в профиле пользователя, которые нужны для разбора.</summary>
    private static readonly string[] UserFilePatterns = ["ui-*.log", "ui-*.log.1", "ui.json", "proxy-backup.json"];

    public IReadOnlyList<string> Write(Stream destination, IEnumerable<DiagnosticsPart> serviceParts) => Write(destination, serviceParts, CancellationToken.None);

    public IReadOnlyList<string> Write(Stream destination, IEnumerable<DiagnosticsPart> serviceParts, CancellationToken cancellationToken, bool serviceDirectoryPrefix = false)
    {
        var problems = new List<string>();
        var entries = new List<string>();
        using (var archive = new ZipArchive(destination, ZipArchiveMode.Create, leaveOpen: true, Encoding.UTF8))
        {
            // Квоту хранения знает поток пакета: перед каждой записью сверяется, поместится ли она вместе с запасом
            // на манифест и каталог, — иначе первая же неудачная запись испортила бы весь архив.
            var zip = new ArchiveWriter(archive, serviceDirectoryPrefix ? "service/" : "", destination as QuotaWriteStream, entries, problems, cancellationToken);
            // Части службы — снимки в памяти, они строятся здесь же. Системные обращаются к службам Windows и идут со
            // сроком: зависшая пропускается, и предел брошенных потоков не отнимает у архива состояние самой службы.
            var system = Safe(systemParts, problems);
            foreach (var part in serviceParts)
            {
                cancellationToken.ThrowIfCancellationRequested();
                AddPart(zip, entries, problems, part, timed: false, cancellationToken);
            }

            foreach (var part in system)
            {
                cancellationToken.ThrowIfCancellationRequested();
                AddPart(zip, entries, problems, part, timed: true, cancellationToken);
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
            if (zip.Skipped > MaxListedSkips)
            {
                problems.Add(string.Create(CultureInfo.InvariantCulture, $"архив достиг предела размера: пропущено ещё {zip.Skipped - MaxListedSkips} файлов"));
            }

            var manifest = JsonSerializer.Serialize(new { generatedUtc = time.GetUtcNow(), entries, problems }, JsonDefaults.Options);
            // Манифест пишется всегда: под него и каталог оставлен запас.
            Add(zip, entries, problems, "service-manifest.json", manifest, reserved: true);
        }

        return problems;
    }

    private sealed class ArchiveWriter(ZipArchive archive, string prefix, QuotaWriteStream? quota, List<string> entries, List<string> problems, CancellationToken token)
    {
        public CancellationToken Token => token;

        /// <summary>Сколько файлов не взято из-за предела размера архива.</summary>
        public int Skipped { get; private set; }

        public ZipArchiveEntry CreateEntry(string path) => archive.CreateEntry(prefix + path, CompressionLevel.Optimal);

        /// <summary>
        /// Поместится ли запись такого объёма вместе с запасом на манифест и каталог. Нет — файл пропускается без
        /// попытки записи (о нём — строка в списке проблем), и архив остаётся целым.
        /// </summary>
        public bool Fits(string path, long bytes)
        {
            if (quota is null || quota.Length + EntryBytes(prefix + path, bytes) + Reserve() <= quota.Limit)
            {
                return true;
            }

            if (++Skipped <= MaxListedSkips)
            {
                problems.Add(path + ": пропущен — архив достиг предела размера");
            }

            return false;
        }

        /// <summary>Худший случай записи: несжимаемые данные (блоки deflate без сжатия), локальный заголовок и дескриптор.</summary>
        private static long EntryBytes(string name, long bytes) => bytes + (bytes / 1000) + 1024 + (2L * Encoding.UTF8.GetByteCount(name));

        /// <summary>
        /// Оценка того, что ещё запишется в конце: центральный каталог (имя и около ста байт на запись) и манифест со
        /// списком записей и проблем (экранирование JSON не больше чем втрое) — с постоянным запасом сверху.
        /// </summary>
        private long Reserve()
        {
            long total = ArchiveReserveBytes;
            foreach (var entry in entries)
            {
                total += 256 + (4L * Encoding.UTF8.GetByteCount(prefix + entry));
            }

            foreach (var problem in problems)
            {
                total += 16 + (3L * Encoding.UTF8.GetByteCount(problem));
            }

            return total;
        }
    }

    /// <summary>
    /// Часть архива; <paramref name="timed"/> — в отдельном потоке со сроком (см. <see cref="DiagnosticsPartRunner"/>):
    /// зависший системный вызов пропускает только свою часть. Отмена сбора прерывает ожидание сразу.
    /// </summary>
    private void AddPart(ArchiveWriter zip, List<string> entries, List<string> problems, DiagnosticsPart part, bool timed, CancellationToken cancellationToken)
    {
        string text;
        try
        {
            string? content;
            if (!timed)
            {
                content = part.Content();
            }
            else if (!_parts.TryRun(part.Content, PartTimeout, MaxStuckParts, cancellationToken, out content, out var skipped))
            {
                problems.Add(part.Path + ": пропущен — " + skipped);
                return;
            }

            text = content ?? "";
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            problems.Add(part.Path + ": " + ex.GetType().Name + ": " + ex.Message);
            return;
        }

        Add(zip, entries, problems, part.Path, text);
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

        // Записи подключения Wi-Fi обычно малы (сотни строк), но мигающая связь даёт файлы до предела самописца: у них
        // свой бюджет, новые — первыми.
        long incidentTotal = 0;
        var incidentsTruncated = false;
        foreach (var log in Newest(paths.Logs, Coordination.WifiIncidentRecorder.FilePattern, problems, cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (incidentTotal + log.Length > MaxWifiIncidentBytes)
            {
                if (!incidentsTruncated) { problems.Add("logs: часть записей подключения Wi-Fi пропущена из-за ограничения размера"); }
                incidentsTruncated = true;
                continue;
            }

            incidentTotal += log.Length;
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
                // Не помещающийся в архив файл и не читается: чтение файла пользователя ограничено по времени и числу.
                if (!zip.Fits(path, Math.Min(file.Length, Math.Min(MaxUserFileBytes, budget))))
                {
                    continue;
                }

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

    /// <summary>Текст в архив (UTF-8 без BOM); <paramref name="reserved"/> — запись, под которую оставлен запас (манифест).</summary>
    private static void Add(ArchiveWriter zip, List<string> entries, List<string> problems, string path, string text, bool reserved = false)
    {
        try
        {
            var data = new UTF8Encoding(false).GetBytes(text);
            if (!reserved && !zip.Fits(path, data.Length))
            {
                return;
            }

            var entry = zip.CreateEntry(path);
            using var output = entry.Open();
            output.Write(data);
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

        // Адрес PAC в копии прокси пользователя может нести логин и токен — как и в настройках, он режется до пути.
        var data = path.EndsWith("proxy-backup.json", StringComparison.OrdinalIgnoreCase)
            ? new UTF8Encoding(false).GetBytes(LogText.StripUrls(Encoding.UTF8.GetString(file.Data)))
            : file.Data;
        if (!zip.Fits(path, data.Length))
        {
            return 0;
        }

        var entry = zip.CreateEntry(path);
        ArchiveTime.Set(entry, file.LastWriteTime, problems);
        using var output = entry.Open();
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

    /// <summary>
    /// Файл, открытый журналом или другим процессом, читается с общим доступом; нет файла — не проблема. Берётся не
    /// больше длины на момент открытия: дописываемый журнал не выходит за проверенный по квоте объём.
    /// </summary>
    private static void AddFile(ArchiveWriter zip, List<string> entries, List<string> problems, string path, string source, Func<string, string>? sanitize = null)
    {
        try
        {
            using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var modified = File.GetLastWriteTime(input.SafeFileHandle);
            if (sanitize is null)
            {
                var length = input.Length;
                if (!zip.Fits(path, length))
                {
                    return;
                }

                var entry = zip.CreateEntry(path);
                ArchiveTime.Set(entry, modified, problems);
                using var output = entry.Open();
                CopyBounded(input, output, length, zip.Token);
            }
            else
            {
                // Очищаемые файлы малы (состояние, телефонная книга): читаются целиком, в архив идёт уже очищенный текст.
                string text;
                using (var reader = new StreamReader(input, new UTF8Encoding(false), true, leaveOpen: true))
                {
                    text = reader.ReadToEnd();
                }

                var data = new UTF8Encoding(false).GetBytes(sanitize(text));
                if (!zip.Fits(path, data.Length))
                {
                    return;
                }

                var entry = zip.CreateEntry(path);
                ArchiveTime.Set(entry, modified, problems);
                using var output = entry.Open();
                output.Write(data);
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

    private static void CopyBounded(Stream input, Stream output, long length, CancellationToken cancellationToken)
    {
        var buffer = new byte[81920];
        while (length > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var read = input.Read(buffer, 0, (int)Math.Min(buffer.Length, length));
            if (read == 0)
            {
                break;
            }

            output.Write(buffer, 0, read);
            length -= read;
        }
    }
}

/// <summary>
/// Части архива со сроком. Каждая строится в своём потоке; не уложившаяся в срок бросается: её поток доработает сам,
/// а поздний результат никуда не пишется — архив пишет только вызывающий поток и только то, что пришло в срок.
/// Число живых брошенных потоков ограничено: при исчерпании части пропускаются сразу, не дожидаясь срока.
/// </summary>
internal sealed class DiagnosticsPartRunner
{
    private int _running;

    /// <summary>
    /// false — часть пропущена (<paramref name="problem"/> — почему). Исключение части выбрасывается вызывающему;
    /// отмена <paramref name="cancellationToken"/> прерывает ожидание сразу.
    /// </summary>
    public bool TryRun(Func<string> content, TimeSpan timeout, int maxStuck, CancellationToken cancellationToken, out string? text, out string? problem)
    {
        text = null;
        problem = null;
        // Поток каждой прежней части к началу следующей либо закончил, либо брошен: живые здесь — только брошенные,
        // и их не больше maxStuck (сбор архива ждёт не дольше maxStuck сроков).
        if (Interlocked.Increment(ref _running) > maxStuck)
        {
            Interlocked.Decrement(ref _running);
            problem = "предел незавершённых частей: прежние системные вызовы ещё не вернулись";
            return false;
        }

        var done = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            // Место освобождается до выдачи результата: следующая часть не застанет закончившийся поток живым.
            string? result = null;
            Exception? error = null;
            try { result = content(); }
            catch (Exception ex) { error = ex; }
            finally { Interlocked.Decrement(ref _running); }

            if (error is null) done.TrySetResult(result!);
            else done.TrySetException(error);
        })
        {
            IsBackground = true,
            Name = "Часть архива разбора",
        };

        try
        {
            thread.Start();
        }
        catch
        {
            Interlocked.Decrement(ref _running);
            throw;
        }

        bool completed;
        try
        {
            completed = done.Task.Wait(timeout, cancellationToken);
        }
        catch (AggregateException ex) when (ex.InnerException is { } inner)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(inner).Throw();
            throw;
        }
        catch (OperationCanceledException)
        {
            Abandon(done.Task);
            throw;
        }

        if (!completed)
        {
            Abandon(done.Task);
            problem = string.Create(CultureInfo.InvariantCulture, $"не получена за {timeout.TotalSeconds:0.#} с (системный вызов не ответил)");
            return false;
        }

        text = done.Task.Result;
        return true;
    }

    /// <summary>Исключение брошенной части наблюдается, чтобы не всплыть необработанным.</summary>
    private static void Abandon(Task task) => _ = task.ContinueWith(t => _ = t.Exception, CancellationToken.None,
        TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
}
