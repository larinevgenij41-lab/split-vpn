using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Diagnostics;

/// <summary>Файл клиента для архива: путь внутри zip и либо файл на диске, либо готовый текст.</summary>
public sealed record ArchiveFile(string EntryPath, string? SourcePath = null, string? Text = null);

/// <summary>Итог сборки: путь к архиву и что собрать не удалось.</summary>
public sealed record ArchiveResult(string Path, bool ServiceIncluded, IReadOnlyList<string> Problems);

/// <summary>
/// Один архив для разбора: часть службы (service/…), файлы клиента (ui/…), README.txt и manifest.json.
/// Если служба недоступна или отказала, архив всё равно собирается — с объяснением в service-missing.txt:
/// именно такой случай (отказ в доступе другому пользователю) и нужно разбирать.
/// </summary>
public static class DiagnosticsArchive
{
    /// <summary>Файлы интерфейса текущего пользователя (%LOCALAPPDATA%\SplitVpn) для раздела ui/.</summary>
    public static IReadOnlyList<ArchiveFile> UserFiles()
    {
        var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SplitVpn");
        string[] names = ["ui-verbose.log", "ui-verbose.log.1", "ui-errors.log", "ui-errors.log.1", "ui.json", "proxy-backup.json"];
        return names
            .Select(name => new ArchiveFile("ui/" + name, Path.Combine(folder, name)))
            .ToList();
    }

    /// <summary>Имя архива по умолчанию: время, пользователь и сеанс — архивы из разных сеансов не путаются.</summary>
    public static string DefaultFileName(DateTimeOffset now) => string.Create(CultureInfo.InvariantCulture,
        $"SplitVpn-diag-{now:yyyyMMdd-HHmmss}-{Environment.UserName}-s{System.Diagnostics.Process.GetCurrentProcess().SessionId}.zip");

    public static async Task<ArchiveResult> BuildAsync(
        Func<IpcRequest, CancellationToken, Task<IpcResponse>>? send,
        IReadOnlyList<ArchiveFile> clientFiles,
        string outPath,
        IProgress<string>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(clientFiles);
        ArgumentNullException.ThrowIfNull(outPath);
        var problems = new List<string>();
        var partial = outPath + ".part";
        var serviceZip = Path.GetTempFileName();
        try
        {
            progress?.Report("Служба собирает журналы…");
            var (serviceIncluded, missing) = await DownloadServicePartAsync(send, serviceZip, problems, progress, cancellationToken);
            progress?.Report("Архив упаковывается…");
            await using (var stream = new FileStream(partial, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var zip = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: false, Encoding.UTF8))
            {
                if (serviceIncluded)
                {
                    CopyServicePart(zip, serviceZip);
                }
                else
                {
                    AddText(zip, "service-missing.txt", missing!);
                }

                foreach (var file in clientFiles)
                {
                    AddClientFile(zip, file, problems);
                }

                AddText(zip, "README.txt", Readme);
                AddText(zip, "manifest.json", JsonSerializer.Serialize(new
                {
                    generated = DateTimeOffset.Now,
                    machine = Environment.MachineName,
                    user = Environment.UserDomainName + "\\" + Environment.UserName,
                    version = Update.UpdateVersion.Text(Update.UpdateVersion.Current),
                    serviceIncluded,
                    problems,
                }, JsonDefaults.Options));
            }

            File.Move(partial, outPath, overwrite: true);
            return new ArchiveResult(outPath, serviceIncluded, problems);
        }
        finally
        {
            TryDelete(serviceZip);
            TryDelete(partial);
        }
    }

    /// <summary>Часть службы во временный файл; ошибка — объяснение для service-missing.txt.</summary>
    private static async Task<(bool Included, string? Missing)> DownloadServicePartAsync(
        Func<IpcRequest, CancellationToken, Task<IpcResponse>>? send, string path, List<string> problems, IProgress<string>? progress, CancellationToken cancellationToken)
    {
        if (send is null)
        {
            return (false, "Служба не опрашивалась: нет подключения к ней.");
        }

        try
        {
            var collected = await send(new CollectDiagnosticsRequest(), cancellationToken);
            if (!collected.Ok || collected.ResultAs<DiagnosticsPackageDto>() is not { } package)
            {
                return (false, $"Служба не собрала свою часть: {collected.ErrorCode} — {collected.ErrorMessage}");
            }

            problems.AddRange(package.Problems.Select(p => "служба: " + p));
            await using (var output = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                long offset = 0;
                while (true)
                {
                    var response = await send(new ReadDiagnosticsChunkRequest(package.Token, offset), cancellationToken);
                    if (!response.Ok || response.ResultAs<DiagnosticsChunkDto>() is not { } chunk)
                    {
                        return (false, $"Архив службы не получен: {response.ErrorCode} — {response.ErrorMessage}");
                    }

                    await output.WriteAsync(chunk.Data, cancellationToken);
                    offset += chunk.Data.Length;
                    progress?.Report(string.Create(CultureInfo.CurrentCulture, $"Получено {offset / 1_048_576} из {package.Length / 1_048_576} МБ…"));
                    if (chunk.Last)
                    {
                        break;
                    }
                }
            }

            await using var check = File.OpenRead(path);
            var sha = Convert.ToHexStringLower(await SHA256.HashDataAsync(check, cancellationToken));
            return sha == package.Sha256
                ? (true, null)
                : (false, "Архив службы повреждён при передаче: контрольная сумма не совпала.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            return (false, "Служба недоступна: " + ex.GetType().Name + ": " + ex.Message);
        }
    }

    private static void CopyServicePart(ZipArchive zip, string serviceZip)
    {
        using var source = ZipFile.OpenRead(serviceZip);
        foreach (var entry in source.Entries)
        {
            var copy = zip.CreateEntry("service/" + entry.FullName, CompressionLevel.Optimal);
            copy.LastWriteTime = entry.LastWriteTime;
            using var input = entry.Open();
            using var output = copy.Open();
            input.CopyTo(output);
        }
    }

    private static void AddClientFile(ZipArchive zip, ArchiveFile file, List<string> problems)
    {
        try
        {
            if (file.Text is { } text)
            {
                AddText(zip, file.EntryPath, text);
                return;
            }

            if (file.SourcePath is not { } source || !File.Exists(source))
            {
                return;
            }

            using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var entry = zip.CreateEntry(file.EntryPath, CompressionLevel.Optimal);
            ArchiveTime.Set(entry, File.GetLastWriteTime(input.SafeFileHandle), problems);
            using var output = entry.Open();
            input.CopyTo(output);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            problems.Add(file.EntryPath + ": " + ex.Message);
        }
    }

    private static void AddText(ZipArchive zip, string path, string text)
    {
        var entry = zip.CreateEntry(path, CompressionLevel.Optimal);
        using var writer = new StreamWriter(entry.Open(), new UTF8Encoding(false));
        writer.Write(text);
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Временный файл удалит система.
        }
    }

    private const string Readme = """
        Архив для разбора «Раздельный VPN»

        manifest.json               когда и кем собран, версия, что собрать не удалось
        service-missing.txt         (если есть) почему нет части службы: служба недоступна или отказала
        ui/environment.json         процесс интерфейса: пользователь, SID, сеанс, права, автозапуск, служба
        ui/ui-verbose.log           подробный журнал интерфейса этого пользователя (подключения к службе,
                                    отказы, вход через браузер, прокси); строки: время, [PID], категория
        ui/ui-errors.log            необработанные ошибки интерфейса
        service/service-manifest.json  состав части службы и ошибки её сбора
        service/logs/service-*.log  основной журнал службы (сведения и выше)
        service/logs/verbose-*.log  подробный журнал службы: IPC (кто подключался, отказы и причины),
                                    сеансы Windows, очередь, сверка, WFP, маршруты, RAS, AnyConnect
        service/logs/dns-*.log      строка на каждый DNS-запрос: имя, правило, путь, итог, время
        service/status.json         состояние службы на момент сбора
        service/settings.json       настройки (паролей в них нет)
        service/events.json         события службы, как на странице «Диагностика»
        service/net/                адаптеры, маршруты, DNS адаптеров, DNS-посредник, объекты WFP
        service/system/             Windows, время, службы BFE и SplitVpn, сеансы пользователей
        service/eventlog/           журналы событий Windows за трое суток (RAS, сеансы, службы, сбои)
        service/files/              state.json, резервная копия DNS, телефонная книга, обновления
        service/users/<профиль>/    журналы интерфейса всех пользователей Windows этого компьютера

        Пароли, cookie входа и токены в архив не попадают. Адреса, имена и учётные записи — как есть.
        """;
}
