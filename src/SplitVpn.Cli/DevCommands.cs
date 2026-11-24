using System.Text;
using System.Text.Json;
using SplitVpn.Cli.Proto;
using SplitVpn.Core.Settings;
using SplitVpn.Windows.Wfp;

namespace SplitVpn.Cli;

/// <summary>Вспомогательные команды испытаний КТ2 (с повышением).</summary>
internal static class DevCommands
{
    /// <summary>wfp-groups: число фильтров продукта по группам, JSON.</summary>
    public static Task<int> WfpGroupsAsync(CliArgs args)
    {
        using var engine = WfpEngine.Open(dynamicSession: false);
        var filters = WfpOps.ListFilters(engine, WfpIdentity.Product);
        var groups = filters.GroupBy(f => f.Name.StartsWith('[') ? f.Name[..(f.Name.IndexOf(']') + 1)] : "(без группы)")
            .ToDictionary(g => g.Key, g => g.Count());
        Console.WriteLine(JsonSerializer.Serialize(new { total = filters.Count, persistent = filters.Count(f => f.Persistent), groups }, JsonDefaults.Options));
        return Task.FromResult(0);
    }

    /// <summary>wfp-delete-one --group Direct: удалить один фильтр группы (имитация изменения извне).</summary>
    public static Task<int> WfpDeleteOneAsync(CliArgs args)
    {
        var prefix = "[" + (args.Option("--group") ?? "Direct") + "] ";
        using var engine = WfpEngine.Open(dynamicSession: false);
        var victim = WfpOps.ListFilters(engine, WfpIdentity.Product).FirstOrDefault(f => f.Name.StartsWith(prefix, StringComparison.Ordinal));
        if (victim is null)
        {
            Console.WriteLine("Фильтров группы нет.");
            return Task.FromResult(1);
        }

        WfpOps.DeleteFilters(engine, [victim.Id]);
        Console.WriteLine($"Удалён фильтр {victim.Id}: {victim.Name}");
        return Task.FromResult(0);
    }

    /// <summary>
    /// secret-scan --path a --path b: ищет пароль профиля прототипа (UTF-8 и UTF-16) в файлах. Пароль не печатается;
    /// выводятся только пути с совпадениями.
    /// </summary>
    public static Task<int> SecretScanAsync(CliArgs args)
    {
        var password = ProtoContext.LoadPassword();
        try
        {
            var needles = new[] { Encoding.UTF8.GetBytes(password), Encoding.Unicode.GetBytes(password) };
            var roots = args.Values("--path");
            var (files, hits, skipped) = (0, new List<string>(), new List<string>());
            foreach (var file in roots.SelectMany(Enumerate))
            {
                files++;
                switch (Contains(file, needles, out var problem))
                {
                    case true:
                        hits.Add(file);
                        break;
                    case null:
                        skipped.Add($"{file} ({problem})");
                        break;
                }
            }

            Console.WriteLine($"Просмотрено файлов: {files}; совпадений: {hits.Count}; пропущено (не прочитаны): {skipped.Count}");
            hits.ForEach(h => Console.WriteLine("  СОВПАДЕНИЕ: " + h));
            skipped.ForEach(s => Console.WriteLine("  ПРОПУЩЕН: " + s));
            foreach (var needle in needles)
            {
                Array.Clear(needle);
            }

            return Task.FromResult(hits.Count == 0 ? 0 : 1);
        }
        finally
        {
            Array.Clear(password);
        }
    }

    private static IEnumerable<string> Enumerate(string root) =>
        File.Exists(root) ? [root]
        : Directory.Exists(root) ? Directory.EnumerateFiles(root, "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true })
        : [];

    /// <summary>Есть ли в файле одна из игл; null — файл не прочитан (причина в <paramref name="problem"/>).</summary>
    private static bool? Contains(string file, byte[][] needles, out string? problem)
    {
        problem = null;
        try
        {
            using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return StreamContains(stream, needles);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            problem = ex.Message;
            return null;
        }
    }

    /// <summary>
    /// Потоковый поиск игл блоками: файл любого размера не читается в память целиком. Между блоками сохраняется
    /// хвост длиной (самая длинная игла − 1), чтобы не пропустить совпадение на границе. Буфер с фрагментами
    /// пароля стирается.
    /// </summary>
    internal static bool StreamContains(Stream stream, IReadOnlyList<byte[]> needles, int blockSize = 1 << 20)
    {
        var active = needles.Where(n => n.Length > 0).ToList();
        if (active.Count == 0)
        {
            return false;
        }

        var overlap = active.Max(n => n.Length) - 1;
        var buffer = new byte[overlap + blockSize];
        try
        {
            var kept = 0;
            while (true)
            {
                var read = stream.Read(buffer, kept, blockSize);
                if (read == 0)
                {
                    return false;
                }

                var length = kept + read;
                var window = buffer.AsSpan(0, length);
                foreach (var needle in active)
                {
                    if (window.IndexOf(needle) >= 0)
                    {
                        return true;
                    }
                }

                kept = Math.Min(overlap, length);
                buffer.AsSpan(length - kept, kept).CopyTo(buffer);
            }
        }
        finally
        {
            Array.Clear(buffer);
        }
    }
}
