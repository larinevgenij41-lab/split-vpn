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
            var (files, hits) = (0, new List<string>());
            foreach (var file in roots.SelectMany(Enumerate))
            {
                files++;
                if (Contains(file, needles))
                {
                    hits.Add(file);
                }
            }

            Console.WriteLine($"Просмотрено файлов: {files}; совпадений: {hits.Count}");
            hits.ForEach(h => Console.WriteLine("  СОВПАДЕНИЕ: " + h));
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

    private static bool Contains(string file, byte[][] needles)
    {
        byte[] content;
        try
        {
            using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            content = new byte[stream.Length];
            stream.ReadExactly(content);
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }

        return needles.Any(n => n.Length > 0 && content.AsSpan().IndexOf(n) >= 0);
    }
}
