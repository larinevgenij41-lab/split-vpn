using System.Diagnostics;
using SplitVpn.Core.Geo;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;

namespace SplitVpn.Cli;

internal static class GeoCommands
{
    public static async Task<int> FetchAsync(CliArgs args)
    {
        using var client = CreateClient();
        var source = new LoyalsoldierSource();
        var result = await new GeoDownloader(client).FetchAsync(source, null, CancellationToken.None);
        if (result.Status != GeoFetchStatus.Downloaded || result.Content is null)
        {
            Console.WriteLine(Text.Inv($"Загрузка не удалась: {result.Failure} — {result.Message}"));
            return 1;
        }

        var text = source.ToCidrText(result.Content);
        var validation = GeoValidator.Validate(GeoListParser.Parse(text));
        Console.WriteLine(Text.Inv($"Источник: {result.Url}"));
        Console.WriteLine(Text.Inv($"Размер: {result.Content.Length} байт, ETag: {result.ETag}"));
        Console.WriteLine(Text.Inv($"SHA-256: {GeoStore.ComputeId(result.Content)}"));
        Console.WriteLine(Text.Inv($"IPv4 записей: {validation.V4EntryCount}, IPv6 записей: {validation.V6EntryCount}"));
        Console.WriteLine(Text.Inv($"Нормализованных IPv4-диапазонов: {validation.V4.Count}, адресов: {validation.V4.TotalAddresses}"));
        PrintList("Проблемы", validation.Problems);
        PrintList("Предупреждения", validation.Warnings);

        var outDir = args.Option("--out") ?? Path.Combine("artifacts", "geo");
        Directory.CreateDirectory(outDir);
        var path = Path.Combine(outDir, "ru.txt");
        await File.WriteAllBytesAsync(path, result.Content);
        Console.WriteLine("Сохранено: " + Path.GetFullPath(path));
        return validation.IsValid ? 0 : 1;
    }

    public static async Task<int> CompileStatsAsync(CliArgs args)
    {
        var file = args.Option("--file") ?? Path.Combine("artifacts", "geo", "ru.txt");
        if (!File.Exists(file))
        {
            Console.WriteLine("Нет файла базы: " + file + ". Сначала выполните geo-fetch.");
            return 1;
        }

        var validation = GeoValidator.Validate(GeoListParser.Parse(await File.ReadAllTextAsync(file)));
        var stopwatch = Stopwatch.StartNew();
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            Geo = validation.V4,
            ServerAddresses = [Ipv4.Parse("203.0.113.20")],
            OnLinePrefixes = [Ipv4Cidr.Parse("192.168.1.0/24"), Ipv4Cidr.Parse("26.0.0.0/8"), Ipv4Cidr.Parse("172.29.128.0/20")],
        });
        stopwatch.Stop();

        Console.WriteLine(Text.Inv($"Записей IPv4 в базе: {validation.V4EntryCount}"));
        Console.WriteLine(Text.Inv($"Direct-диапазонов (WFP FWP_RANGE): {policy.DirectRanges.Count}"));
        Console.WriteLine(Text.Inv($"Direct-маршрутов (CIDR): {policy.DirectRouteCidrs.Count}"));
        Console.WriteLine(Text.Inv($"Оценка static-фильтров Direct: {policy.DirectRanges.Count * 2} (CONNECT_V4 + RECV_ACCEPT_V4)"));
        Console.WriteLine(Text.Inv($"Сегментов разметки: {policy.SegmentCount}; время компиляции: {stopwatch.ElapsedMilliseconds} мс"));
        return 0;
    }

    private static HttpClient CreateClient()
    {
        var client = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("SplitVpn-dev/0.1");
        return client;
    }

    private static void PrintList(string title, IReadOnlyList<string> items)
    {
        if (items.Count == 0)
        {
            return;
        }

        Console.WriteLine(title + ":");
        foreach (var item in items)
        {
            Console.WriteLine("  " + item);
        }
    }
}
