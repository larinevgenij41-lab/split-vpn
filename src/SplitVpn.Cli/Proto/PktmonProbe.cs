using System.Diagnostics;
using System.Text.Json;
using SplitVpn.Core.Net;

namespace SplitVpn.Cli.Proto;

/// <summary>Пакеты к отслеживаемым адресам на одной группе pktmon (сетевой адаптер и его стек).</summary>
internal sealed record PktmonGroupCount(string Group, long OutboundFlowPackets, long InboundFlowPackets, long OutboundDrops, long InboundDrops);

/// <summary>
/// Счётчики pktmon для пакетов к заданным адресам. Счётчики «Потоки» — пакеты, прошедшие через компонент;
/// «Сбросы» — отброшенные (например, фильтром WFP), на провод они не уходят.
/// </summary>
internal sealed class PktmonProbe : IDisposable
{
    private bool _started;

    public string? LastRawJson { get; private set; }

    public void Start(IEnumerable<uint> addresses)
    {
        Run("stop");
        Run("filter remove");
        var index = 0;
        foreach (var address in addresses.Take(32))
        {
            Run($"filter add splitvpn{index++} -i {Ipv4.Format(address)}");
        }

        Run("start --capture --counters-only");
        _started = true;
    }

    public static void Reset() => Run("reset");

    /// <summary>Почему последний снимок пуст (pktmon не ответил, вывод не разобран); null — снимок получен.</summary>
    public string? LastProblem { get; private set; }

    public IReadOnlyList<PktmonGroupCount> Snapshot()
    {
        try
        {
            LastRawJson = Run("counters --json");
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            LastRawJson = null;
            LastProblem = "pktmon не запустился: " + ex.Message;
            return [];
        }

        if (LastRawJson is null)
        {
            LastProblem = "pktmon не ответил за отведённое время";
            return [];
        }

        var groups = Parse(LastRawJson, out var problem);
        LastProblem = problem;
        return groups;
    }

    /// <summary>
    /// Разбор «pktmon counters --json». Формат не документирован и меняется между сборками Windows: отсутствующие
    /// поля и значения не того типа пропускаются, а невалидный JSON или корень не-массив дают пустой список
    /// с объяснением в <paramref name="problem"/>.
    /// </summary>
    internal static IReadOnlyList<PktmonGroupCount> Parse(string json, out string? problem)
    {
        problem = null;
        try
        {
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Array)
            {
                problem = "вывод pktmon не является массивом групп";
                return [];
            }

            return document.RootElement.EnumerateArray().Where(g => g.ValueKind == JsonValueKind.Object).Select(ReadGroup).ToList();
        }
        catch (JsonException ex)
        {
            problem = "вывод pktmon не разобран: " + ex.Message;
            return [];
        }
    }

    private static JsonElement[] Items(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var items) && items.ValueKind == JsonValueKind.Array
            ? [.. items.EnumerateArray()]
            : [];

    public void Dispose()
    {
        if (!_started)
        {
            return;
        }

        Run("stop");
        Run("filter remove");
        _started = false;
    }

    /// <summary>По группе берётся максимум по компонентам: один пакет проходит через несколько уровней стека.</summary>
    private static PktmonGroupCount ReadGroup(JsonElement group)
    {
        long outFlow = 0, inFlow = 0, outDrop = 0, inDrop = 0;
        foreach (var component in Items(group, "Components"))
        {
            foreach (var counter in Items(component, "Counters"))
            {
                var outbound = Packets(counter, "Outbound", out var outIsDrop);
                var inbound = Packets(counter, "Inbound", out var inIsDrop);
                if (outIsDrop || inIsDrop)
                {
                    outDrop = Math.Max(outDrop, outbound);
                    inDrop = Math.Max(inDrop, inbound);
                }
                else
                {
                    outFlow = Math.Max(outFlow, outbound);
                    inFlow = Math.Max(inFlow, inbound);
                }
            }
        }

        var name = group.TryGetProperty("Group", out var title) && title.ValueKind == JsonValueKind.String ? title.GetString() ?? "" : "";
        return new PktmonGroupCount(name, outFlow, inFlow, outDrop, inDrop);
    }

    private static long Packets(JsonElement counter, string direction, out bool isDrop)
    {
        isDrop = false;
        if (counter.ValueKind != JsonValueKind.Object || !counter.TryGetProperty(direction, out var value) || value.ValueKind != JsonValueKind.Object)
        {
            return 0;
        }

        isDrop = value.TryGetProperty("Last Drop Reason", out _);
        return value.TryGetProperty("Packets", out var packets) && packets.ValueKind == JsonValueKind.Number && packets.TryGetInt64(out var count) ? count : 0;
    }

    private static readonly TimeSpan RunTimeout = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Запуск pktmon. Оба потока читаются асинхронно: заполненный буфер stderr не блокирует процесс. По таймауту
    /// процесс убивается, результат — null.
    /// </summary>
    private static string? Run(string arguments)
    {
        using var process = Process.Start(new ProcessStartInfo("pktmon.exe", arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        })!;
        var output = process.StandardOutput.ReadToEndAsync();
        var errors = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(RunTimeout))
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                // Процесс успел завершиться сам.
            }

            return null;
        }

        _ = errors.GetAwaiter().GetResult();
        return output.GetAwaiter().GetResult();
    }
}
