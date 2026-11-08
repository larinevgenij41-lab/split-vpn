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

    public IReadOnlyList<PktmonGroupCount> Snapshot()
    {
        LastRawJson = Run("counters --json");
        try
        {
            using var document = JsonDocument.Parse(LastRawJson);
            return document.RootElement.EnumerateArray().Select(ReadGroup).ToList();
        }
        catch (JsonException)
        {
            return [];
        }
    }

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
        foreach (var component in group.GetProperty("Components").EnumerateArray())
        {
            foreach (var counter in component.GetProperty("Counters").EnumerateArray())
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

        return new PktmonGroupCount(group.GetProperty("Group").GetString() ?? "", outFlow, inFlow, outDrop, inDrop);
    }

    private static long Packets(JsonElement counter, string direction, out bool isDrop)
    {
        isDrop = false;
        if (!counter.TryGetProperty(direction, out var value))
        {
            return 0;
        }

        isDrop = value.TryGetProperty("Last Drop Reason", out _);
        return value.TryGetProperty("Packets", out var packets) ? packets.GetInt64() : 0;
    }

    private static string Run(string arguments)
    {
        using var process = Process.Start(new ProcessStartInfo("pktmon.exe", arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        })!;
        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit(30_000);
        return output;
    }
}
