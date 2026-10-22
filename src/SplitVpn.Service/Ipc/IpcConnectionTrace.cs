using System.Globalization;
using System.Text;
using SplitVpn.Core.Ipc;

namespace SplitVpn.Service.Ipc;

/// <summary>
/// Что известно об одном соединении канала для подробного журнала: кто подключился и какие запросы
/// прислал. Опрос интерфейса (состояние и события каждые полторы секунды) не пишется построчно —
/// только ошибки и медленные ответы, а при закрытии соединения сводка по счётчикам.
/// </summary>
internal sealed class IpcConnectionTrace(string process)
{
    /// <summary>Ответ на опрос дольше этого пишется отдельной строкой.</summary>
    public static readonly TimeSpan SlowPoll = TimeSpan.FromMilliseconds(250);

    private readonly Dictionary<string, (int Count, TimeSpan Longest)> _counts = new(StringComparer.Ordinal);
    private readonly Lock _lock = new();

    public string Process { get; } = process;

    public string Caller { get; set; } = "учётная запись не определена";

    public string DenialReason { get; set; } = "не определена";

    public bool HasRequests
    {
        get
        {
            lock (_lock)
            {
                return _counts.Count > 0;
            }
        }
    }

    /// <summary>Учесть запрос; строка для журнала или null, если это рядовой опрос.</summary>
    public string? Record(IpcRequest? request, IpcResponse response, TimeSpan elapsed)
    {
        var type = request?.GetType().Name ?? "неразобранный";
        lock (_lock)
        {
            _counts.TryGetValue(type, out var entry);
            _counts[type] = (entry.Count + 1, elapsed > entry.Longest ? elapsed : entry.Longest);
        }

        if (request is GetStatusRequest or GetEventsRequest && response.Ok && elapsed < SlowPoll)
        {
            return null;
        }

        var result = response.Ok ? "ok" : response.ErrorCode + " «" + response.ErrorMessage + "»";
        return string.Create(CultureInfo.InvariantCulture, $"{type}: {result} за {(int)elapsed.TotalMilliseconds} мс");
    }

    /// <summary>«GetStatus×412 (дольше всех 18 мс), GetEvents×410 (…)».</summary>
    public string Summary()
    {
        var text = new StringBuilder();
        lock (_lock)
        {
            foreach (var (type, (count, longest)) in _counts.OrderByDescending(p => p.Value.Count))
            {
                text.Append(text.Length == 0 ? "" : ", ")
                    .Append(CultureInfo.InvariantCulture, $"{type}×{count} (дольше всех {(int)longest.TotalMilliseconds} мс)");
            }
        }

        return text.ToString();
    }
}
