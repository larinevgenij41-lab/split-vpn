using System.Text.Json;
using System.Text.Json.Nodes;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Ipc;

/// <summary>
/// Последняя защита канала от ответа больше кадра (<see cref="FrameCodec.MaxFrameBytes"/>). Состояние запрашивается и при
/// подключении, и каждые полторы секунды: отказ вместо него отрезал бы от службы и интерфейс, и командную строку.
/// Поэтому ответ с состоянием сначала теряет списки сетей шлюзов (их число остаётся), и только если и это не помогло,
/// клиент получает ошибку.
/// </summary>
public static class ResponseTrimming
{
    /// <summary>
    /// Тот же ответ без списков сетей шлюзов у туннелей (StatusDto.Tunnels[].ServerNetworks.Networks) или null, если
    /// в ответе нет состояния или списки уже пусты.
    /// </summary>
    public static IpcResponse? WithoutNetworkLists(IpcResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.Result is not { ValueKind: JsonValueKind.Object } result
            || JsonNode.Parse(result.GetRawText()) is not JsonObject root
            || root["tunnels"] is not JsonArray tunnels)
        {
            return null;
        }

        var changed = false;
        foreach (var tunnel in tunnels.OfType<JsonObject>())
        {
            if (tunnel["serverNetworks"] is not JsonObject networks || networks["networks"] is not JsonArray { Count: > 0 } list)
            {
                continue;
            }

            var count = networks["networkCount"] is JsonValue value && value.TryGetValue<int>(out var known) ? known : 0;
            networks["networkCount"] = Math.Max(count, list.Count);
            networks["networks"] = new JsonArray();
            networks["networksTruncated"] = true;
            changed = true;
        }

        return changed ? response with { Result = JsonSerializer.SerializeToElement(root, JsonDefaults.Compact) } : null;
    }
}
