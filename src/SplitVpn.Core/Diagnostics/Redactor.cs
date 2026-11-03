using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Diagnostics;

/// <summary>Маскирование персональных данных в диагностическом отчёте (PLAN §7).</summary>
public static partial class Redactor
{
    public static string Redact(string text, IEnumerable<string?>? secrets = null)
    {
        ArgumentNullException.ThrowIfNull(text);
        var result = text;
        foreach (var secret in (secrets ?? []).Where(s => !string.IsNullOrWhiteSpace(s)).OrderByDescending(s => s!.Length))
        {
            result = result.Replace(secret!, "<скрыто>", StringComparison.OrdinalIgnoreCase);
        }

        result = GuidPattern().Replace(result, "<guid>");
        result = MacPattern().Replace(result, "<mac>");
        result = Ipv6Pattern().Replace(result, "<ipv6>");
        result = Ipv4Pattern().Replace(result, "<ipv4>");
        return result;
    }

    /// <summary>
    /// То же для JSON: маскируются только строковые значения, структура (кавычки, имена полей) не затрагивается.
    /// Обратную косую черту и кавычки в секретах экранировать не нужно — значения уже разобраны.
    /// </summary>
    public static string RedactJson(string json, IEnumerable<string?>? secrets = null)
    {
        ArgumentNullException.ThrowIfNull(json);
        var list = (secrets ?? []).ToList();
        return RedactNode(JsonNode.Parse(json), list)?.ToJsonString(JsonDefaults.Options) ?? "null";
    }

    private static JsonNode? RedactNode(JsonNode? node, List<string?> secrets)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (var key in obj.Select(p => p.Key).ToList())
                {
                    var child = obj[key];
                    var masked = RedactNode(child, secrets);
                    if (!ReferenceEquals(masked, child))
                    {
                        obj[key] = masked;
                    }
                }

                return obj;
            case JsonArray array:
                for (var i = 0; i < array.Count; i++)
                {
                    var child = array[i];
                    var masked = RedactNode(child, secrets);
                    if (!ReferenceEquals(masked, child))
                    {
                        array[i] = masked;
                    }
                }

                return array;
            case JsonValue value when value.TryGetValue<string>(out var text):
                return JsonValue.Create(Redact(text, secrets));
            default:
                return node;
        }
    }

    [GeneratedRegex(@"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")]
    private static partial Regex GuidPattern();

    [GeneratedRegex(@"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")]
    private static partial Regex MacPattern();

    // Полная форма из 8 групп либо сокращённая с «::» — время вида 12:30:45 не совпадает.
    [GeneratedRegex(@"(?<![\w:])(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6})?::(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6})?)(?:%\w+)?(?![\w:])")]
    private static partial Regex Ipv6Pattern();

    [GeneratedRegex(@"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:/\d{1,2})?\b")]
    private static partial Regex Ipv4Pattern();
}
