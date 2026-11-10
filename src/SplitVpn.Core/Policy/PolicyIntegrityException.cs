namespace SplitVpn.Core.Policy;

/// <summary>
/// Разметка адресов нарушилась при сборке политики. Сообщение короткое — оно попадает в статус;
/// нарушение и входы сборки лежат в Details, их пишет журнал службы.
/// </summary>
public sealed class PolicyIntegrityException : Exception
{
    public PolicyIntegrityException(string layer, string violation, string input)
        : base($"Внутренняя ошибка разметки адресов (слой «{layer}»). Подробности — в журнале службы.")
    {
        Layer = layer;
        Details = $"Слой «{layer}»: {violation}{Environment.NewLine}Входы сборки:{Environment.NewLine}{input}";
    }

    public string Layer { get; }

    public string Details { get; }
}
