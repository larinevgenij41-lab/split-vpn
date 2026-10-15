namespace SplitVpn.Core.Protection;

/// <summary>Record сравнивает список условий по ссылке; здесь сравниваются все условия по значению.</summary>
public sealed class FilterSpecComparer : IEqualityComparer<FilterSpec>
{
    public static FilterSpecComparer Instance { get; } = new();

    public bool Equals(FilterSpec? x, FilterSpec? y) => ReferenceEquals(x, y)
        || (x is not null && y is not null && x.Name == y.Name && x.Group == y.Group
            && x.Family == y.Family && x.Weight == y.Weight && x.Action == y.Action
            && x.Conditions.SequenceEqual(y.Conditions));

    public int GetHashCode(FilterSpec obj)
    {
        ArgumentNullException.ThrowIfNull(obj);
        var hash = new HashCode();
        hash.Add(obj.Name, StringComparer.Ordinal);
        hash.Add(obj.Group);
        hash.Add(obj.Family);
        hash.Add(obj.Weight);
        hash.Add(obj.Action);
        foreach (var condition in obj.Conditions)
        {
            hash.Add(condition);
        }

        return hash.ToHashCode();
    }
}
