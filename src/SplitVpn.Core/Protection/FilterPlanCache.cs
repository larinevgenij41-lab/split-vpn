using SplitVpn.Core.Policy;

namespace SplitVpn.Core.Protection;

/// <summary>Повторно использует адресные планы; динамические и небольшие Runtime строятся по текущим фактам.</summary>
public sealed class FilterPlanCache
{
    private readonly DomainFilterCache _pins = new();
    private ProtectionInputs? _previous;
    private IReadOnlyList<FilterSpec> _base = [];
    private IReadOnlyList<FilterSpec> _direct = [];

    public Dictionary<FilterGroup, IReadOnlyList<FilterSpec>> Build(ProtectionInputs inputs)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        var samePolicy = _previous is not null && inputs.Policy.SharesAddressPolicy(_previous.Policy);
        if (!samePolicy || _previous!.LocalAccess != inputs.LocalAccess)
        {
            _base = FilterPlanBuilder.BuildBase(inputs);
        }

        if (!samePolicy || _previous!.PrimaryLuid != inputs.PrimaryLuid
            || !_previous.Tunnels.Select(DirectKey).SequenceEqual(inputs.Tunnels.Select(DirectKey)))
        {
            _direct = FilterPlanBuilder.BuildDirect(inputs);
        }

        _previous = inputs with { Tunnels = inputs.Tunnels.ToArray() };
        return new Dictionary<FilterGroup, IReadOnlyList<FilterSpec>>
        {
            [FilterGroup.Base] = _base,
            [FilterGroup.Runtime] = FilterPlanBuilder.BuildRuntime(inputs),
            [FilterGroup.Dynamic] = FilterPlanBuilder.BuildDynamic(inputs, _pins),
            [FilterGroup.Direct] = _direct,
        };
    }

    private static (Guid Id, string Name, ulong? Luid) DirectKey(TunnelInput tunnel) =>
        (tunnel.Id, tunnel.Name, tunnel.Luid);
}

/// <summary>От одного построения к следующему сохраняет спецификации действующих адресов с тем же действием и интерфейсом.</summary>
internal sealed class DomainFilterCache
{
    private Dictionary<(uint, TargetKind, ulong?), FilterSpec[]> _previous = [];
    private Dictionary<(uint, TargetKind, ulong?), FilterSpec[]> _current = [];

    public bool Reuse((uint, TargetKind, ulong?) key, List<FilterSpec> destination)
    {
        if (!_previous.TryGetValue(key, out var specs)) { return false; }
        destination.AddRange(specs);
        _current[key] = specs;
        return true;
    }

    public void Remember((uint, TargetKind, ulong?) key, List<FilterSpec> source, int start)
    {
        var specs = new FilterSpec[source.Count - start];
        source.CopyTo(start, specs, 0, specs.Length);
        _current[key] = specs;
    }

    public void Complete()
    {
        (_previous, _current) = (_current, _previous);
        _current.Clear();
    }
}
