namespace SplitVpn.Core.Protection;

/// <summary>Повторно использует адресные планы; динамические и небольшие Runtime строятся по текущим фактам.</summary>
public sealed class FilterPlanCache
{
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
            [FilterGroup.Dynamic] = FilterPlanBuilder.BuildDynamic(inputs),
            [FilterGroup.Direct] = _direct,
        };
    }

    private static (Guid Id, string Name, ulong? Luid) DirectKey(TunnelInput tunnel) =>
        (tunnel.Id, tunnel.Name, tunnel.Luid);
}
