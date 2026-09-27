namespace SplitVpn.Core.Policy;

/// <summary>
/// Кеш адресных слоёв для последовательной очереди координатора. Изменение DNS-закреплений
/// не пересобирает диапазоны и CIDR. Входы сравниваются полностью, без вероятностных хешей.
/// </summary>
public sealed class PolicyCompilationCache
{
    private PolicyInput? _input;
    private CompiledPolicy? _policy;

    public CompiledPolicy Compile(PolicyInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (_input is not null && SameAddressInputs(_input, input))
        {
            _policy = _policy!.WithPins(input);
            return _policy;
        }

        var policy = PolicyCompiler.Compile(input);
        // Коллекции вызывающего могут изменяться на месте. Снимок ключа не должен меняться вместе с ними.
        _input = input with
        {
            Rules = input.Rules.ToArray(),
            Groups = input.Groups.Select(g => g with { Members = g.Members.ToArray() }).ToArray(),
            OnLinePrefixes = input.OnLinePrefixes.ToArray(),
            ServerAddresses = input.ServerAddresses.ToArray(),
            ServiceDnsAddresses = input.ServiceDnsAddresses.ToArray(),
            ServerNetworks = input.ServerNetworks.Select(n => n with { Cidrs = n.Cidrs.ToArray() }).ToArray(),
            TunnelHosts = input.TunnelHosts.ToArray(),
            PinnedHosts = [],
        };
        _policy = policy;
        return policy;
    }

    private static bool SameAddressInputs(PolicyInput a, PolicyInput b) =>
        a.DefaultTarget == b.DefaultTarget && a.GeoTarget == b.GeoTarget && a.BypassTarget == b.BypassTarget
        && ReferenceEquals(a.Geo, b.Geo) && ReferenceEquals(a.Bypass, b.Bypass)
        && a.Rules.SequenceEqual(b.Rules)
        && a.OnLinePrefixes.SequenceEqual(b.OnLinePrefixes)
        && a.ServerAddresses.SequenceEqual(b.ServerAddresses)
        && a.ServiceDnsAddresses.SequenceEqual(b.ServiceDnsAddresses)
        && a.TunnelHosts.SequenceEqual(b.TunnelHosts)
        && a.Groups.Count == b.Groups.Count && a.Groups.Zip(b.Groups).All(p =>
            p.First.Id == p.Second.Id && p.First.Members.SequenceEqual(p.Second.Members))
        && a.ServerNetworks.Count == b.ServerNetworks.Count && a.ServerNetworks.Zip(b.ServerNetworks).All(p =>
            p.First.Target == p.Second.Target && p.First.Cidrs.SequenceEqual(p.Second.Cidrs));
}
