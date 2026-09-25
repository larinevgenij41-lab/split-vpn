using System.Globalization;
using SplitVpn.Core.Net;

namespace SplitVpn.Core.Policy;

public sealed record ValidationResult(IReadOnlyList<string> Errors, IReadOnlyList<string> Warnings)
{
    public bool IsValid => Errors.Count == 0;

    public static ValidationResult Ok { get; } = new([], []);
}

public static class PolicyValidator
{
    public static ValidationResult ValidateRules(IReadOnlyList<UserRule> rules, IReadOnlyList<uint> serviceAddresses)
    {
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(serviceAddresses);
        var errors = new List<string>();
        var warnings = new List<string>();

        foreach (var rule in rules.Where(r => r.Cidr.PrefixLength == 0))
        {
            errors.Add(Text($"Правило {rule.Cidr} охватывает весь интернет — назначьте цель карточке «Остальной интернет»."));
        }

        foreach (var group in rules.GroupBy(r => r.Cidr).Where(g => g.Select(r => r.Target).Distinct().Count() > 1))
        {
            errors.Add(Text($"Для подсети {group.Key} заданы противоречащие цели: {string.Join(", ", group.Select(r => TargetName(r.Target)).Distinct())}."));
        }

        AddOverlapWarnings(rules, serviceAddresses, warnings);
        return new ValidationResult(errors, warnings);
    }

    /// <summary>Название цели без имени туннеля: имя знает только слой настроек.</summary>
    public static string TargetName(RouteTarget target) => target.Kind switch
    {
        TargetKind.Direct => "напрямую",
        TargetKind.Block => "блокировать",
        _ => "через VPN",
    };

    private static void AddOverlapWarnings(IReadOnlyList<UserRule> rules, IReadOnlyList<uint> serviceAddresses, List<string> warnings)
    {
        // Частные сети правило перекрывает, поэтому они здесь не предупреждаются; сеть адаптера служба
        // проверяет отдельно — здесь она неизвестна.
        var protectedSet = SpecialRanges.LinkScope.Union(SpecialRanges.Loopback).Union(RangeSet.From(serviceAddresses.Select(Ipv4Range.Host)));
        foreach (var rule in rules.Where(r => r.Cidr.PrefixLength > 0 && protectedSet.Overlaps(r.Cidr.ToRange())))
        {
            warnings.Add(Text($"Правило {rule.Cidr} пересекается с loopback, multicast, link-local или служебными адресами; для них правило не действует."));
        }
    }

    private static string Text(FormattableString text) => text.ToString(CultureInfo.InvariantCulture);
}
