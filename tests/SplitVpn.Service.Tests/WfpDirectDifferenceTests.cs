using SplitVpn.Core.Protection;
using SplitVpn.Windows.Operations;
using SplitVpn.Windows.Wfp;

namespace SplitVpn.Service.Tests;

public sealed class WfpDirectDifferenceTests
{
    [Theory]
    [InlineData(FilterFamily.V4, 2)]
    [InlineData(FilterFamily.V6, 2)]
    [InlineData(FilterFamily.Both, 4)]
    public void CompleteLayerSet_IsKeptWithoutNativeChanges(FilterFamily family, int expected)
    {
        var spec = Spec("kept", family);
        var copies = Copies(spec, 1);

        var plan = SystemWfpOps.PlanDirectDifference(copies, [spec]);

        Assert.Equal(expected, plan.KeptCount);
        Assert.Empty(plan.Stale);
        Assert.Empty(plan.Missing);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void MissingOneLayer_RebuildsOnlyDamagedSpec(int missingLayer)
    {
        var damaged = Spec("damaged");
        var kept = Spec("kept");
        var remaining = Copies(damaged, 1).Where((_, index) => index != missingLayer).ToList();
        var installed = remaining.Concat(Copies(kept, 10)).ToList();

        var plan = SystemWfpOps.PlanDirectDifference(installed, [damaged, kept]);

        Assert.Equal(2, plan.KeptCount);
        Assert.Equal(remaining.Select(f => f.Id), plan.Stale);
        Assert.Equal([damaged], plan.Missing);
        Assert.Equal(4, plan.KeptCount + plan.Missing.Sum(s => WfpOps.LayersOf(s.Family).Count));
    }

    [Theory]
    [InlineData("duplicate")]
    [InlineData("wrong-layer")]
    [InlineData("extra-layer")]
    [InlineData("wrong-weight")]
    [InlineData("persistent")]
    public void InvalidLayerSet_IsRebuilt(string defect)
    {
        var spec = Spec("damaged");
        var copies = Copies(spec, 1).ToList();
        switch (defect)
        {
            case "duplicate": copies[1] = copies[1] with { Layer = copies[0].Layer }; break;
            case "wrong-layer": copies[1] = copies[1] with { Layer = Guid.NewGuid() }; break;
            case "extra-layer": copies.Add(copies[0] with { Id = 3 }); break;
            case "wrong-weight": copies[1] = copies[1] with { Weight = (byte)(spec.Weight - 1) }; break;
            case "persistent": copies[1] = copies[1] with { Persistent = true }; break;
        }

        var plan = SystemWfpOps.PlanDirectDifference(copies, [spec]);

        Assert.Equal(0, plan.KeptCount);
        Assert.Equal(copies.Select(f => f.Id), plan.Stale);
        Assert.Equal([spec], plan.Missing);
    }

    [Fact]
    public void RemovedAndNewSpec_DeleteAndAddWithoutReplacingHealthyNeighbor()
    {
        var removed = Spec("removed");
        var added = Spec("added");
        var kept = Spec("kept");
        var removedCopies = Copies(removed, 1);
        var plan = SystemWfpOps.PlanDirectDifference([.. removedCopies, .. Copies(kept, 10)], [added, kept]);

        Assert.Equal(2, plan.KeptCount);
        Assert.Equal(removedCopies.Select(f => f.Id), plan.Stale);
        Assert.Equal([added], plan.Missing);
    }

    private static FilterSpec Spec(string name, FilterFamily family = FilterFamily.V4) =>
        new(name, FilterGroup.Direct, family, FilterPlanBuilder.WeightRouteGuard, FilterAction.Block, []);

    private static List<WfpFilterInfo> Copies(FilterSpec spec, ulong firstId) =>
        WfpOps.LayersOf(spec.Family).Select((layer, index) =>
            new WfpFilterInfo(firstId + (ulong)index, spec.Name, spec.Weight, false, layer)).ToList();
}
