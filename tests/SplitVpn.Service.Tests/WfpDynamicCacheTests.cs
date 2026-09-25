using SplitVpn.Core.Protection;
using SplitVpn.Windows.Operations;
using SplitVpn.Windows.Wfp;

namespace SplitVpn.Service.Tests;

public sealed class WfpDynamicCacheTests
{
    [Fact]
    public void OneNewPin_AddsFourFiltersWithoutListingOrDeletingExistingThousand()
    {
        var native = new FakeSession();
        using var wfp = new SystemWfpOps(() => native);
        var first = Pins(1_000);
        wfp.ReplaceGroups(Groups(first));
        var ids = native.Filters.Keys.ToHashSet();
        native.ResetCounters();

        var counts = wfp.ReplaceGroups(Groups(Pins(1_001)));

        Assert.Equal(4_004, counts[FilterGroup.Dynamic]);
        Assert.Equal(4, native.Added);
        Assert.Equal(0, native.Deleted);
        Assert.Equal(0, native.Lists);
        Assert.True(ids.IsSubsetOf(native.Filters.Keys));
    }

    [Theory]
    [InlineData("interface")]
    [InlineData("action")]
    [InlineData("family")]
    [InlineData("weight")]
    [InlineData("address")]
    [InlineData("port")]
    public void ChangedSpec_ReplacesOnlyItsLayersEvenWhenNameIsUnchanged(string change)
    {
        var native = new FakeSession();
        using var wfp = new SystemWfpOps(() => native);
        var specs = Pins(2);
        wfp.ReplaceGroups(Groups(specs));
        var oldIds = native.Filters.Values.Where(f => f.Spec.Name.EndsWith(specs[0].Name, StringComparison.Ordinal)).Select(f => f.Info.Id).ToArray();
        var updated = specs[0] with { Conditions = specs[0].Conditions.ToArray() };
        updated = change switch
        {
            "interface" => updated with { Conditions = [updated.Conditions[0], new LocalInterfaceCondition(99, true)] },
            "action" => updated with { Action = FilterAction.Permit },
            "family" => updated with { Family = FilterFamily.Both },
            "weight" => updated with { Weight = 13 },
            "address" => updated with { Conditions = [new RemoteRangeV4(1, 1), updated.Conditions[1]] },
            "port" => updated with { Conditions = [.. updated.Conditions, new RemotePortCondition(53, true)] },
            _ => throw new InvalidOperationException(),
        };
        specs[0] = updated;
        native.ResetCounters();
        wfp.ReplaceGroups(Groups(specs));

        Assert.Equal(2, native.Deleted);
        Assert.Equal(change == "family" ? 4 : 2, native.Added);
        Assert.Equal(0, native.Lists);
        Assert.All(oldIds, id => Assert.False(native.Filters.ContainsKey(id)));
    }

    [Fact]
    public void RemovedPin_DeletesOnlyItsFourFilters()
    {
        var native = new FakeSession();
        using var wfp = new SystemWfpOps(() => native);
        wfp.ReplaceGroups(Groups(Pins(2)));
        native.ResetCounters();
        var counts = wfp.ReplaceGroups(Groups(Pins(1)));
        Assert.Equal(4, native.Deleted);
        Assert.Equal(0, native.Added);
        Assert.Equal(4, counts[FilterGroup.Dynamic]);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CommitFailure_DoesNotPublishUncommittedIds(bool includeOtherGroup)
    {
        var native = new FakeSession();
        using var wfp = new SystemWfpOps(() => native);
        wfp.ReplaceGroups(Groups(Pins(1)));
        var oldIds = native.Filters.Keys.Order().ToArray();
        native.FailCommit = true;
        var groups = Groups(Pins(2));
        if (includeOtherGroup)
        {
            groups[FilterGroup.Runtime] = [new("runtime", FilterGroup.Runtime, FilterFamily.Both, 1, FilterAction.Block, [])];
        }

        Assert.Throws<InvalidOperationException>(() => wfp.ReplaceGroups(groups));
        Assert.Equal(oldIds, native.Filters.Keys.Order());
        native.FailCommit = false;
        native.ResetCounters();
        wfp.ReplaceGroups(groups);
        Assert.Equal(includeOtherGroup ? 8 : 4, native.Added);
        Assert.Equal(0, native.Deleted);
        Assert.True(oldIds.All(native.Filters.ContainsKey));
        Assert.Equal(includeOtherGroup ? 12 : 8, native.Filters.Count);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(1_000)]
    public void MissingLayer_IsDetectedAndRestoredByPeriodicCheck(int pins)
    {
        var native = new FakeSession();
        using var wfp = new SystemWfpOps(() => native);
        var groups = Groups(Pins(pins));
        groups[FilterGroup.Base] = [];
        groups[FilterGroup.Runtime] = [];
        wfp.ReplaceGroups(groups);
        native.Filters.Remove(native.Filters.Keys.First());
        native.ResetCounters();

        var counts = wfp.InstalledCounts(includeDirect: false);
        Assert.NotEqual(pins * 4, counts[FilterGroup.Dynamic]);
        Assert.Equal(pins == 1 ? 0 : 1, native.Lists);
        Assert.Equal(pins == 1 ? 4 : 0, native.PointChecks);
        wfp.ReplaceGroups(Groups(Pins(pins)));
        Assert.Equal(pins * 4, native.Filters.Count);
        Assert.Equal(pins * 4, wfp.InstalledCounts(false)[FilterGroup.Dynamic]);
    }

    [Fact]
    public void SameCountWithForeignIds_IsDetectedByFullCheck()
    {
        var native = new FakeSession();
        using var wfp = new SystemWfpOps(() => native);
        wfp.ReplaceGroups(Groups(Pins(1)));
        var replaced = native.Filters.First();
        native.Filters.Remove(replaced.Key);
        native.Filters.Add(999, replaced.Value with { Info = replaced.Value.Info with { Id = 999 } });
        Assert.Equal(-1, wfp.InstalledCounts(true)[FilterGroup.Dynamic]);
        wfp.ReplaceGroups(Groups(Pins(1)));
        Assert.False(native.Filters.ContainsKey(999));
        Assert.Equal(4, native.Filters.Count);
    }

    [Fact]
    public void Reopen_DiscardsCacheAndRemovesUnknownOldLayers()
    {
        var native = new FakeSession();
        using var wfp = new SystemWfpOps(() => native);
        wfp.ReplaceGroups(Groups(Pins(1)));
        wfp.Reopen();
        native.ResetCounters();
        wfp.ReplaceGroups(Groups(Pins(1)));
        Assert.Equal(1, native.Lists);
        Assert.Equal(4, native.Deleted);
        Assert.Equal(4, native.Added);
    }

    [Fact]
    public void FailedDriftRepair_RemainsRequiredUntilCommitEvenWithSameCount()
    {
        var native = new FakeSession();
        using var wfp = new SystemWfpOps(() => native);
        var groups = Groups(Pins(1));
        groups[FilterGroup.Base] = [];
        groups[FilterGroup.Runtime] = [];
        wfp.ReplaceGroups(groups);
        var replaced = native.Filters.First();
        native.Filters.Remove(replaced.Key);
        native.Filters.Add(999, replaced.Value with { Info = replaced.Value.Info with { Id = 999 } });
        Assert.Equal(-1, wfp.InstalledCounts(true)[FilterGroup.Dynamic]);
        native.FailCommit = true;
        Assert.Throws<InvalidOperationException>(() => wfp.ReplaceGroups(Groups(Pins(1))));
        Assert.Equal(-1, wfp.InstalledCounts(true)[FilterGroup.Dynamic]);
        Assert.Equal(-1, wfp.InstalledCounts(false)[FilterGroup.Dynamic]);
        native.FailCommit = false;
        wfp.ReplaceGroups(Groups(Pins(1)));
        Assert.Equal(4, wfp.InstalledCounts(false)[FilterGroup.Dynamic]);
        Assert.False(native.Filters.ContainsKey(999));
    }

    private static Dictionary<FilterGroup, IReadOnlyList<FilterSpec>> Groups(IReadOnlyList<FilterSpec> specs) =>
        new() { [FilterGroup.Dynamic] = specs };

    private static List<FilterSpec> Pins(int count) => Enumerable.Range(0, count).SelectMany(i => new[]
    {
        new FilterSpec($"pin-{i}-guard", FilterGroup.Dynamic, FilterFamily.V4, 14, FilterAction.Block,
            [new RemoteRangeV4((uint)i, (uint)i), new LocalInterfaceCondition(9, true)]),
        new FilterSpec($"pin-{i}-permit", FilterGroup.Dynamic, FilterFamily.V4, 14, FilterAction.Permit,
            [new RemoteRangeV4((uint)i, (uint)i), new LocalInterfaceCondition(9, false)]),
    }).ToList();

    private sealed record Installed(FilterSpec Spec, WfpFilterInfo Info);

    private sealed class FakeSession : IWfpSession
    {
        private ulong _nextId;
        public Dictionary<ulong, Installed> Filters { get; private set; } = [];
        public bool FailCommit { get; set; }
        public int Added { get; private set; }
        public int Deleted { get; private set; }
        public int Lists { get; private set; }
        public int PointChecks { get; private set; }

        public void ResetCounters() => Added = Deleted = Lists = PointChecks = 0;
        public void EnsureProvider() { }
        public IReadOnlyList<WfpFilterInfo> ListFilters()
        {
            Lists++;
            return Filters.Values.Select(f => f.Info).ToArray();
        }

        public IReadOnlyList<ulong> AddFilters(IEnumerable<FilterSpec> specs, bool persistent, bool indexed)
        {
            var ids = new List<ulong>();
            foreach (var spec in specs)
            {
                foreach (var layer in WfpOps.LayersOf(spec.Family))
                {
                    var id = ++_nextId;
                    ids.Add(id);
                    Filters.Add(id, new Installed(spec, new WfpFilterInfo(id, spec.Name, spec.Weight, persistent, layer)));
                    Added++;
                }
            }

            return ids;
        }

        public void DeleteFilters(IEnumerable<ulong> ids)
        {
            foreach (var id in ids.ToArray())
            {
                if (Filters.Remove(id))
                {
                    Deleted++;
                }
            }
        }

        public bool FilterExists(ulong id)
        {
            PointChecks++;
            return Filters.ContainsKey(id);
        }

        public void InTransaction(Action body)
        {
            var previous = new Dictionary<ulong, Installed>(Filters);
            try
            {
                body();
                if (FailCommit)
                {
                    throw new InvalidOperationException("commit failed");
                }
            }
            catch
            {
                Filters = previous;
                throw;
            }
        }

        public void DeleteAll() => Filters.Clear();
        public void Dispose() { }
    }
}
