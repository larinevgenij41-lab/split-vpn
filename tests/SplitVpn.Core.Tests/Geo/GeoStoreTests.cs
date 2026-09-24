using System.Text;
using SplitVpn.Core.Geo;
using SplitVpn.Core.Net;

namespace SplitVpn.Core.Tests.Geo;

public sealed class GeoStoreTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "splitvpn-tests", Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [Fact]
    public void Activate_KeepsPreviousAndRemovesOlderRevisions()
    {
        var store = new GeoStore(_root);
        var a = Save(store, "a");
        store.Activate(a);
        var b = Save(store, "b");
        store.Activate(b);
        var c = Save(store, "c");

        var state = store.Activate(c);

        Assert.Equal(c, state.Active);
        Assert.Equal(b, state.Previous);
        Assert.False(store.HasRevision(a));
        Assert.True(store.HasRevision(b));
    }

    [Fact]
    public void Rollback_RestoresPrevious_AndSkipsReplacedRevision()
    {
        var store = new GeoStore(_root);
        var a = Save(store, "a");
        store.Activate(a);
        var b = Save(store, "b");
        store.Activate(b);

        var state = store.Rollback();

        Assert.NotNull(state);
        Assert.Equal(a, state.Active);
        Assert.Null(state.Previous);
        Assert.Contains(b, state.Skipped);
        Assert.Null(store.Rollback());
    }

    [Fact]
    public void Import_SkipsReplacedRevision_AndEvaluatorHonoursSkip()
    {
        var store = new GeoStore(_root);
        var downloaded = Save(store, "downloaded");
        store.Activate(downloaded);
        var imported = Save(store, "imported");

        var state = store.Activate(imported, skipReplaced: true);
        var evaluation = GeoUpdateEvaluator.Evaluate(
            Content("downloaded"), new LoyalsoldierSource(), state, RangeSet.Empty, Info(), new GeoValidationOptions { MinV4Count = 1 });

        Assert.Equal(GeoEvaluationOutcome.Skipped, evaluation.Outcome);
    }

    [Fact]
    public void PendingRevision_CanBeRejected()
    {
        var store = new GeoStore(_root);
        var a = Save(store, "a");
        store.Activate(a);
        var b = Save(store, "b");
        store.SetPending(b, "резкое изменение");

        var state = store.RejectPending();

        Assert.Null(state.Pending);
        Assert.Contains(b, state.Skipped);
        Assert.False(store.HasRevision(b));
        Assert.Empty(store.ClearSkipped().Skipped);
    }

    [Fact]
    public void State_SurvivesReload()
    {
        var store = new GeoStore(_root);
        var a = Save(store, "a");
        store.Activate(a);
        store.SaveState(store.LoadState() with { LastCheckUtc = new DateTimeOffset(2026, 9, 12, 10, 0, 0, TimeSpan.Zero) });

        var reloaded = new GeoStore(_root).LoadState();

        Assert.Equal(a, reloaded.Active);
        Assert.NotNull(reloaded.LastCheckUtc);
        Assert.Equal(a, new GeoStore(_root).ReadRevisionMeta(a)?.Id);
    }

    [Fact]
    public void Evaluator_CoversOutcomes()
    {
        var store = new GeoStore(_root);
        var options = new GeoValidationOptions { MinV4Count = 1 };
        var baseText = string.Join('\n', Enumerable.Range(0, 100).Select(i => $"5.{i * 2}.0.0/16"));
        var baseBytes = Encoding.UTF8.GetBytes(baseText);
        var baseId = GeoStore.ComputeId(baseBytes);
        store.SaveRevision(baseBytes, Meta(baseId));
        var state = store.Activate(baseId);
        var active = GeoUpdateEvaluator.LoadRevision(store, baseId).V4;
        var source = new LoyalsoldierSource();

        Assert.Equal(GeoEvaluationOutcome.Unchanged, GeoUpdateEvaluator.Evaluate(baseBytes, source, state, active, Info(), options).Outcome);
        Assert.Equal(GeoEvaluationOutcome.Rejected, GeoUpdateEvaluator.Evaluate(Encoding.UTF8.GetBytes("<html>"), source, state, active, Info(), options).Outcome);

        var halved = Encoding.UTF8.GetBytes(string.Join('\n', Enumerable.Range(0, 50).Select(i => $"5.{i * 2}.0.0/16")));
        Assert.Equal(GeoEvaluationOutcome.NeedsReview, GeoUpdateEvaluator.Evaluate(halved, source, state, active, Info(), options).Outcome);
        Assert.Equal(GeoEvaluationOutcome.Accept, GeoUpdateEvaluator.Evaluate(halved, source, state, active, Info(), options, isManual: true).Outcome);

        var grown = Encoding.UTF8.GetBytes(baseText + "\n5.201.0.0/16");
        var accepted = GeoUpdateEvaluator.Evaluate(grown, source, state, active, Info(), options);
        Assert.Equal(GeoEvaluationOutcome.Accept, accepted.Outcome);
        Assert.Equal(101, accepted.Revision?.V4Count);
        Assert.Equal(1, accepted.Diff?.AddedRanges);
    }

    private static string Save(GeoStore store, string seed)
    {
        var content = Content(seed);
        var id = GeoStore.ComputeId(content);
        store.SaveRevision(content, Meta(id));
        return id;
    }

    [Fact]
    public void CleanupFailure_DoesNotFailCommittedActivation_AndIsRetried()
    {
        var store = new GeoStore(_root);
        var a = Save(store, "a");
        store.Activate(a);
        var b = Save(store, "b");
        store.Activate(b);
        var c = Save(store, "c");
        using (var locked = new FileStream(Path.Combine(_root, "revisions", a, "list.txt"), FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            Assert.Equal(c, store.Activate(c).Active);
            Assert.Equal(c, store.LoadState().Active);
        }

        store.ClearSkipped();
        Assert.False(Directory.Exists(Path.Combine(_root, "revisions", a)));
    }

    private static byte[] Content(string seed) => Encoding.UTF8.GetBytes("# " + seed + "\n5.8.0.0/16\n");

    private static GeoRevision Meta(string id) => new() { Id = id, SourceId = LoyalsoldierSource.SourceId };

    private static GeoRevisionInfo Info() => new(null, DateTimeOffset.UnixEpoch, null, null);
}
