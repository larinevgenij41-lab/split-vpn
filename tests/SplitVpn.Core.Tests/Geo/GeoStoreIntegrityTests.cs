using System.Text;
using SplitVpn.Core.Geo;
using SplitVpn.Core.Net;

namespace SplitVpn.Core.Tests.Geo;

/// <summary>Повреждённое состояние и потерянная активная версия списка: исправления аудита 2026-11-01 (ID63, ID65).</summary>
public sealed class GeoStoreIntegrityTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "splitvpn-tests", Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private static readonly GeoValidationOptions Options = new() { MinV4Count = 1 };

    private static GeoRevisionInfo Info() => new(null, DateTimeOffset.UnixEpoch, null, null);

    /// <summary>ID65: «skipped»: null в state.json не роняет проверку обновлений.</summary>
    [Fact]
    public void NullSkipped_IsLoadedAsEmpty()
    {
        var store = new GeoStore(_root);
        File.WriteAllText(Path.Combine(_root, "state.json"), """{"active":null,"skipped":null}""");

        var state = store.LoadState();

        Assert.NotNull(state.Skipped);
        Assert.Empty(state.Skipped);
        var evaluation = GeoUpdateEvaluator.Evaluate(Encoding.UTF8.GetBytes("5.8.0.0/16\n"), new LoyalsoldierSource(), state, RangeSet.Empty, Info(), Options);
        Assert.Equal(GeoEvaluationOutcome.Accept, evaluation.Outcome);
    }

    /// <summary>
    /// ID63: файл списка активной версии удалён, база пуста. То же содержимое из источника не «не изменилось»,
    /// а принимается без подтверждения и перезаписывает потерянный файл.
    /// </summary>
    [Fact]
    public void LostActiveRevision_IsRestoredBySameContent()
    {
        var store = new GeoStore(_root);
        var content = Encoding.UTF8.GetBytes(string.Join('\n', Enumerable.Range(0, 100).Select(i => $"5.{i * 2}.0.0/16")));
        var id = GeoStore.ComputeId(content);
        var source = new LoyalsoldierSource();
        store.SaveRevision(content, new GeoRevision { Id = id, SourceId = LoyalsoldierSource.SourceId });
        var state = store.Activate(id);
        var active = GeoUpdateEvaluator.LoadRevision(store, id, Options).V4;
        Assert.Equal(GeoEvaluationOutcome.Unchanged, GeoUpdateEvaluator.Evaluate(content, source, state, active, Info(), Options).Outcome);

        File.Delete(Path.Combine(_root, "revisions", id, "list.txt"));

        var evaluation = GeoUpdateEvaluator.Evaluate(content, source, state, RangeSet.Empty, Info(), Options);
        Assert.Equal(GeoEvaluationOutcome.Accept, evaluation.Outcome);

        // Ревизия с тем же номером перезаписывается: без этого восстановленная база снова не читалась бы.
        store.SaveRevision(GeoUpdateEvaluator.ToStoredBytes(evaluation.CidrText!), evaluation.Revision!);
        Assert.Equal(id, store.Activate(id).Active);
        Assert.Equal(active.Count, GeoUpdateEvaluator.LoadRevision(store, id, Options).V4.Count);
    }
}
