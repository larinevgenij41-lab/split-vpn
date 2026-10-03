using System.Text;
using SplitVpn.Core.Net;

namespace SplitVpn.Core.Geo;

public enum GeoEvaluationOutcome
{
    /// <summary>Содержимое совпадает с активной базой.</summary>
    Unchanged,

    /// <summary>Ревизия помечена пропускаемой и не применяется автоматически.</summary>
    Skipped,

    /// <summary>Проверка не пройдена, работает прежняя база.</summary>
    Rejected,

    /// <summary>Резкое изменение: ревизия ждёт решения пользователя.</summary>
    NeedsReview,

    /// <summary>Можно применять.</summary>
    Accept,
}

public sealed record GeoEvaluation(
    GeoEvaluationOutcome Outcome,
    string Message,
    GeoRevision? Revision,
    string? CidrText,
    GeoValidationResult? Validation,
    GeoDiffResult? Diff);

/// <summary>Решение по скачанному или импортированному списку (RESEARCH, шаги 5–7).</summary>
public static class GeoUpdateEvaluator
{
    public static GeoEvaluation Evaluate(
        byte[] content,
        IGeoSource source,
        GeoStoreState state,
        RangeSet? activeSet,
        GeoRevisionInfo info,
        GeoValidationOptions? validation = null,
        GeoAnomalyThresholds? thresholds = null,
        bool isManual = false)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(state);
        var id = GeoStore.ComputeId(content);
        if (id == state.Active)
        {
            return new GeoEvaluation(GeoEvaluationOutcome.Unchanged, "Список не изменился.", null, null, null, null);
        }

        if (!isManual && state.Skipped.Contains(id))
        {
            return new GeoEvaluation(GeoEvaluationOutcome.Skipped, "Ревизия пропускается по решению пользователя.", null, null, null, null);
        }

        var text = source.ToCidrText(content);
        var result = GeoValidator.Validate(GeoListParser.Parse(text), validation);
        if (!result.IsValid)
        {
            return new GeoEvaluation(GeoEvaluationOutcome.Rejected, string.Join(" ", result.Problems), null, null, result, null);
        }

        var revision = new GeoRevision
        {
            Id = id,
            SourceId = source.Id,
            Url = info.Url?.ToString(),
            DownloadedUtc = info.RetrievedUtc,
            DataDateUtc = info.LastModified,
            ETag = info.ETag,
            V4Count = result.V4EntryCount,
            V6Count = result.V6EntryCount,
            V4Addresses = result.V4.TotalAddresses,
        };
        var diff = GeoDiff.Compare(activeSet ?? RangeSet.Empty, result.V4);
        var outcome = !isManual && GeoDiff.IsAnomalous(diff, thresholds ?? new GeoAnomalyThresholds())
            ? GeoEvaluationOutcome.NeedsReview
            : GeoEvaluationOutcome.Accept;
        var message = outcome == GeoEvaluationOutcome.NeedsReview
            ? "Резкое изменение состава списка — требуется подтверждение."
            : "Новая версия списка прошла проверку.";
        return new GeoEvaluation(outcome, message, revision, text, result, diff);
    }

    /// <summary>Загружает сохранённую ревизию (текст CIDR) и проверяет её заново порогами своего списка.</summary>
    public static GeoValidationResult LoadRevision(GeoStore store, string id, GeoValidationOptions? validation = null)
    {
        ArgumentNullException.ThrowIfNull(store);
        return GeoValidator.Validate(GeoListParser.Parse(store.ReadRevisionText(id)), validation);
    }

    public static byte[] ToStoredBytes(string cidrText) => Encoding.UTF8.GetBytes(cidrText);
}

public sealed record GeoRevisionInfo(Uri? Url, DateTimeOffset RetrievedUtc, DateTimeOffset? LastModified, string? ETag);
