using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using SplitVpn.Core.Geo;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Service.Coordination;

namespace SplitVpn.Service.Tests;

public sealed partial class CoordinatorTests
{
    private const string GeoUrlA = "https://lists.example/a.txt";
    private const string GeoUrlB = "https://lists.example/b.txt";

    private static string GeoContent(int marker) => string.Join('\n',
        Enumerable.Range(0, 1200).Select(i => $"5.{i / 250}.{i % 250}.0/24")
            .Append("77.88.0.0/18").Append($"11.0.{marker}.0/24"));

    private sealed class GeoHttpSource : HttpMessageHandler
    {
        public TaskCompletionSource? Release { get; init; }
        public bool ThrowOnRequest { get; init; }
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Cancelled { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public ConcurrentQueue<(string Url, string ETag)> Requests { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Enqueue((request.RequestUri!.AbsoluteUri, request.Headers.IfNoneMatch.ToString()));
            Entered.TrySetResult();
            if (ThrowOnRequest)
            {
                throw new InvalidOperationException("HTTP handler failed");
            }

            try
            {
                if (Release is not null)
                {
                    await Release.Task.WaitAsync(cancellationToken);
                }
            }
            catch (OperationCanceledException)
            {
                Cancelled.TrySetResult();
                throw;
            }

            var response = new HttpResponseMessage(request.Headers.IfNoneMatch.Count > 0 ? HttpStatusCode.NotModified : HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(Encoding.UTF8.GetBytes(GeoContent(request.RequestUri.AbsoluteUri == GeoUrlA ? 1 : 2))),
            };
            response.Headers.ETag = new EntityTagHeaderValue("\"same-tag\"");
            return response;
        }
    }

    private async Task<Coordinator> StartGeoAsync(GeoHttpSource source)
    {
        SaveSettings(Settings() with
        {
            GeoUpdate = new GeoUpdateSettings { Source = GeoSourceKind.CustomUrl, CustomUrl = GeoUrlA },
            BypassUpdate = new GeoUpdateSettings { AutoUpdate = false },
            AppUpdate = new AppUpdateSettings { AutoCheck = false },
        });
        _world.HttpHandler = source;
        return await StartAsync();
    }

    [Fact]
    public async Task GeoDownloads_ManualAndScheduledRequestsShareOneActiveOperation()
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var source = new GeoHttpSource { Release = gate };
        var coordinator = await StartGeoAsync(source);
        var first = coordinator.SubmitAsync(new GeoUpdateNowRequest(), CancellationToken.None);
        await coordinator.DrainAsync();
        await source.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3), TestContext.Current.CancellationToken);
        var second = coordinator.SubmitAsync(new GeoUpdateNowRequest(), CancellationToken.None);
        try
        {
            await coordinator.DrainAsync();
            await coordinator.TickAsync(CancellationToken.None);
        }
        finally
        {
            gate.TrySetResult();
            await PumpAsync(coordinator, first, second);
        }

        Assert.True((await first).Ok);
        Assert.Equal(IpcErrorCodes.Busy, (await second).ErrorCode);
        Assert.Single(source.Requests);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task GeoDownloads_IgnoreResultsSupersededByUserChoice(bool import)
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var source = new GeoHttpSource { Release = gate };
        var coordinator = await StartGeoAsync(source);
        var pending = coordinator.SubmitAsync(new GeoUpdateNowRequest(), CancellationToken.None);
        await coordinator.DrainAsync();
        await source.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3), TestContext.Current.CancellationToken);
        string? expected = null;
        try
        {
            var change = import
                ? await coordinator.HandleRequestAsync(new GeoImportRequest(GeoContent(3)), CancellationToken.None)
                : await coordinator.HandleRequestAsync(new SaveSettingsRequest(coordinator.Settings with
                {
                    GeoUpdate = coordinator.Settings.GeoUpdate with { CustomUrl = GeoUrlB },
                }), CancellationToken.None);
            Assert.True(change.Ok, change.ErrorMessage);
            expected = coordinator.BuildStatus().GeoRevision;
        }
        finally
        {
            gate.TrySetResult();
            await PumpAsync(coordinator, pending);
        }

        Assert.False((await pending).Ok);
        Assert.Equal(expected, coordinator.BuildStatus().GeoRevision);
    }

    [Fact]
    public async Task GeoDownloads_ETagDoesNotTransferToAnotherUrl()
    {
        var source = new GeoHttpSource();
        var coordinator = await StartGeoAsync(source);
        var first = coordinator.SubmitAsync(new GeoUpdateNowRequest(), CancellationToken.None);
        await PumpAsync(coordinator, first);
        Assert.True((await first).Ok);
        var before = coordinator.BuildStatus().GeoRevision;
        await coordinator.HandleRequestAsync(new SaveSettingsRequest(coordinator.Settings with
        {
            GeoUpdate = coordinator.Settings.GeoUpdate with { CustomUrl = GeoUrlB },
        }), CancellationToken.None);

        var second = coordinator.SubmitAsync(new GeoUpdateNowRequest(), CancellationToken.None);
        await PumpAsync(coordinator, second);

        Assert.True((await second).Ok);
        Assert.Empty(source.Requests.Last().ETag);
        Assert.NotEqual(before, coordinator.BuildStatus().GeoRevision);
    }

    [Fact]
    public async Task GeoDownloads_ETagIsReusedForTheSameUrl()
    {
        var source = new GeoHttpSource();
        var coordinator = await StartGeoAsync(source);
        var first = coordinator.SubmitAsync(new GeoUpdateNowRequest(), CancellationToken.None);
        await PumpAsync(coordinator, first);
        Assert.True((await first).Ok);
        var before = coordinator.BuildStatus().GeoRevision;

        var second = coordinator.SubmitAsync(new GeoUpdateNowRequest(), CancellationToken.None);
        await PumpAsync(coordinator, second);

        Assert.True((await second).Ok);
        Assert.Equal("\"same-tag\"", source.Requests.Last().ETag);
        Assert.Equal(before, coordinator.BuildStatus().GeoRevision);
        Assert.Contains("304", new GeoStore(_world.Paths.Geo).LoadState().LastResult);
    }

    [Fact]
    public async Task GeoDownloads_ClearingSkippedAllowsPreviouslyDownloadedRevision()
    {
        var source = new GeoHttpSource();
        var coordinator = await StartGeoAsync(source);
        var first = coordinator.SubmitAsync(new GeoUpdateNowRequest(), CancellationToken.None);
        await PumpAsync(coordinator, first);
        Assert.True((await first).Ok);
        var downloaded = coordinator.BuildStatus().GeoRevision;
        Assert.True((await coordinator.HandleRequestAsync(new GeoImportRequest(GeoContent(3)), CancellationToken.None)).Ok);
        var imported = coordinator.BuildStatus().GeoRevision;

        var skipped = coordinator.SubmitAsync(new GeoUpdateNowRequest(), CancellationToken.None);
        await PumpAsync(coordinator, skipped);
        Assert.True((await skipped).Ok);
        Assert.Equal(imported, coordinator.BuildStatus().GeoRevision);
        Assert.True((await coordinator.HandleRequestAsync(new GeoClearSkippedRequest(), CancellationToken.None)).Ok);

        var retry = coordinator.SubmitAsync(new GeoUpdateNowRequest(), CancellationToken.None);
        await PumpAsync(coordinator, retry);

        Assert.True((await retry).Ok);
        Assert.Equal(downloaded, coordinator.BuildStatus().GeoRevision);
    }

    [Fact]
    public async Task GeoDownloads_ScheduledOperationRemainsActiveUntilResultIsApplied()
    {
        var source = new GeoHttpSource();
        var coordinator = await StartGeoAsync(source);
        await coordinator.TickAsync(CancellationToken.None);
        await WaitForQueuedUpdateAsync(coordinator);

        await coordinator.TickAsync(CancellationToken.None);
        await PumpAsync(coordinator, coordinator.GeoWork);

        Assert.Single(source.Requests);
    }

    [Fact]
    public async Task GeoDownloads_UnexpectedHttpFailureSchedulesRetryInsteadOfRepeatingEveryTick()
    {
        var source = new GeoHttpSource { ThrowOnRequest = true };
        var coordinator = await StartGeoAsync(source);
        await coordinator.TickAsync(CancellationToken.None);
        await PumpAsync(coordinator, coordinator.GeoWork);
        await coordinator.TickAsync(CancellationToken.None);
        await PumpAsync(coordinator, coordinator.GeoWork);

        Assert.Single(source.Requests);
        var state = new GeoStore(_world.Paths.Geo).LoadState();
        Assert.Contains("HTTP handler failed", state.LastResult);
        Assert.True(state.NextCheckUtc > state.LastCheckUtc);
    }

    [Fact]
    public async Task GeoDownloads_StopTokenCancelsScheduledHttpWork()
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var source = new GeoHttpSource { Release = gate };
        var coordinator = await StartGeoAsync(source);
        using var stop = new CancellationTokenSource();
        try
        {
            await coordinator.TickAsync(stop.Token);
            await source.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3), TestContext.Current.CancellationToken);
            stop.Cancel();
            await source.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        }
        finally
        {
            gate.TrySetResult();
            await coordinator.GeoWork.WaitAsync(TimeSpan.FromSeconds(3), TestContext.Current.CancellationToken);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task GeoActivation_RevalidatesStoredCandidate(bool rollback)
    {
        var store = new GeoStore(_world.Paths.Geo);
        var original = store.LoadState().Active!;
        var bytes = Encoding.UTF8.GetBytes(GeoContent(1));
        var candidate = GeoStore.ComputeId(bytes);
        store.SaveRevision(bytes, new GeoRevision { Id = candidate, SourceId = "custom-url", V4Count = 1202 });
        if (rollback)
        {
            store.Activate(candidate);
        }
        else
        {
            store.SetPending(candidate, "Для проверки");
        }

        var coordinator = await StartGeoAsync(new GeoHttpSource());
        await ConnectAsync(coordinator);
        var before = coordinator.BuildStatus().GeoRevision;
        var damaged = rollback ? original : candidate;
        await File.WriteAllTextAsync(Path.Combine(_world.Paths.Geo, "revisions", damaged, "list.txt"),
            "11.0.1.0/24", TestContext.Current.CancellationToken);

        var response = await coordinator.HandleRequestAsync(
            rollback ? new GeoRollbackRequest() : new GeoAcceptPendingRequest(), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(before, coordinator.BuildStatus().GeoRevision);
        Assert.Equal(before, store.LoadState().Active);
        Assert.Equal(DecisionSource.Geo, coordinator.Facts.Policy!.Classify(Ipv4.Parse("77.88.8.8")).Source);
    }

    [Fact]
    public async Task GeoActivation_StateWriteFailureRestoresPreviousPolicy()
    {
        var coordinator = await StartGeoAsync(new GeoHttpSource());
        await ConnectAsync(coordinator);
        var store = new GeoStore(_world.Paths.Geo);
        var before = store.LoadState().Active;
        IpcResponse response;
        using (var locked = new FileStream(Path.Combine(_world.Paths.Geo, "state.json"), FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            var request = coordinator.SubmitAsync(new GeoImportRequest(GeoContent(1)), CancellationToken.None);
            await PumpAsync(coordinator, request);
            response = await request;
        }

        Assert.False(response.Ok);
        Assert.Equal(before, store.LoadState().Active);
        Assert.Equal(before, coordinator.BuildStatus().GeoRevision);
        Assert.Equal(DecisionSource.Default, coordinator.Facts.Policy!.Classify(Ipv4.Parse("11.0.1.1")).Source);
        Assert.True((await coordinator.HandleRequestAsync(new GeoImportRequest(GeoContent(1)), CancellationToken.None)).Ok);
    }

    [Fact]
    public async Task GeoRollback_ApplyFailureKeepsCurrentRevision()
    {
        var coordinator = await StartGeoAsync(new GeoHttpSource());
        await ConnectAsync(coordinator);
        Assert.True((await coordinator.HandleRequestAsync(new GeoImportRequest(GeoContent(1)), CancellationToken.None)).Ok);
        var store = new GeoStore(_world.Paths.Geo);
        var before = store.LoadState();
        _world.Routes.FailNext = 1;

        var response = await coordinator.HandleRequestAsync(new GeoRollbackRequest(), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Contains("сбой", response.ErrorMessage);
        Assert.Equal(before.Active, coordinator.BuildStatus().GeoRevision);
        Assert.Equal(before.Active, store.LoadState().Active);
        Assert.Equal(before.Previous, store.LoadState().Previous);
        Assert.Equal(DecisionSource.Geo, coordinator.Facts.Policy!.Classify(Ipv4.Parse("11.0.1.1")).Source);
    }
}
