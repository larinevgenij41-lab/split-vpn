using System.Threading.Channels;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Operations;

namespace SplitVpn.Service.Tests;

public sealed class CoordinatorResolveTests
{
    [Fact]
    public async Task SequentialDial_HeldServerDnsReleasesTheNextProfileAfterDeadline()
    {
        using var world = new FakeWorld();
        var first = new ConnectionProfile { Name = "DNS", Server = "held.example", UserName = "test", Role = ProfileRole.Primary };
        var second = new ConnectionProfile { Name = "Ready", Server = "203.0.113.10", UserName = "test", Role = ProfileRole.Secondary };
        world.Secrets.Save(second.Id, "secret");
        new ServiceStores(world.Paths).SaveSettings(new AppSettings
        {
            Profiles = [first, second], DefaultTarget = RouteTarget.Tunnel(first.Id), SequentialDial = true,
        });
        var resolver = new HeldServerResolver();
        var coordinator = new Coordinator(world.Dependencies() with { Resolver = resolver });
        using var stop = new CancellationTokenSource();
        var actor = coordinator.RunAsync(stop.Token);
        try
        {
            Assert.True((await coordinator.SubmitAsync(new ConnectRequest(null, null), stop.Token)).Ok);
            await resolver.Requests.Reader.ReadAsync(TestContext.Current.CancellationToken).AsTask()
                .WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
            Assert.Equal(0, world.Ras.Dials);
            world.Time.Advance(Coordinator.SequentialDialWait + TimeSpan.FromSeconds(1));
            for (var i = 0; i < 100 && world.Ras.Dials == 0; i++)
            {
                await coordinator.SubmitAsync(new GetStatusRequest(), stop.Token);
                await Task.Delay(10, TestContext.Current.CancellationToken);
            }

            Assert.Equal(1, world.Ras.Dials);
        }
        finally
        {
            await stop.CancelAsync();
            try { await actor; } catch (OperationCanceledException) { }
        }
    }

    [Fact]
    public async Task ServerDns_BoundsConcurrencyAndCancelsPendingLookupsOnShutdown()
    {
        using var world = new FakeWorld();
        var profiles = Enumerable.Range(0, 6).Select(i => new ConnectionProfile
        {
            Name = $"DNS {i}", Server = $"vpn{i}.example", UserName = "test",
            Role = i == 0 ? ProfileRole.Primary : ProfileRole.Secondary,
        }).ToList();
        new ServiceStores(world.Paths).SaveSettings(new AppSettings { Profiles = profiles, DefaultTarget = RouteTarget.Tunnel(profiles[0].Id) });
        var resolver = new HeldServerResolver();
        var coordinator = new Coordinator(world.Dependencies() with { Resolver = resolver });
        using var stop = new CancellationTokenSource();
        var actor = coordinator.RunAsync(stop.Token);
        var pending = new List<PendingLookup>();
        try
        {
            Assert.True((await coordinator.SubmitAsync(new ConnectRequest(null, null), stop.Token)).Ok);
            for (var i = 0; i < Coordinator.MaxServerResolutions; i++)
            {
                pending.Add(await resolver.Requests.Reader.ReadAsync(TestContext.Current.CancellationToken).AsTask()
                    .WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken));
            }

            Assert.Equal(Coordinator.MaxServerResolutions, coordinator.Facts.Tunnels.Values.Count(t => t.ServerResolving));
            Assert.False(resolver.Requests.Reader.TryRead(out _));
            pending[0].Answer.TrySetResult([FakeWorld.Server]);
            pending.Add(await resolver.Requests.Reader.ReadAsync(TestContext.Current.CancellationToken).AsTask()
                .WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken));
            Assert.Equal(5, pending.Select(p => p.Host).Distinct().Count());
        }
        finally
        {
            await stop.CancelAsync();
            try { await actor.WaitAsync(TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken); } catch (OperationCanceledException) { }
        }

        Assert.All(pending.Skip(1), p => Assert.True(p.Token.IsCancellationRequested));
    }

    [Fact]
    public async Task PendingServerDns_DoesNotHoldConnectOrDisconnect_AndIsCancelled()
    {
        using var world = new FakeWorld();
        var profile = new ConnectionProfile { Name = "DNS", Server = "vpn.example", UserName = "test", Role = ProfileRole.Primary };
        new ServiceStores(world.Paths).SaveSettings(new AppSettings { Profiles = [profile], DefaultTarget = RouteTarget.Tunnel(profile.Id) });
        var resolver = new HeldServerResolver();
        var coordinator = new Coordinator(world.Dependencies() with { Resolver = resolver });
        using var stop = new CancellationTokenSource();
        var actor = coordinator.RunAsync(stop.Token);
        try
        {
            using var caller = new CancellationTokenSource();
            var connect = coordinator.SubmitAsync(new ConnectRequest(null, null), caller.Token);
            var pending = await resolver.Requests.Reader.ReadAsync(TestContext.Current.CancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
            Assert.True((await connect.WaitAsync(TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken)).Ok);
            await caller.CancelAsync();
            Assert.False(pending.Token.IsCancellationRequested);
            Assert.True((await coordinator.SubmitAsync(new DisconnectRequest(false), stop.Token).WaitAsync(TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken)).Ok);
            Assert.True(pending.Token.IsCancellationRequested);
            Assert.Equal(0, world.Ras.Dials);
        }
        finally
        {
            await stop.CancelAsync();
            try { await actor; } catch (OperationCanceledException) { }
        }
    }

    [Fact]
    public async Task ChangedServer_DiscardsOldAnswer_AndStartsNewLookup()
    {
        using var world = new FakeWorld();
        var profile = new ConnectionProfile { Name = "DNS", Server = "old.example", UserName = "test", Role = ProfileRole.Primary };
        var settings = new AppSettings { Profiles = [profile], DefaultTarget = RouteTarget.Tunnel(profile.Id) };
        new ServiceStores(world.Paths).SaveSettings(settings);
        var resolver = new HeldServerResolver();
        var coordinator = new Coordinator(world.Dependencies() with { Resolver = resolver });
        using var stop = new CancellationTokenSource();
        var actor = coordinator.RunAsync(stop.Token);
        try
        {
            var connect = coordinator.SubmitAsync(new ConnectRequest(null, null), stop.Token);
            var old = await resolver.Requests.Reader.ReadAsync(TestContext.Current.CancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
            await connect.WaitAsync(TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
            var saved = await coordinator.SubmitAsync(new SaveSettingsRequest(settings with
            {
                Profiles = [profile with { Server = "new.example" }],
            }), stop.Token).WaitAsync(TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
            Assert.True(saved.Ok, saved.ErrorMessage);
            var current = await resolver.Requests.Reader.ReadAsync(TestContext.Current.CancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
            Assert.Equal("new.example", current.Host);
            old.Answer.TrySetResult([FakeWorld.SecondServer]);
            current.Answer.TrySetResult([FakeWorld.Server]);
            // Очередь должна принять ответ, прежде чем проверять адреса.
            for (var i = 0; i < 100; i++)
            {
                var status = await coordinator.SubmitAsync(new GetStatusRequest(), stop.Token);
                if (status.ResultAs<StatusDto>()!.ServerAddress == "203.0.113.10") break;
                await Task.Delay(10, TestContext.Current.CancellationToken);
            }

            Assert.Equal([FakeWorld.Server], coordinator.Facts.Tunnels[profile.Id].ServerAddresses);
        }
        finally
        {
            await stop.CancelAsync();
            try { await actor; } catch (OperationCanceledException) { }
        }
    }

    private sealed class HeldServerResolver : IResolver
    {
        public Channel<PendingLookup> Requests { get; } = Channel.CreateUnbounded<PendingLookup>();

        public async Task<IReadOnlyList<uint>> ResolveAsync(string host, IReadOnlyList<uint> servers, uint? index, CancellationToken token)
        {
            var pending = new PendingLookup(host, token);
            await Requests.Writer.WriteAsync(pending, token);

            return await pending.Answer.Task.WaitAsync(token);
        }
    }

    private sealed class PendingLookup(string host, CancellationToken token)
    {
        public string Host { get; } = host;
        public TaskCompletionSource<IReadOnlyList<uint>> Answer { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public CancellationToken Token { get; } = token;
    }
}
