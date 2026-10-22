using System.Net;
using System.Security.Principal;
using Microsoft.Extensions.Time.Testing;
using SplitVpn.Core.Diagnostics;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Service.Ipc;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.OpenConnect;

namespace SplitVpn.Service.Tests;

/// <summary>Строки подробного журнала: что пишется, что нет и что не попадает туда никогда.</summary>
[Collection("Verbose")]
public sealed class VerboseTraceTests : IDisposable
{
    private readonly List<(string Category, string Text)> _lines = [];

    public VerboseTraceTests()
    {
        Verbose.Sink = (category, text) =>
        {
            lock (_lines)
            {
                _lines.Add((category, text));
            }
        };
    }

    public void Dispose()
    {
        Verbose.Set(false);
        Verbose.Sink = null;
    }

    [Fact]
    public void AccessDescription_NamesAccountAndWhatDecidesAdmission()
    {
        using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);

        var text = IpcServer.DescribeAccess(identity);

        Assert.Contains(identity.Name, text, StringComparison.Ordinal);
        Assert.Contains(identity.User!.Value, text, StringComparison.Ordinal);
        Assert.Contains("Administrators: ", text, StringComparison.Ordinal);
        Assert.Contains("INTERACTIVE: ", text, StringComparison.Ordinal);
        Assert.False(string.IsNullOrWhiteSpace(IpcServer.DenialReason(identity)));
    }

    [Fact]
    public void ConnectionTrace_SkipsRoutinePollsButCountsThem()
    {
        var trace = new IpcConnectionTrace("PID 1, сеанс 2");
        var ok = IpcResponse.Success();

        Assert.Null(trace.Record(new GetStatusRequest(), ok, TimeSpan.FromMilliseconds(5)));
        Assert.Null(trace.Record(new GetEventsRequest(0), ok, TimeSpan.FromMilliseconds(5)));
        Assert.NotNull(trace.Record(new GetStatusRequest(), ok, TimeSpan.FromMilliseconds(400)));
        Assert.NotNull(trace.Record(new GetStatusRequest(), IpcResponse.Failure(IpcErrorCodes.Denied, "нет"), TimeSpan.FromMilliseconds(1)));
        var command = trace.Record(new ConnectRequest(null, null), ok, TimeSpan.FromMilliseconds(12));

        Assert.Equal("ConnectRequest: ok за 12 мс", command);
        var summary = trace.Summary();
        Assert.StartsWith("GetStatusRequest×3", summary, StringComparison.Ordinal);
        Assert.Contains("ConnectRequest×1", summary, StringComparison.Ordinal);
    }

    [Fact]
    public void ConnectionTrace_NeverContainsRequestBody()
    {
        const string Secret = "Pa$$-verbose-7f3c9";
        var trace = new IpcConnectionTrace("PID 1, сеанс 2");

        var lines = new[]
        {
            trace.Record(new SetPasswordRequest(Guid.NewGuid(), Secret), IpcResponse.Success(), TimeSpan.Zero),
            trace.Record(new ConnectRequest(Guid.NewGuid(), Secret), IpcResponse.Failure(IpcErrorCodes.Failed, "дозвон не удался"), TimeSpan.Zero),
            trace.Record(new SubmitAuthFormRequest(Guid.NewGuid(), Guid.NewGuid(), new Dictionary<string, string> { ["password"] = Secret }, false), IpcResponse.Success(), TimeSpan.Zero),
        };

        Assert.All(lines, line => Assert.DoesNotContain(Secret, line!, StringComparison.Ordinal));
        Assert.DoesNotContain(Secret, trace.Summary(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task DnsQuery_IsTracedOnlyWhileVerbose()
    {
        await using var proxy = new DnsProxyServer(IPAddress.Loopback, new DnsCache(new FakeTimeProvider()));
        proxy.Configuration = new DnsProxyConfiguration
        {
            Mode = DnsProxyMode.DirectAllowed,
            DomainRoutes = [new DomainRoute("ads.example", RouteTarget.Blocked, Route: null)],
        };

        await proxy.HandleAsync(DnsMessage.BuildQuery(1, "before.ads.example", DnsMessage.TypeA), CancellationToken.None);
        Verbose.Set(true);
        await proxy.HandleAsync(DnsMessage.BuildQuery(2, "x.ads.example", DnsMessage.TypeA), CancellationToken.None);
        await proxy.HandleAsync(DnsMessage.BuildQuery(3, "free.example", DnsMessage.TypeAaaa), CancellationToken.None);
        Verbose.Set(false);
        await proxy.HandleAsync(DnsMessage.BuildQuery(4, "after.ads.example", DnsMessage.TypeA), CancellationToken.None);

        var dns = _lines.Where(l => l.Category == "Dns.Query").Select(l => l.Text).ToList();
        Assert.Equal(2, dns.Count);
        Assert.StartsWith("A x.ads.example: блокировка; правило *.ads.example → блокировать; rcode 3", dns[0], StringComparison.Ordinal);
        Assert.StartsWith("AAAA free.example: нет пути", dns[1], StringComparison.Ordinal);
    }

    [Fact]
    public void AnyConnectHelper_GetsVerboseOnlyInVerboseMode()
    {
        Assert.DoesNotContain("--verbose", SystemAnyConnectOps.Arguments("1", "2", verbose: false));
        Assert.Equal(["--pipes", "1", "2", "--verbose"], SystemAnyConnectOps.Arguments("1", "2", verbose: true));
    }
}
