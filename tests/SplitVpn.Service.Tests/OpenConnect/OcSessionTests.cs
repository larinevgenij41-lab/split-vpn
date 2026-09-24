using System.Collections.Concurrent;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.OpenConnect;
using SplitVpn.OpenConnect;

namespace SplitVpn.Service.Tests.OpenConnect;

public sealed class OcSessionTests
{
    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(10);

    private static StartCommand Start(string group = "", string? user = null, string? password = null) =>
        new("https://avpn.example.org/", group, "AnyConnect Windows 4.10.06090", true, null, "SplitVpn AC 1", user, password);

    [Fact]
    public async Task Sso_ContinuesUntilLibraryAccepts_ThenEstablishesAndStops()
    {
        var world = new SessionWorld();
        var loads = new List<string>();
        world.Lib.OnObtain = callbacks => callbacks.OpenWebview("https://sso.example.org/adfs/ls");
        world.Lib.OnWebviewLoad = (uri, _) =>
        {
            loads.Add(uri);
            return uri.EndsWith("saml_ac_login.html", StringComparison.Ordinal) ? 0 : -OcCodesForTests.Eagain;
        };
        world.Lib.OnMainloop = () => world.Lib.WaitForCancel();

        var run = world.RunAsync(Start());
        var open = world.Output.Next<SsoOpenEvent>(Wait);
        Assert.Equal("avpn.example.org", open.GatewayHost);
        world.Session.Post(new WebviewLoadCommand(open.RequestId, "https://sso.example.org/adfs/ls", []));
        world.Session.Post(new WebviewLoadCommand(Guid.NewGuid(), "https://stale", []));
        world.Session.Post(new WebviewLoadCommand(open.RequestId, "https://avpn.example.org/+CSCOE+/saml_ac_login.html", [new SsoCookie("acSamlv2Token", "t")]));

        Assert.True(world.Output.Next<SsoResultEvent>(Wait).Done);
        var established = world.Output.Next<EstablishedEvent>(Wait);
        Assert.Equal(1230, established.Session.Mtu);
        Assert.Equal("SplitVpn AC 1", world.System.ConfiguredInterface);
        Assert.Equal("SplitVpn AC 1", world.System.CleanedInterface);

        world.Session.Post(new StopCommand());
        Assert.Equal(TerminationKind.Cancelled, (await run.WaitAsync(Wait, TestContext.Current.CancellationToken)));
        Assert.Equal(2, loads.Count);
        Assert.Equal(TerminationKind.Cancelled, world.Output.Next<TerminatedEvent>(Wait).Kind);
    }

    [Fact]
    public async Task Sso_WindowClosed_CancelsWithoutTunnel()
    {
        var world = new SessionWorld();
        world.Lib.OnObtain = callbacks => callbacks.OpenWebview("https://sso");

        var run = world.RunAsync(Start());
        var open = world.Output.Next<SsoOpenEvent>(Wait);
        world.Session.Post(new WebviewClosedCommand(open.RequestId));

        Assert.False(world.Output.Next<SsoResultEvent>(Wait).Done);
        Assert.Equal(TerminationKind.Cancelled, (await run.WaitAsync(Wait, TestContext.Current.CancellationToken)));
        Assert.DoesNotContain(world.Output.All, e => e is EstablishedEvent);
        Assert.Equal(0, world.Lib.CstpCalls);
    }

    [Fact]
    public async Task Stop_DuringSso_EndsAsCancelled()
    {
        var world = new SessionWorld();
        world.Lib.OnObtain = callbacks => callbacks.OpenWebview("https://sso");

        var run = world.RunAsync(Start());
        world.Output.Next<SsoOpenEvent>(Wait);
        world.Session.Post(new StopCommand());

        Assert.Equal(TerminationKind.Cancelled, (await run.WaitAsync(Wait, TestContext.Current.CancellationToken)));
        Assert.True(world.Lib.CancelSent);
    }

    [Fact]
    public void Form_GroupFromProfile_SwitchesOnceAndSavedPasswordIsOfferedOnce()
    {
        var world = new SessionWorld();
        var group = new FakeField("group_list", OcFieldKindForTests.Select, ["Sso", "Staff"]);
        var user = new FakeField("username", OcFieldKindForTests.Text);
        var password = new FakeField("password", OcFieldKindForTests.Password);
        var results = new List<int>();
        world.Lib.OnObtain = callbacks =>
        {
            results.Add(callbacks.ProcessForm(FakeField.Form(group, 0, group, user, password)));
            results.Add(callbacks.ProcessForm(FakeField.Form(group, 1, group, user, password)));
            return 0;
        };

        world.RunAsync(Start(group: "Staff", user: "user", password: "secret"));
        world.Output.Next<EstablishedEvent>(Wait);
        world.Session.Post(new StopCommand());

        Assert.Equal([OcCodesForTests.FormNewGroup, OcCodesForTests.FormOk], results);
        Assert.Equal("Staff", group.Value);
        Assert.Equal("user", user.Value);
        Assert.Equal("secret", password.Value);
        Assert.DoesNotContain(world.Output.All, e => e is AuthFormEvent);
    }

    [Fact]
    public async Task Form_MissingPassword_AsksUserAndAppliesReply()
    {
        var world = new SessionWorld();
        var password = new FakeField("password", OcFieldKindForTests.Password);
        var answer = 0;
        world.Lib.OnObtain = callbacks =>
        {
            answer = callbacks.ProcessForm(FakeField.Form(null, 0, password) with { Error = "Login failed" });
            return answer == OcCodesForTests.FormOk ? 0 : -1;
        };

        var run = world.RunAsync(Start(password: "stale"));
        var form = world.Output.Next<AuthFormEvent>(Wait);
        Assert.Equal("Login failed", form.Error);
        Assert.Equal(AuthFieldKind.Password, Assert.Single(form.Fields).Kind);
        world.Session.Post(new FormReplyCommand(form.RequestId, new Dictionary<string, string> { ["password"] = "fresh" }, false));

        world.Output.Next<EstablishedEvent>(Wait);
        world.Session.Post(new StopCommand());
        await run.WaitAsync(Wait, TestContext.Current.CancellationToken);
        Assert.Equal("fresh", password.Value);
    }

    [Fact]
    public async Task Form_CancelledByUser_EndsAsCancelled()
    {
        var world = new SessionWorld();
        var password = new FakeField("password", OcFieldKindForTests.Password);
        world.Lib.OnObtain = callbacks => callbacks.ProcessForm(FakeField.Form(null, 0, password)) == OcCodesForTests.FormOk ? 0 : -1;

        var run = world.RunAsync(Start());
        var form = world.Output.Next<AuthFormEvent>(Wait);
        world.Session.Post(new FormReplyCommand(form.RequestId, new Dictionary<string, string>(), true));

        Assert.Equal(TerminationKind.Cancelled, (await run.WaitAsync(Wait, TestContext.Current.CancellationToken)));
    }

    [Fact]
    public void Resolve_AsksServiceForGatewayAddress()
    {
        var world = new SessionWorld();
        string? resolved = null;
        world.Lib.OnObtain = callbacks =>
        {
            resolved = callbacks.Resolve("avpn.example.org");
            return 0;
        };

        world.RunAsync(Start());
        Assert.Equal("avpn.example.org", world.Output.Next<ResolveHostEvent>(Wait).Host);
        world.Session.Post(new ResolveReplyCommand("other.host", "1.1.1.1"));
        world.Session.Post(new ResolveReplyCommand("avpn.example.org", "198.51.100.10"));
        world.Output.Next<EstablishedEvent>(Wait);
        world.Session.Post(new StopCommand());

        Assert.Equal("198.51.100.10", resolved);
    }

    [Theory]
    [InlineData(-1, TerminationKind.AuthRejected)]
    [InlineData(-32, TerminationKind.SessionExpired)]
    [InlineData(-110, TerminationKind.NetworkError)]
    public async Task MainloopExit_IsClassified(int code, TerminationKind expected)
    {
        var world = new SessionWorld();
        world.Lib.OnMainloop = () => code;

        Assert.Equal(expected, (await world.RunAsync(Start()).WaitAsync(Wait, TestContext.Current.CancellationToken)));
        Assert.Equal(expected, world.Output.Next<TerminatedEvent>(Wait).Kind);
    }

    [Fact]
    public async Task Cstp401_IsAuthRejected_AndNoAdapter()
    {
        var world = new SessionWorld();
        world.Lib.OnCstp = () => -1;

        Assert.Equal(TerminationKind.AuthRejected, (await world.RunAsync(Start()).WaitAsync(Wait, TestContext.Current.CancellationToken)));
        Assert.Null(world.System.ConfiguredInterface);
    }

    [Fact]
    public async Task CertificateRejection_IsReported()
    {
        var world = new SessionWorld();
        world.Lib.OnObtain = callbacks => callbacks.ValidatePeerCertificate("certificate does not match hostname") == 0 ? 0 : -5;

        Assert.Equal(TerminationKind.CertificateRejected, (await world.RunAsync(Start()).WaitAsync(Wait, TestContext.Current.CancellationToken)));
    }

    [Fact]
    public async Task ObtainFailureWithoutAnyForm_IsNetworkError()
    {
        var world = new SessionWorld();
        world.Lib.OnObtain = _ => -110;

        Assert.Equal(TerminationKind.NetworkError, (await world.RunAsync(Start()).WaitAsync(Wait, TestContext.Current.CancellationToken)));
    }

    [Fact]
    public void NetworkFailure_CarriesLastLibraryError()
    {
        var world = new SessionWorld();
        world.Lib.OnObtain = callbacks =>
        {
            callbacks.Log(0, "Failed to connect to host avpn.example.org\n");
            callbacks.Log(0, "SSL connection failure: Error in the pull function.\n");
            return -5;
        };

        world.RunAsync(Start());
        var terminated = world.Output.Next<TerminatedEvent>(Wait);

        Assert.Equal(TerminationKind.NetworkError, terminated.Kind);
        Assert.Equal("Шлюз недоступен (код -5): SSL connection failure: Error in the pull function", terminated.Text);
    }

    [Fact]
    public void Reconnect_SendsNewSessionInfo_AndStatsCarryDtls()
    {
        var world = new SessionWorld();
        world.Lib.OnMainloop = () =>
        {
            world.Lib.Callbacks!.Reconnected();
            world.Lib.Callbacks.Stats(100, 200);
            return world.Lib.WaitForCancel();
        };

        world.RunAsync(Start());
        Assert.NotNull(world.Output.Next<IpInfoChangedEvent>(Wait).Session);
        var stats = world.Output.Next<StatsEvent>(Wait);
        world.Session.Post(new StopCommand());

        Assert.Equal((100ul, 200ul, true), (stats.BytesSent, stats.BytesReceived, stats.DtlsActive));
    }

    [Theory]
    [InlineData("Set-Cookie: webvpn=ABCDEF123; path=/", "ABCDEF123")]
    [InlineData("X-DTLS-Session-ID: 17D7F120A90C7335F3D414A80F995ED09CF7", "17D7F120A90C")]
    [InlineData("cookie acSamlv2Token=eyJhbGciOi; x", "eyJhbGciOi")]
    [InlineData("<session-token>9F8E7D6C</session-token>", "9F8E7D6C")]
    [InlineData("openconnect_strapkey=MHcCAQEE; webvpn=1", "MHcCAQEE")]
    public void Log_RedactsSecrets(string line, string secret)
    {
        var world = new SessionWorld();
        world.Lib.OnObtain = callbacks =>
        {
            callbacks.Log(1, line);
            return 0;
        };

        world.RunAsync(Start());
        world.Output.Next<EstablishedEvent>(Wait);
        world.Session.Post(new StopCommand());

        Assert.DoesNotContain(world.Output.All.OfType<LogEvent>(), e => e.Text.Contains(secret, StringComparison.Ordinal));
    }

    [Fact]
    public void DebugLog_IsDroppedUnlessVerbose()
    {
        var world = new SessionWorld();
        world.Lib.OnObtain = callbacks =>
        {
            callbacks.Log(2, "подробности протокола");
            return 0;
        };

        world.RunAsync(Start());
        world.Output.Next<EstablishedEvent>(Wait);
        world.Session.Post(new StopCommand());

        Assert.DoesNotContain(world.Output.All.OfType<LogEvent>(), e => e.Text.Contains("подробности", StringComparison.Ordinal));
    }

    private sealed class SessionWorld
    {
        public SessionWorld()
        {
            Session = new OcSession(Lib, Output, System);
        }

        public FakeOcLib Lib { get; } = new();

        public RecordingOutput Output { get; } = new();

        public FakeSystem System { get; } = new();

        public OcSession Session { get; }

        public Task<TerminationKind> RunAsync(StartCommand start) => Task.Factory.StartNew(() => Session.Run(start), TaskCreationOptions.LongRunning);
    }
}

internal static class OcCodesForTests
{
    public const int Eagain = 11, FormOk = 0, FormNewGroup = 2;
}

internal enum OcFieldKindForTests
{
    Text = 0,
    Password = 1,
    Select = 2,
}

internal sealed class FakeField(string name, OcFieldKindForTests kind, string[]? choices = null)
{
    public string? Value { get; private set; }

    public OcField ToField() => new(name, name, (OcFieldKind)(int)kind, false,
        (choices ?? []).Select(c => new AuthChoiceDto(c, c)).ToList(), value => Value = value);

    public static OcForm Form(FakeField? group, int selection, params FakeField[] fields)
    {
        var converted = fields.Select(f => (Source: f, Field: f.ToField())).ToList();
        return new OcForm
        {
            AuthId = "main",
            Fields = converted.Select(c => c.Field).ToList(),
            Group = group is null ? null : converted.First(c => ReferenceEquals(c.Source, group)).Field,
            GroupSelection = selection,
        };
    }
}

internal sealed class RecordingOutput : IHelperOutput
{
    private readonly BlockingCollection<HelperEvent> _queue = new();
    private readonly ConcurrentQueue<HelperEvent> _all = new();

    public IReadOnlyCollection<HelperEvent> All => _all.ToArray();

    public void Send(HelperEvent helperEvent)
    {
        _all.Enqueue(helperEvent);
        _queue.Add(helperEvent);
    }

    /// <summary>Следующее событие указанного типа; события других типов пропускаются.</summary>
    public T Next<T>(TimeSpan timeout)
        where T : HelperEvent
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (_queue.TryTake(out var next, deadline - DateTime.UtcNow) && next is T match)
            {
                return match;
            }
        }

        throw new TimeoutException($"Событие {typeof(T).Name} не пришло. Были: {string.Join(", ", _all.Select(e => e.GetType().Name))}");
    }
}

internal sealed class FakeSystem : IHelperSystem
{
    public string? ConfiguredInterface { get; private set; }

    public string? CleanedInterface { get; private set; }

    public ulong ConfigureInterface(string interfaceName, SessionInfo session)
    {
        ConfiguredInterface = interfaceName;
        return 56;
    }

    public int RemoveStaleInterface(string interfaceName)
    {
        CleanedInterface = interfaceName;
        return 0;
    }

    public (string Certificate, string Key) PrepareClientCertificate(string thumbprint) => ("system:win:id=1;type=cert", "system:win:id=1;type=privkey");
}

internal sealed class FakeOcLib : IOcLib
{
    private readonly ManualResetEventSlim _cancel = new();

    public IOcCallbacks? Callbacks { get; private set; }

    public Func<IOcCallbacks, int> OnObtain { get; set; } = _ => 0;

    public Func<int> OnCstp { get; set; } = () => 0;

    public Func<int>? OnMainloop { get; set; }

    public Func<string, IReadOnlyList<SsoCookie>, int> OnWebviewLoad { get; set; } = (_, _) => 0;

    public int CstpCalls { get; private set; }

    public bool CancelSent => _cancel.IsSet;

    public string Version => "v9.21-test";

    public bool DtlsActive => true;

    public void Create(IOcCallbacks callbacks, string userAgent, bool verbose) => Callbacks = callbacks;

    public int ParseUrl(string url) => 0;

    public int SetClientCertificate(string certificateUrl, string keyUrl) => 0;

    public int ObtainCookie() => OnObtain(Callbacks!);

    public int MakeCstpConnection()
    {
        CstpCalls++;
        return OnCstp();
    }

    public int SetupDtls() => 0;

    public int DisableDtls() => 0;

    public int SetupTunDevice(string interfaceName) => 0;

    public SessionInfo ReadSession() => new() { Address = "10.0.7.190", Netmask = "255.255.255.0", Mtu = 1230, Dns = ["10.0.16.21"], SplitIncludes = ["10.0.0.0/255.0.0.0"] };

    public void SetupCommandPipe()
    {
    }

    public int Mainloop() => OnMainloop is { } run ? run() : WaitForCancel();

    public int WaitForCancel()
    {
        _cancel.Wait(TimeSpan.FromSeconds(30));
        return -4;
    }

    public void SendCommand(byte command)
    {
        if (command == (byte)'x')
        {
            _cancel.Set();
        }
    }

    public int WebviewLoadChanged(string uri, IReadOnlyList<SsoCookie> cookies) => OnWebviewLoad(uri, cookies);

    public void Dispose() => _cancel.Dispose();
}
