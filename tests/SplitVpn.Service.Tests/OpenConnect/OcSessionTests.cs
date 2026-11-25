using System.Collections.Concurrent;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.OpenConnect;
using SplitVpn.OpenConnect;

namespace SplitVpn.Service.Tests.OpenConnect;

public sealed class OcSessionTests
{
    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(10);

    private static StartCommand Start(string group = "", string? user = null, string? password = null) =>
        new("https://avpn.example.org/", group, "AnyConnect Windows 4.10.06090", true, null, "SplitVpn AC 1", user, password?.ToCharArray());

    [Fact]
    public async Task Dispose_WaitsForAnInFlightCancelCommand()
    {
        var world = new SessionWorld();
        world.Lib.OnMainloop = () => -4;
        await world.RunAsync(Start()).WaitAsync(Wait, TestContext.Current.CancellationToken);
        using var release = new ManualResetEventSlim();
        var sending = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        world.Lib.OnSendCommand = _ =>
        {
            sending.TrySetResult();
            release.Wait(Wait);
        };
        var stop = Task.Run(world.Session.RequestStop, TestContext.Current.CancellationToken);
        Task? dispose = null;
        try
        {
            await sending.Task.WaitAsync(Wait, TestContext.Current.CancellationToken);
            dispose = Task.Run(world.Session.Dispose, TestContext.Current.CancellationToken);
            var delay = Task.Delay(100, TestContext.Current.CancellationToken);
            Assert.Same(delay, await Task.WhenAny(dispose, delay));
            Assert.False(world.Lib.Disposed);
        }
        finally
        {
            release.Set();
            await stop.WaitAsync(Wait, TestContext.Current.CancellationToken);
            if (dispose is not null)
            {
                await dispose.WaitAsync(Wait, TestContext.Current.CancellationToken);
            }
            else
            {
                world.Session.Dispose();
            }
        }

        Assert.True(world.Lib.Disposed);
        world.Session.RequestStop();
    }

    [Fact]
    public async Task SessionEnd_WaitsForRunningStatisticsCallback()
    {
        var world = new SessionWorld();
        using var releaseCallback = new ManualResetEventSlim();
        var callbackEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var mainloopExited = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        world.Lib.OnSendCommand = command =>
        {
            if (command == (byte)'s')
            {
                callbackEntered.TrySetResult();
                releaseCallback.Wait(Wait);
            }
        };
        world.Lib.OnMainloop = () =>
        {
            callbackEntered.Task.WaitAsync(Wait).GetAwaiter().GetResult();
            mainloopExited.TrySetResult();
            return -4;
        };

        var run = world.RunAsync(Start());
        try
        {
            await mainloopExited.Task.WaitAsync(Wait, TestContext.Current.CancellationToken);
            var wait = Task.Delay(100, TestContext.Current.CancellationToken);
            Assert.Same(wait, await Task.WhenAny(run, wait));
        }
        finally
        {
            releaseCallback.Set();
            await run.WaitAsync(Wait, TestContext.Current.CancellationToken);
            world.Session.Dispose();
        }
    }

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

    /// <summary>Остановка пришла, когда туннель CSTP уже поднят: цикл библиотеки всё равно запускается и прощается со шлюзом.</summary>
    [Fact]
    public async Task Stop_AfterCstp_StillSaysByeToGateway()
    {
        var world = new SessionWorld();
        var mainloops = 0;
        world.Lib.OnCstp = () =>
        {
            world.Session.RequestStop();
            return 0;
        };
        world.Lib.OnMainloop = () =>
        {
            mainloops++;
            return world.Lib.WaitForCancel();
        };

        Assert.Equal(TerminationKind.Cancelled, (await world.RunAsync(Start()).WaitAsync(Wait, TestContext.Current.CancellationToken)));
        Assert.Equal(1, mainloops);
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

    [Theory]
    [InlineData("secondary_password", "Secondary password", null)]
    [InlineData("password", "OTP", null)]
    [InlineData("password", "Password", "Enter the verification code from your authenticator")]
    public async Task FirstOtpForm_RequestsOtpWithoutOfferingSavedPassword(string fieldName, string label, string? message)
    {
        var world = new SessionWorld();
        var otp = new FakeField(fieldName, OcFieldKindForTests.Password, label: label);
        world.Lib.OnObtain = callbacks => callbacks.ProcessForm(FakeField.Form(null, 0, otp) with { Message = message });
        var run = world.RunAsync(Start(password: "saved"));
        var form = world.Output.Next<AuthFormEvent>(Wait);
        Assert.Equal(fieldName, Assert.Single(form.Fields).Name);
        world.Session.Post(new FormReplyCommand(form.RequestId, new Dictionary<string, string> { [fieldName] = "123456" }, false));
        world.Output.Next<EstablishedEvent>(Wait);
        world.Session.Post(new StopCommand());
        await run.WaitAsync(Wait, TestContext.Current.CancellationToken);
        Assert.Equal("123456", otp.Value);
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

    /// <summary>Аудит ID8: после переподключения шлюз выдал другой адрес и MTU — адаптер настраивается заново.</summary>
    [Fact]
    public void Reconnect_ReconfiguresAdapterWithNewAddressAndMtu()
    {
        var world = new SessionWorld();
        var renewed = world.Lib.Session with { Address = "10.0.7.201", Mtu = 1300 };
        world.Lib.OnMainloop = () =>
        {
            world.Lib.Session = renewed;
            world.Lib.Callbacks!.Reconnected();
            return world.Lib.WaitForCancel();
        };

        world.RunAsync(Start());
        Assert.Equal("10.0.7.201", world.Output.Next<IpInfoChangedEvent>(Wait).Session.Address);
        world.Session.Post(new StopCommand());

        Assert.Equal(["10.0.7.190", "10.0.7.201"], world.System.Configured.Select(s => s.Address));
        Assert.Equal(1300, world.System.Configured.Last().Mtu);
    }

    /// <summary>Аудит ID18: сертификат шлюза отклонён при переподключении внутри mainloop — блокирующий отказ, а не сбой сети.</summary>
    [Fact]
    public async Task CertificateRejectedDuringReconnect_IsCertificateRejected()
    {
        var world = new SessionWorld();
        world.Lib.OnMainloop = () => world.Lib.Callbacks!.ValidatePeerCertificate("certificate does not match hostname") == 0 ? 0 : -5;

        Assert.Equal(TerminationKind.CertificateRejected, await world.RunAsync(Start()).WaitAsync(Wait, TestContext.Current.CancellationToken));
        Assert.Equal(TerminationKind.CertificateRejected, world.Output.Next<TerminatedEvent>(Wait).Kind);
    }

    /// <summary>Аудит ID37: после перенаправления на другой узел SSO открывается для нового узла — UI берёт его cookie.</summary>
    [Fact]
    public void Sso_AfterRedirect_ReportsCurrentGatewayHost()
    {
        var world = new SessionWorld();
        world.Lib.CurrentHost = "node2.example.org";
        world.Lib.OnObtain = callbacks => callbacks.OpenWebview("https://sso.example.org/adfs/ls");

        world.RunAsync(Start());
        var open = world.Output.Next<SsoOpenEvent>(Wait);
        world.Session.Post(new StopCommand());

        Assert.Equal("node2.example.org", open.GatewayHost);
    }

    /// <summary>Аудит ID39: группа, выбранная шлюзом, приходит в форму значением по умолчанию, а не теряется.</summary>
    [Fact]
    public void Form_WithoutProfileGroup_KeepsGatewaySelectedGroup()
    {
        var world = new SessionWorld();
        var group = new FakeField("group_list", OcFieldKindForTests.Select, ["Sso", "Staff", "Admins"]);
        var password = new FakeField("password", OcFieldKindForTests.Password);
        world.Lib.OnObtain = callbacks => callbacks.ProcessForm(FakeField.Form(group, 1, group, password)) == OcCodesForTests.FormOk ? 0 : -1;

        world.RunAsync(Start());
        var form = world.Output.Next<AuthFormEvent>(Wait);
        world.Session.Post(new StopCommand());

        Assert.Equal("Staff", form.Fields.Single(f => f.Name == "group_list").Value);
    }

    /// <summary>
    /// Ревью круг 3, М9: пользователь выбрал в форме другую группу — шлюз получает FormNewGroup, а не FormOk, и в форме
    /// новой группы введённые логин и пароль подставляются сами, без второго окна.
    /// </summary>
    [Fact]
    public void Form_UserChangesGroup_RequestsNewGroupForm_AndCarriesTypedValues()
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

        world.RunAsync(Start());
        var form = world.Output.Next<AuthFormEvent>(Wait);
        world.Session.Post(new FormReplyCommand(form.RequestId,
            new Dictionary<string, string> { ["group_list"] = "Staff", ["username"] = "user", ["password"] = "typed-secret" }, false));
        world.Output.Next<EstablishedEvent>(Wait);
        world.Session.Post(new StopCommand());

        Assert.Equal([OcCodesForTests.FormNewGroup, OcCodesForTests.FormOk], results);
        Assert.Equal("Staff", group.Value);
        Assert.Equal("user", user.Value);
        Assert.Equal("typed-secret", password.Value);
        Assert.Single(world.Output.All.OfType<AuthFormEvent>());
    }

    /// <summary>Группу пользователь не менял: форма отправляется как есть.</summary>
    [Fact]
    public void Form_UserKeepsGatewayGroup_SubmitsForm()
    {
        var world = new SessionWorld();
        var group = new FakeField("group_list", OcFieldKindForTests.Select, ["Sso", "Staff"]);
        var password = new FakeField("password", OcFieldKindForTests.Password);
        var result = -1;
        world.Lib.OnObtain = callbacks =>
        {
            result = callbacks.ProcessForm(FakeField.Form(group, 1, group, password));
            return 0;
        };

        world.RunAsync(Start());
        var form = world.Output.Next<AuthFormEvent>(Wait);
        world.Session.Post(new FormReplyCommand(form.RequestId, new Dictionary<string, string> { ["group_list"] = "Staff", ["password"] = "p4ss" }, false));
        world.Output.Next<EstablishedEvent>(Wait);
        world.Session.Post(new StopCommand());

        Assert.Equal(OcCodesForTests.FormOk, result);
    }

    /// <summary>Ревью круг 3, М13: первый адрес узла не принимает соединение — помощник берёт следующий из присланных службой.</summary>
    [Fact]
    public void Resolve_FirstAddressUnreachable_UsesNextOne()
    {
        var world = new SessionWorld();
        world.System.Reachable = ["198.51.100.11"];
        string? resolved = null;
        world.Lib.OnObtain = callbacks =>
        {
            resolved = callbacks.Resolve("avpn.example.org");
            return 0;
        };

        world.RunAsync(Start());
        world.Output.Next<ResolveHostEvent>(Wait);
        world.Session.Post(new ResolveReplyCommand("avpn.example.org", "198.51.100.10", ["198.51.100.10", "198.51.100.11"]));
        world.Output.Next<EstablishedEvent>(Wait);
        world.Session.Post(new StopCommand());

        Assert.Equal("198.51.100.11", resolved);
        Assert.Equal(["198.51.100.10", "198.51.100.11"], world.System.Probed.ToArray());
    }

    /// <summary>Один адрес (или служба прежней версии без списка) — без пробных соединений.</summary>
    [Fact]
    public void Resolve_SingleAddress_IsUsedWithoutProbe()
    {
        var world = new SessionWorld();
        string? resolved = null;
        world.Lib.OnObtain = callbacks =>
        {
            resolved = callbacks.Resolve("avpn.example.org");
            return 0;
        };

        world.RunAsync(Start());
        world.Output.Next<ResolveHostEvent>(Wait);
        world.Session.Post(new ResolveReplyCommand("avpn.example.org", "198.51.100.10"));
        world.Output.Next<EstablishedEvent>(Wait);
        world.Session.Post(new StopCommand());

        Assert.Equal("198.51.100.10", resolved);
        Assert.Empty(world.System.Probed);
    }

    /// <summary>
    /// Ревью круг 3, С15: ключ сертификата недоступен библиотеке (например, ключ компьютера в CNG) — понятная причина
    /// и итог «сертификат отклонён»: повторять вход без действия пользователя бессмысленно.
    /// </summary>
    [Fact]
    public async Task ClientCertificateFailure_IsCertificateRejectedWithReason()
    {
        var world = new SessionWorld();
        world.System.CertificateFailure = new InvalidOperationException("Закрытый ключ клиентского сертификата хранится в поставщике CNG.");
        var start = Start() with { CertificateThumbprint = new string('A', 40) };

        Assert.Equal(TerminationKind.CertificateRejected, await world.RunAsync(start).WaitAsync(Wait, TestContext.Current.CancellationToken));
        var terminated = world.Output.Next<TerminatedEvent>(Wait);
        Assert.Contains("CNG", terminated.Text, StringComparison.Ordinal);
        Assert.Equal(0, world.Lib.CstpCalls);
    }

    /// <summary>Предупреждение о чужих сертификатах с тем же ключом попадает в журнал, вход продолжается.</summary>
    [Fact]
    public async Task ClientCertificateWarning_IsLogged()
    {
        var world = new SessionWorld();
        world.System.CertificateWarning = "В хранилище SYSTEM есть другие сертификаты с тем же ключом";
        var start = Start() with { CertificateThumbprint = new string('A', 40) };

        var run = world.RunAsync(start);
        world.Output.Next<EstablishedEvent>(Wait);
        world.Session.Post(new StopCommand());
        await run.WaitAsync(Wait, TestContext.Current.CancellationToken);

        Assert.Contains(world.Output.All.OfType<LogEvent>(), e => e.Text.Contains("другие сертификаты с тем же ключом", StringComparison.Ordinal));
        // Обычная остановка - не сбой: подсказка о сертификате к ней не добавляется.
        Assert.DoesNotContain("другие сертификаты", world.Output.Next<TerminatedEvent>(Wait).Text, StringComparison.Ordinal);
    }

    /// <summary>
    /// Отказ входа при чужих сертификатах с тем же ключом: предупреждение добавляется к причине завершения, иначе
    /// пользователь видел бы только код отказа.
    /// </summary>
    [Theory]
    [InlineData(-5, TerminationKind.NetworkError)]
    [InlineData(-1, TerminationKind.AuthRejected)]
    public async Task ClientCertificateWarning_IsAddedToFailureBeforeTunnel(int code, TerminationKind expected)
    {
        var world = new SessionWorld();
        world.System.CertificateWarning = "В хранилище SYSTEM есть другие сертификаты с тем же ключом.";
        world.Lib.OnObtain = callbacks =>
        {
            if (expected == TerminationKind.AuthRejected)
            {
                // Форма была показана: отказ классифицируется как отказ входа, а не недоступность шлюза.
                callbacks.ProcessForm(FakeField.Form(null, 0) with { AuthId = "success" });
            }

            return code;
        };
        var start = Start() with { CertificateThumbprint = new string('A', 40) };

        Assert.Equal(expected, await world.RunAsync(start).WaitAsync(Wait, TestContext.Current.CancellationToken));
        var text = world.Output.Next<TerminatedEvent>(Wait).Text;
        Assert.Contains($"(код {code}). ", text, StringComparison.Ordinal);
        Assert.EndsWith("другие сертификаты с тем же ключом.", text, StringComparison.Ordinal);
    }

    /// <summary>Сбой уже поднятого туннеля с сертификатом клиента не связан: подсказка не добавляется.</summary>
    [Fact]
    public async Task ClientCertificateWarning_IsNotAddedAfterTunnelEstablished()
    {
        var world = new SessionWorld();
        world.System.CertificateWarning = "В хранилище SYSTEM есть другие сертификаты с тем же ключом.";
        world.Lib.OnMainloop = () => -5;
        var start = Start() with { CertificateThumbprint = new string('A', 40) };

        Assert.Equal(TerminationKind.NetworkError, await world.RunAsync(start).WaitAsync(Wait, TestContext.Current.CancellationToken));
        Assert.DoesNotContain("другие сертификаты", world.Output.Next<TerminatedEvent>(Wait).Text, StringComparison.Ordinal);
    }

    /// <summary>Аудит ID75: запрос адреса узла несёт его порт — после перенаправления служба откроет фильтры на новый порт.</summary>
    [Fact]
    public void Resolve_CarriesCurrentGatewayPort()
    {
        var world = new SessionWorld();
        world.Lib.CurrentPort = 8443;
        world.Lib.OnObtain = callbacks =>
        {
            callbacks.Resolve("node2.example.org");
            return 0;
        };

        world.RunAsync(Start());
        var resolve = world.Output.Next<ResolveHostEvent>(Wait);
        world.Session.Post(new StopCommand());

        Assert.Equal(("node2.example.org", 8443), (resolve.Host, resolve.Port));
    }

    /// <summary>Аудит ID88: туннель запрашивается только IPv4 — до входа.</summary>
    [Fact]
    public void Connect_DisablesIpv6BeforeSignIn()
    {
        var world = new SessionWorld();
        var disabledBeforeObtain = false;
        world.Lib.OnObtain = _ =>
        {
            disabledBeforeObtain = world.Lib.Ipv6Disabled;
            return 0;
        };

        world.RunAsync(Start());
        world.Output.Next<EstablishedEvent>(Wait);
        world.Session.Post(new StopCommand());

        Assert.True(disabledBeforeObtain);
    }

    [Theory]
    [InlineData("Set-Cookie: webvpn=ABCDEF123; path=/", "ABCDEF123")]
    [InlineData("X-DTLS-Session-ID: 17D7F120A90C7335F3D414A80F995ED09CF7", "17D7F120A90C")]
    [InlineData("cookie acSamlv2Token=eyJhbGciOi; x", "eyJhbGciOi")]
    [InlineData("<session-token>9F8E7D6C</session-token>", "9F8E7D6C")]
    [InlineData("openconnect_strapkey=MHcCAQEE; webvpn=1", "MHcCAQEE")]
    [InlineData("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz")]
    [InlineData("Proxy-Authorization: Negotiate YIIGhgYJKoZI", "YIIGhgYJKoZI")]
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
    public async Task VerboseLog_HidesPasswordTypedIntoGatewayForm()
    {
        const string Typed = "typed-Secret-42";
        var world = new SessionWorld(verbose: true);
        var password = new FakeField("password", OcFieldKindForTests.Password);
        world.Lib.OnObtain = callbacks =>
        {
            var answer = callbacks.ProcessForm(FakeField.Form(null, 0, password) with { Error = "Login failed" });
            callbacks.Log(2, "POST /auth: username=user&password=" + Typed);
            return answer == OcCodesForTests.FormOk ? 0 : -1;
        };

        var run = world.RunAsync(Start(password: "stale"));
        var form = world.Output.Next<AuthFormEvent>(Wait);
        world.Session.Post(new FormReplyCommand(form.RequestId, new Dictionary<string, string> { ["password"] = Typed }, false));
        world.Output.Next<EstablishedEvent>(Wait);
        world.Session.Post(new StopCommand());
        await run.WaitAsync(Wait, TestContext.Current.CancellationToken);

        var logs = world.Output.All.OfType<LogEvent>().ToList();
        Assert.Contains(logs, e => e.Text.Contains("password=<скрыто>", StringComparison.Ordinal));
        Assert.DoesNotContain(logs, e => e.Text.Contains(Typed, StringComparison.Ordinal));
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

    /// <summary>
    /// Без адаптера mainloop сначала ещё раз создаёт его и только потом читает отмену: BYE не отправляется, чтобы медленный
    /// сбой Wintun не повторялся до сообщения службе.
    /// </summary>
    [Fact]
    public async Task TunSetupFailure_AfterCstp_DoesNotRunMainloopAndKeepsReason()
    {
        var world = new SessionWorld();
        var steps = RecordClose(world);
        world.Lib.OnSetupTun = () =>
        {
            world.Lib.Callbacks!.Log(0, "Could not create Wintun adapter");
            return -1;
        };

        var kind = await world.RunAsync(Start()).WaitAsync(Wait, TestContext.Current.CancellationToken);

        Assert.Equal(TerminationKind.Internal, kind);
        Assert.Empty(steps);
        var terminated = world.Output.Next<TerminatedEvent>(Wait);
        Assert.Contains("Could not create Wintun adapter", terminated.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("Set up tun device failed", terminated.Text, StringComparison.Ordinal);
        Assert.DoesNotContain(world.Output.All, e => e is EstablishedEvent);
    }

    [Fact]
    public async Task ReadSessionFailure_AfterCstp_SaysByeAndKeepsError()
    {
        var world = new SessionWorld();
        var steps = RecordClose(world);
        world.Lib.ReadSessionFailure = new InvalidOperationException("openconnect_get_ip_info завершился с ошибкой");

        var kind = await world.RunAsync(Start()).WaitAsync(Wait, TestContext.Current.CancellationToken);

        Assert.Equal(TerminationKind.Internal, kind);
        Assert.Equal(["cancel", "mainloop"], steps);
        var terminated = world.Output.Next<TerminatedEvent>(Wait);
        Assert.StartsWith("openconnect_get_ip_info завершился с ошибкой", terminated.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("Set up tun device failed", terminated.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConfigureInterfaceFailure_AfterCstp_SaysByeAndKeepsError()
    {
        var world = new SessionWorld();
        var steps = RecordClose(world);
        world.System.ConfigureFailure = new InvalidOperationException("Адаптер не найден");

        var kind = await world.RunAsync(Start()).WaitAsync(Wait, TestContext.Current.CancellationToken);

        Assert.Equal(TerminationKind.Internal, kind);
        Assert.Equal(["cancel", "mainloop"], steps);
        Assert.StartsWith("Адаптер не найден", world.Output.Next<TerminatedEvent>(Wait).Text, StringComparison.Ordinal);
        Assert.DoesNotContain(world.Output.All, e => e is EstablishedEvent);
    }

    [Fact]
    public async Task CloseFailure_AfterCstp_DoesNotReplaceOriginalError()
    {
        var world = new SessionWorld();
        world.System.ConfigureFailure = new InvalidOperationException("Адаптер не найден");
        world.Lib.OnMainloop = () => throw new InvalidOperationException("сбой прощания");

        var kind = await world.RunAsync(Start()).WaitAsync(Wait, TestContext.Current.CancellationToken);

        Assert.Equal(TerminationKind.Internal, kind);
        var terminated = world.Output.Next<TerminatedEvent>(Wait);
        Assert.StartsWith("Адаптер не найден", terminated.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("сбой прощания", terminated.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CstpFailure_DoesNotRunMainloop()
    {
        var world = new SessionWorld();
        var steps = RecordClose(world);
        world.Lib.OnCstp = () => -5;

        var kind = await world.RunAsync(Start()).WaitAsync(Wait, TestContext.Current.CancellationToken);

        Assert.Equal(TerminationKind.NetworkError, kind);
        Assert.Empty(steps);
    }

    /// <summary>Адрес туннеля из служебного диапазона не назначается адаптеру: сеанс прощается со шлюзом с понятной причиной.</summary>
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("0.1.2.3")]
    [InlineData("169.254.10.1")]
    [InlineData("224.0.0.251")]
    [InlineData("255.255.255.255")]
    [InlineData("не адрес")]
    public async Task UnusableTunnelAddress_IsNotConfiguredAndSaysBye(string address)
    {
        var world = new SessionWorld();
        var steps = RecordClose(world);
        world.Lib.Session = world.Lib.Session with { Address = address };

        var kind = await world.RunAsync(Start()).WaitAsync(Wait, TestContext.Current.CancellationToken);

        Assert.Equal(TerminationKind.Internal, kind);
        Assert.Equal(["cancel", "mainloop"], steps);
        Assert.Empty(world.System.Configured);
        Assert.DoesNotContain(world.Output.All, e => e is EstablishedEvent);
        Assert.Contains("адрес туннеля", world.Output.Next<TerminatedEvent>(Wait).Text, StringComparison.Ordinal);
    }

    /// <summary>После переподключения адрес из служебного диапазона тоже не назначается: сеанс завершается как обрыв.</summary>
    [Fact]
    public async Task Reconnect_UnusableTunnelAddress_CancelsSession()
    {
        var world = new SessionWorld();
        world.Lib.OnMainloop = () =>
        {
            world.Lib.Session = world.Lib.Session with { Address = "127.0.0.1" };
            world.Lib.Callbacks!.Reconnected();
            return world.Lib.WaitForCancel();
        };

        var kind = await world.RunAsync(Start()).WaitAsync(Wait, TestContext.Current.CancellationToken);

        Assert.Equal(TerminationKind.NetworkError, kind);
        Assert.Single(world.System.Configured);
        Assert.DoesNotContain(world.Output.All, e => e is IpInfoChangedEvent);
        Assert.Contains("адрес туннеля 127.0.0.1", world.Output.Next<TerminatedEvent>(Wait).Text, StringComparison.Ordinal);
    }

    /// <summary>Событие сеанса не доставлено службе (больше кадра канала): сеанс на шлюзе закрывается, а не висит без службы.</summary>
    [Fact]
    public async Task EstablishedNotDelivered_ClosesGatewaySession()
    {
        var world = new SessionWorld();
        var steps = RecordClose(world);
        world.Output.Undeliverable = e => e is EstablishedEvent;

        var kind = await world.RunAsync(Start()).WaitAsync(Wait, TestContext.Current.CancellationToken);

        Assert.Equal(TerminationKind.Internal, kind);
        Assert.Equal(["cancel", "mainloop"], steps);
        Assert.StartsWith("Параметры сеанса не переданы службе", world.Output.Next<TerminatedEvent>(Wait).Text, StringComparison.Ordinal);
    }

    /// <summary>Новые параметры после переподключения не доставлены: служба осталась бы с прежними, сеанс отменяется.</summary>
    [Fact]
    public async Task IpInfoChangedNotDelivered_CancelsSession()
    {
        var world = new SessionWorld();
        world.Output.Undeliverable = e => e is IpInfoChangedEvent;
        world.Lib.OnMainloop = () =>
        {
            world.Lib.Callbacks!.Reconnected();
            return world.Lib.WaitForCancel();
        };

        var kind = await world.RunAsync(Start()).WaitAsync(Wait, TestContext.Current.CancellationToken);

        Assert.Equal(TerminationKind.NetworkError, kind);
        Assert.True(world.Lib.CancelSent);
        Assert.Contains("не переданы службе", world.Output.Next<TerminatedEvent>(Wait).Text, StringComparison.Ordinal);
    }

    /// <summary>Десятки тысяч сетей шлюза урезаются до предела, и об этом знают служба и журнал.</summary>
    [Fact]
    public void HugeSplitInclude_IsCappedAndReported()
    {
        var world = new SessionWorld();
        var includes = Enumerable.Range(0, 70_000).Select(i => $"10.{i / 65536}.{i / 256 % 256}.{i % 256}/255.255.255.255").ToList();
        world.Lib.Session = world.Lib.Session with { SplitIncludes = includes, SplitDns = Enumerable.Range(0, 100).Select(i => $"d{i}.example.org").ToList() };

        world.RunAsync(Start());
        var established = world.Output.Next<EstablishedEvent>(Wait);
        world.Session.Post(new StopCommand());

        Assert.Equal(HelperLimits.MaxSplitRoutes, established.Session.SplitIncludes.Count);
        Assert.Equal(HelperLimits.MaxSplitDns, established.Session.SplitDns.Count);
        Assert.Equal(2, established.Session.Truncated.Count);
        Assert.True(HelperContract.Serialize(established).Length < FrameCodec.MaxFrameBytes);
        Assert.Contains(world.Output.All.OfType<LogEvent>(), e => e.Text.Contains("взято 16384 из 70000", StringComparison.Ordinal));
    }

    /// <summary>Адрес SSO длиннее предела не отправляется службе: вход завершается с понятной причиной.</summary>
    [Fact]
    public async Task TooLongSsoUri_EndsSignInWithReason()
    {
        var world = new SessionWorld();
        world.Lib.OnObtain = callbacks => callbacks.OpenWebview("https://sso.example.org/?" + new string('a', HelperLimits.MaxSsoUri));

        var kind = await world.RunAsync(Start()).WaitAsync(Wait, TestContext.Current.CancellationToken);

        Assert.Equal(TerminationKind.Internal, kind);
        Assert.DoesNotContain(world.Output.All, e => e is SsoOpenEvent);
        Assert.Contains("слишком длинный адрес страницы входа", world.Output.Next<TerminatedEvent>(Wait).Text, StringComparison.Ordinal);
    }

    /// <summary>Баннер формы в мегабайты и сотни вариантов уходят службе в пределах.</summary>
    [Fact]
    public void HugeForm_IsCappedBeforeSending()
    {
        var world = new SessionWorld();
        var choices = Enumerable.Range(0, 1000).Select(i => "g" + i).ToArray();
        var group = new FakeField("group_list", OcFieldKindForTests.Select, choices, label: new string('L', 5000));
        world.Lib.OnObtain = callbacks => callbacks.ProcessForm(FakeField.Form(group, 0, group) with { Banner = new string('b', 2_000_000) });

        world.RunAsync(Start());
        var form = world.Output.Next<AuthFormEvent>(Wait);
        world.Session.Post(new StopCommand());

        Assert.Equal(HelperLimits.MaxFormText, form.Title!.Length);
        var field = Assert.Single(form.Fields);
        Assert.Equal(HelperLimits.MaxLabel, field.Label.Length);
        Assert.Equal(HelperLimits.MaxChoices, field.Choices.Count);
    }

    /// <summary>Канал помощника: событие больше кадра не отправляется, но канал остаётся годным для следующих.</summary>
    [Fact]
    public async Task HelperHost_OversizedEvent_ReturnsFalseAndKeepsChannel()
    {
        using var output = new MemoryStream();
        var host = new HelperHost(Stream.Null, output, () => throw new InvalidOperationException());

        Assert.False(host.Send(new LogEvent("info", new string('x', FrameCodec.MaxFrameBytes))));
        Assert.True(host.Send(new LogEvent("info", "ok")));

        output.Position = 0;
        var events = new List<HelperEvent>();
        while (await FrameCodec.ReadAsync(output, TestContext.Current.CancellationToken) is { } payload)
        {
            events.Add(HelperContract.TryDeserializeEvent(payload)!);
        }

        Assert.Equal(2, events.Count);
        Assert.Contains("не передано службе", Assert.IsType<LogEvent>(events[0]).Text, StringComparison.Ordinal);
        Assert.Equal("ok", Assert.IsType<LogEvent>(events[1]).Text);
    }

    /// <summary>Порядок отмены и запуска цикла библиотеки; цикл пишет ошибку, как настоящий при неудачном адаптере.</summary>
    private static ConcurrentQueue<string> RecordClose(SessionWorld world)
    {
        var steps = new ConcurrentQueue<string>();
        world.Lib.OnSendCommand = command =>
        {
            if (command == (byte)'x')
            {
                steps.Enqueue("cancel");
            }
        };
        world.Lib.OnMainloop = () =>
        {
            steps.Enqueue("mainloop");
            world.Lib.Callbacks!.Log(0, "Set up tun device failed");
            return -4;
        };
        return steps;
    }

    private sealed class SessionWorld
    {
        public SessionWorld(bool verbose = false)
        {
            Session = new OcSession(Lib, Output, System) { Verbose = verbose };
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

internal sealed class FakeField(string name, OcFieldKindForTests kind, string[]? choices = null, string? label = null)
{
    public string? Value { get; private set; }

    public OcField ToField() => new(name, label ?? name, (OcFieldKind)(int)kind, false,
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

    /// <summary>Какие события не доставляются (как событие больше кадра канала); null — доставляются все.</summary>
    public Func<HelperEvent, bool>? Undeliverable { get; set; }

    public bool Send(HelperEvent helperEvent)
    {
        if (Undeliverable?.Invoke(helperEvent) == true)
        {
            return false;
        }

        _all.Enqueue(helperEvent);
        _queue.Add(helperEvent);
        return true;
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

    /// <summary>Параметры каждой настройки адаптера по порядку.</summary>
    public ConcurrentQueue<SessionInfo> Configured { get; } = new();

    /// <summary>Что бросает настройка адаптера; null — адаптер настраивается.</summary>
    public Exception? ConfigureFailure { get; set; }

    public ulong ConfigureInterface(string interfaceName, SessionInfo session)
    {
        if (ConfigureFailure is { } failure)
        {
            throw failure;
        }

        ConfiguredInterface = interfaceName;
        Configured.Enqueue(session);
        return 56;
    }

    public int RemoveStaleInterface(string interfaceName)
    {
        CleanedInterface = interfaceName;
        return 0;
    }

    public (string Certificate, string Key, string? Warning) PrepareClientCertificate(string thumbprint) =>
        CertificateFailure is { } failure ? throw failure : ("system:win:id=1;type=cert", "system:win:id=1;type=privkey", CertificateWarning);

    /// <summary>Предупреждение подготовки сертификата; null — предупреждать не о чем.</summary>
    public string? CertificateWarning { get; set; }

    /// <summary>Что бросает подготовка клиентского сертификата; null — сертификат готов.</summary>
    public Exception? CertificateFailure { get; set; }

    /// <summary>Адреса, которые принимают соединение; null — принимают все.</summary>
    public HashSet<string>? Reachable { get; set; }

    /// <summary>Адреса, которые помощник пробовал, по порядку.</summary>
    public ConcurrentQueue<string> Probed { get; } = new();

    public bool CanConnect(string address, int port, TimeSpan timeout, CancellationToken cancellationToken)
    {
        Probed.Enqueue(address);
        return Reachable?.Contains(address) != false;
    }
}

internal sealed class FakeOcLib : IOcLib
{
    private readonly ManualResetEventSlim _cancel = new();

    public IOcCallbacks? Callbacks { get; private set; }

    public Func<IOcCallbacks, int> OnObtain { get; set; } = _ => 0;

    public Func<int> OnCstp { get; set; } = () => 0;

    public Func<int>? OnMainloop { get; set; }

    public Action<byte>? OnSendCommand { get; set; }

    public Func<string, IReadOnlyList<SsoCookie>, int> OnWebviewLoad { get; set; } = (_, _) => 0;

    public int CstpCalls { get; private set; }

    public bool CancelSent => _cancel.IsSet;

    public string Version => "v9.21-test";

    public bool DtlsActive => true;

    public void Create(IOcCallbacks callbacks, string userAgent, bool verbose) => Callbacks = callbacks;

    public int ParseUrl(string url) => 0;

    public int DisableIpv6()
    {
        Ipv6Disabled = true;
        return 0;
    }

    public bool Ipv6Disabled { get; private set; }

    public string? CurrentHost { get; set; }

    public int CurrentPort { get; set; } = 443;

    public SessionInfo Session { get; set; } = new() { Address = "10.0.7.190", Netmask = "255.255.255.0", Mtu = 1230, Dns = ["10.0.16.21"], SplitIncludes = ["10.0.0.0/255.0.0.0"] };

    public int SetClientCertificate(string certificateUrl, string keyUrl) => 0;

    public int ObtainCookie() => OnObtain(Callbacks!);

    public int MakeCstpConnection()
    {
        CstpCalls++;
        return OnCstp();
    }

    public int SetupDtls() => 0;

    public int DisableDtls() => 0;

    /// <summary>Код создания адаптера; по умолчанию 0 — адаптер создан.</summary>
    public Func<int> OnSetupTun { get; set; } = () => 0;

    /// <summary>Что бросает чтение параметров сеанса; null — параметры читаются.</summary>
    public Exception? ReadSessionFailure { get; set; }

    public int SetupTunDevice(string interfaceName) => OnSetupTun();

    public SessionInfo ReadSession() => ReadSessionFailure is { } failure ? throw failure : Session;

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
        OnSendCommand?.Invoke(command);
        if (command == (byte)'x')
        {
            _cancel.Set();
        }
    }

    public int WebviewLoadChanged(string uri, IReadOnlyList<SsoCookie> cookies) => OnWebviewLoad(uri, cookies);

    public bool Disposed { get; private set; }

    public void Dispose()
    {
        Disposed = true;
        _cancel.Dispose();
    }
}
