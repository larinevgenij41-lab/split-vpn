using Microsoft.Extensions.Logging;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Core.Update;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Native;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Ревью стабильности 25.11: устойчивый сбой не заливает журнал службы записями со стеком на каждом тике, недоступная
/// служба RAS не оставляет туннель «поднятым», сбой сброса кеша DNS и занятый файл состояния не обрывают обработку,
/// отменённая проба сертификата - не предупреждение, набор имён узлов шлюза ограничен.
/// </summary>
public sealed partial class CoordinatorTests
{
    /// <summary>L-1: шаг тика падает 300 тиков подряд - одна запись со стеком и редкие сводки, затем одна о восстановлении.</summary>
    [Fact]
    public async Task FailingTickStep_IsLoggedOnceThenSummarized()
    {
        var log = new RecordingLog();
        _world.Logger = log;
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        _world.Inventory.FailCapture = true;

        for (var i = 0; i < 300; i++)
        {
            _world.Time.Advance(Coordinator.TickInterval);
            await coordinator.TickAsync(CancellationToken.None);
        }

        var failures = log.Entries(LogLevel.Warning, "сбой шага «смена сети»");
        Assert.InRange(failures.Count, 1, 3);
        Assert.NotNull(failures[0].Exception);
        Assert.All(failures.Skip(1), f => Assert.Null(f.Exception));
        Assert.All(failures.Skip(1), f => Assert.Contains("повторяется", f.Text, StringComparison.Ordinal));
        // Ни один шаг тика не пишет сбой на каждом тике.
        Assert.True(log.Entries(LogLevel.Warning, "Тик службы").Count <= 12, string.Join(Environment.NewLine, log.Entries(LogLevel.Warning, "Тик службы").Select(e => e.Text)));

        _world.Inventory.FailCapture = false;
        _world.Time.Advance(Coordinator.TickInterval);
        await coordinator.TickAsync(CancellationToken.None);
        _world.Time.Advance(Coordinator.TickInterval);
        await coordinator.TickAsync(CancellationToken.None);

        Assert.Single(log.Entries(LogLevel.Information, "шаг «смена сети» снова выполняется"));
    }

    /// <summary>L-1: работа очереди падает раз за разом - со стеком записывается только первая ошибка.</summary>
    [Fact]
    public async Task FailingQueueWork_IsLoggedOnce()
    {
        var log = new RecordingLog();
        _world.Logger = log;
        var coordinator = new Coordinator(_world.Dependencies());
        using var cancellation = new CancellationTokenSource();
        var run = Task.Run(() => coordinator.RunAsync(cancellation.Token), CancellationToken.None);
        try
        {
            for (var i = 0; i < 50; i++)
            {
                await coordinator.EnqueueAsync("Test:Failing", () => throw new InvalidOperationException("сбой в работе"));
            }

            await WaitForQueueAsync(coordinator);
            Assert.Single(log.Entries(LogLevel.Warning, "необработанная ошибка в работе Test:Failing"));

            await coordinator.EnqueueAsync("Test:Failing", () => Task.CompletedTask);
            await WaitForQueueAsync(coordinator);
            Assert.Single(log.Entries(LogLevel.Information, "работа Test:Failing снова выполняется"));
        }
        finally
        {
            await cancellation.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
        }
    }

    /// <summary>L-1: опрос туннеля падает не из-за RAS на каждом тике - предупреждение со стеком одно.</summary>
    [Fact]
    public async Task FailingConnectionPoll_IsLoggedOnce()
    {
        var log = new RecordingLog();
        _world.Logger = log;
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        _world.Ras.StatusFailure = new InvalidOperationException("опрос недоступен");

        for (var i = 0; i < 100; i++)
        {
            _world.Time.Advance(Coordinator.TickInterval);
            await coordinator.TickAsync(CancellationToken.None);
        }

        var polls = log.Entries(LogLevel.Warning, "Ошибка опроса подключения");
        Assert.Single(polls);
        Assert.NotNull(polls[0].Exception);
    }

    /// <summary>
    /// L-2: RasMan остановлен - опрос состояния падает с 711 на каждом тике. Через несколько опросов соединение
    /// считается потерянным, дозвон идёт по нарастающей паузе, а не на каждом тике, и журнал не заливается.
    /// </summary>
    [Fact]
    public async Task RasStatusUnavailable_DropsConnection_AndRedialsWithBackoff()
    {
        var log = new RecordingLog();
        _world.Logger = log;
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        Assert.NotNull(tunnel.Connection);
        var dials = _world.Ras.Dials;
        for (var i = 0; i < 40; i++)
        {
            _world.Ras.Results.Enqueue(new RasDialResult(false, null, 711, "Служба удалённого доступа не запускается"));
        }

        _world.Ras.StatusFailure = new NativeCallException("RasGetConnectStatus", 711);
        for (var i = 0; i < Coordinator.StatusFailuresAllowed; i++)
        {
            _world.Time.Advance(Coordinator.TickInterval);
            await TickAsync(coordinator);
        }

        Assert.Null(tunnel.Connection);
        Assert.NotEqual(default, tunnel.NextDialAt);
        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("служба RAS не сообщает состояние соединения", StringComparison.Ordinal));

        for (var i = 0; i < 30; i++)
        {
            _world.Time.Advance(Coordinator.TickInterval);
            await TickAsync(coordinator);
        }

        // За минуту - несколько попыток по нарастающей паузе, а не дозвон на каждом тике.
        Assert.InRange(_world.Ras.Dials - dials, 1, 6);
        Assert.True(tunnel.NextDialAt > _world.Time.GetUtcNow() - Coordinator.TickInterval);
        Assert.True(log.Entries(LogLevel.Warning, "Ошибка опроса подключения").Count <= 1);
        Assert.True(log.Entries(LogLevel.Warning, "").Count <= 40, string.Join(Environment.NewLine, log.Entries(LogLevel.Warning, "").Select(e => e.Text)));
    }

    /// <summary>
    /// L-3: адреса проверки отзыва открыты, а ipconfig /flushdns не завершился - повтор дозвона всё равно назначен,
    /// сверка выполнена, а сброс кеша повторяется следующей сверкой.
    /// </summary>
    [Fact]
    public async Task RevocationPin_FlushFailure_StillRetriesDialAndReconciles()
    {
        _world.Ras.Results.Enqueue(Failed(ConnectionErrorGuide.RevocationOffline));
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        Assert.Equal(ErrorCategory.Certificate, tunnel.BlockingError);
        Assert.Empty(tunnel.RevocationHosts);

        _world.Resolver.Answers[RevocationHost] = [Ipv4.Parse("198.51.100.7")];
        _world.Dns.FailFlush = true;
        await coordinator.OnCertificateProbedAsync(_profile.Id, tunnel.CertificateProbeGeneration,
            ServerCertificate(_world.Time.GetUtcNow().AddDays(6)), "тест", CancellationToken.None);

        Assert.Equal(ErrorCategory.None, tunnel.BlockingError);
        Assert.True(tunnel.NextDialAt <= _world.Time.GetUtcNow());
        Assert.Contains(_world.Wfp.Group(FilterGroup.Dynamic), f => f.Name.StartsWith("Проверка отзыва", StringComparison.Ordinal));

        var flushes = _world.Dns.Flushes;
        _world.Dns.FailFlush = false;
        await coordinator.ReconcileAsync(CancellationToken.None);
        await CompleteDialAsync(coordinator);
        Assert.True(_world.Dns.Flushes > flushes);
        Assert.True(_world.Ras.Connected);
    }

    /// <summary>
    /// I6-4: файл состояния занят, а сервер получил новый адрес - сверка идёт в том же цикле и открывает новый адрес,
    /// а запись кеша адресов повторяет тик, когда файл освободится.
    /// </summary>
    [Fact]
    public async Task ServerResolved_StateFileLocked_StillReconcilesNewAddress()
    {
        SaveSettings(Settings() with { Profiles = [_profile with { Server = "vpn.example" }] });
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        _world.Resolver.Answer = [FakeWorld.SecondServer];
        _world.Time.Advance(TimeSpan.FromHours(1));

        using (new FileStream(_world.Paths.State, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            await coordinator.ReconcileAsync(CancellationToken.None);
            await CompleteDialAsync(coordinator);

            Assert.Equal([FakeWorld.SecondServer], coordinator.Facts.Tunnels[_profile.Id].ServerAddresses);
            Assert.Contains(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(FakeWorld.SecondServer, 32) && r.InterfaceLuid == FakeWorld.WiFiLuid);
            Assert.Equal(DecisionSource.Server, coordinator.Facts.Policy!.Classify(FakeWorld.SecondServer).Source);
        }

        await TickAsync(coordinator);
        Assert.Contains(Ipv4.Format(FakeWorld.SecondServer), new ServiceStores(_world.Paths).LoadState().Servers.Single().Addresses);
    }

    /// <summary>L-5: DNS сети не отвечает (портал авторизации) - неудача заранее начатого разрешения пишется один раз и при смене ошибки.</summary>
    [Fact]
    public async Task ConnectivityPinFailure_IsLoggedOnFirstFailureAndOnChange()
    {
        var log = new RecordingLog();
        _world.Logger = log;
        _world.Resolver.Failures[Coordinator.ConnectivityCheckWebHost] = new IOException("DNS сети не отвечает");
        var coordinator = await StartProtectedForConnectivityCheckAsync();
        const string Text = "Имя проверки интернета Windows заранее не разрешилось";

        for (var i = 0; i < 30; i++)
        {
            _world.Time.Advance(TimeSpan.FromSeconds(31));
            await coordinator.ReconcileAsync(CancellationToken.None);
            await CompleteDialAsync(coordinator);
        }

        Assert.True(log.Entries(LogLevel.Debug, Text).Count > 5, "повторы не дошли до подробного журнала");
        Assert.Single(log.Entries(LogLevel.Information, Text));

        _world.Resolver.Failures[Coordinator.ConnectivityCheckWebHost] = new IOException("Сокет закрыт");
        for (var i = 0; i < 5; i++)
        {
            _world.Time.Advance(TimeSpan.FromSeconds(31));
            await coordinator.ReconcileAsync(CancellationToken.None);
            await CompleteDialAsync(coordinator);
        }

        var written = log.Entries(LogLevel.Information, Text);
        Assert.Equal(2, written.Count);
        Assert.Contains("Сокет закрыт", written[1].Text, StringComparison.Ordinal);
    }

    /// <summary>L-6: проба сертификата, остановленная самой службой, не пишет предупреждения.</summary>
    [Fact]
    public async Task CancelledCertificateProbe_IsNotAWarning()
    {
        var log = new RecordingLog();
        _world.Logger = log;
        var result = new TaskCompletionSource<ServerCertificateFacts?>(TaskCreationOptions.RunContinuationsAsynchronously);
        _world.Probes.CertificateResult = result;
        var coordinator = await StartAsync();
        try
        {
            await coordinator.HandleRequestAsync(new ConnectRequest(null, null), CancellationToken.None);
            var tunnel = coordinator.Facts.Tunnels[_profile.Id];
            for (var i = 0; i < 600 && (!tunnel.Verified || _world.Probes.ServerCertificateCalls == 0); i++)
            {
                await coordinator.DrainAsync();
                await Task.Delay(5, TestContext.Current.CancellationToken);
            }

            Assert.True(tunnel.CertificateProbeRunning);
            await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: true), CancellationToken.None);
            for (var i = 0; i < 600 && log.Entries(LogLevel.Debug, "Проба сертификата сервера").Count == 0; i++)
            {
                await Task.Delay(5, TestContext.Current.CancellationToken);
            }

            Assert.NotEmpty(log.Entries(LogLevel.Debug, "отменена"));
            Assert.Empty(log.Entries(LogLevel.Warning, "Проба сертификата сервера"));
        }
        finally
        {
            result.TrySetResult(null);
            await CompleteDialAsync(coordinator);
        }
    }

    /// <summary>L-6: загрузку обновления остановило «Пропустить версию» - это не предупреждение со стеком.</summary>
    [Fact]
    public async Task SkippedDownload_IsNotLoggedAsInterrupted()
    {
        var log = new RecordingLog();
        _world.Logger = log;
        SaveSettings(Settings() with { AppUpdate = new AppUpdateSettings { AutoDownload = false } });
        var coordinator = await UpdatingAsync(new UpdateSource(Manifest()));
        var check = coordinator.HandleRequestAsync(new CheckUpdateRequest(), CancellationToken.None);
        await PumpAsync(coordinator, check);

        await coordinator.HandleRequestAsync(new DownloadUpdateRequest("0.9.0"), CancellationToken.None);
        await WaitForQueuedUpdateAsync(coordinator);
        Assert.True((await coordinator.HandleRequestAsync(new SkipUpdateRequest("0.9.0"), CancellationToken.None)).Ok);
        await PumpAsync(coordinator);

        Assert.Equal(UpdatePhase.Idle, Status(coordinator).Phase);
        Assert.Empty(log.Entries(LogLevel.Warning, "Обработка загруженного обновления прервана"));
        Assert.Single(log.Entries(LogLevel.Information, "Загрузка обновления отменена"));
    }

    /// <summary>L-7: имена узлов шлюза не копятся без предела, а имена, ещё упомянутые в журнале, маскируются.</summary>
    [Fact]
    public async Task GatewayNodeHosts_AreBoundedByJournal()
    {
        var coordinator = await StartAsync();
        const string Kept = "kept-node.gateway.example";
        coordinator.Journal("Сведения", $"узел шлюза {Kept}");
        coordinator.RememberGatewayNodeHost(Kept);

        for (var i = 0; i < 1500; i++)
        {
            var host = $"node{i}.gateway.example";
            coordinator.Journal("Сведения", $"узел шлюза {host}");
            coordinator.RememberGatewayNodeHost(host);
            if (i % 100 == 0)
            {
                coordinator.Journal("Сведения", $"снова узел шлюза {Kept}");
            }
        }

        var hosts = coordinator.GatewayNodeHosts;
        Assert.InRange(hosts.Count, 1, Coordinator.MaxGatewayNodeHosts);
        Assert.Contains(Kept, hosts);
        Assert.Contains("node1499.gateway.example", hosts);
        Assert.DoesNotContain("node0.gateway.example", hosts);

        // Имена, которых журнал не упоминает (журнал стоит), всё равно ограничены пределом.
        for (var i = 0; i < 2000; i++)
        {
            coordinator.RememberGatewayNodeHost($"silent{i}.gateway.example");
        }

        hosts = coordinator.GatewayNodeHosts;
        Assert.InRange(hosts.Count, 1, Coordinator.MaxGatewayNodeHosts);
        Assert.Contains(Kept, hosts);
        Assert.Contains("silent1999.gateway.example", hosts);
    }

    /// <summary>Дождаться, пока очередь дойдёт до поставленной сейчас работы.</summary>
    private static async Task WaitForQueueAsync(Coordinator coordinator)
    {
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await coordinator.EnqueueAsync("Test:Marker", () =>
        {
            reached.TrySetResult();
            return Task.CompletedTask;
        });
        await reached.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
    }

    /// <summary>Журнал службы, запоминающий все записи с уровнем и исключением.</summary>
    private sealed class RecordingLog : ILogger
    {
        private readonly Lock _lock = new();
        private readonly List<(LogLevel Level, string Text, Exception? Exception)> _entries = [];

        /// <summary>Записи не ниже уровня <paramref name="atLeast"/> (Debug - ровно Debug), содержащие фрагмент.</summary>
        public List<(LogLevel Level, string Text, Exception? Exception)> Entries(LogLevel atLeast, string fragment)
        {
            lock (_lock)
            {
                return _entries.Where(e => (atLeast == LogLevel.Debug ? e.Level == LogLevel.Debug
                        : atLeast == LogLevel.Information ? e.Level == LogLevel.Information : e.Level >= atLeast)
                    && e.Text.Contains(fragment, StringComparison.Ordinal)).ToList();
            }
        }

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (_lock)
            {
                _entries.Add((logLevel, formatter(state, exception), exception));
            }
        }
    }
}
