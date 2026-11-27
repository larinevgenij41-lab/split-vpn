using System.Net;
using System.Security.Cryptography;
using System.Text;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;
using SplitVpn.Core.Update;
using SplitVpn.Service.Coordination;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Обновление самой программы: плановая проверка, подпись манифеста, загрузка установщика и
/// подготовка установки. Сеть подменена обработчиком HTTP, подпись — проверяющим из мира фейков.
/// </summary>
public sealed partial class CoordinatorTests
{
    private static readonly byte[] Package = Encoding.UTF8.GetBytes(new string('м', 2048));

    private static string PackageHash => Convert.ToHexStringLower(SHA256.HashData(Package));

    /// <summary>Отвечает манифестом, подписью и установщиком; считает обращения к каждому виду файла.</summary>
    private sealed class UpdateSource(string manifest) : HttpMessageHandler
    {
        public int ManifestCalls { get; private set; }

        public int PackageCalls { get; private set; }

        public Func<HttpRequestMessage, HttpResponseMessage?>? Override { get; set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (Override?.Invoke(request) is { } custom)
            {
                return Task.FromResult(custom);
            }

            var url = request.RequestUri!.AbsoluteUri;
            if (url.EndsWith(".sig", StringComparison.Ordinal))
            {
                return Task.FromResult(Ok(Encoding.UTF8.GetBytes(Convert.ToBase64String(new byte[64]))));
            }

            if (url.EndsWith(".msi", StringComparison.Ordinal))
            {
                PackageCalls++;
                return Task.FromResult(Ok(Package));
            }

            ManifestCalls++;
            return Task.FromResult(Ok(Encoding.UTF8.GetBytes(manifest)));
        }

        private static HttpResponseMessage Ok(byte[] body) =>
            new(HttpStatusCode.OK) { Content = new ByteArrayContent(body) };
    }

    private static string Manifest(string version = "0.9.0", string? minUpgradable = null, string? expires = null) => $$"""
        {
          "schema": 1,
          "product": "SplitVpn",
          "version": "{{version}}",
          "tag": "v{{version}}",
          "releasedUtc": "2026-09-28T09:15:00+00:00",
          {{(expires is null ? "" : $"\"expiresUtc\": \"{expires}\",")}}
          {{(minUpgradable is null ? "" : $"\"minUpgradableVersion\": \"{minUpgradable}\",")}}
          "package": {
            "fileName": "SplitVpn-{{version}}.msi",
            "size": {{Package.Length}},
            "sha256": "{{PackageHash}}",
            "urls": ["https://github.com/o/r/releases/download/v{{version}}/SplitVpn-{{version}}.msi"]
          },
          "notes": "Что нового.",
          "notesUrl": "https://github.com/o/r/releases/tag/v{{version}}",
          "kid": "sv-2026-09"
        }
        """;

    /// <summary>Очередь актора в тестах не крутится сама: её подталкивают, пока фоновая работа не кончится.</summary>
    private static async Task PumpAsync(Coordinator coordinator, params Task[] tasks)
    {
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (DateTime.UtcNow < deadline)
        {
            await coordinator.DrainAsync();
            if (tasks.All(t => t.IsCompleted) && coordinator.UpdateWork.IsCompleted)
            {
                await coordinator.DrainAsync();
                return;
            }

            await Task.Delay(5);
        }

        throw new TimeoutException("Фоновая работа обновления не завершилась.");
    }

    private async Task<Coordinator> UpdatingAsync(UpdateSource source)
    {
        _world.HttpHandler = source;
        var coordinator = await StartAsync();
        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: false), CancellationToken.None);
        return coordinator;
    }

    private static UpdateStatusDto Status(Coordinator coordinator) => coordinator.BuildStatus().Update!;

    [Fact]
    public async Task Tick_FindsNewVersion_DownloadsAndWarns()
    {
        var source = new UpdateSource(Manifest());
        var coordinator = await UpdatingAsync(source);

        await TickAsync(coordinator);
        await PumpAsync(coordinator);

        var status = Status(coordinator);
        Assert.Equal(UpdatePhase.Ready, status.Phase);
        Assert.Equal("0.9.0", status.AvailableVersion);
        Assert.Equal(Package.Length, status.DownloadedBytes);
        Assert.Equal("Что нового.", status.Notes);
        Assert.Equal(1, source.PackageCalls);
        Assert.Contains(coordinator.BuildStatus().Warnings, w => w.Code == "update-ready");
        Assert.True(File.Exists(Path.Combine(_world.Paths.Update, "SplitVpn-0.9.0.msi")));
    }

    /// <summary>Срок следующей проверки — интервал плюс случайный сдвиг до часа.</summary>
    [Fact]
    public async Task Tick_SchedulesNextCheckWithJitter()
    {
        var coordinator = await UpdatingAsync(new UpdateSource(Manifest()));
        var now = _world.Time.GetUtcNow();

        await TickAsync(coordinator);
        await PumpAsync(coordinator);

        var next = Status(coordinator).NextCheckUtc!.Value;
        Assert.InRange(next, now.AddDays(1), now.AddDays(1).AddHours(1));
    }

    [Fact]
    public async Task Tick_DefersOnMeteredNetwork()
    {
        var source = new UpdateSource(Manifest());
        var coordinator = await UpdatingAsync(source);
        _world.Metered = true;

        await TickAsync(coordinator);
        await PumpAsync(coordinator);

        Assert.Equal(0, source.ManifestCalls);
        Assert.Equal(UpdatePhase.Idle, Status(coordinator).Phase);
        Assert.Contains("лимитная", Status(coordinator).LastResult, StringComparison.Ordinal);
    }

    /// <summary>Под защитой без проверенного туннеля запрос оборвали бы фильтры: он не отправляется.</summary>
    [Fact]
    public async Task Tick_SkippedWhileProtectionBlocksNetwork()
    {
        var source = new UpdateSource(Manifest());
        _world.HttpHandler = source;
        var coordinator = await StartAsync();
        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: true), CancellationToken.None);

        await TickAsync(coordinator);
        await PumpAsync(coordinator);

        Assert.Equal(0, source.ManifestCalls);
    }

    [Fact]
    public async Task Check_BadSignature_IsRejectedAndNothingDownloaded()
    {
        _world.ManifestVerifier = new RejectingVerifier();
        var source = new UpdateSource(Manifest());
        var coordinator = await UpdatingAsync(source);

        var task = coordinator.HandleRequestAsync(new CheckUpdateRequest(), CancellationToken.None);
        await PumpAsync(coordinator, task);

        Assert.False((await task).Ok);
        Assert.Equal(UpdatePhase.Idle, Status(coordinator).Phase);
        Assert.Equal(0, source.PackageCalls);
        Assert.Contains(_world.Journal.Since(0), e => e.Level == "Ошибка" && e.Text.Contains("подпись", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Check_OlderVersion_IsIgnored()
    {
        var coordinator = await UpdatingAsync(new UpdateSource(Manifest("0.7.0")));

        var task = coordinator.HandleRequestAsync(new CheckUpdateRequest(), CancellationToken.None);
        await PumpAsync(coordinator, task);

        Assert.Equal(UpdatePhase.Idle, Status(coordinator).Phase);
        Assert.Null(Status(coordinator).AvailableVersion);
    }

    /// <summary>
    /// Подменённый (или ещё не обновлённый в кэше) ответ со старым, но верно подписанным манифестом не откатывает
    /// программу: младшая версия не предлагается. Но это не сбой: «обновлений нет», проверка по обычному расписанию,
    /// без ошибки в журнале и без ежечасного повтора, а предупреждение о таком манифесте пишется один раз.
    /// </summary>
    [Fact]
    public async Task Check_BelowHighestSeen_IsNoUpdate_AndLoggedOnce()
    {
        var source = new UpdateSource(Manifest("0.9.5"));
        var coordinator = await UpdatingAsync(source);
        var first = coordinator.HandleRequestAsync(new CheckUpdateRequest(), CancellationToken.None);
        await PumpAsync(coordinator, first);

        source.Override = request => request.RequestUri!.AbsoluteUri.EndsWith("update.json", StringComparison.Ordinal)
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(Encoding.UTF8.GetBytes(Manifest("0.9.1"))) }
            : null;
        var journalBefore = _world.Journal.Since(0).Count;
        for (var i = 0; i < 2; i++)
        {
            var check = coordinator.HandleRequestAsync(new CheckUpdateRequest(), CancellationToken.None);
            await PumpAsync(coordinator, check);
            Assert.True((await check).Ok);
        }

        Assert.Equal("0.9.5", Status(coordinator).AvailableVersion);
        Assert.True(Status(coordinator).NextCheckUtc >= _world.Time.GetUtcNow().AddDays(1));
        var added = _world.Journal.Since(0).Skip(journalBefore).ToList();
        Assert.DoesNotContain(added, e => e.Level == "Ошибка");
        Assert.Single(added, e => e.Text.Contains("0.9.1", StringComparison.Ordinal));
    }

    /// <summary>Просроченный манифест — не ошибка, а «обновлений нет» с причиной; проверка идёт по обычному расписанию.</summary>
    [Fact]
    public async Task Check_ExpiredManifest_MeansNoUpdates()
    {
        var source = new UpdateSource(Manifest("0.9.6", expires: "2026-09-01T00:00:00Z"));
        var coordinator = await UpdatingAsync(source);

        var task = coordinator.HandleRequestAsync(new CheckUpdateRequest(), CancellationToken.None);
        await PumpAsync(coordinator, task);

        Assert.True((await task).Ok);
        Assert.Equal(UpdatePhase.Idle, Status(coordinator).Phase);
        Assert.Null(Status(coordinator).AvailableVersion);
        Assert.Contains("устарел", Status(coordinator).LastResult, StringComparison.Ordinal);
        Assert.Equal(0, source.PackageCalls);
        Assert.DoesNotContain(_world.Journal.Since(0), e => e.Level == "Ошибка" && e.Text.Contains("устарел", StringComparison.Ordinal));
        Assert.True(Status(coordinator).NextCheckUtc >= _world.Time.GetUtcNow().AddDays(1));
    }

    /// <summary>Основной адрес отдаёт старый (просроченный) манифест — используется свежий с зеркала.</summary>
    [Fact]
    public async Task Check_ExpiredOnPrimary_FreshMirrorIsUsed()
    {
        var source = new UpdateSource(Manifest("0.9.6", expires: "2026-12-01T00:00:00Z"));
        source.Override = request => request.RequestUri!.Host == UpdateSources.LatestRelease.Host
            && request.RequestUri.AbsoluteUri.EndsWith("update.json", StringComparison.Ordinal)
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(Encoding.UTF8.GetBytes(Manifest("0.9.6", expires: "2026-09-01T00:00:00Z"))) }
            : null;
        var coordinator = await UpdatingAsync(source);

        var task = coordinator.HandleRequestAsync(new CheckUpdateRequest(), CancellationToken.None);
        await PumpAsync(coordinator, task);

        Assert.True((await task).Ok);
        Assert.Equal("0.9.6", Status(coordinator).AvailableVersion);
    }

    /// <summary>Выпуск новее 0.9.5 без срока годности не принимается.</summary>
    [Fact]
    public async Task Check_NewManifestWithoutExpiry_IsRejected()
    {
        var coordinator = await UpdatingAsync(new UpdateSource(Manifest("0.9.6")));

        var task = coordinator.HandleRequestAsync(new CheckUpdateRequest(), CancellationToken.None);
        await PumpAsync(coordinator, task);

        Assert.False((await task).Ok);
        Assert.Null(Status(coordinator).AvailableVersion);
    }

    /// <summary>
    /// Установлена 0.9.6: повтор старого манифеста без срока годности — «список устарел», а не «установлена
    /// последняя версия»; ETag не запоминается, и следующий настоящий манифест с полем срока принимается.
    /// </summary>
    [Fact]
    public async Task Check_ManifestWithoutExpiry_IsStaleForInstalled096()
    {
        _world.ProductVersion = new Version(0, 9, 6);
        var source = new UpdateSource(Manifest("0.9.5"));
        var coordinator = await UpdatingAsync(source);

        var first = coordinator.HandleRequestAsync(new CheckUpdateRequest(), CancellationToken.None);
        await PumpAsync(coordinator, first);

        Assert.True((await first).Ok);
        Assert.Contains("устарел", Status(coordinator).LastResult, StringComparison.Ordinal);
        Assert.Null(Status(coordinator).AvailableVersion);

        source.Override = request => request.RequestUri!.AbsoluteUri.EndsWith("update.json", StringComparison.Ordinal)
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(Encoding.UTF8.GetBytes(Manifest("0.9.7", expires: "2026-12-01T00:00:00Z"))) }
            : null;
        var second = coordinator.HandleRequestAsync(new CheckUpdateRequest(), CancellationToken.None);
        await PumpAsync(coordinator, second);

        Assert.True((await second).Ok);
        Assert.Equal("0.9.7", Status(coordinator).AvailableVersion);
    }

    [Fact]
    public async Task Check_MinUpgradableAbove_IsRefusedWithExplanation()
    {
        var coordinator = await UpdatingAsync(new UpdateSource(Manifest("0.9.0", minUpgradable: "0.8.5")));

        var task = coordinator.HandleRequestAsync(new CheckUpdateRequest(), CancellationToken.None);
        await PumpAsync(coordinator, task);

        Assert.False((await task).Ok);
        Assert.Contains("промежуточная", Status(coordinator).LastResult, StringComparison.Ordinal);
    }

    /// <summary>
    /// Промежуточную версию поставили вручную: ETag, полученный при прежней версии, не отправляется, и плановая
    /// проверка предлагает выпуск, а не отвечает "список выпусков не изменился" до смены манифеста.
    /// </summary>
    [Fact]
    public async Task Tick_AfterManualInstallOfIntermediateVersion_IgnoresOldETag()
    {
        var manifest = Manifest("0.9.0", minUpgradable: "0.8.5", expires: "2026-10-30T00:00:00+00:00");
        var conditional = 0;
        var source = new UpdateSource(manifest);
        source.Override = r =>
        {
            if (!r.RequestUri!.AbsoluteUri.EndsWith(".json", StringComparison.Ordinal))
            {
                return null;
            }

            conditional += r.Headers.IfNoneMatch.Count > 0 ? 1 : 0;
            var response = r.Headers.IfNoneMatch.Count > 0
                ? new HttpResponseMessage(HttpStatusCode.NotModified)
                : new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(Encoding.UTF8.GetBytes(manifest)) };
            response.Headers.ETag = new System.Net.Http.Headers.EntityTagHeaderValue("\"m1\"");
            return response;
        };
        var coordinator = await UpdatingAsync(source);
        await TickAsync(coordinator);
        await PumpAsync(coordinator);
        Assert.Contains("промежуточная", Status(coordinator).LastResult, StringComparison.Ordinal);

        _world.ProductVersion = new Version(0, 8, 5);
        var restarted = await UpdatingAsync(source);
        _world.Time.Advance(TimeSpan.FromHours(3));
        await TickAsync(restarted);
        await PumpAsync(restarted);

        Assert.Equal(0, conditional);
        Assert.Equal("0.9.0", Status(restarted).AvailableVersion);
    }

    [Fact]
    public async Task Skip_HidesVersionUntilManualCheck()
    {
        var coordinator = await UpdatingAsync(new UpdateSource(Manifest()));
        await TickAsync(coordinator);
        await PumpAsync(coordinator);

        await coordinator.HandleRequestAsync(new SkipUpdateRequest("0.9.0"), CancellationToken.None);
        Assert.Equal("0.9.0", Status(coordinator).SkippedVersion);
        Assert.Equal(UpdatePhase.Idle, Status(coordinator).Phase);

        // Плановая проверка пропущенную версию не предлагает.
        _world.Time.Advance(TimeSpan.FromDays(3));
        await TickAsync(coordinator);
        await PumpAsync(coordinator);
        Assert.Equal(UpdatePhase.Idle, Status(coordinator).Phase);

        // Проверка по команде — предлагает: пользователь передумал.
        var task = coordinator.HandleRequestAsync(new CheckUpdateRequest(), CancellationToken.None);
        await PumpAsync(coordinator, task);
        Assert.Equal(UpdatePhase.Ready, Status(coordinator).Phase);
    }

    [Fact]
    public async Task Download_ChecksumMismatch_KeepsAvailableAndRemovesFile()
    {
        var source = new UpdateSource(Manifest());
        source.Override = request => request.RequestUri!.AbsoluteUri.EndsWith(".msi", StringComparison.Ordinal)
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(Encoding.UTF8.GetBytes(new string('д', 2048))) }
            : null;
        var coordinator = await UpdatingAsync(source);

        await TickAsync(coordinator);
        await PumpAsync(coordinator);

        Assert.Equal(UpdatePhase.Available, Status(coordinator).Phase);
        Assert.False(File.Exists(Path.Combine(_world.Paths.Update, "SplitVpn-0.9.0.msi")));
        Assert.Contains("сумма", Status(coordinator).LastResult, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Install_RejectedUntilPackageIsReady()
    {
        var coordinator = await UpdatingAsync(new UpdateSource(Manifest()));

        var response = await coordinator.HandleRequestAsync(new InstallUpdateRequest("0.9.0"), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.NotFound, response.ErrorCode);
    }

    [Fact]
    public async Task Install_ReturnsMsiexecCommandAndMarksInstalling()
    {
        var coordinator = await ReadyAsync();

        var task = coordinator.HandleRequestAsync(new InstallUpdateRequest("0.9.0"), CancellationToken.None);
        await PumpAsync(coordinator, task);
        var response = await task;

        Assert.True(response.Ok);
        var install = response.ResultAs<UpdateInstallDto>()!;
        Assert.EndsWith("msiexec.exe", install.FileName, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("/passive", install.Arguments, StringComparison.Ordinal);
        Assert.Contains("/norestart", install.Arguments, StringComparison.Ordinal);
        Assert.Contains("REBOOT=ReallySuppress", install.Arguments, StringComparison.Ordinal);
        Assert.Contains(Path.Combine(_world.Paths.Update, "SplitVpn-0.9.0.msi"), install.Arguments, StringComparison.Ordinal);
        Assert.Equal(UpdatePhase.Installing, Status(coordinator).Phase);
    }

    /// <summary>
    /// Команда, которую служба строит для настоящих путей пакета и журнала, проходит ту проверку, которой её встречают
    /// интерфейс и командная строка перед запуском с повышением прав: иначе правка формата в службе молча сломала бы
    /// установку обновлений у всех.
    /// </summary>
    [Fact]
    public async Task Install_CommandBuiltByServicePassesClientCheck()
    {
        var coordinator = await ReadyAsync();

        var task = coordinator.HandleRequestAsync(new InstallUpdateRequest("0.9.0"), CancellationToken.None);
        await PumpAsync(coordinator, task);
        var install = (await task).ResultAs<UpdateInstallDto>()!;

        Assert.Null(UpdateInstallCommand.Problem(install, UpdateInstallCommand.SystemRoot, _world.Paths.Update));
        Assert.Equal(UpdateInstallCommand.BuildArguments(Path.Combine(_world.Paths.Update, "SplitVpn-0.9.0.msi"), install.LogPath), install.Arguments);
    }

    [Fact]
    public async Task Install_RejectedWhenVersionDiffers()
    {
        var coordinator = await ReadyAsync();

        var response = await coordinator.HandleRequestAsync(new InstallUpdateRequest("1.2.3"), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(UpdatePhase.Ready, Status(coordinator).Phase);
    }

    /// <summary>Отказ в окне контроля учётных записей возвращает состояние к готовности, а не подвешивает его.</summary>
    [Fact]
    public async Task InstallStarted_WithoutProcess_ReturnsToReady()
    {
        var coordinator = await InstallingAsync();

        await coordinator.HandleRequestAsync(new UpdateStartedRequest(0), CancellationToken.None);

        Assert.Equal(UpdatePhase.Ready, Status(coordinator).Phase);
        Assert.Empty(_world.WatchedProcesses);
    }

    [Fact]
    public async Task InstallStarted_StaleConsentCannotCancelNewAttempt()
    {
        var coordinator = await ReadyAsync();
        var first = coordinator.HandleRequestAsync(new InstallUpdateRequest("0.9.0"), CancellationToken.None);
        await PumpAsync(coordinator, first);
        var obsolete = (await first).ResultAs<UpdateInstallDto>()!.AttemptId;
        _world.Time.Advance(TimeSpan.FromMinutes(6));
        await TickAsync(coordinator);
        var next = coordinator.HandleRequestAsync(new InstallUpdateRequest("0.9.0"), CancellationToken.None);
        await PumpAsync(coordinator, next);
        var current = (await next).ResultAs<UpdateInstallDto>()!.AttemptId;
        Assert.NotNull(current);
        Assert.NotEqual(obsolete, current);
        await coordinator.HandleRequestAsync(new UpdateStartedRequest(0) { AttemptId = obsolete }, CancellationToken.None);
        Assert.Equal(UpdatePhase.Installing, Status(coordinator).Phase);
        await coordinator.HandleRequestAsync(new UpdateStartedRequest(0) { AttemptId = current }, CancellationToken.None);
        Assert.Equal(UpdatePhase.Ready, Status(coordinator).Phase);
    }

    /// <summary>
    /// Интерфейс повторяет недоставленный отчёт об отказе UAC: повтор с тем же AttemptId ничего не ломает, повторная
    /// установка сразу принимается, а запоздавший дубль прежней попытки новую не отменяет.
    /// </summary>
    [Fact]
    public async Task InstallStarted_RepeatedRefusal_IsIdempotent()
    {
        var coordinator = await ReadyAsync();
        var first = coordinator.HandleRequestAsync(new InstallUpdateRequest("0.9.0"), CancellationToken.None);
        await PumpAsync(coordinator, first);
        var attempt = (await first).ResultAs<UpdateInstallDto>()!.AttemptId;

        Assert.True((await coordinator.HandleRequestAsync(new UpdateStartedRequest(0) { AttemptId = attempt }, CancellationToken.None)).Ok);
        Assert.True((await coordinator.HandleRequestAsync(new UpdateStartedRequest(0) { AttemptId = attempt }, CancellationToken.None)).Ok);
        Assert.Equal(UpdatePhase.Ready, Status(coordinator).Phase);

        var retry = coordinator.HandleRequestAsync(new InstallUpdateRequest("0.9.0"), CancellationToken.None);
        await PumpAsync(coordinator, retry);
        Assert.True((await retry).Ok);
        Assert.Equal(UpdatePhase.Installing, Status(coordinator).Phase);

        Assert.True((await coordinator.HandleRequestAsync(new UpdateStartedRequest(0) { AttemptId = attempt }, CancellationToken.None)).Ok);
        Assert.Equal(UpdatePhase.Installing, Status(coordinator).Phase);
    }

    [Fact]
    public async Task InstallStarted_BusyInstaller_ReturnsToReadyWithHint()
    {
        var coordinator = await InstallingAsync();
        _world.ProcessExitCodes[4242] = 1618;

        var task = coordinator.HandleRequestAsync(new UpdateStartedRequest(4242), CancellationToken.None);
        await PumpAsync(coordinator, task);

        Assert.Contains(4242, _world.WatchedProcesses);
        Assert.Equal(UpdatePhase.Ready, Status(coordinator).Phase);
        Assert.Contains("другой программы", Status(coordinator).LastInstallResult, StringComparison.Ordinal);
    }

    [Fact]
    public async Task InstallStarted_Failure_MarksFailedAndKeepsPackage()
    {
        var coordinator = await InstallingAsync();
        _world.ProcessExitCodes[77] = 1603;

        var task = coordinator.HandleRequestAsync(new UpdateStartedRequest(77), CancellationToken.None);
        await PumpAsync(coordinator, task);

        Assert.Equal(UpdatePhase.Failed, Status(coordinator).Phase);
        Assert.True(File.Exists(Path.Combine(_world.Paths.Update, "SplitVpn-0.9.0.msi")));
        Assert.Contains(coordinator.BuildStatus().Warnings, w => w.Code == "update-failed");
    }

    /// <summary>Установку довёл MSI, остановив службу: новая служба видит новую версию сборки.</summary>
    [Fact]
    public async Task Startup_AfterSuccessfulInstall_ReportsSuccess()
    {
        await InstallingAsync();
        _world.ProductVersion = new Version(0, 9, 0);

        var restarted = await StartAsync();

        Assert.Equal(UpdatePhase.Idle, Status(restarted).Phase);
        Assert.Equal("Обновление установлено.", Status(restarted).LastInstallResult);
        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("0.9.0 установлено", StringComparison.Ordinal));
        Assert.False(File.Exists(Path.Combine(_world.Paths.Update, "SplitVpn-0.9.0.msi")));
    }

    [Fact]
    public async Task Startup_WithLongRunningInstaller_PreservesWatch()
    {
        var coordinator = await InstallingAsync();
        _world.RunningProcesses.Add(4243);
        await coordinator.HandleRequestAsync(new UpdateStartedRequest(4243), CancellationToken.None);
        // В пределах срока установки; после него живой установщик отпускает фазу (Install_HungInstaller_*).
        _world.Time.Advance(TimeSpan.FromMinutes(10));

        var restarted = await StartAsync();

        Assert.Equal(UpdatePhase.Installing, Status(restarted).Phase);
        Assert.Equal(4243, new UpdateStore(_world.Paths.Update).LoadState().InstallerProcessId);
    }

    /// <summary>Интерфейс получил команду установки, но о запуске msiexec не сообщил: через 5 минут снова «Готово».</summary>
    [Fact]
    public async Task Tick_UnconfirmedInstall_ReturnsToReady()
    {
        var coordinator = await InstallingAsync();
        _world.Time.Advance(TimeSpan.FromMinutes(6));

        await TickAsync(coordinator);

        Assert.Equal(UpdatePhase.Ready, Status(coordinator).Phase);
        Assert.Equal("Установка не запущена или прервана.", Status(coordinator).LastInstallResult);
    }

    /// <summary>msiexec ещё работает: служба перезапустилась по другой причине и ничего не решает.</summary>
    [Fact]
    public async Task Startup_WhileInstallerStillRunning_KeepsInstalling()
    {
        await InstallingAsync();
        _world.Time.Advance(TimeSpan.FromMinutes(2));

        var restarted = await StartAsync();

        Assert.Equal(UpdatePhase.Installing, Status(restarted).Phase);
    }

    /// <summary>Аудит ID22: загрузка, прерванная перезапуском, не остаётся в состоянии "Загружается" даже при выключенной автопроверке.</summary>
    [Fact]
    public async Task Startup_InterruptedDownload_ResetsToAvailable()
    {
        new ServiceStores(_world.Paths).SaveSettings(Settings() with { AppUpdate = new AppUpdateSettings { AutoCheck = false } });
        new UpdateStore(_world.Paths.Update).SaveState(new UpdateState
        {
            Phase = UpdatePhase.Downloading,
            AvailableVersion = "0.9.0",
            PackageFileName = "SplitVpn-0.9.0.msi",
            PackageSha256 = PackageHash,
            PackageSize = Package.Length,
        });

        var restarted = await StartAsync();

        Assert.Equal(UpdatePhase.Available, Status(restarted).Phase);
        Assert.Contains("прервана", Status(restarted).LastResult, StringComparison.Ordinal);
    }

    /// <summary>
    /// msiexec исчез до открытия номера процесса (например, 1618 "Windows занята" за доли секунды): сбой не
    /// объявляется сразу, а тик через 5 минут после подготовки по неизменной версии снова предлагает установить
    /// (аудит ID42: не ждать 15 минут).
    /// </summary>
    [Fact]
    public async Task InstallStarted_ProcessAlreadyGone_ReturnsToReadyByTick()
    {
        var coordinator = await InstallingAsync();

        var task = coordinator.HandleRequestAsync(new UpdateStartedRequest(999), CancellationToken.None);
        await PumpAsync(coordinator, task);

        Assert.Contains(999, _world.WatchedProcesses);
        Assert.Equal(UpdatePhase.Installing, Status(coordinator).Phase);
        Assert.DoesNotContain(_world.Journal.Since(0), e => e.Level == "Ошибка" && e.Text.Contains("установ", StringComparison.Ordinal));

        _world.Time.Advance(TimeSpan.FromMinutes(6));
        await TickAsync(coordinator);

        Assert.Equal(UpdatePhase.Ready, Status(coordinator).Phase);
        Assert.Equal("Установка не запущена или прервана.", Status(coordinator).LastInstallResult);
    }

    /// <summary>msiexec исчез до открытия номера, а служба уже работает новой версией: тик объявляет успех.</summary>
    [Fact]
    public async Task InstallStarted_ProcessAlreadyGone_NewVersionReportsSuccess()
    {
        var coordinator = await InstallingAsync();
        var task = coordinator.HandleRequestAsync(new UpdateStartedRequest(999), CancellationToken.None);
        await PumpAsync(coordinator, task);
        Assert.Equal(UpdatePhase.Installing, Status(coordinator).Phase);

        _world.ProductVersion = new Version(0, 9, 0);
        var restarted = await StartAsync();

        Assert.Equal(UpdatePhase.Idle, Status(restarted).Phase);
        Assert.Equal("Обновление установлено.", Status(restarted).LastInstallResult);
    }

    /// <summary>Аудит ID9: 304 на запрос без ETag не считается успешной проверкой.</summary>
    [Fact]
    public async Task Tick_NotModifiedWithoutCachedManifest_IsFailure()
    {
        var source = new UpdateSource(Manifest())
        {
            Override = r => r.RequestUri!.AbsoluteUri.EndsWith(".json", StringComparison.Ordinal) ? new HttpResponseMessage(HttpStatusCode.NotModified) : null,
        };
        var coordinator = await UpdatingAsync(source);

        await TickAsync(coordinator);
        await PumpAsync(coordinator);

        Assert.Contains("не удалась", Status(coordinator).LastResult, StringComparison.Ordinal);
        Assert.NotEqual(UpdatePhase.Ready, Status(coordinator).Phase);
    }

    [Fact]
    public async Task CorruptState_IsReplacedAndReported()
    {
        Directory.CreateDirectory(_world.Paths.Update);
        await File.WriteAllTextAsync(Path.Combine(_world.Paths.Update, "state.json"), "{не json", TestContext.Current.CancellationToken);

        var coordinator = await StartAsync();

        Assert.Equal(UpdatePhase.Idle, Status(coordinator).Phase);
        Assert.Contains(coordinator.BuildStatus().Warnings, w => w.Code == "data-corrupt");
    }

    [Fact]
    public async Task Settings_AutoDownloadOff_KeepsAvailableAndWarns()
    {
        new ServiceStores(_world.Paths).SaveSettings(Settings() with { AppUpdate = new AppUpdateSettings { AutoDownload = false } });
        var source = new UpdateSource(Manifest());
        var coordinator = await UpdatingAsync(source);

        await TickAsync(coordinator);
        await PumpAsync(coordinator);

        Assert.Equal(UpdatePhase.Available, Status(coordinator).Phase);
        Assert.Equal(0, source.PackageCalls);
        Assert.Contains(coordinator.BuildStatus().Warnings, w => w.Code == "update-available");

        var task = coordinator.HandleRequestAsync(new DownloadUpdateRequest("0.9.0"), CancellationToken.None);
        await PumpAsync(coordinator, task);

        Assert.Equal(UpdatePhase.Ready, Status(coordinator).Phase);
        Assert.Equal(1, source.PackageCalls);
    }

    /// <summary>
    /// Источник раз за разом отдаёт файл не с той контрольной суммой: прежде счётчик попыток сбрасывался, и полный
    /// установщик качался заново каждый час без конца и молча. Теперь повтор откладывается всё дольше, после трёх
    /// несовпадений автозагрузка стоит с предупреждением в шапке, а загрузка по команде и новый выпуск её возобновляют.
    /// </summary>
    [Fact]
    public async Task Download_RepeatedChecksumMismatch_BacksOffThenStopsAndWarns()
    {
        var source = new UpdateSource(Manifest());
        var wrongPackages = 0;
        source.Override = request =>
        {
            if (!request.RequestUri!.AbsoluteUri.EndsWith(".msi", StringComparison.Ordinal))
            {
                return null;
            }

            wrongPackages++;
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(Encoding.UTF8.GetBytes(new string('д', 2048))) };
        };
        var coordinator = await UpdatingAsync(source);

        var delays = new List<TimeSpan>();
        for (var attempt = 1; attempt <= UpdateManager.MaxHashMismatches; attempt++)
        {
            var now = _world.Time.GetUtcNow();
            await TickAsync(coordinator);
            await PumpAsync(coordinator);
            Assert.Equal(attempt, wrongPackages);
            Assert.Equal(UpdatePhase.Available, Status(coordinator).Phase);
            var next = Status(coordinator).NextCheckUtc!.Value;
            delays.Add(next - now);
            _world.Time.Advance(next - now + TimeSpan.FromMinutes(1));
        }

        Assert.Equal(TimeSpan.FromHours(1), delays[0]);
        Assert.Equal(TimeSpan.FromHours(2), delays[1]);
        Assert.Contains(coordinator.BuildStatus().Warnings, w => w.Code == "update-download-failed");
        Assert.Contains("остановлена", Status(coordinator).LastResult, StringComparison.Ordinal);

        // Плановые проверки идут, но тот же выпуск больше сам не качается.
        var manifestCalls = source.ManifestCalls;
        _world.Time.Advance(TimeSpan.FromDays(2));
        await TickAsync(coordinator);
        await PumpAsync(coordinator);
        Assert.True(source.ManifestCalls > manifestCalls);
        Assert.Equal(UpdateManager.MaxHashMismatches, wrongPackages);
        Assert.Contains(coordinator.BuildStatus().Warnings, w => w.Code == "update-download-failed");

        // Загрузка по команде пользователя идёт и при остановленной автозагрузке.
        var manual = coordinator.HandleRequestAsync(new DownloadUpdateRequest("0.9.0"), CancellationToken.None);
        await PumpAsync(coordinator, manual);
        Assert.Equal(UpdateManager.MaxHashMismatches + 1, wrongPackages);

        // Новый выпуск в манифесте - счёт с нуля, и исправный файл скачивается сам.
        source.Override = null;
        var fixedSource = new UpdateSource(Manifest("0.9.1"));
        _world.HttpHandler = fixedSource;
        var restarted = await StartAsync();
        await restarted.HandleRequestAsync(new DisconnectRequest(KeepProtection: false), CancellationToken.None);
        _world.Time.Advance(TimeSpan.FromDays(2));
        await TickAsync(restarted);
        await PumpAsync(restarted);
        Assert.Equal(1, fixedSource.PackageCalls);
        Assert.Equal(UpdatePhase.Ready, Status(restarted).Phase);
        Assert.DoesNotContain(restarted.BuildStatus().Warnings, w => w.Code == "update-download-failed");
    }

    /// <summary>
    /// Неудачная установка не скрывается следующим ответом манифеста о том же выпуске: прежде фаза становилась
    /// «Готово», причина пропадала из шапки, и та же установка предлагалась снова. Новый выпуск начинается с чистого листа.
    /// </summary>
    [Fact]
    public async Task Check_SamePackageAfterFailedInstall_KeepsFailure()
    {
        var coordinator = await InstallingAsync();
        _world.ProcessExitCodes[77] = 1603;
        var started = coordinator.HandleRequestAsync(new UpdateStartedRequest(77), CancellationToken.None);
        await PumpAsync(coordinator, started);
        Assert.Equal(UpdatePhase.Failed, Status(coordinator).Phase);
        var failure = Status(coordinator).LastInstallResult;
        Assert.Contains("1603", failure, StringComparison.Ordinal);

        var check = coordinator.HandleRequestAsync(new CheckUpdateRequest(), CancellationToken.None);
        await PumpAsync(coordinator, check);

        Assert.True((await check).Ok);
        Assert.Equal(UpdatePhase.Failed, Status(coordinator).Phase);
        Assert.Equal(failure, Status(coordinator).LastInstallResult);
        Assert.Contains(coordinator.BuildStatus().Warnings, w => w.Code == "update-failed");

        var newer = new UpdateSource(Manifest("0.9.1"));
        _world.HttpHandler = newer;
        var restarted = await StartAsync();
        await restarted.HandleRequestAsync(new DisconnectRequest(KeepProtection: false), CancellationToken.None);
        var next = restarted.HandleRequestAsync(new CheckUpdateRequest(), CancellationToken.None);
        await PumpAsync(restarted, next);

        Assert.Equal("0.9.1", Status(restarted).AvailableVersion);
        Assert.Equal(UpdatePhase.Ready, Status(restarted).Phase);
        Assert.Null(Status(restarted).LastInstallResult);
        Assert.DoesNotContain(restarted.BuildStatus().Warnings, w => w.Code == "update-failed");
    }

    /// <summary>Готовый к установке установщик: проверка, загрузка и сверка контрольной суммы уже прошли.</summary>
    private async Task<Coordinator> ReadyAsync()
    {
        var coordinator = await UpdatingAsync(new UpdateSource(Manifest()));
        await TickAsync(coordinator);
        await PumpAsync(coordinator);
        Assert.Equal(UpdatePhase.Ready, Status(coordinator).Phase);
        return coordinator;
    }

    private async Task<Coordinator> InstallingAsync()
    {
        var coordinator = await ReadyAsync();
        var task = coordinator.HandleRequestAsync(new InstallUpdateRequest("0.9.0"), CancellationToken.None);
        await PumpAsync(coordinator, task);
        Assert.True((await task).Ok);
        return coordinator;
    }

    private sealed class RejectingVerifier : IManifestVerifier
    {
        public string? Verify(byte[] manifest, byte[] signature, string? keyId) => "Подпись манифеста обновления неверна.";
    }
}
