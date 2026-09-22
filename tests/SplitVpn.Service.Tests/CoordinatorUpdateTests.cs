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

    private static string Manifest(string version = "0.9.0", string? minUpgradable = null) => $$"""
        {
          "schema": 1,
          "product": "SplitVpn",
          "version": "{{version}}",
          "tag": "v{{version}}",
          "releasedUtc": "2026-09-28T09:15:00+00:00",
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

    /// <summary>Подменённый ответ со старым, но верно подписанным манифестом не откатывает программу.</summary>
    [Fact]
    public async Task Check_BelowHighestSeen_IsRejected()
    {
        var source = new UpdateSource(Manifest("0.9.5"));
        var coordinator = await UpdatingAsync(source);
        var first = coordinator.HandleRequestAsync(new CheckUpdateRequest(), CancellationToken.None);
        await PumpAsync(coordinator, first);

        source.Override = request => request.RequestUri!.AbsoluteUri.EndsWith("update.json", StringComparison.Ordinal)
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(Encoding.UTF8.GetBytes(Manifest("0.9.1"))) }
            : null;
        var second = coordinator.HandleRequestAsync(new CheckUpdateRequest(), CancellationToken.None);
        await PumpAsync(coordinator, second);

        Assert.False((await second).Ok);
        Assert.Equal("0.9.5", Status(coordinator).AvailableVersion);
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
    public async Task Startup_AfterAbandonedInstall_ReportsFailure()
    {
        await InstallingAsync();
        _world.Time.Advance(TimeSpan.FromMinutes(30));

        var restarted = await StartAsync();

        Assert.Equal(UpdatePhase.Failed, Status(restarted).Phase);
        Assert.Contains(_world.Journal.Since(0), e => e.Level == "Ошибка" && e.Text.Contains("не установилось", StringComparison.Ordinal));
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
