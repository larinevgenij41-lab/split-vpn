using System.Net;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;
using SplitVpn.Core.Update;
using SplitVpn.Service.Coordination;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Обновление программы, стабильность: фаза «Установка» не держится вечно (часы переведены назад, установщик завис или
/// пропал), автоматическая загрузка останавливается выключением автообновления, а пропуск версии во время загрузки не
/// оставляет недокачанный файл до перезапуска службы.
/// </summary>
public sealed partial class CoordinatorTests
{
    /// <summary>Часы перевели назад, служба перезапущена: отметка подготовки в будущем не держит «Идёт установка».</summary>
    [Fact]
    public async Task Install_ClockSetBackBeforeRestart_UnconfirmedInstallIsReleased()
    {
        await InstallingAsync();
        var clock = new ShiftedTimeProvider(_world.Time) { Offset = -TimeSpan.FromHours(1) };

        var restarted = await StartWithClockAsync(clock);
        await TickAsync(restarted);

        Assert.Equal(UpdatePhase.Ready, Status(restarted).Phase);
        Assert.Equal("Установка не запущена или прервана.", Status(restarted).LastInstallResult);
    }

    /// <summary>Часы перевели назад в том же процессе: срок подтверждения считается по монотонным часам.</summary>
    [Fact]
    public async Task Install_ClockSetBackInSameProcess_DeadlineUsesMonotonicTime()
    {
        _world.HttpHandler = new UpdateSource(Manifest());
        var clock = new ShiftedTimeProvider(_world.Time);
        var coordinator = await StartWithClockAsync(clock);
        await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: false), CancellationToken.None);
        await TickAsync(coordinator);
        await PumpAsync(coordinator);
        var install = coordinator.HandleRequestAsync(new InstallUpdateRequest("0.9.0"), CancellationToken.None);
        await PumpAsync(coordinator, install);
        Assert.True((await install).Ok);

        clock.Offset = -TimeSpan.FromHours(1);
        _world.Time.Advance(TimeSpan.FromMinutes(6));
        await TickAsync(coordinator);

        Assert.Equal(UpdatePhase.Ready, Status(coordinator).Phase);
    }

    /// <summary>
    /// msiexec жив дольше срока установки: фаза отпускается (проверка и пропуск версии снова доступны), но вторая
    /// установка поверх живого установщика не запускается, пока он не завершится.
    /// </summary>
    [Fact]
    public async Task Install_HungInstaller_ReleasesPhaseButBlocksSecondInstaller()
    {
        var coordinator = await InstallingAsync();
        _world.RunningProcesses.Add(4243);
        await coordinator.HandleRequestAsync(new UpdateStartedRequest(4243), CancellationToken.None);
        _world.Time.Advance(TimeSpan.FromMinutes(14));
        await TickAsync(coordinator);
        Assert.Equal(UpdatePhase.Installing, Status(coordinator).Phase);

        _world.Time.Advance(TimeSpan.FromMinutes(2));
        await TickAsync(coordinator);

        Assert.Equal(UpdatePhase.Failed, Status(coordinator).Phase);
        Assert.Contains("дольше 15 минут", Status(coordinator).LastInstallResult, StringComparison.Ordinal);
        var blocked = coordinator.HandleRequestAsync(new InstallUpdateRequest("0.9.0"), CancellationToken.None);
        await PumpAsync(coordinator, blocked);
        Assert.Equal(IpcErrorCodes.Busy, (await blocked).ErrorCode);
        Assert.Contains("Прежний установщик", (await blocked).ErrorMessage, StringComparison.Ordinal);

        _world.RunningProcesses.Remove(4243);
        var retry = coordinator.HandleRequestAsync(new InstallUpdateRequest("0.9.0"), CancellationToken.None);
        await PumpAsync(coordinator, retry);
        Assert.True((await retry).Ok);
        Assert.Equal(UpdatePhase.Installing, Status(coordinator).Phase);
    }

    /// <summary>Номер установщика известен, его ожидание не кончилось, а процесса уже нет: после срока — неудача, а не вечная установка.</summary>
    [Fact]
    public async Task Install_KnownInstallerGoneAfterDeadline_IsFailure()
    {
        var coordinator = await InstallingAsync();
        _world.RunningProcesses.Add(4244);
        await coordinator.HandleRequestAsync(new UpdateStartedRequest(4244), CancellationToken.None);
        _world.RunningProcesses.Remove(4244);
        _world.Time.Advance(TimeSpan.FromMinutes(16));

        await TickAsync(coordinator);

        Assert.Equal(UpdatePhase.Failed, Status(coordinator).Phase);
        Assert.Contains("не установилось", Status(coordinator).LastInstallResult, StringComparison.Ordinal);
    }

    /// <summary>Установщик отдаёт первые байты и ждёт; отмена загрузки прерывает ожидание.</summary>
    private sealed class GatedStream(byte[] data, int first, Task gate) : Stream
    {
        private int _position;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => _position; set => throw new NotSupportedException(); }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_position >= data.Length)
            {
                return 0;
            }

            if (_position >= first)
            {
                try
                {
                    await gate.WaitAsync(cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    // Как у настоящего сокета: отмена доходит до загрузки не синхронно внутри Cancel(), и файл ещё
                    // открыт, когда «Пропустить версию» убирает каталог.
                    await Task.Delay(100, CancellationToken.None);
                    throw;
                }
            }

            var count = Math.Min(buffer.Length, (_position < first ? first : data.Length) - _position);
            data.AsMemory(_position, count).CopyTo(buffer);
            _position += count;
            return count;
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private static UpdateSource GatedSource(Task gate) => new(Manifest())
    {
        Override = request => request.RequestUri!.AbsoluteUri.EndsWith(".msi", StringComparison.Ordinal)
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new GatedStream(Package, 1024, gate)) }
            : null,
    };

    /// <summary>Подталкивает очередь, пока загрузка не дойдёт до первых байт.</summary>
    private static async Task WaitDownloadingAsync(Coordinator coordinator)
    {
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (!(Status(coordinator) is { Phase: UpdatePhase.Downloading, DownloadedBytes: 1024 }))
        {
            Assert.True(DateTime.UtcNow < deadline, "Загрузка не началась.");
            await coordinator.DrainAsync();
            await Task.Delay(5);
        }
    }

    private static Task<IpcResponse> SaveAppUpdateAsync(Coordinator coordinator, Func<AppUpdateSettings, AppUpdateSettings> change) =>
        coordinator.HandleRequestAsync(new SaveSettingsRequest(coordinator.Settings with { AppUpdate = change(coordinator.Settings.AppUpdate) }), CancellationToken.None);

    private string PartialPackage => Path.Combine(_world.Paths.Update, "SplitVpn-0.9.0.msi.part");

    /// <summary>Автозагрузку выключили в настройках: идущая автоматическая загрузка останавливается, недокачанное остаётся.</summary>
    [Fact]
    public async Task Settings_AutoDownloadTurnedOff_StopsAutomaticDownloadKeepingPartial()
    {
        var gate = new TaskCompletionSource();
        var coordinator = await UpdatingAsync(GatedSource(gate.Task));
        await TickAsync(coordinator);
        await WaitDownloadingAsync(coordinator);

        Assert.True((await SaveAppUpdateAsync(coordinator, s => s with { AutoDownload = false })).Ok);
        await TickAsync(coordinator);
        await PumpAsync(coordinator);

        Assert.Equal(UpdatePhase.Available, Status(coordinator).Phase);
        Assert.Contains("остановлена", Status(coordinator).LastResult, StringComparison.Ordinal);
        Assert.Equal(1024, new FileInfo(PartialPackage).Length);
        gate.SetResult();
    }

    /// <summary>Загрузку по кнопке «Скачать» выключение автопроверки и автозагрузки не останавливает.</summary>
    [Fact]
    public async Task Settings_AutoUpdateTurnedOff_DoesNotStopUserDownload()
    {
        new ServiceStores(_world.Paths).SaveSettings(Settings() with { AppUpdate = new AppUpdateSettings { AutoDownload = false } });
        var gate = new TaskCompletionSource();
        var coordinator = await UpdatingAsync(GatedSource(gate.Task));
        await TickAsync(coordinator);
        await PumpAsync(coordinator);
        Assert.Equal(UpdatePhase.Available, Status(coordinator).Phase);
        var download = coordinator.HandleRequestAsync(new DownloadUpdateRequest("0.9.0"), CancellationToken.None);
        await WaitDownloadingAsync(coordinator);

        Assert.True((await SaveAppUpdateAsync(coordinator, s => s with { AutoCheck = false })).Ok);
        await TickAsync(coordinator);
        Assert.Equal(UpdatePhase.Downloading, Status(coordinator).Phase);

        gate.SetResult();
        await PumpAsync(coordinator, download);
        Assert.Equal(UpdatePhase.Ready, Status(coordinator).Phase);
    }

    /// <summary>Версию пропустили посреди загрузки: недокачанный файл, открытый загрузкой, убирается сразу после её отмены.</summary>
    [Fact]
    public async Task Skip_DuringDownload_RemovesPartialFile()
    {
        var gate = new TaskCompletionSource();
        var coordinator = await UpdatingAsync(GatedSource(gate.Task));
        await TickAsync(coordinator);
        await WaitDownloadingAsync(coordinator);

        Assert.True((await coordinator.HandleRequestAsync(new SkipUpdateRequest("0.9.0"), CancellationToken.None)).Ok);
        await PumpAsync(coordinator);

        Assert.Equal(UpdatePhase.Idle, Status(coordinator).Phase);
        Assert.False(File.Exists(PartialPackage));
        Assert.Empty(Directory.GetFiles(_world.Paths.Update, "*.msi*"));
        gate.SetResult();
    }
}
