using System.Net;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;
using SplitVpn.Core.Update;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Общий срок попытки загрузки установщика: медленная, но живая загрузка с докачкой продолжается со скачанного места.
/// Срок сам по себе не ошибка; загрузка, начатая пользователем, продолжается сразу, без расписания и автозагрузки.
/// </summary>
public sealed partial class CoordinatorTests
{
    /// <summary>Медленный источник установщика с докачкой: отвечает на диапазон частью (206), без диапазона - целиком с Accept-Ranges.</summary>
    private void SlowResumablePackage(UpdateSource source)
    {
        source.Override = request =>
        {
            if (!request.RequestUri!.AbsoluteUri.EndsWith(".msi", StringComparison.Ordinal))
            {
                return null;
            }

            var from = (int)(request.Headers.Range?.Ranges.First().From ?? 0);
            var response = new HttpResponseMessage(from > 0 ? HttpStatusCode.PartialContent : HttpStatusCode.OK)
            {
                Content = new StreamContent(new TrickleStream(Package[from..], chunk: 512, delay: TimeSpan.FromMilliseconds(40))),
            };
            response.Headers.AcceptRanges.Add("bytes");
            if (from > 0)
            {
                response.Content.Headers.ContentRange = new System.Net.Http.Headers.ContentRangeHeaderValue(from, Package.Length - 1, Package.Length);
            }

            return response;
        };
        _world.UpdateAttemptTimeout = TimeSpan.FromMilliseconds(150);
    }

    /// <summary>
    /// Автозагрузка выключена, пользователь нажал «Скачать»: попытка упирается в срок, но загрузка продолжается докачкой
    /// сразу (продолжения по расписанию без автозагрузки нет) и доходит до конца. «Ошибки» в журнале нет.
    /// </summary>
    [Fact]
    public async Task Download_ByUser_AttemptDeadline_ContinuesUntilReady()
    {
        new ServiceStores(_world.Paths).SaveSettings(Settings() with { AppUpdate = new AppUpdateSettings { AutoDownload = false } });
        var source = new UpdateSource(Manifest());
        SlowResumablePackage(source);
        var coordinator = await UpdatingAsync(source);
        await TickAsync(coordinator);
        await PumpAsync(coordinator);
        Assert.Equal(UpdatePhase.Available, Status(coordinator).Phase);

        var task = coordinator.HandleRequestAsync(new DownloadUpdateRequest("0.9.0"), CancellationToken.None);
        await PumpAsync(coordinator, task);

        Assert.Equal(UpdatePhase.Ready, Status(coordinator).Phase);
        Assert.True(File.Exists(Path.Combine(_world.Paths.Update, "SplitVpn-0.9.0.msi")));
        Assert.DoesNotContain(_world.Journal.Since(0), DownloadError);
    }

    /// <summary>
    /// Плановая автозагрузка упирается в срок попытки с продвижением: это не «Ошибка», а пауза, и следующая проверка по
    /// расписанию докачивает файл с того же места до конца.
    /// </summary>
    [Fact]
    public async Task Download_Scheduled_AttemptDeadline_IsPauseNotError_AndResumes()
    {
        var source = new UpdateSource(Manifest());
        SlowResumablePackage(source);
        var coordinator = await UpdatingAsync(source);

        await TickAsync(coordinator);
        await PumpAsync(coordinator);

        var paused = Status(coordinator);
        Assert.Equal(UpdatePhase.Available, paused.Phase);
        Assert.InRange(paused.DownloadedBytes, 1, Package.Length - 1);
        Assert.Contains("приостановлена", paused.LastResult, StringComparison.Ordinal);
        Assert.DoesNotContain(_world.Journal.Since(0), DownloadError);
        Assert.Contains(_world.Journal.Since(0), e => e.Level == "Сведения" && e.Text.Contains("приостановлена", StringComparison.Ordinal));

        for (var i = 0; i < 20 && Status(coordinator).Phase != UpdatePhase.Ready; i++)
        {
            _world.Time.Advance(TimeSpan.FromMinutes(11));
            await TickAsync(coordinator);
            await PumpAsync(coordinator);
        }

        Assert.Equal(UpdatePhase.Ready, Status(coordinator).Phase);
        Assert.DoesNotContain(_world.Journal.Since(0), DownloadError);
    }

    /// <summary>Запись «Ошибка» о загрузке обновления (прочие ошибки мира - списки адресов без сети - не в счёт).</summary>
    private static bool DownloadError(ServiceEvent e) =>
        e.Level == "Ошибка" && e.Text.Contains("Загрузка обновления", StringComparison.Ordinal);

    /// <summary>Тело ответа, которое отдаётся кусками с задержкой: живая, но медленная связь.</summary>
    private sealed class TrickleStream(byte[] data, int chunk, TimeSpan delay) : Stream
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

            await Task.Delay(delay, cancellationToken);
            var count = Math.Min(Math.Min(chunk, buffer.Length), data.Length - _position);
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
}
