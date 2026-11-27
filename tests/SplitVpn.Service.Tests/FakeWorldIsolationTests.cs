using System.Net;
using System.Net.Sockets;
using SplitVpn.Core.Ipc;
using SplitVpn.Service.Coordination;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Мир фейков не выходит в сеть: прежде без своего обработчика HTTP координатор в тестах ходил на GitHub и jsDelivr
/// и мог скачать настоящий установщик (75 МБ) в %TEMP% - проверка подписи в мире фейков принимает всё.
/// </summary>
public sealed class FakeWorldIsolationTests : IDisposable
{
    private readonly FakeWorld _world = new();

    public void Dispose() => _world.Dispose();

    [Fact]
    public async Task DefaultHttp_NeverOpensConnection()
    {
        // Слушатель на loopback: настоящий HttpClient соединился бы с ним; обработчик мира фейков - нет.
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var url = $"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/manifest.json";
            using var http = _world.Dependencies().Http;

            using var response = await http.GetAsync(url, TestContext.Current.CancellationToken);

            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            Assert.Equal(1, _world.OfflineRequests);
            Assert.False(listener.Pending(), "обработчик по умолчанию открыл соединение");
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public void DefaultSettings_HaveScheduledFetchesOff()
    {
        var settings = _world.Dependencies().Stores.LoadSettings(out var error);

        Assert.Null(error);
        Assert.False(settings.AppUpdate.AutoCheck);
        Assert.False(settings.GeoUpdate.AutoUpdate);
        Assert.False(settings.BypassUpdate.AutoUpdate);
    }

    [Fact]
    public void OptIn_KeepsProductDefaults()
    {
        _world.ScheduledFetches = true;

        var settings = _world.Dependencies().Stores.LoadSettings(out _);

        Assert.True(settings.AppUpdate.AutoCheck);
        Assert.True(settings.GeoUpdate.AutoUpdate);
        Assert.True(settings.BypassUpdate.AutoUpdate);
    }

    /// <summary>Явная проверка обновлений в мире по умолчанию доходит только до обработчика «без сети».</summary>
    [Fact]
    public async Task UpdateCheck_InDefaultWorld_StaysOffline()
    {
        var coordinator = new Coordinator(_world.Dependencies());
        await coordinator.StartupAsync(TestContext.Current.CancellationToken);

        var check = coordinator.HandleRequestAsync(new CheckUpdateRequest(), CancellationToken.None);
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (!(check.IsCompleted && coordinator.UpdateWork.IsCompleted) && DateTime.UtcNow < deadline)
        {
            await coordinator.DrainAsync();
            await Task.Delay(5, TestContext.Current.CancellationToken);
        }

        Assert.True(check.IsCompleted, "проверка обновлений не завершилась");
        Assert.False((await check).Ok);
        Assert.True(_world.OfflineRequests > 0);
        Assert.False(Directory.Exists(_world.Paths.Update) && Directory.GetFiles(_world.Paths.Update, "*.msi", SearchOption.AllDirectories).Length > 0);
    }
}
