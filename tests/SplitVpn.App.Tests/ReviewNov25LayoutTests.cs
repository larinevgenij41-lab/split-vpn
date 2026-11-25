using System.Windows;
using System.Windows.Threading;
using SplitVpn.App.Services;
using SplitVpn.App.ViewModels;
using SplitVpn.App.Views;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;

namespace SplitVpn.App.Tests;

/// <summary>Ревью вёрстки 25.11: поиск по доске, размер окон, передача колёсика мыши.</summary>
public sealed class ReviewNov25LayoutTests
{
    // ---------- L-1: поиск по доске ----------

    [Fact]
    public Task SearchShowsFirst200AndFlagsMore() => RunStaAsync(async () =>
    {
        var store = new FakeService
        {
            Settings = new AppSettings
            {
                DomainRules = [.. Enumerable.Range(0, 900).Select(i => new DomainRuleSetting { Suffix = $"host{i}.example.ru", Target = RouteTarget.Direct })],
            },
        };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Routing;
        await page.OnOpenedAsync();

        page.Search = ".ru";

        Assert.Equal(RoutingViewModel.SearchLimit, page.SearchResults.Count);
        Assert.Equal(200, page.SearchResults.Count);
        Assert.True(page.SearchHasMore);
        Assert.Equal("Показаны первые 200 — уточните запрос", RoutingViewModel.SearchLimitText);

        // Уточнённый запрос укладывается в предел: отметка «есть ещё» снимается.
        page.Search = "host899.";
        var found = Assert.Single(page.SearchResults);
        Assert.Equal("host899.example.ru", found.Entry!.Title);
        Assert.False(page.SearchHasMore);

        page.Search = "";
        Assert.Empty(page.SearchResults);
        Assert.False(page.SearchHasMore);
    });

    [Fact]
    public Task SearchResultsSurviveEditsInPlace() => RunStaAsync(async () =>
    {
        var tunnel = new ConnectionProfile { Name = "Основное", Server = "vpn.example", UserName = "user", Role = ProfileRole.Primary };
        var store = new FakeService
        {
            Settings = new AppSettings
            {
                Profiles = [tunnel],
                DomainRules = [.. Enumerable.Range(0, 5).Select(i => new DomainRuleSetting { Suffix = $"site{i}.example.org", Target = RouteTarget.Direct })],
            },
        };
        using var service = new ServiceConnection(store.SendAsync);
        using var main = new MainViewModel(service, new UiPreferences());
        var page = main.Routing;
        await page.OnOpenedAsync();
        page.Search = "example.org";
        var before = page.SearchResults.ToList();
        Assert.Equal(5, before.Count);
        var resets = 0;
        page.SearchResults.CollectionChanged += (_, e) => { if (e.Action == System.Collections.Specialized.NotifyCollectionChangedAction.Reset) { resets++; } };

        // Отметка правки (смена приоритета, переименование группы) не пересоздаёт строки.
        page.MarkDirty();
        Assert.Equal(before, page.SearchResults);

        // Перенос найденной карточки: та же строка (переезжает за карточки «Напрямую»), меняется только подпись «где».
        var card = (BoardCard)before[2].Entry!;
        page.Move(card, page.Columns.Single(c => c.Target == RouteTarget.Tunnel(tunnel.Id)));
        Assert.Equal(new[] { before[0], before[1], before[3], before[4], before[2] }, page.SearchResults);
        Assert.Equal("Основное", before[2].Location);

        // Удалённая карточка уходит из результатов, остальные строки — прежние объекты.
        page.Remove((BoardCard)before[0].Entry!);
        Assert.Equal(new[] { before[1], before[3], before[4], before[2] }, page.SearchResults);
        Assert.Equal(0, resets);
    });

    // ---------- L-2: окна не больше рабочей области ----------

    [Fact]
    public void SignInWindowFitsSmallWorkArea()
    {
        var fit = WindowFit.Fit(new Rect(0, 0, 1280, 688), 920, 780, 480, 400, left: 180, top: -46);

        Assert.True(fit.Height <= 672, $"Высота {fit.Height}");
        Assert.Equal(920, fit.Width);
        Assert.True(fit.Top >= 0, $"Top {fit.Top}");
        Assert.True(fit.Top + fit.Height <= 688);
        Assert.Equal(400, fit.MinHeight);
    }

    [Fact]
    public void MinimumSizeNeverExceedsWorkArea()
    {
        // 1366×768 при 150 %: рабочая область около 910×480 единиц WPF.
        var fit = WindowFit.Fit(new Rect(0, 0, 910, 480), 1080, 740, 640, 520);

        Assert.True(fit.Width <= 910 - WindowFit.Gap);
        Assert.True(fit.Height <= 480 - WindowFit.Gap);
        Assert.True(fit.MinHeight <= fit.Height);
        Assert.Equal(640, fit.MinWidth);
        Assert.Null(fit.Left);
        Assert.Null(fit.Top);
    }

    [Fact]
    public void WindowOnSecondMonitorStaysOnIt()
    {
        // Второй монитор слева от основного; окно вылезло за его нижний и правый край.
        var fit = WindowFit.Fit(new Rect(-1920, 0, 1920, 1040), 800, 600, 0, 0, left: -1000, top: 700);

        Assert.Equal(-1000, fit.Left);
        Assert.Equal(440, fit.Top);
    }

    [Fact]
    public void SizeToContentHeightIsLeftToWindow()
    {
        var fit = WindowFit.Fit(new Rect(0, 0, 1280, 688), 440, double.NaN, 0, 0);

        Assert.True(double.IsNaN(fit.Height));
        Assert.Equal(440, fit.Width);
    }

    // ---------- L-3: колёсико мыши ----------

    [Theory]
    [InlineData(0, 0, 120, true)]        // прокручивать нечего
    [InlineData(0, 0, -120, true)]
    [InlineData(0, 300, 120, true)]      // в начале, колёсико вверх
    [InlineData(0, 300, -120, false)]    // в начале, вниз — прокрутит сам
    [InlineData(150, 300, 120, false)]   // в середине — прокрутит сам в обе стороны
    [InlineData(150, 300, -120, false)]
    [InlineData(300, 300, -120, true)]   // в конце, вниз
    [InlineData(299.7, 300, -120, true)] // в конце с дробным остатком раскладки
    [InlineData(300, 300, 120, false)]   // в конце, вверх — прокрутит сам
    public void WheelGoesOutwardOnlyAtEdge(double offset, double scrollable, int delta, bool forward) =>
        Assert.Equal(forward, WheelChain.ShouldForward(offset, scrollable, delta));

    // ---------- Вспомогательное ----------

    /// <summary>Подставная служба: настройки в памяти.</summary>
    private sealed class FakeService
    {
        public AppSettings Settings { get; set; } = new();

        public Task<IpcResponse> SendAsync(IpcRequest request, CancellationToken cancellationToken) => Task.FromResult(request switch
        {
            GetSettingsRequest => IpcResponse.Success(Settings),
            GetAdaptersRequest => IpcResponse.Success(new List<AdapterDto>()),
            GetStatusRequest => IpcResponse.Success(new StatusDto()),
            GetEventsRequest => IpcResponse.Success(new List<ServiceEvent>()),
            _ => IpcResponse.Success(),
        });
    }

    private static Task RunStaAsync(Func<Task> action)
    {
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            var dispatcher = Dispatcher.CurrentDispatcher;
            SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(dispatcher));
            dispatcher.BeginInvoke(new Action(async () =>
            {
                try { await action(); completion.TrySetResult(); }
                catch (Exception ex) { completion.TrySetException(ex); }
                finally { dispatcher.BeginInvokeShutdown(DispatcherPriority.Background); }
            }));
            Dispatcher.Run();
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        return completion.Task.WaitAsync(TimeSpan.FromSeconds(15), TestContext.Current.CancellationToken);
    }
}
