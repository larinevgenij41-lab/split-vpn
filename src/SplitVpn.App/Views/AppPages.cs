using System.Windows;
using System.Windows.Controls;
using SplitVpn.App.ViewModels;
using Wpf.Ui.Abstractions;

namespace SplitVpn.App.Views;

/// <summary>Страница NavigationView: содержимое — модель страницы, отрисованная шаблоном данных из Pages.xaml.</summary>
public class VmPage : Page
{
    protected VmPage(PageViewModel viewModel)
    {
        ViewModel = viewModel;
        DataContext = viewModel;
        // Прокрутку даёт сам NavigationView; вторая ScrollViewer внутри страницы перехватывала бы колёсико мыши.
        Content = new Border
        {
            Padding = new Thickness(28, 12, 28, 24),
            Child = new ContentControl { Content = viewModel, Focusable = false },
        };
    }

    public PageViewModel ViewModel { get; }
}

public sealed class HomePage(MainViewModel main) : VmPage(main.Home);

public sealed class ConnectionsPage(MainViewModel main) : VmPage(main.Connections);

public sealed class RoutingPage(MainViewModel main) : VmPage(main.Routing);

public sealed class CheckAddressPage(MainViewModel main) : VmPage(main.CheckAddress);

public sealed class ProtectionPage(MainViewModel main) : VmPage(main.Protection);

public sealed class SettingsPage(MainViewModel main) : VmPage(main.Settings);

public sealed class DiagnosticsPage(MainViewModel main) : VmPage(main.Diagnostics);

public sealed class AboutPage(MainViewModel main) : VmPage(main.About);

/// <summary>Одна страница на тип, живёт всё время работы окна (состояние ввода сохраняется при переходах).</summary>
public sealed class PageProvider(MainViewModel main) : INavigationViewPageProvider
{
    private readonly Dictionary<Type, VmPage> _pages = [];

    public static readonly IReadOnlyDictionary<Type, Func<MainViewModel, VmPage>> Factories = new Dictionary<Type, Func<MainViewModel, VmPage>>
    {
        [typeof(HomePage)] = m => new HomePage(m),
        [typeof(ConnectionsPage)] = m => new ConnectionsPage(m),
        [typeof(RoutingPage)] = m => new RoutingPage(m),
        [typeof(CheckAddressPage)] = m => new CheckAddressPage(m),
        [typeof(ProtectionPage)] = m => new ProtectionPage(m),
        [typeof(SettingsPage)] = m => new SettingsPage(m),
        [typeof(DiagnosticsPage)] = m => new DiagnosticsPage(m),
        [typeof(AboutPage)] = m => new AboutPage(m),
    };

    public object? GetPage(Type pageType)
    {
        if (!_pages.TryGetValue(pageType, out var page))
        {
            _pages[pageType] = page = Factories[pageType](main);
        }

        return page;
    }

    /// <summary>Тип страницы для модели — для навигации по команде из модели (предупреждения, мастер).</summary>
    public Type? PageTypeFor(PageViewModel viewModel) =>
        _pages.FirstOrDefault(p => p.Value.ViewModel == viewModel).Key
        ?? Factories.Keys.FirstOrDefault(t => GetPage(t) is VmPage p && p.ViewModel == viewModel);
}
