using System.ComponentModel;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using SplitVpn.App.Services;
using SplitVpn.App.ViewModels;
using Wpf.Ui.Controls;

namespace SplitVpn.App.Views;

public partial class MainWindow : FluentWindow
{
    /// <summary>Уже этой ширины меню сворачивается до значков, чтобы содержимому страниц хватало места.</summary>
    private const double CompactPaneWidth = 920;

    private PageProvider? _pages;
    private bool? _wasNarrow;

    public MainWindow()
    {
        InitializeComponent();
        DataContextChanged += (_, _) => Attach();
        Loaded += (_, _) =>
        {
            if (DataContext is MainViewModel main)
            {
                ThemeService.Watch(this, main.Preferences.Theme);
                Navigation.Navigate(typeof(HomePage));
            }

            NameUnlabeledButtons(this);
        };
        SizeChanged += (_, _) =>
        {
            AdaptPane();
            NameUnlabeledButtons(this);
        };
        Navigation.Navigated += (_, e) =>
        {
            if (e.Page is VmPage page && DataContext is MainViewModel main && main.CurrentPage != page.ViewModel)
            {
                main.CurrentPage = page.ViewModel;
            }

            Dispatcher.BeginInvoke(DispatcherPriority.Loaded, () => NameUnlabeledButtons(this));
        };
    }

    /// <summary>Закрытие окна прячет его в трей; выход — из меню трея.</summary>
    public bool AllowClose { get; set; }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (!AllowClose)
        {
            e.Cancel = true;
            Hide();
            (DataContext as MainViewModel)?.OnHiddenToTray();
        }

        base.OnClosing(e);
    }

    private void Attach()
    {
        if (DataContext is not MainViewModel main)
        {
            return;
        }

        main.IsWindowVisible = IsVisible;
        IsVisibleChanged += (_, _) => main.IsWindowVisible = IsVisible;
        main.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(MainViewModel.Wizard))
            {
                OnWizardChanged(main.Wizard is not null);
            }
        };
        _pages = new PageProvider(main);
        Navigation.SetPageProviderService(_pages);
        main.NavigationRequested += page =>
        {
            if (_pages.PageTypeFor(page) is { } type)
            {
                Navigation.Navigate(type);
            }
        };
    }

    /// <summary>
    /// Мастер поверх окна — модальный: меню и страницы под ним недоступны с клавиатуры, фокус переходит
    /// в мастер, а после закрытия возвращается к меню.
    /// </summary>
    private void OnWizardChanged(bool shown)
    {
        Navigation.IsEnabled = !shown;
        Dispatcher.BeginInvoke(DispatcherPriority.Loaded, () =>
        {
            var target = shown ? (UIElement)WizardHost : Navigation;
            target.MoveFocus(new TraversalRequest(FocusNavigationDirection.First));
        });
    }

    /// <summary>В узком окне меню сворачивается до значков; при расширении раскрывается снова (только при переходе через порог).</summary>
    private void AdaptPane()
    {
        var narrow = ActualWidth < CompactPaneWidth;
        if (_wasNarrow == narrow)
        {
            return;
        }

        _wasNarrow = narrow;
        Navigation.IsPaneOpen = !narrow;
    }

    /// <summary>
    /// Кнопки из шаблонов WPF-UI (заголовок окна, прокрутка) без имени озвучиваются названием значка
    /// («CaretUp24») или никак: даём им понятные имена.
    /// </summary>
    internal static void NameUnlabeledButtons(DependencyObject root)
    {
        var stack = new Stack<DependencyObject>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var current = stack.Pop();
            if (current is ButtonBase button && button.ReadLocalValue(AutomationProperties.NameProperty) == DependencyProperty.UnsetValue
                && NameFor(button) is { } name)
            {
                AutomationProperties.SetName(button, name);
            }

            for (var i = 0; i < VisualTreeHelper.GetChildrenCount(current); i++)
            {
                stack.Push(VisualTreeHelper.GetChild(current, i));
            }
        }
    }

    private static string? NameFor(ButtonBase button) => button switch
    {
        TitleBarButton { ButtonType: TitleBarButtonType.Minimize } => "Свернуть",
        TitleBarButton { ButtonType: TitleBarButtonType.Maximize } => "Развернуть",
        TitleBarButton { ButtonType: TitleBarButtonType.Restore } => "Восстановить размер",
        TitleBarButton { ButtonType: TitleBarButtonType.Close } => "Закрыть в трей",
        TitleBarButton { ButtonType: TitleBarButtonType.Help } => "Справка",
        _ when button.Name == "PART_ToggleButton" => "Показать или скрыть меню",
        _ when button.Command == ScrollBar.LineUpCommand => "Прокрутить вверх",
        _ when button.Command == ScrollBar.LineDownCommand => "Прокрутить вниз",
        _ when button.Command == ScrollBar.LineLeftCommand => "Прокрутить влево",
        _ when button.Command == ScrollBar.LineRightCommand => "Прокрутить вправо",
        _ when button.Content is not string && button.ToolTip is string tip && tip.Length > 0 => tip,
        _ => null,
    };
}
