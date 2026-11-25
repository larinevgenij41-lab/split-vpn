using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace SplitVpn.App.Views;

/// <summary>
/// Передача колёсика мыши наружу. ScrollViewer забирает колёсико всегда, даже когда прокручивать ему
/// некуда: список правил в папке не отдавал бы прокрутку колонке, а колонка - странице, и указатель над
/// коротким списком «запирал» бы прокрутку.
/// Решение принимается в PreviewMouseWheel по состоянию до прокрутки (VerticalOffset после прокрутки
/// обновляется только раскладкой): список, который может сдвинуться в эту сторону, прокручивается сам и
/// наружу событие не отдаёт; список на краю помечает событие обработанным и передаёт щелчок ближайшему
/// внешнему списку, которому есть куда прокручиваться. Один щелчок двигает ровно один список.
/// </summary>
public static class WheelChain
{
    public static readonly DependencyProperty IsEnabledProperty = DependencyProperty.RegisterAttached(
        "IsEnabled", typeof(bool), typeof(WheelChain), new PropertyMetadata(false, OnIsEnabledChanged));

    /// <summary>
    /// То же для списка с готовым шаблоном (ui:ListView): включается у первого ScrollViewer внутри шаблона,
    /// выделение и клавиатурная навигация списка не меняются.
    /// </summary>
    public static readonly DependencyProperty IsEnabledInsideProperty = DependencyProperty.RegisterAttached(
        "IsEnabledInside", typeof(bool), typeof(WheelChain), new PropertyMetadata(false, OnIsEnabledInsideChanged));

    public static bool GetIsEnabledInside(DependencyObject element)
    {
        ArgumentNullException.ThrowIfNull(element);
        return (bool)element.GetValue(IsEnabledInsideProperty);
    }

    public static void SetIsEnabledInside(DependencyObject element, bool value)
    {
        ArgumentNullException.ThrowIfNull(element);
        element.SetValue(IsEnabledInsideProperty, value);
    }

    private static void OnIsEnabledInsideChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not FrameworkElement element)
        {
            return;
        }

        element.Loaded -= OnHostLoaded;
        if ((bool)e.NewValue)
        {
            element.Loaded += OnHostLoaded;
            if (element.IsLoaded)
            {
                OnHostLoaded(element, null!);
            }
        }
    }

    private static void OnHostLoaded(object sender, RoutedEventArgs e)
    {
        var element = (FrameworkElement)sender;
        element.ApplyTemplate();
        if (FindScrollViewer(element) is { } viewer)
        {
            SetIsEnabled(viewer, GetIsEnabledInside(element));
        }
    }

    private static ScrollViewer? FindScrollViewer(DependencyObject root)
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            if (child is ScrollViewer viewer)
            {
                return viewer;
            }

            if (FindScrollViewer(child) is { } nested)
            {
                return nested;
            }
        }

        return null;
    }

    public static bool GetIsEnabled(DependencyObject element)
    {
        ArgumentNullException.ThrowIfNull(element);
        return (bool)element.GetValue(IsEnabledProperty);
    }

    public static void SetIsEnabled(DependencyObject element, bool value)
    {
        ArgumentNullException.ThrowIfNull(element);
        element.SetValue(IsEnabledProperty, value);
    }

    private static void OnIsEnabledChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not ScrollViewer viewer)
        {
            return;
        }

        viewer.PreviewMouseWheel -= OnPreviewMouseWheel;
        if ((bool)e.NewValue)
        {
            viewer.PreviewMouseWheel += OnPreviewMouseWheel;
        }
    }

    private static void OnPreviewMouseWheel(object sender, MouseWheelEventArgs e)
    {
        if (e.Handled || sender is not ScrollViewer viewer)
        {
            return;
        }

        // Preview идёт сверху вниз: внешний список узнаёт о щелчке раньше вложенного. Если ближе к указателю
        // есть другой список с WheelChain или список, которому есть куда сдвинуться, решает он.
        var innerSwallows = false;
        for (var node = e.OriginalSource as DependencyObject; node is not null && !ReferenceEquals(node, viewer); node = Parent(node))
        {
            if (node is ScrollViewer inner)
            {
                if (GetIsEnabled(inner) || !ShouldForward(inner.VerticalOffset, inner.ScrollableHeight, e.Delta))
                {
                    return;
                }

                // Вложенный список (поле ввода, список без WheelChain) прокрутиться не может, но событие заберёт.
                innerSwallows = true;
            }
        }

        if (!ShouldForward(viewer.VerticalOffset, viewer.ScrollableHeight, e.Delta))
        {
            if (innerSwallows)
            {
                e.Handled = true;
                Scroll(viewer, e);
            }

            return;
        }

        e.Handled = true;
        for (var node = Parent(viewer); node is not null; node = Parent(node))
        {
            if (node is ScrollViewer outer && !ShouldForward(outer.VerticalOffset, outer.ScrollableHeight, e.Delta))
            {
                Scroll(outer, e);
                return;
            }
        }
    }

    /// <summary>Щелчок колёсика доставляется списку напрямую: его собственный обработчик прокручивает его.</summary>
    private static void Scroll(ScrollViewer target, MouseWheelEventArgs e) =>
        target.RaiseEvent(new MouseWheelEventArgs(e.MouseDevice, e.Timestamp, e.Delta) { RoutedEvent = UIElement.MouseWheelEvent, Source = target });

    private static DependencyObject? Parent(DependencyObject node) =>
        node is Visual or System.Windows.Media.Media3D.Visual3D ? VisualTreeHelper.GetParent(node) : LogicalTreeHelper.GetParent(node);

    /// <summary>
    /// Список не сдвинется от щелчка в эту сторону (по состоянию до прокрутки): прокручивать нечего, вверх — уже в
    /// начале, вниз — уже в конце. Delta &gt; 0 — колёсико от себя (вверх).
    /// </summary>
    internal static bool ShouldForward(double verticalOffset, double scrollableHeight, int delta) =>
        scrollableHeight <= 0
        || (delta > 0 && verticalOffset <= 0)
        || (delta < 0 && verticalOffset >= scrollableHeight - 0.5);
}
