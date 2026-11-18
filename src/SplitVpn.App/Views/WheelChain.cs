using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace SplitVpn.App.Views;

/// <summary>
/// Передача колёсика мыши наружу. ScrollViewer забирает колёсико всегда, даже когда прокручивать ему
/// некуда: список правил в папке не отдавал бы прокрутку колонке, а колонка - странице, и указатель над
/// коротким списком «запирал» бы прокрутку. Список, который не сдвинулся, передаёт событие родителю.
/// </summary>
public static class WheelChain
{
    public static readonly DependencyProperty IsEnabledProperty = DependencyProperty.RegisterAttached(
        "IsEnabled", typeof(bool), typeof(WheelChain), new PropertyMetadata(false, OnIsEnabledChanged));

    private static readonly DependencyProperty OffsetBeforeProperty = DependencyProperty.RegisterAttached(
        "OffsetBefore", typeof(double), typeof(WheelChain), new PropertyMetadata(0d));

    /// <summary>
    /// Один щелчок колёсика доходит до внешнего списка дважды: пересланной копией и исходным событием.
    /// Каждый список решает о щелчке один раз, а после того как кто-то из них сдвинулся, щелчок исчерпан.
    /// Все события одного щелчка несут одну отметку времени. Обращения - только из потока интерфейса.
    /// </summary>
    private static int _tick;
    private static bool _consumed;
    private static readonly List<ScrollViewer> Decided = [];

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
        viewer.RemoveHandler(UIElement.MouseWheelEvent, (MouseWheelEventHandler)OnMouseWheel);
        if ((bool)e.NewValue)
        {
            viewer.PreviewMouseWheel += OnPreviewMouseWheel;
            // Свой обработчик ScrollViewer помечает событие обработанным: слушать нужно и такие.
            viewer.AddHandler(UIElement.MouseWheelEvent, (MouseWheelEventHandler)OnMouseWheel, handledEventsToo: true);
        }
    }

    private static void OnPreviewMouseWheel(object sender, MouseWheelEventArgs e)
    {
        if (sender is ScrollViewer viewer)
        {
            viewer.SetValue(OffsetBeforeProperty, viewer.VerticalOffset);
        }
    }

    private static void OnMouseWheel(object sender, MouseWheelEventArgs e)
    {
        if (sender is not ScrollViewer viewer)
        {
            return;
        }

        if (e.Timestamp != _tick)
        {
            _tick = e.Timestamp;
            _consumed = false;
            Decided.Clear();
        }

        if (_consumed || Decided.Contains(viewer))
        {
            return;
        }

        Decided.Add(viewer);
        if (!ShouldForward((double)viewer.GetValue(OffsetBeforeProperty), viewer.VerticalOffset))
        {
            _consumed = true;
            return;
        }

        if (VisualTreeHelper.GetParent(viewer) is UIElement parent)
        {
            e.Handled = true;
            parent.RaiseEvent(new MouseWheelEventArgs(e.MouseDevice, e.Timestamp, e.Delta) { RoutedEvent = UIElement.MouseWheelEvent, Source = viewer });
        }
    }

    /// <summary>Список не сдвинулся: он на краю или ему нечего прокручивать.</summary>
    internal static bool ShouldForward(double offsetBefore, double offsetAfter) => Math.Abs(offsetAfter - offsetBefore) < 0.01;
}
