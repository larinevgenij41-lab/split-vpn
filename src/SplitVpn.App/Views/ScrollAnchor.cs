using System.Collections.Specialized;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace SplitVpn.App.Views;

/// <summary>
/// Список, в начало которого добавляются строки (журнал событий): если пользователь прокрутил его вниз и читает,
/// прокрутка сдвигается на число строк, вставленных выше видимой части, и читаемая строка остаётся на месте.
/// Список, открытый в самом начале, так и показывает новые события сверху. Рассчитано на прокрутку по строкам
/// (CanContentScroll у VirtualizingStackPanel): смещение прокрутки — номер первой видимой строки.
/// </summary>
public static class ScrollAnchor
{
    public static readonly DependencyProperty KeepOnInsertProperty = DependencyProperty.RegisterAttached(
        "KeepOnInsert", typeof(bool), typeof(ScrollAnchor), new PropertyMetadata(false, OnChanged));

    /// <summary>Смещение, заказанное, но ещё не применённое раскладкой: несколько вставок подряд складываются.</summary>
    private static readonly DependencyProperty PendingOffsetProperty = DependencyProperty.RegisterAttached(
        "PendingOffset", typeof(double), typeof(ScrollAnchor), new PropertyMetadata(double.NaN));

    public static bool GetKeepOnInsert(DependencyObject element) => (bool)element.GetValue(KeepOnInsertProperty);

    public static void SetKeepOnInsert(DependencyObject element, bool value) => element.SetValue(KeepOnInsertProperty, value);

    private static void OnChanged(DependencyObject element, DependencyPropertyChangedEventArgs e)
    {
        if (element is ItemsControl list && e.NewValue is true && e.OldValue is not true)
        {
            // Ссылка только от списка к обработчику: отписка при выгрузке не нужна.
            ((INotifyCollectionChanged)list.Items).CollectionChanged += (_, args) => OnItemsChanged(list, args);
        }
    }

    private static void OnItemsChanged(ItemsControl list, NotifyCollectionChangedEventArgs args)
    {
        if (args.Action != NotifyCollectionChangedAction.Add || args.NewItems is not { Count: > 0 } added
            || FindScrollViewer(list) is not { } viewer)
        {
            return;
        }

        var pending = (double)viewer.GetValue(PendingOffsetProperty);
        var offset = double.IsNaN(pending) ? viewer.VerticalOffset : pending;
        if (offset <= 0 || args.NewStartingIndex > offset)
        {
            // Список в самом начале — новые строки видны сверху; вставка ниже видимой части ничего не сдвигает.
            return;
        }

        offset += added.Count;
        viewer.SetValue(PendingOffsetProperty, offset);
        viewer.ScrollToVerticalOffset(offset);
        viewer.Dispatcher.BeginInvoke(DispatcherPriority.Loaded, () => viewer.ClearValue(PendingOffsetProperty));
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
}
