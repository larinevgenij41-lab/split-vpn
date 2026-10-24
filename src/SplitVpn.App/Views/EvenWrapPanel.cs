using System.Windows;
using System.Windows.Controls;

namespace SplitVpn.App.Views;

/// <summary>Плитки равной ширины заполняют строку; количество колонок зависит от доступного места.</summary>
public sealed class EvenWrapPanel : Panel
{
    public static readonly DependencyProperty MinItemWidthProperty = DependencyProperty.Register(
        nameof(MinItemWidth), typeof(double), typeof(EvenWrapPanel),
        new FrameworkPropertyMetadata(240d, FrameworkPropertyMetadataOptions.AffectsMeasure));

    private const double Gap = 12;

    public double MinItemWidth
    {
        get => (double)GetValue(MinItemWidthProperty);
        set => SetValue(MinItemWidthProperty, value);
    }

    protected override Size MeasureOverride(Size availableSize)
    {
        var width = double.IsFinite(availableSize.Width) ? availableSize.Width : MinItemWidth;
        return Layout(width, arrange: false);
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        Layout(finalSize.Width, arrange: true);
        return finalSize;
    }

    private Size Layout(double width, bool arrange)
    {
        var children = InternalChildren.Cast<UIElement>().Where(c => c.Visibility != Visibility.Collapsed).ToArray();
        var columns = Math.Max(1, (int)Math.Floor((width + Gap) / (Math.Max(1, MinItemWidth) + Gap)));
        var itemWidth = Math.Max(0, (width - (columns - 1) * Gap) / columns);
        double top = 0;
        for (var start = 0; start < children.Length; start += columns)
        {
            var end = Math.Min(start + columns, children.Length);
            double rowHeight = 0;
            for (var i = start; i < end; i++)
            {
                if (!arrange)
                {
                    children[i].Measure(new Size(itemWidth, double.PositiveInfinity));
                }

                rowHeight = Math.Max(rowHeight, children[i].DesiredSize.Height);
            }

            if (arrange)
            {
                for (var i = start; i < end; i++)
                {
                    children[i].Arrange(new Rect((i - start) * (itemWidth + Gap), top, itemWidth, rowHeight));
                }
            }

            top += rowHeight + (end < children.Length ? Gap : 0);
        }

        return new Size(width, top);
    }
}
