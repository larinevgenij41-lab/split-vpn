using System.Windows;
using System.Windows.Controls;

namespace SplitVpn.App.Views;

/// <summary>Две колонки с общим интервалом; в узком окне содержимое идёт сверху вниз в порядке Tab.</summary>
public sealed class ResponsiveColumns : Panel
{
    public static readonly DependencyProperty FixedColumnWidthProperty = DependencyProperty.Register(
        nameof(FixedColumnWidth), typeof(double), typeof(ResponsiveColumns),
        new FrameworkPropertyMetadata(280d, FrameworkPropertyMetadataOptions.AffectsMeasure));

    public static readonly DependencyProperty FixedColumnOnRightProperty = DependencyProperty.Register(
        nameof(FixedColumnOnRight), typeof(bool), typeof(ResponsiveColumns),
        new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsMeasure));

    public static readonly DependencyProperty BreakpointProperty = DependencyProperty.Register(
        nameof(Breakpoint), typeof(double), typeof(ResponsiveColumns),
        new FrameworkPropertyMetadata(720d, FrameworkPropertyMetadataOptions.AffectsMeasure));

    public static readonly DependencyProperty GapProperty = DependencyProperty.Register(
        nameof(Gap), typeof(double), typeof(ResponsiveColumns),
        new FrameworkPropertyMetadata(16d, FrameworkPropertyMetadataOptions.AffectsMeasure));

    public double FixedColumnWidth
    {
        get => (double)GetValue(FixedColumnWidthProperty);
        set => SetValue(FixedColumnWidthProperty, value);
    }

    public bool FixedColumnOnRight
    {
        get => (bool)GetValue(FixedColumnOnRightProperty);
        set => SetValue(FixedColumnOnRightProperty, value);
    }

    public double Breakpoint
    {
        get => (double)GetValue(BreakpointProperty);
        set => SetValue(BreakpointProperty, value);
    }

    public double Gap
    {
        get => (double)GetValue(GapProperty);
        set => SetValue(GapProperty, value);
    }

    protected override Size MeasureOverride(Size availableSize)
    {
        var children = InternalChildren.Cast<UIElement>().Where(c => c.Visibility != Visibility.Collapsed).ToArray();
        var stacked = availableSize.Width < Breakpoint || children.Length != 2;
        double width = 0, height = 0;
        for (var i = 0; i < children.Length; i++)
        {
            var columnWidth = stacked ? availableSize.Width : ColumnWidth(availableSize.Width, i);
            children[i].Measure(new Size(columnWidth, double.PositiveInfinity));
            var desired = children[i].DesiredSize;
            width = stacked ? Math.Max(width, desired.Width) : width + desired.Width;
            height = stacked ? height + desired.Height : Math.Max(height, desired.Height);
        }

        var gaps = Math.Max(0, children.Length - 1) * Gap;
        return new Size(double.IsFinite(availableSize.Width) ? availableSize.Width : width + (stacked ? 0 : gaps), height + (stacked ? gaps : 0));
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        var children = InternalChildren.Cast<UIElement>().Where(c => c.Visibility != Visibility.Collapsed).ToArray();
        var stacked = finalSize.Width < Breakpoint || children.Length != 2;
        double offset = 0;
        for (var i = 0; i < children.Length; i++)
        {
            var width = stacked ? finalSize.Width : ColumnWidth(finalSize.Width, i);
            children[i].Arrange(new Rect(stacked ? 0 : offset, stacked ? offset : 0, width,
                stacked ? children[i].DesiredSize.Height : finalSize.Height));
            offset += (stacked ? children[i].DesiredSize.Height : width) + Gap;
        }

        return finalSize;
    }

    private double ColumnWidth(double width, int index) =>
        (index == 1) == FixedColumnOnRight ? FixedColumnWidth : Math.Max(0, width - FixedColumnWidth - Gap);
}
