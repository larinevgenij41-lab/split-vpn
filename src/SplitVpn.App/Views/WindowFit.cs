using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;

namespace SplitVpn.App.Views;

/// <summary>
/// Окно не больше рабочей области монитора. Размеры окон заданы для большого экрана (вход — 920×780, главное —
/// 1080×740), а CenterScreen не прижимает окно к рабочей области: на 1366×768 или при масштабе 150 % заголовок
/// с кнопкой закрытия уходил за верх экрана, низ — под панель задач.
/// До показа размеры ограничиваются рабочей областью монитора, на котором окно откроется (CenterScreen выбирает
/// монитор под указателем мыши), после показа окно сдвигается целиком в рабочую область своего монитора.
/// </summary>
internal static partial class WindowFit
{
    /// <summary>Запас от краёв рабочей области: рамка и тень окна не прилипают к панели задач.</summary>
    public const double Gap = 16;

    /// <summary>Итог расчёта: размеры, минимальные размеры и положение (null — положение не задано, решает CenterScreen).</summary>
    internal readonly record struct Placement(double Width, double Height, double MinWidth, double MinHeight, double? Left, double? Top);

    /// <summary>
    /// Чистый расчёт: размеры не больше рабочей области за вычетом запаса, минимальные — не больше размеров,
    /// заданное положение — так, чтобы окно целиком лежало в рабочей области. NaN в размерах (SizeToContent) не трогается.
    /// </summary>
    internal static Placement Fit(Rect workArea, double width, double height, double minWidth, double minHeight, double? left = null, double? top = null)
    {
        var maxWidth = Math.Max(0, workArea.Width - Gap);
        var maxHeight = Math.Max(0, workArea.Height - Gap);
        var fittedWidth = double.IsNaN(width) ? width : Math.Min(width, maxWidth);
        var fittedHeight = double.IsNaN(height) ? height : Math.Min(height, maxHeight);
        var fittedMinWidth = Math.Min(minWidth, maxWidth);
        var fittedMinHeight = Math.Min(minHeight, maxHeight);
        double? fittedLeft = left, fittedTop = top;
        if (left is { } x && !double.IsNaN(fittedWidth))
        {
            fittedLeft = Clamp(x, workArea.Left, workArea.Right - fittedWidth);
        }

        if (top is { } y && !double.IsNaN(fittedHeight))
        {
            fittedTop = Clamp(y, workArea.Top, workArea.Bottom - fittedHeight);
        }

        return new Placement(fittedWidth, fittedHeight, fittedMinWidth, fittedMinHeight, fittedLeft, fittedTop);
    }

    /// <summary>Левый или верхний край: не дальше правой/нижней границы, но и не раньше левой/верхней.</summary>
    private static double Clamp(double value, double start, double end) => Math.Max(start, Math.Min(value, end));

    /// <summary>
    /// Вызывается в конструкторе окна, до показа. Размеры ограничиваются сразу (по монитору под указателем),
    /// положение проверяется после показа — по монитору, на котором окно оказалось.
    /// </summary>
    public static void Apply(Window window)
    {
        ArgumentNullException.ThrowIfNull(window);
        var area = WorkAreaUnderCursor() ?? SystemParameters.WorkArea;
        var fit = Fit(area, window.Width, window.Height, window.MinWidth, window.MinHeight);
        window.MinWidth = fit.MinWidth;
        window.MinHeight = fit.MinHeight;
        window.Width = fit.Width;
        window.Height = fit.Height;
        if (window.MaxHeight > area.Height)
        {
            window.MaxHeight = area.Height;
        }

        window.Loaded -= OnLoaded;
        window.Loaded += OnLoaded;
    }

    /// <summary>Окно показано: если хоть частью вышло за рабочую область своего монитора — сдвигается внутрь.</summary>
    private static void OnLoaded(object sender, RoutedEventArgs e)
    {
        var window = (Window)sender;
        var handle = new WindowInteropHelper(window).Handle;
        // Окно, нарочно открытое за пределами экранов (самопроверка рисует окна за экраном), не трогаем.
        var monitor = MonitorFromWindow(handle, MonitorDefaultToNull);
        if (monitor == IntPtr.Zero || window.WindowState != WindowState.Normal || !GetWindowRect(handle, out var rect)
            || GetMonitorWorkArea(monitor) is not { } work)
        {
            return;
        }

        // Сравнение в пикселях экрана, сдвиг — в единицах окна: так не важно, как WPF пересчитывает Left/Top при разном масштабе мониторов.
        var scale = VisualTreeHelper.GetDpi(window).DpiScaleX;
        var bounds = new Rect(rect.Left, rect.Top, rect.Right - rect.Left, rect.Bottom - rect.Top);
        var fit = Fit(work, bounds.Width, bounds.Height, 0, 0, bounds.Left, bounds.Top);
        var dx = fit.Left!.Value - bounds.Left;
        var dy = fit.Top!.Value - bounds.Top;
        if (Math.Abs(dx) >= 1 || Math.Abs(dy) >= 1)
        {
            window.Left += dx / scale;
            window.Top += dy / scale;
        }
    }

    /// <summary>Рабочая область монитора под указателем мыши в единицах WPF (с учётом масштаба этого монитора).</summary>
    private static Rect? WorkAreaUnderCursor()
    {
        if (!GetCursorPos(out var point))
        {
            return null;
        }

        var monitor = MonitorFromPoint(point, MonitorDefaultToNearest);
        if (monitor == IntPtr.Zero || GetMonitorWorkArea(monitor) is not { } work)
        {
            return null;
        }

        var dpi = GetDpiForMonitor(monitor, 0, out var dpiX, out _) == 0 && dpiX > 0 ? dpiX : 96u;
        var scale = dpi / 96d;
        return new Rect(work.X / scale, work.Y / scale, work.Width / scale, work.Height / scale);
    }

    /// <summary>Рабочая область монитора в пикселях экрана (без панели задач).</summary>
    private static Rect? GetMonitorWorkArea(IntPtr monitor)
    {
        var info = new MonitorInfo { Size = Marshal.SizeOf<MonitorInfo>() };
        if (!GetMonitorInfo(monitor, ref info))
        {
            return null;
        }

        var work = info.Work;
        return new Rect(work.Left, work.Top, work.Right - work.Left, work.Bottom - work.Top);
    }

    private const uint MonitorDefaultToNull = 0;
    private const uint MonitorDefaultToNearest = 2;

    [StructLayout(LayoutKind.Sequential)]
    private struct NativePoint
    {
        public int X;
        public int Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeRect
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MonitorInfo
    {
        public int Size;
        public NativeRect Monitor;
        public NativeRect Work;
        public uint Flags;
    }

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetCursorPos(out NativePoint point);

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial IntPtr MonitorFromPoint(NativePoint point, uint flags);

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial IntPtr MonitorFromWindow(IntPtr hwnd, uint flags);

    [LibraryImport("user32.dll", EntryPoint = "GetMonitorInfoW")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetMonitorInfo(IntPtr monitor, ref MonitorInfo info);

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetWindowRect(IntPtr hwnd, out NativeRect rect);

    [LibraryImport("shcore.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int GetDpiForMonitor(IntPtr monitor, int dpiType, out uint dpiX, out uint dpiY);
}
