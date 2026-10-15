using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Media;
using SplitVpn.Core.Policy;
using Wpf.Ui.Controls;

namespace SplitVpn.App.Views;

/// <summary>Строка настроек в стиле Windows 11: значок, заголовок с описанием, элемент управления справа.</summary>
public sealed class CardRow : ContentControl
{
    public static readonly DependencyProperty TitleProperty = DependencyProperty.Register(nameof(Title), typeof(string), typeof(CardRow), new PropertyMetadata(""));
    public static readonly DependencyProperty DescriptionProperty = DependencyProperty.Register(nameof(Description), typeof(string), typeof(CardRow), new PropertyMetadata(null));
    public static readonly DependencyProperty IconProperty = DependencyProperty.Register(nameof(Icon), typeof(IconElement), typeof(CardRow), new PropertyMetadata(null));

    static CardRow() => DefaultStyleKeyProperty.OverrideMetadata(typeof(CardRow), new FrameworkPropertyMetadata(typeof(CardRow)));

    /// <summary>
    /// Переключатель или поле строки без собственного имени озвучивается заголовком строки, а описание
    /// становится подсказкой: иначе экранный диктор читает «переключатель» без смысла.
    /// </summary>
    protected override void OnContentChanged(object oldContent, object newContent)
    {
        base.OnContentChanged(oldContent, newContent);
        NameContent();
    }

    protected override void OnPropertyChanged(DependencyPropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (e.Property == TitleProperty || e.Property == DescriptionProperty)
        {
            NameContent();
        }
    }

    private void NameContent()
    {
        if (Content is not DependencyObject control)
        {
            return;
        }

        // Имя, заданное в разметке, не трогаем; своё прежнее — обновляем при смене заголовка.
        if (_namedByRow || control.ReadLocalValue(AutomationProperties.NameProperty) == DependencyProperty.UnsetValue)
        {
            AutomationProperties.SetName(control, Title);
            _namedByRow = true;
        }

        if (string.IsNullOrEmpty(AutomationProperties.GetHelpText(control)) && Description is { Length: > 0 } description)
        {
            AutomationProperties.SetHelpText(control, description);
        }
    }

    private bool _namedByRow;

    public string Title
    {
        get => (string)GetValue(TitleProperty);
        set => SetValue(TitleProperty, value);
    }

    public string? Description
    {
        get => (string?)GetValue(DescriptionProperty);
        set => SetValue(DescriptionProperty, value);
    }

    public IconElement? Icon
    {
        get => (IconElement?)GetValue(IconProperty);
        set => SetValue(IconProperty, value);
    }
}

/// <summary>Плитка показателя: значок, подпись, значение.</summary>
public sealed class Tile : ContentControl
{
    public static readonly DependencyProperty CaptionProperty = DependencyProperty.Register(nameof(Caption), typeof(string), typeof(Tile), new PropertyMetadata(""));
    public static readonly DependencyProperty IconProperty = DependencyProperty.Register(nameof(Icon), typeof(IconElement), typeof(Tile), new PropertyMetadata(null));

    static Tile() => DefaultStyleKeyProperty.OverrideMetadata(typeof(Tile), new FrameworkPropertyMetadata(typeof(Tile)));

    public string Caption
    {
        get => (string)GetValue(CaptionProperty);
        set => SetValue(CaptionProperty, value);
    }

    public IconElement? Icon
    {
        get => (IconElement?)GetValue(IconProperty);
        set => SetValue(IconProperty, value);
    }
}

public enum StateTone
{
    Neutral,
    Accent,
    Success,
    Caution,
    Critical,
}

/// <summary>
/// Тон состояния → кисть темы (системные цвета WinUI) ссылкой на ресурс: при смене темы, в том числе
/// на высокую контрастность, цвет индикатора обновляется сам, а не остаётся кистью прежней темы.
/// </summary>
public static class Tone
{
    public static readonly DependencyProperty FillProperty = Register("Fill");

    public static readonly DependencyProperty ForegroundProperty = Register("Foreground");

    public static readonly DependencyProperty BackgroundProperty = Register("Background");

    public static object? GetFill(DependencyObject element) => element.GetValue(FillProperty);

    public static void SetFill(DependencyObject element, object? value) => element.SetValue(FillProperty, value);

    public static object? GetForeground(DependencyObject element) => element.GetValue(ForegroundProperty);

    public static void SetForeground(DependencyObject element, object? value) => element.SetValue(ForegroundProperty, value);

    public static object? GetBackground(DependencyObject element) => element.GetValue(BackgroundProperty);

    public static void SetBackground(DependencyObject element, object? value) => element.SetValue(BackgroundProperty, value);

    public static string ResourceKey(StateTone tone) => tone switch
    {
        StateTone.Success => "SystemFillColorSuccessBrush",
        StateTone.Caution => "SystemFillColorCautionBrush",
        StateTone.Critical => "SystemFillColorCriticalBrush",
        StateTone.Accent => "AccentFillColorDefaultBrush",
        _ => "SystemFillColorNeutralBrush",
    };

    /// <summary>Свойство цели ищется по имени у типа элемента: у Border, Shape и значка это разные свойства.</summary>
    private static DependencyProperty Register(string target) => DependencyProperty.RegisterAttached(
        target, typeof(object), typeof(Tone), new PropertyMetadata(null, (element, e) =>
        {
            if (element is FrameworkElement framework && e.NewValue is StateTone tone
                && System.ComponentModel.DependencyPropertyDescriptor.FromName(target, framework.GetType(), framework.GetType()) is { } property)
            {
                framework.SetResourceReference(property.DependencyProperty, ResourceKey(tone));
            }
        }));
}

/// <summary>
/// Живая область для экранного диктора: при смене привязанного значения элемент сообщает об изменении
/// (LiveRegionChanged). Одного AutomationProperties.LiveSetting для этого мало — событие поднимает приложение.
/// </summary>
public static class LiveRegion
{
    public static readonly DependencyProperty ValueProperty = DependencyProperty.RegisterAttached(
        "Value", typeof(object), typeof(LiveRegion), new PropertyMetadata(null, OnValueChanged));

    public static object? GetValue(DependencyObject element) => element.GetValue(ValueProperty);

    public static void SetValue(DependencyObject element, object? value) => element.SetValue(ValueProperty, value);

    private static void OnValueChanged(DependencyObject element, DependencyPropertyChangedEventArgs e)
    {
        if (element is not UIElement ui || Equals(e.OldValue, e.NewValue) || !AutomationPeer.ListenerExists(AutomationEvents.LiveRegionChanged))
        {
            return;
        }

        (UIElementAutomationPeer.FromElement(ui) ?? UIElementAutomationPeer.CreatePeerForElement(ui))?.RaiseAutomationEvent(AutomationEvents.LiveRegionChanged);
    }
}

/// <summary>Уровень события журнала → вид бейджа: ошибка красная, остальное — сведения.</summary>
public sealed class LevelToAppearanceConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value switch
        {
            "Ошибка" => ControlAppearance.Danger,
            "Предупреждение" => ControlAppearance.Caution,
            _ => ControlAppearance.Info,
        };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Действие правила или решение политики → вид бейджа.</summary>
public sealed class DecisionToAppearanceConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        TargetKind.Direct or "Direct" or "Local" or "Server" or "напрямую" => ControlAppearance.Success,
        TargetKind.Block or "Block" or "блокировать" => ControlAppearance.Danger,
        _ => ControlAppearance.Info,
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>
/// Перетаскивание карточек доски маршрутизации. Кроме мыши у карточки есть меню «Переместить в…»,
/// поэтому доска работает и с клавиатуры, и с экранным диктором.
/// </summary>
public static class BoardDrag
{
    public static readonly DependencyProperty IsCardProperty = DependencyProperty.RegisterAttached(
        "IsCard", typeof(bool), typeof(BoardDrag), new PropertyMetadata(false, OnIsCardChanged));

    public static readonly DependencyProperty IsColumnProperty = DependencyProperty.RegisterAttached(
        "IsColumn", typeof(bool), typeof(BoardDrag), new PropertyMetadata(false, OnIsColumnChanged));

    private static Point _origin;

    public static bool GetIsCard(DependencyObject element) => (bool)element.GetValue(IsCardProperty);

    public static void SetIsCard(DependencyObject element, bool value) => element.SetValue(IsCardProperty, value);

    public static bool GetIsColumn(DependencyObject element) => (bool)element.GetValue(IsColumnProperty);

    public static void SetIsColumn(DependencyObject element, bool value) => element.SetValue(IsColumnProperty, value);

    private static void OnIsCardChanged(DependencyObject element, DependencyPropertyChangedEventArgs e)
    {
        if (element is not FrameworkElement card)
        {
            return;
        }

        card.PreviewMouseLeftButtonDown -= OnCardPressed;
        card.PreviewMouseMove -= OnCardMoved;
        card.Loaded -= OnCardLoaded;
        if (e.NewValue is true)
        {
            card.PreviewMouseLeftButtonDown += OnCardPressed;
            card.PreviewMouseMove += OnCardMoved;
            card.Loaded += OnCardLoaded;
        }
    }

    private static void OnIsColumnChanged(DependencyObject element, DependencyPropertyChangedEventArgs e)
    {
        if (element is not FrameworkElement column)
        {
            return;
        }

        column.DragOver -= OnDragOver;
        column.Drop -= OnDrop;
        column.AllowDrop = e.NewValue is true;
        if (e.NewValue is true)
        {
            column.DragOver += OnDragOver;
            column.Drop += OnDrop;
        }
    }

    private static void OnCardPressed(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        _origin = e.GetPosition(null);
        _pressedOnButton = FindAncestor<System.Windows.Controls.Primitives.ButtonBase>(e.OriginalSource as DependencyObject, sender as DependencyObject) is not null;
    }

    private static bool _pressedOnButton;

    /// <summary>Перенесённая карточка забирает фокус клавиатуры на свою первую кнопку.</summary>
    private static void OnCardLoaded(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: ViewModels.BoardCard { FocusOnLoad: true } card } element)
        {
            card.FocusOnLoad = false;
            element.MoveFocus(new System.Windows.Input.TraversalRequest(System.Windows.Input.FocusNavigationDirection.First));
        }
    }

    private static T? FindAncestor<T>(DependencyObject? from, DependencyObject? stop)
        where T : DependencyObject
    {
        for (var current = from; current is not null && current != stop; current = current is Visual or System.Windows.Media.Media3D.Visual3D ? VisualTreeHelper.GetParent(current) : LogicalTreeHelper.GetParent(current))
        {
            if (current is T found)
            {
                return found;
            }
        }

        return null;
    }

    private static void OnCardMoved(object sender, System.Windows.Input.MouseEventArgs e)
    {
        // Перетаскивание не начинается с кнопок карточки: иначе меню «Переместить в…» и «Убрать» срабатывают через раз.
        if (e.LeftButton != System.Windows.Input.MouseButtonState.Pressed || _pressedOnButton || sender is not FrameworkElement { DataContext: ViewModels.BoardCard card } element)
        {
            return;
        }

        var moved = e.GetPosition(null) - _origin;
        if (Math.Abs(moved.X) < SystemParameters.MinimumHorizontalDragDistance && Math.Abs(moved.Y) < SystemParameters.MinimumVerticalDragDistance)
        {
            return;
        }

        DragDrop.DoDragDrop(element, new DataObject(typeof(ViewModels.BoardCard), card), DragDropEffects.Move);
    }

    private static void OnDragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(typeof(ViewModels.BoardCard)) ? DragDropEffects.Move : DragDropEffects.None;
        e.Handled = true;
    }

    private static void OnDrop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(typeof(ViewModels.BoardCard)) is ViewModels.BoardCard card
            && sender is FrameworkElement { DataContext: ViewModels.BoardColumn column })
        {
            column.Accept(card);
        }

        e.Handled = true;
    }
}

/// <summary>
/// Перетаскивание строк списка подключений: порядок задаёт и вид на экране, и очерёдность подъёма.
/// Кроме мыши порядок меняют кнопки «Выше» и «Ниже», поэтому список работает и с клавиатуры.
/// </summary>
public static class ListDrag
{
    public static readonly DependencyProperty IsRowProperty = DependencyProperty.RegisterAttached(
        "IsRow", typeof(bool), typeof(ListDrag), new PropertyMetadata(false, OnIsRowChanged));

    public static readonly DependencyProperty IsListProperty = DependencyProperty.RegisterAttached(
        "IsList", typeof(bool), typeof(ListDrag), new PropertyMetadata(false, OnIsListChanged));

    private static Point _origin;
    private static bool _pressedOnButton;

    public static bool GetIsRow(DependencyObject element) => (bool)element.GetValue(IsRowProperty);

    public static void SetIsRow(DependencyObject element, bool value) => element.SetValue(IsRowProperty, value);

    public static bool GetIsList(DependencyObject element) => (bool)element.GetValue(IsListProperty);

    public static void SetIsList(DependencyObject element, bool value) => element.SetValue(IsListProperty, value);

    private static void OnIsRowChanged(DependencyObject element, DependencyPropertyChangedEventArgs e)
    {
        if (element is not FrameworkElement row)
        {
            return;
        }

        row.PreviewMouseLeftButtonDown -= OnRowPressed;
        row.PreviewMouseMove -= OnRowMoved;
        if (e.NewValue is true)
        {
            row.PreviewMouseLeftButtonDown += OnRowPressed;
            row.PreviewMouseMove += OnRowMoved;
        }
    }

    private static void OnIsListChanged(DependencyObject element, DependencyPropertyChangedEventArgs e)
    {
        if (element is not FrameworkElement list)
        {
            return;
        }

        list.DragOver -= OnDragOver;
        list.Drop -= OnDrop;
        list.AllowDrop = e.NewValue is true;
        if (e.NewValue is true)
        {
            list.DragOver += OnDragOver;
            list.Drop += OnDrop;
        }
    }

    private static void OnRowPressed(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        _origin = e.GetPosition(null);
        _pressedOnButton = FindAncestor<System.Windows.Controls.Primitives.ButtonBase>(e.OriginalSource as DependencyObject, sender as DependencyObject) is not null;
    }

    private static void OnRowMoved(object sender, System.Windows.Input.MouseEventArgs e)
    {
        // Перетаскивание не начинается с кнопки в строке: иначе выключатель срабатывает через раз.
        if (e.LeftButton != System.Windows.Input.MouseButtonState.Pressed || _pressedOnButton
            || sender is not FrameworkElement { DataContext: ViewModels.ProfileItem item } element)
        {
            return;
        }

        var moved = e.GetPosition(null) - _origin;
        if (Math.Abs(moved.X) < SystemParameters.MinimumHorizontalDragDistance && Math.Abs(moved.Y) < SystemParameters.MinimumVerticalDragDistance)
        {
            return;
        }

        DragDrop.DoDragDrop(element, new DataObject(typeof(ViewModels.ProfileItem), item), DragDropEffects.Move);
    }

    private static void OnDragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(typeof(ViewModels.ProfileItem)) ? DragDropEffects.Move : DragDropEffects.None;
        e.Handled = true;
    }

    private static void OnDrop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(typeof(ViewModels.ProfileItem)) is ViewModels.ProfileItem dragged
            && sender is FrameworkElement { DataContext: ViewModels.ConnectionsViewModel page } list
            && TargetIndex(list, e, page, dragged) is { } index)
        {
            _ = page.MoveToAsync(dragged, index);
        }

        e.Handled = true;
    }

    /// <summary>
    /// Куда встанет строка: под курсором, с учётом того, выше или ниже середины её отпустили. Место вставки
    /// считается по исходному списку, а перенос идёт уже без самой строки — поэтому при движении вниз
    /// индекс на единицу меньше, иначе строка перепрыгивает через соседнюю.
    /// </summary>
    private static int? TargetIndex(FrameworkElement list, DragEventArgs e, ViewModels.ConnectionsViewModel page, ViewModels.ProfileItem dragged)
    {
        var from = page.Profiles.IndexOf(dragged);
        if (from < 0 || page.Profiles.Count == 0)
        {
            return null;
        }

        int insertAt;
        if (FindAncestor<ListBoxItem>(e.OriginalSource as DependencyObject, list) is { DataContext: ViewModels.ProfileItem over } container
            && page.Profiles.IndexOf(over) is var index and >= 0)
        {
            insertAt = e.GetPosition(container).Y > container.ActualHeight / 2 ? index + 1 : index;
        }
        else
        {
            // Отпустили мимо строк — в конец списка.
            insertAt = page.Profiles.Count;
        }

        return Math.Clamp(insertAt > from ? insertAt - 1 : insertAt, 0, page.Profiles.Count - 1);
    }

    private static T? FindAncestor<T>(DependencyObject? from, DependencyObject? stop)
        where T : DependencyObject
    {
        for (var current = from; current is not null && current != stop; current = current is Visual or System.Windows.Media.Media3D.Visual3D ? VisualTreeHelper.GetParent(current) : LogicalTreeHelper.GetParent(current))
        {
            if (current is T found)
            {
                return found;
            }
        }

        return null;
    }
}
