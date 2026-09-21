using System.Globalization;
using System.Windows;
using System.Windows.Data;
using SplitVpn.Core.Settings;
using Wpf.Ui.Controls;

namespace SplitVpn.App.Views;

/// <summary>true/непустое → Visible; параметр «invert» меняет смысл.</summary>
public sealed class VisibleWhenConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var truthy = value switch
        {
            null => false,
            bool b => b,
            string s => s.Length > 0,
            int i => i != 0,
            Enum e => System.Convert.ToInt64(e, CultureInfo.InvariantCulture) != 0,
            System.Collections.ICollection c => c.Count > 0,
            _ => true,
        };
        if (string.Equals(parameter as string, "invert", StringComparison.Ordinal))
        {
            truthy = !truthy;
        }

        return truthy ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Номер шага мастера == параметр → Visible.</summary>
public sealed class StepVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is int step && int.TryParse(parameter as string, NumberStyles.Integer, CultureInfo.InvariantCulture, out var expected) && step == expected
            ? Visibility.Visible
            : Visibility.Collapsed;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Непустое значение → true (для IsOpen у InfoBar).</summary>
public sealed class HasValueConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is string s ? s.Length > 0 : value is not null;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true ? Binding.DoNothing : string.Empty;
}

/// <summary>Признак ошибки → уровень InfoBar.</summary>
public sealed class SeverityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true ? Wpf.Ui.Controls.InfoBarSeverity.Error : Wpf.Ui.Controls.InfoBarSeverity.Success;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class InverseBoolConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value is not true;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => value is not true;
}

public sealed class DecisionTextConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        ViewModels.CheckAddressViewModel.DecisionText(value as string ?? "");

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class LocalTimeConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is DateTimeOffset time ? time.ToLocalTime().ToString("dd.MM HH:mm:ss", CultureInfo.GetCultureInfo("ru-RU")) : "";

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>Роль подключения → вид бейджа.</summary>
public sealed class RoleToAppearanceConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        ProfileRole.Primary => ControlAppearance.Success,
        ProfileRole.Secondary => ControlAppearance.Info,
        _ => ControlAppearance.Secondary,
    };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}
