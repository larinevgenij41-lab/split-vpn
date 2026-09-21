using System.Windows;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;

namespace SplitVpn.App.Services;

/// <summary>
/// Тема интерфейса: выбранная пользователем или системная. Высокая контрастность Windows важнее выбора:
/// в ней приложение всегда использует контрастную тему WPF-UI и следует за её включением и выключением.
/// </summary>
public static class ThemeService
{
    private static ThemeChoice _choice = ThemeChoice.System;
    private static bool _listening;

    public static void Apply(ThemeChoice choice)
    {
        _choice = choice;
        if (!_listening)
        {
            // Включение и выключение высокой контрастности приходит изменением системного параметра.
            SystemParameters.StaticPropertyChanged += (_, e) =>
            {
                if (e.PropertyName == nameof(SystemParameters.HighContrast))
                {
                    Application.Current?.Dispatcher.BeginInvoke(() => Apply(_choice));
                }
            };
            _listening = true;
        }

        var highContrast = SystemParameters.HighContrast;
        var theme = highContrast ? ApplicationTheme.HighContrast : choice switch
        {
            ThemeChoice.Light => ApplicationTheme.Light,
            ThemeChoice.Dark => ApplicationTheme.Dark,
            _ => ApplicationThemeManager.GetSystemTheme() == SystemTheme.Dark ? ApplicationTheme.Dark : ApplicationTheme.Light,
        };
        var backdrop = highContrast ? WindowBackdropType.None : WindowBackdropType.Mica;
        ApplicationThemeManager.Apply(theme, backdrop, true);
        foreach (Window window in Application.Current.Windows)
        {
            ApplicationThemeManager.Apply(window);
        }

        if (Application.Current.MainWindow is { IsLoaded: true } main)
        {
            // Смена выбора в «Настройках» должна включать или снимать слежение за системной темой сразу, а не после перезапуска.
            Watch(main, choice);
        }
    }

    /// <summary>Следовать системной теме, пока выбрана «Как в системе» и не включена высокая контрастность.</summary>
    public static void Watch(Window window, ThemeChoice choice)
    {
        if (choice == ThemeChoice.System && !SystemParameters.HighContrast)
        {
            SystemThemeWatcher.Watch(window, WindowBackdropType.Mica, true);
        }
        else
        {
            SystemThemeWatcher.UnWatch(window);
        }
    }
}
