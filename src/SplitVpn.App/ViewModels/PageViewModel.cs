using CommunityToolkit.Mvvm.ComponentModel;
using SplitVpn.App.Services;
using SplitVpn.Core.Ipc;
using Wpf.Ui.Controls;

namespace SplitVpn.App.ViewModels;

/// <summary>Страница главного окна: заголовок, значок, общий доступ к службе и выполнение команд с отображением ошибки.</summary>
public abstract partial class PageViewModel(MainViewModel main, string title, SymbolRegular symbol) : ObservableObject
{
    /// <summary>Сколько видно короткое сообщение об успехе («Сохранено.»): дольше оно только мешает и вводит в заблуждение.</summary>
    internal static readonly TimeSpan SuccessMessageLifetime = TimeSpan.FromSeconds(6);

    /// <summary>
    /// Длинные сообщения об успехе несут указания или предупреждения (путь к архиву, замечания службы): они не
    /// скрываются по таймеру, а живут до следующего сообщения или повторного открытия страницы.
    /// </summary>
    internal const int AutoHideMaxLength = 80;

    public MainViewModel Main { get; } = main;

    public string Title { get; } = title;

    public SymbolRegular Symbol { get; } = symbol;

    protected ServiceConnection Service => Main.Service;

    private int _runningActions;
    private IDisposable? _hideMessage;

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private string? _message;

    [ObservableProperty]
    private bool _messageIsError;

    /// <summary>
    /// На странице есть несохранённые правки: перед выходом из приложения и установкой обновления о них
    /// спрашивают, а пункт меню страницы отмечен. Страницы с отметкой «Dirty» сообщают об её изменении сами.
    /// </summary>
    public virtual bool HasUnsavedChanges => false;

    /// <summary>
    /// Счётчик правок пользователя на странице. Сохранение запоминает его, когда собирает запрос, и снимает
    /// отметку несохранённых правок, только если за время запроса новых правок не было.
    /// </summary>
    protected int EditGeneration { get; private set; }

    protected void NoteEdit() => EditGeneration++;

    /// <summary>Снимает только отметки правок, вошедших в подтверждённое сохранение.</summary>
    protected static void AcceptSavedEdits(Dictionary<string, int> fields, int generation)
    {
        foreach (var name in fields.Where(p => p.Value <= generation).Select(p => p.Key).ToArray())
        {
            fields.Remove(name);
        }
    }

    /// <summary>Имя пункта навигации для экранного диктора.</summary>
    public override string ToString() => Title;

    /// <summary>Вызывается при открытии страницы.</summary>
    public virtual Task OnOpenedAsync() => Task.CompletedTask;

    /// <summary>Вызывается после каждого обновления статуса.</summary>
    public virtual void OnStatus(StatusDto? status)
    {
    }

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (e.PropertyName == "Dirty")
        {
            OnPropertyChanged(nameof(HasUnsavedChanges));
        }
    }

    protected Task RunAsync(Func<Task> action, string? success = null) => RunAsync(async () =>
    {
        await action();
        return success;
    });

    /// <summary>Действие само решает, чем закончилось: текст успеха или null (отменено, отклонено, сообщение уже показано).</summary>
    protected async Task RunAsync(Func<Task<string?>> action)
    {
        _runningActions++;
        IsBusy = true;
        Message = null;
        try
        {
            if (await action() is { } success)
            {
                ShowMessage(success, isError: false);
            }
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or ServiceCommandException or FormatException or UserFacingException)
        {
            ShowMessage(ex.Message, isError: true);
        }
        catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            // Сообщения .NET английские и без указания, что делать: пользователю — русская фраза, исходное — в журнал.
            ShowMessage(UiText.FileError(ex), isError: true);
        }
        finally
        {
            IsBusy = --_runningActions > 0;
        }
    }

    public void ShowError(string text) => ShowMessage(text, isError: true);

    /// <summary>Сообщение без ошибки (например, «отменено»): короткое скрывается само.</summary>
    public void ShowInfo(string text) => ShowMessage(text, isError: false);

    protected void ShowMessage(string text, bool isError)
    {
        Message = text;
        MessageIsError = isError;
    }

    /// <summary>
    /// Новое сообщение отменяет скрытие прежнего. Короткое сообщение об успехе скрывается само через
    /// <see cref="SuccessMessageLifetime"/>; ошибки и длинные пояснения остаются, пока их не сменят.
    /// </summary>
    partial void OnMessageChanged(string? value) => ScheduleHide();

    partial void OnMessageIsErrorChanged(bool value) => ScheduleHide();

    private void ScheduleHide()
    {
        _hideMessage?.Dispose();
        _hideMessage = null;
        if (Message is { } text && !MessageIsError && text.Length <= AutoHideMaxLength)
        {
            _hideMessage = Main.ScheduleUi(SuccessMessageLifetime, () =>
            {
                if (Message == text && !MessageIsError)
                {
                    Message = null;
                }
            });
        }
    }

    /// <summary>Повторное открытие страницы: прежнее сообщение об успехе к новому визиту не относится.</summary>
    internal void ClearSuccessMessage()
    {
        if (Message is not null && !MessageIsError)
        {
            Message = null;
        }
    }

    /// <summary>Записывает текст в файл, выбранный пользователем; ошибка — с понятным текстом и именем файла.</summary>
    protected static async Task WriteUserFileAsync(string path, string text)
    {
        try
        {
            await System.IO.File.WriteAllTextAsync(path, text);
        }
        catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            throw new UserFacingException(UiText.FileError(ex, path, writing: true), ex);
        }
    }

    /// <summary>Читает файл, выбранный пользователем; ошибка — с понятным текстом и именем файла.</summary>
    protected static async Task<string> ReadUserFileAsync(string path)
    {
        try
        {
            return await System.IO.File.ReadAllTextAsync(path);
        }
        catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            throw new UserFacingException(UiText.FileError(ex, path), ex);
        }
    }
}

/// <summary>Ошибка, текст которой уже написан для пользователя: страница показывает его как есть.</summary>
public sealed class UserFacingException(string message, Exception? inner = null) : Exception(message, inner);
