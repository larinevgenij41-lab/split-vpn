using CommunityToolkit.Mvvm.ComponentModel;
using SplitVpn.App.Services;
using SplitVpn.Core.Ipc;
using Wpf.Ui.Controls;

namespace SplitVpn.App.ViewModels;

/// <summary>Страница главного окна: заголовок, значок, общий доступ к службе и выполнение команд с отображением ошибки.</summary>
public abstract partial class PageViewModel(MainViewModel main, string title, SymbolRegular symbol) : ObservableObject
{
    public MainViewModel Main { get; } = main;

    public string Title { get; } = title;

    public SymbolRegular Symbol { get; } = symbol;

    protected ServiceConnection Service => Main.Service;

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private string? _message;

    [ObservableProperty]
    private bool _messageIsError;

    /// <summary>Имя пункта навигации для экранного диктора.</summary>
    public override string ToString() => Title;

    /// <summary>Вызывается при открытии страницы.</summary>
    public virtual Task OnOpenedAsync() => Task.CompletedTask;

    /// <summary>Вызывается после каждого обновления статуса.</summary>
    public virtual void OnStatus(StatusDto? status)
    {
    }

    protected Task RunAsync(Func<Task> action, string? success = null) => RunAsync(async () =>
    {
        await action();
        return success;
    });

    /// <summary>Действие само решает, чем закончилось: текст успеха или null (отменено, отклонено, сообщение уже показано).</summary>
    protected async Task RunAsync(Func<Task<string?>> action)
    {
        IsBusy = true;
        Message = null;
        try
        {
            if (await action() is { } success)
            {
                ShowMessage(success, isError: false);
            }
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or ServiceCommandException or System.IO.IOException or UnauthorizedAccessException or FormatException or System.Text.Json.JsonException)
        {
            ShowMessage(ex.Message, isError: true);
        }
        finally
        {
            IsBusy = false;
        }
    }

    public void ShowError(string text) => ShowMessage(text, isError: true);

    protected void ShowMessage(string text, bool isError)
    {
        Message = text;
        MessageIsError = isError;
    }
}
