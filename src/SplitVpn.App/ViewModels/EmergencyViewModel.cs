using System.Runtime.InteropServices;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SplitVpn.App.Services;
using SplitVpn.Core.Diagnostics;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Recovery;

namespace SplitVpn.App.ViewModels;

/// <summary>
/// Экстренное выключение программы в приложении: состояние «выключена» (флаг из статуса службы, а когда служба молчит —
/// из реестра), «Экстренно выключить» (одно подтверждение и окно UAC) и «Включить программу», ход команды и её итог.
/// Канал управления здесь не используется: кнопка работает при зависшей, остановленной и подменённой службе.
/// </summary>
public sealed partial class EmergencyViewModel(MainViewModel main) : ObservableObject
{
    /// <summary>Флаг в реестре; в проверках подменяется.</summary>
    internal IEmergencyFlagSource FlagSource { get; set; } = new RegistryEmergencyFlagSource();

    /// <summary>Запуск команд с правами администратора; в проверках подменяется.</summary>
    internal IEmergencyLauncher Launcher { get; set; } = new EmergencyLauncher();

    /// <summary>
    /// Снять свой PAC-прокси шлюза (вернуть прокси пользователя): служба работает от SYSTEM и прокси пользователя не
    /// трогает. Ставит приложение; вызывается до окна UAC.
    /// </summary>
    public Func<Task>? RevertProxy { get; set; }

    /// <summary>Программа экстренно выключена.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(BannerText), nameof(TrayActionText))]
    [NotifyCanExecuteChangedFor(nameof(TurnOnCommand))]
    private bool _isOff;

    /// <summary>Когда выключили (если известно).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(BannerText))]
    private DateTimeOffset? _since;

    /// <summary>Идёт команда: повторный запуск игнорируется, кнопки недоступны.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(TurnOffCommand), nameof(TurnOnCommand))]
    private bool _isRunning;

    [ObservableProperty]
    private string _runningText = "";

    /// <summary>Итог последней команды; null — не показывается.</summary>
    [ObservableProperty]
    private EmergencyRunResult? _result;

    public string BannerText => UiText.EmergencyBannerText(Since);

    /// <summary>Пункт меню трея: выключить или, если уже выключена, включить.</summary>
    public string TrayActionText => IsOff ? UiText.EmergencyOnAction : UiText.EmergencyOffAction + "…";

    /// <summary>Служба ответила: флаг — из её статуса.</summary>
    internal void ApplyStatus(StatusDto status)
    {
        ArgumentNullException.ThrowIfNull(status);
        Set(status.EmergencyOff ? new EmergencyFlag(status.EmergencyOffSinceUtc) : null);
    }

    /// <summary>Служба не отвечает: флаг — из реестра (читается без прав администратора).</summary>
    internal void ApplyUnavailable() => Set(ReadFlag());

    /// <summary>Служба отказала с кодом «emergency-off»: программа выключена, даже если статус этого ещё не показал.</summary>
    internal void OnRefused() => Set(ReadFlag() ?? new EmergencyFlag(Since));

    /// <summary>Показать состояние без службы и реестра (самопроверка разметки).</summary>
    internal void Show(EmergencyFlag? flag) => Set(flag);

    private void Set(EmergencyFlag? flag)
    {
        Since = flag?.SinceUtc;
        IsOff = flag is not null;
    }

    private EmergencyFlag? ReadFlag()
    {
        try
        {
            return FlagSource.Read();
        }
        catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            Verbose.Write("Ui", "флаг экстренного выключения не прочитан: " + ex.GetType().Name + " «" + ex.Message + "»");
            return null;
        }
    }

    private bool CanTurnOff() => !IsRunning;

    private bool CanTurnOn() => !IsRunning && IsOff;

    /// <summary>«Экстренно выключить»: одно подтверждение, затем окно UAC. Состояние службы не проверяется.</summary>
    [RelayCommand(CanExecute = nameof(CanTurnOff))]
    private async Task TurnOffAsync()
    {
        if (IsRunning)
        {
            return;
        }

        main.ShowWindow?.Invoke();
        if (!await main.Confirm(UiText.EmergencyConfirmTitle, UiText.EmergencyConfirmText, UiText.EmergencyOffAction))
        {
            return;
        }

        await RunAsync(on: false);
    }

    /// <summary>«Включить программу»: окно UAC подтверждает действие само; подключение — кнопкой «Подключить».</summary>
    [RelayCommand(CanExecute = nameof(CanTurnOn))]
    private Task TurnOnAsync() => RunAsync(on: true);

    [RelayCommand]
    private void CloseResult() => Result = null;

    [RelayCommand]
    private void CopyReport()
    {
        if (Result is not { } result)
        {
            return;
        }

        try
        {
            System.Windows.Clipboard.SetText(result.ToReportText());
            main.CurrentPage.ShowInfo("Отчёт скопирован в буфер обмена.");
        }
        catch (Exception ex) when (ex is COMException or ExternalException)
        {
            // Буфер обмена занят другой программой.
            main.CurrentPage.ShowError("Буфер обмена занят другой программой. Повторите через пару секунд.");
        }
    }

    /// <summary>
    /// Запуск команды. Пока она идёт, повторный запуск (кнопка, трей, баннер) ничего не делает. Перед выключением
    /// снимается свой прокси шлюза. После команды флаг перечитывается из реестра, затем опрашивается служба.
    /// </summary>
    internal async Task RunAsync(bool on)
    {
        if (IsRunning)
        {
            return;
        }

        IsRunning = true;
        Result = null;
        RunningText = UiText.EmergencyRunningText(on);
        main.ExpectServiceLoss(true);
        try
        {
            if (!on && RevertProxy is { } revert)
            {
                try
                {
                    await revert();
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    // Прокси вернётся при следующем опросе; экстренное выключение важнее.
                    Verbose.Write("Ui", "прокси перед экстренным выключением не снят: " + ex.GetType().Name + " «" + ex.Message + "»");
                }
            }

            var result = await Launcher.RunAsync(on);
            if (result.Kind == EmergencyRunKind.Cancelled)
            {
                main.CurrentPage.ShowInfo(result.Summary);
            }
            else
            {
                Result = result;
            }
        }
        finally
        {
            IsRunning = false;
            RunningText = "";
            main.ExpectServiceLoss(false);
        }

        Set(ReadFlag());
        await main.RefreshAsync();
    }
}
