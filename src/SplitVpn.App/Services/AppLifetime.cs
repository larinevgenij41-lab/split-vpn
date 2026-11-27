using SplitVpn.Core.Diagnostics;

namespace SplitVpn.App.Services;

/// <summary>
/// Пути завершения интерфейса, которые обходятся без штатного выхода: сбой запуска первой копии, лавина одинаковых
/// ошибок, необработанное исключение и конец сеанса Windows. Вынесены из <see cref="App"/>, чтобы их можно было
/// проверить: после сбоя запуска не должно оставаться невидимого процесса с мьютексом единственного экземпляра, а
/// перед любым внезапным выходом свой прокси шлюза снимается. С окнами и диспетчером класс связан только через
/// действия, которые задаёт <see cref="App"/>.
/// </summary>
/// <param name="record">Запись ошибки в журнал интерфейса; false — лавина одинаковых ошибок, пора завершаться.</param>
internal sealed class AppLifetime(Func<Exception, bool> record)
{
    private bool _stormExit;

    /// <summary>Мьютекс единственного экземпляра этого сеанса (захвачен первой копией).</summary>
    public Mutex? Instance { get; set; }

    /// <summary>Снять свой прокси шлюза с ограниченным ожиданием (<see cref="ProxyService.Close"/>); null — прокси ещё нет.</summary>
    public Func<TimeSpan, bool>? CloseProxy { get; set; }

    /// <summary>Убрать значок из области уведомлений.</summary>
    public Action? DisposeTray { get; set; }

    /// <summary>Остановить слушатель активации второй копии.</summary>
    public Action? CancelActivation { get; set; }

    /// <summary>Сообщить человеку, что интерфейс не запустился.</summary>
    public Action? ShowStartupError { get; set; }

    /// <summary>Разрешить главному окну закрыться (обычно оно прячется в трей).</summary>
    public Action? AllowWindowClose { get; set; }

    /// <summary>Штатное завершение приложения с кодом (Application.Shutdown).</summary>
    public Action<int> Shutdown { get; set; } = _ => { };

    /// <summary>Немедленное завершение процесса с кодом; в проверках подменяется.</summary>
    public Action<int> Exit { get; init; } = Environment.Exit;

    /// <summary>
    /// Запуск первой копии после захвата мьютекса. Любой сбой — <see cref="FailStartup"/>: без этого процесс оставался
    /// без окна и значка, но с мьютексом, и каждый следующий запуск лишь просил его показать окно, которого нет.
    /// </summary>
    public void StartFirstInstance(Action start)
    {
        ArgumentNullException.ThrowIfNull(start);
        try
        {
            start();
        }
        catch (Exception ex)
        {
            FailStartup(ex);
        }
    }

    /// <summary>
    /// Сбой инициализации после захвата мьютекса: ошибка записана, мьютекс освобождён (следующий запуск станет первой
    /// копией), человеку сказано, что делать, процесс завершается с кодом 1. OnExit освободит то, что успело
    /// создаться, и снимет прокси шлюза, если он был поставлен.
    /// </summary>
    public void FailStartup(Exception exception)
    {
        record(exception);
        CancelActivation?.Invoke();
        try
        {
            Instance?.ReleaseMutex();
        }
        catch (ApplicationException)
        {
            // Мьютекс уже не принадлежит этому потоку: освобождать нечего.
        }

        Instance?.Dispose();
        Instance = null;
        try
        {
            ShowStartupError?.Invoke();
        }
        catch (Exception shown) when (shown is not OutOfMemoryException)
        {
            record(shown);
        }

        AllowWindowClose?.Invoke();
        Shutdown(1);
    }

    /// <summary>
    /// Ошибка UI-потока: не закрывает приложение (служба и защита от него не зависят), кроме лавины одинаковых ошибок.
    /// </summary>
    public void OnDispatcherError(Exception exception)
    {
        if (!record(exception))
        {
            ExitAfterErrorStorm();
        }
    }

    /// <summary>
    /// Необработанное исключение: процесс сейчас завершится без OnExit, поэтому свой прокси шлюза снимается здесь —
    /// иначе браузеры останутся с PAC недоступного шлюза до следующего запуска интерфейса.
    /// </summary>
    public void OnCrash(object? exceptionObject)
    {
        if (exceptionObject is Exception exception)
        {
            record(exception);
        }

        RevertProxyBeforeExit();
    }

    /// <summary>
    /// Выход из Windows и Restart Manager установщика закрывают интерфейс по-настоящему. Прокси шлюза снимается
    /// сразу, до ответа Windows: Shutdown асинхронен, и OnExit может не успеть до конца сеанса. Затем коротко ждётся
    /// идущая запись настроек интерфейса.
    /// </summary>
    /// <param name="waitPreferences">Дождаться записи настроек не дольше заданного; false — не дописаны.</param>
    /// <param name="wait">Сколько ждать записи настроек.</param>
    /// <param name="exitApplication">Штатный выход приложения.</param>
    public void OnSessionEnding(Func<TimeSpan, bool> waitPreferences, TimeSpan wait, Action exitApplication)
    {
        ArgumentNullException.ThrowIfNull(waitPreferences);
        ArgumentNullException.ThrowIfNull(exitApplication);
        RevertProxyBeforeExit();
        if (!waitPreferences(wait))
        {
            Verbose.Write("Ui", "настройки интерфейса не дописаны за " + wait.TotalSeconds + " с до конца сеанса");
        }

        exitApplication();
    }

    /// <summary>
    /// Лавина одинаковых ошибок UI-потока: контролируемый выход вместо падения — прокси шлюза снят, значок убран,
    /// код завершения ненулевой. Немедленный выход, а не Shutdown: штатное завершение идёт через тот же диспетчер,
    /// который сейчас крутит ошибку.
    /// </summary>
    public void ExitAfterErrorStorm()
    {
        // Ожидание прокси может прокачать сообщения окна (STA), и ошибка повторится: выход начинается один раз.
        if (_stormExit) { return; }
        _stormExit = true;
        Verbose.Write("Ui", "лавина одинаковых ошибок: интерфейс завершается");
        RevertProxyBeforeExit();
        try
        {
            DisposeTray?.Invoke();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Verbose.Write("Ui", "значок в трее не убран: " + ex.Message);
        }

        Exit(2);
    }

    /// <summary>
    /// Снять свой прокси шлюза перед завершением, которое может обойтись без OnExit (сбой, конец сеанса). Ожидание
    /// фоновой синхронизации ограничено; ошибка здесь не должна мешать завершению.
    /// </summary>
    public void RevertProxyBeforeExit()
    {
        try
        {
            CloseProxy?.Invoke(ProxyService.ExitWait);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Verbose.Write("Ui", "прокси шлюза перед завершением не снят: " + ex.GetType().Name + " «" + ex.Message + "»");
        }
    }
}
