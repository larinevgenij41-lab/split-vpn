namespace SplitVpn.Cli;

/// <summary>
/// Прерывание по Ctrl+C. Команды, которые наблюдают общий токен (запросы к службе, сценарии прототипа),
/// получают отмену вместо мгновенного завершения процесса: иначе не выполнились бы блоки finally и остались бы
/// маршруты, DNS на loopback и соединение RAS. Повторное Ctrl+C завершает процесс сразу. Команды, не
/// запросившие токен, прерываются по умолчанию, как и раньше.
/// </summary>
internal static class CliCancellation
{
    private static readonly CancellationTokenSource s_source = new();
    private static int s_installed;
    private static volatile bool s_cooperative;

    /// <summary>Подключить обработчик Ctrl+C; повторный вызов ничего не делает.</summary>
    public static void Install()
    {
        if (Interlocked.Exchange(ref s_installed, 1) == 0)
        {
            Console.CancelKeyPress += OnCancelKeyPress;
        }
    }

    /// <summary>Токен прерывания. Запросивший его обязуется наблюдать отмену и завершаться сам.</summary>
    public static CancellationToken Token
    {
        get
        {
            s_cooperative = true;
            return s_source.Token;
        }
    }

    public static bool IsInterrupted => s_source.IsCancellationRequested;

    /// <summary>Объявить, что команда наблюдает прерывание (например, через отчёт сценария).</summary>
    public static void Cooperate() => s_cooperative = true;

    public static void ThrowIfInterrupted()
    {
        if (s_source.IsCancellationRequested)
        {
            throw new OperationCanceledException("Прервано пользователем (Ctrl+C).", s_source.Token);
        }
    }

    /// <summary>Решение для обработчика: true — подавить завершение процесса и отменить токен.</summary>
    internal static bool Intercept(bool cooperative, bool alreadyInterrupted) => cooperative && !alreadyInterrupted;

    private static void OnCancelKeyPress(object? sender, ConsoleCancelEventArgs e)
    {
        if (!Intercept(s_cooperative, s_source.IsCancellationRequested))
        {
            if (s_source.IsCancellationRequested)
            {
                Console.Error.WriteLine("Повторное прерывание: процесс завершается без очистки. Если менялись маршруты, DNS или RAS, выполните «splitvpn-cli recover».");
            }

            return;
        }

        e.Cancel = true;
        Console.Error.WriteLine("Прерывание: команда завершит текущий шаг и выполнит очистку. Повторное Ctrl+C завершит процесс сразу.");
        try
        {
            s_source.Cancel();
        }
        catch (AggregateException ex)
        {
            Console.Error.WriteLine("Ошибка при прерывании: " + ex.InnerException?.Message);
        }
    }
}
