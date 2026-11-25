namespace SplitVpn.Cli;

/// <summary>Входной файл команды не прочитан: это ошибка использования (код 2), а не отказ службы.</summary>
internal sealed class InputFileException(string path, Exception inner)
    : Exception($"Не удалось прочитать файл {path}: {inner.Message}", inner);

/// <summary>
/// Коды возврата утилиты: 0 — выполнено; 1 — служба отклонила команду или проверка не пройдена;
/// 2 — ошибка использования (параметры, входные файлы); 3 — связи со службой нет, она не ответила в срок
/// или команда прервана до ответа.
/// </summary>
internal static class CliExit
{
    public const int Failed = 1;
    public const int Usage = 2;

    /// <summary>Код и текст для исключения, дошедшего до верхнего уровня.</summary>
    public static (int Code, string Message) ForException(Exception exception) => exception switch
    {
        ArgumentException ex => (Usage, "Ошибка использования: " + ex.Message),
        InputFileException ex => (Usage, ex.Message),
        FileNotFoundException ex => (Usage, "Файл не найден: " + (ex.FileName ?? ex.Message)),
        DirectoryNotFoundException ex => (Usage, "Каталог не найден: " + ex.Message),
        OperationCanceledException when CliCancellation.IsInterrupted =>
            (Failed, "Прервано пользователем. Если сценарий менял маршруты, DNS или RAS и очистка не завершилась, выполните «splitvpn-cli recover»."),
        _ => (Failed, "Ошибка: " + exception.Message),
    };
}
