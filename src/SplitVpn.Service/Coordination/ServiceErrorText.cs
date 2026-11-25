using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace SplitVpn.Service.Coordination;

/// <summary>
/// Сбой службы — пользователю: что произошло и что делать, по-русски. Исходный текст исключения (английский,
/// с путями и кодами) уходит только в журнал службы вместе с коротким кодом; тот же код показывается пользователю,
/// чтобы поддержка нашла строку журнала.
/// </summary>
internal static class ServiceErrorText
{
    private const int DiskFull = 112;
    private const int HandleDiskFull = 39;
    private const int SharingViolation = 32;
    private const int LockViolation = 33;

    /// <summary>Что случилось и что делать — одной-двумя фразами, без текста исключения.</summary>
    public static string Describe(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        return exception switch
        {
            IOException io when Win32Code(io) is DiskFull or HandleDiskFull
                => "на системном диске нет места. Освободите место и повторите.",
            IOException io when Win32Code(io) is SharingViolation or LockViolation
                => "файл занят другой программой (часто антивирусом или резервным копированием). Повторите через несколько секунд.",
            IOException => "не удалось прочитать или записать файл на диске. Повторите; если ошибка повторится, проверьте диск и соберите архив в «Диагностике».",
            UnauthorizedAccessException => "нет доступа к файлам программы. Повторите; если ошибка повторится, переустановите программу — установщик восстанавливает права.",
            CryptographicException => "Windows не смогла зашифровать или расшифровать данные (DPAPI). Повторите через минуту; если ошибка повторится, перезагрузите компьютер.",
            TimeoutException => "операция не завершилась вовремя. Повторите через минуту.",
            Windows.Native.NativeCallException native => string.Create(CultureInfo.InvariantCulture,
                $"системная функция Windows вернула ошибку 0x{native.Code:X8}. Повторите; если ошибка повторится, соберите архив в «Диагностике»."),
            OperationCanceledException => "операция прервана: служба останавливается или запрос отменён. Повторите.",
            // Свои отказы программы (запись телефонной книги, EAP) написаны по-русски для пользователя.
            InvalidOperationException own when IsRussian(own.Message) => own.Message.TrimEnd().TrimEnd('.') + ". Проверьте параметры подключения.",
            _ => "непредвиденная ошибка службы. Повторите; если ошибка повторится, соберите архив в «Диагностике».",
        };
    }

    /// <summary>Короткий код для поддержки: восемь шестнадцатеричных знаков, свой у каждого сбоя.</summary>
    public static string NewId() => Convert.ToHexString(RandomNumberGenerator.GetBytes(4));

    /// <summary>
    /// Пишет исключение в журнал службы с кодом и возвращает текст для пользователя:
    /// «{what}: {что случилось и что делать} Код для поддержки: XXXXXXXX.».
    /// </summary>
    public static string Report(ILogger logger, string what, Exception exception)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(exception);
        var id = NewId();
        logger.LogError(exception, "[{ErrorId}] {What}", id, what);
        return Format(what, exception, id);
    }

    public static string Format(string what, Exception exception, string id) => $"{what}: {Describe(exception)} Код для поддержки: {id}.";

    private static bool IsRussian(string text) => text.Any(c => c is >= 'А' and <= 'я' or 'Ё' or 'ё');

    /// <summary>Код Win32 из HRESULT вида 0x8007xxxx, иначе -1.</summary>
    private static int Win32Code(Exception exception) =>
        (exception.HResult & unchecked((int)0xFFFF0000)) == unchecked((int)0x80070000) ? exception.HResult & 0xFFFF : -1;
}
