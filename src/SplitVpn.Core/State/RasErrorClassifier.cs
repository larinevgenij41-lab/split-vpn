using System.Globalization;

namespace SplitVpn.Core.State;

public readonly record struct RasErrorInfo(ErrorCategory Category, bool Retryable);

/// <summary>Категории ошибок подключения. Без повторов — отказ аутентификации и ошибки сертификата.</summary>
public static class RasErrorClassifier
{
    private static readonly Dictionary<int, ErrorCategory> Known = new()
    {
        [691] = ErrorCategory.Authentication, // неверное имя пользователя или пароль
        [649] = ErrorCategory.Authentication, // нет права на удалённый доступ
        [647] = ErrorCategory.Authentication, // учётная запись отключена
        [648] = ErrorCategory.Authentication, // срок действия пароля истёк
        [812] = ErrorCategory.Authentication, // политика/метод аутентификации сервера
        [789] = ErrorCategory.Authentication, // ошибка согласования безопасности L2TP
        [13801] = ErrorCategory.Authentication, // IKE authentication credentials unacceptable
        [741] = ErrorCategory.Authentication, // не согласовано шифрование
        [742] = ErrorCategory.Authentication, // сервер требует другое шифрование
        [850] = ErrorCategory.Authentication, // тип EAP не установлен в системе
        [734] = ErrorCategory.Authentication, // согласование PPP (LCP) прервано: способ входа не принят сервером
        [13843] = ErrorCategory.Authentication, // IKE: неверные данные согласования (обычно не совпал общий ключ)
        [13868] = ErrorCategory.Authentication, // IKE: нет общей политики шифрования с сервером
        [732] = ErrorCategory.Other, // не согласованы протоколы управления PPP: повтор, но со своей расшифровкой
        [735] = ErrorCategory.Other, // сервер отклонил запрошенный адрес: обычно проходит при повторе
        [619] = ErrorCategory.ServerUnreachable, // порт закрыт: соединение с сервером не установилось
        [13809] = ErrorCategory.ServerUnreachable, // IKE: запрос согласования слишком долго ждал ответа
        [766] = ErrorCategory.Certificate, // сертификат не найден
        [798] = ErrorCategory.Certificate, // не найден сертификат для EAP
        [781] = ErrorCategory.Certificate, // нет действительного сертификата L2TP
        [786] = ErrorCategory.Certificate, // нет действительного сертификата компьютера
        [13806] = ErrorCategory.Certificate, // IKE не нашёл сертификат компьютера
        [868] = ErrorCategory.NameResolution, // не удалось разрешить имя сервера
        [800] = ErrorCategory.ServerUnreachable,
        [809] = ErrorCategory.ServerUnreachable,
        [815] = ErrorCategory.ServerUnreachable,
        [651] = ErrorCategory.ServerUnreachable,
        [678] = ErrorCategory.ServerUnreachable,
        [806] = ErrorCategory.ServerUnreachable, // не проходит GRE (PPTP)
        [813] = ErrorCategory.ServerUnreachable,
        [-2146762487] = ErrorCategory.Certificate, // 0x800B0109 недоверенный корень
        [-2146762481] = ErrorCategory.Certificate, // 0x800B010F имя не совпадает
        [-2146762480] = ErrorCategory.Certificate, // 0x800B0110 сертификат не годится для запрошенного использования
        [-2146762495] = ErrorCategory.Certificate, // 0x800B0101 срок действия истёк
        [-2146885613] = ErrorCategory.Certificate, // 0x80092013 проверка отзыва недоступна
        [-2146885616] = ErrorCategory.Certificate, // 0x80092010 сертификат отозван
        [-2146885614] = ErrorCategory.Certificate, // 0x80092012 проверка отзыва не выполнена
        [-2146762486] = ErrorCategory.Certificate, // 0x800B010A цепочка не строится до доверенного корня
    };

    /// <summary>Коды, которые программа узнаёт по имени: у каждого есть своя расшифровка для интерфейса.</summary>
    public static IReadOnlyCollection<int> KnownCodes => Known.Keys;

    public static RasErrorInfo Classify(int code)
    {
        if (!Known.TryGetValue(code, out var category))
        {
            return new RasErrorInfo(ErrorCategory.Other, Retryable: true);
        }

        var retryable = category is not (ErrorCategory.Authentication or ErrorCategory.Certificate);
        return new RasErrorInfo(category, retryable);
    }

    public static string CategoryText(ErrorCategory category) => category switch
    {
        ErrorCategory.NameResolution => "Не удалось разрешить имя сервера",
        ErrorCategory.ServerUnreachable => "Сервер недоступен",
        ErrorCategory.Certificate => "Ошибка сертификата VPN",
        ErrorCategory.Authentication => "Отказ аутентификации: проверьте способ входа, учётные данные и ключ IPsec",
        ErrorCategory.NoInternetInTunnel => "Нет интернета в туннеле",
        ErrorCategory.Routes => "Не удалось применить маршруты",
        ErrorCategory.Other => "Ошибка подключения",
        _ => "",
    };

    /// <summary>
    /// Текст неудачной проверки готовности: сколько проверок подряд не пройдено и когда следующая попытка.
    /// Повторы не останавливаются — за kill switch подключение должно подняться само, как только сервер вернётся.
    /// </summary>
    public static string VerificationText(int failures, TimeSpan delay)
    {
        var count = Math.Max(failures, 1);
        var (noun, verb) = Plural(count);
        return string.Create(CultureInfo.InvariantCulture,
            $"{CategoryText(ErrorCategory.NoInternetInTunnel)}: {count} {noun} подряд не {verb}, следующая попытка через {delay.TotalSeconds:F0} с");
    }

    private static (string Noun, string Verb) Plural(int count)
    {
        var tail = count % 100;
        if (tail is >= 11 and <= 14)
        {
            return ("проверок", "пройдено");
        }

        return (count % 10) switch
        {
            1 => ("проверка", "пройдена"),
            2 or 3 or 4 => ("проверки", "пройдены"),
            _ => ("проверок", "пройдено"),
        };
    }
}
