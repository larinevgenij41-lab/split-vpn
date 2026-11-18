namespace SplitVpn.Core.Diagnostics;

/// <summary>
/// Подробный журнал для кода без внедрения зависимостей (DNS-посредник, RAS, маршруты, интерфейс).
/// Выключенный режим стоит одного чтения поля: строку сообщения собирают только под проверкой
/// <see cref="IsOn"/>. Куда уходят строки, решает процесс: служба — в Serilog, интерфейс — в свой файл.
/// </summary>
public static class Verbose
{
    private static volatile bool _on;

    public static bool IsOn => _on;

    /// <summary>Получатель строк: категория и текст. Ошибки получателя не выходят наружу.</summary>
    public static Action<string, string>? Sink { get; set; }

    public static void Set(bool on) => _on = on;

    public static void Write(string category, string message)
    {
        if (!_on)
        {
            return;
        }

        try
        {
            Sink?.Invoke(category, message);
        }
#pragma warning disable CA1031 // Журнал не должен ломать вызывающий код, в том числе неуправляемые обратные вызовы RAS.
        catch (Exception)
#pragma warning restore CA1031
        {
        }
    }
}
