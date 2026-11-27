using SplitVpn.Core.OpenConnect;

namespace SplitVpn.App.Services;

/// <summary>
/// Работа с каталогами профилей браузера входа (<see cref="SignInBrowserProfiles"/>): рекурсивное удаление кэша в
/// тысячи файлов, перенос общего профиля, отметки шлюза. Она идёт вне потока интерфейса — иначе окно замирает — и
/// по одной операции за раз: прежде их упорядочивал сам поток интерфейса, а перенос общего профиля одним окном входа
/// и его удаление другим, идущие одновременно, потеряли бы запомненный вход организации.
/// </summary>
internal static class SignInProfileWork
{
    private static readonly SemaphoreSlim Gate = new(1, 1);

    public static async Task<T> RunAsync<T>(Func<SignInBrowserProfiles, T> work)
    {
        ArgumentNullException.ThrowIfNull(work);
        // Без возврата в поток вызвавшего: очередь освобождается и тогда, когда его поток интерфейса уже завершён
        // (окно закрыто, приложение выходит), — иначе следующая операция ждала бы вечно.
        await Gate.WaitAsync().ConfigureAwait(false);
        try
        {
            return await Task.Run(() => work(SignInBrowserProfiles.Default)).ConfigureAwait(false);
        }
        finally
        {
            Gate.Release();
        }
    }

    public static Task RunAsync(Action<SignInBrowserProfiles> work)
    {
        ArgumentNullException.ThrowIfNull(work);
        return RunAsync(profiles =>
        {
            work(profiles);
            return true;
        });
    }
}
