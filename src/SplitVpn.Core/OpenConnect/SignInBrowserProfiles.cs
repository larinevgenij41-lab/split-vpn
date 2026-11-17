using SplitVpn.Core.Diagnostics;

namespace SplitVpn.Core.OpenConnect;

/// <summary>
/// Каталоги профилей встроенного браузера для входа в AnyConnect: у каждого подключения свой, чтобы вход одной
/// организации (её cookie и учётная запись SSO) не подставлялся при входе в другую.
/// </summary>
/// <param name="root">Каталог данных приложения пользователя (%LOCALAPPDATA%\SplitVpn).</param>
public sealed class SignInBrowserProfiles(string root)
{
    public static SignInBrowserProfiles Default { get; } = new(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SplitVpn"));

    /// <summary>Общий профиль прежних версий: в нём cookie организации, с которой входили до обновления.</summary>
    public string LegacyFolder { get; } = Path.Combine(root, "WebView2");

    /// <summary>Каталог профилей подключений. Его появление отмечает, что судьба общего профиля решена.</summary>
    public string ProfilesFolder { get; } = Path.Combine(root, "WebView2Profiles");

    public string FolderOf(Guid profileId) => Path.Combine(ProfilesFolder, profileId.ToString("N"));

    /// <summary>
    /// Каталог профиля подключения. Общий профиль прежних версий переносится один раз — в профиль первого подключения,
    /// открывшего вход после обновления: при одном подключении AnyConnect (обычный случай) запомненный вход
    /// организации сохраняется. Если перенос не удался (профиль занят), общий профиль никому больше не достаётся —
    /// иначе cookie одной организации попали бы в профиль другой, — а удаляется при следующем входе.
    /// </summary>
    public string Prepare(Guid profileId)
    {
        var folder = FolderOf(profileId);
        if (!Directory.Exists(LegacyFolder))
        {
            return folder;
        }

        if (!Directory.Exists(ProfilesFolder))
        {
            try
            {
                Directory.CreateDirectory(ProfilesFolder);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Перенос не начинался и решится при следующем входе.
                Verbose.Write("SignIn", "каталог профилей браузера не создан: " + ex.Message);
                return folder;
            }

            try
            {
                Settings.FileRetry.Run(() => Directory.Move(LegacyFolder, folder), () => !Directory.Exists(folder));
                Verbose.Write("SignIn", "общий профиль браузера прежней версии перенесён в профиль подключения");
                return folder;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Verbose.Write("SignIn", "общий профиль браузера не перенесён и будет удалён: " + ex.Message);
            }
        }

        TryDelete(LegacyFolder, "общий профиль браузера прежней версии");
        return folder;
    }

    /// <summary>Подключение удалено: его профиль браузера (cookie и вход организации) больше не нужен.</summary>
    public void Delete(Guid profileId) => TryDelete(FolderOf(profileId), "профиль браузера удалённого подключения");

    private static void TryDelete(string folder, string what)
    {
        try
        {
            if (Directory.Exists(folder))
            {
                Directory.Delete(folder, recursive: true);
                Verbose.Write("SignIn", what + " удалён");
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Профиль занят процессом браузера: общий профиль удалится при следующем входе, профиль удалённого
            // подключения останется на диске.
            Verbose.Write("SignIn", what + " не удалён: " + ex.Message);
        }
    }
}
