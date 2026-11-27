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
    /// <param name="gatewayHost">
    /// Шлюз, для которого открывается вход. Профиль помнит шлюз, для которого создан (<see cref="HostMarkerOf"/>): у
    /// подключения сменили адрес на шлюз другой организации — прежний профиль (её cookie и вход SSO) сбрасывается.
    /// null — шлюз не известен, профиль не сверяется.
    /// </param>
    public string Prepare(Guid profileId, string? gatewayHost = null)
    {
        RetryPendingDeletes();
        var folder = FolderOf(profileId);
        if (File.Exists(folder + ".delete"))
        {
            throw new IOException("Профиль браузера ожидает удаления. Закройте прежнее окно входа и повторите.");
        }

        MigrateLegacy(folder);
        if (!string.IsNullOrWhiteSpace(gatewayHost))
        {
            BindToHost(folder, HostMarkerOf(profileId), gatewayHost.Trim());
        }

        return folder;
    }

    /// <summary>Отметка шлюза профиля — рядом с каталогом, а не в нём: каталог целиком принадлежит браузеру.</summary>
    public string HostMarkerOf(Guid profileId) => FolderOf(profileId) + ".host";

    /// <summary>
    /// Профиль привязывается к шлюзу. Отметки нет — профиль прежней версии или перенесённый общий: он остаётся (вход
    /// организации сохраняется) и получает отметку. Отметка другого шлюза — каталог удаляется; не удалился (занят
    /// прежним окном входа) — исключение: чужой вход в профиле не используется.
    /// </summary>
    private static void BindToHost(string folder, string marker, string host)
    {
        string? previous = null;
        try
        {
            previous = File.Exists(marker) ? File.ReadAllText(marker).Trim() : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Verbose.Write("SignIn", "отметка шлюза профиля браузера не прочитана: " + ex.Message);
            previous = "";
        }

        if (previous is not null && !string.Equals(previous, host, StringComparison.OrdinalIgnoreCase) && Directory.Exists(folder))
        {
            TryDelete(folder, "профиль браузера прежнего шлюза");
            if (Directory.Exists(folder))
            {
                throw new IOException("Адрес шлюза изменился, а прежний профиль браузера не удаляется. Закройте прежнее окно входа и повторите.");
            }
        }

        if (string.Equals(previous, host, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(marker)!);
            File.WriteAllText(marker, host);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Без отметки профиль сверится при следующем входе: отсутствующая отметка его не сбрасывает.
            Verbose.Write("SignIn", "отметка шлюза профиля браузера не записана: " + ex.Message);
        }
    }

    private void MigrateLegacy(string folder)
    {
        if (!Directory.Exists(LegacyFolder))
        {
            return;
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
                return;
            }

            try
            {
                Settings.FileRetry.Run(() => Directory.Move(LegacyFolder, folder), () => !Directory.Exists(folder));
                Verbose.Write("SignIn", "общий профиль браузера прежней версии перенесён в профиль подключения");
                return;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Verbose.Write("SignIn", "общий профиль браузера не перенесён и будет удалён: " + ex.Message);
            }
        }

        TryDelete(LegacyFolder, "общий профиль браузера прежней версии");
    }

    /// <summary>
    /// Удаляет профили браузера подключений, которых нет в настройках: подключение удалил другой администратор, или
    /// настройки заменены импортом. Вызывается только с успешно прочитанным списком подключений; пустой список не
    /// применяется вовсе — так выглядели бы и настройки, сброшенные службой после сбоя чтения, а cookie входа лишь
    /// пережили бы подключение. Возвращает число удалённых профилей.
    /// </summary>
    public int PruneOrphans(IReadOnlyCollection<Guid> existingProfiles)
    {
        ArgumentNullException.ThrowIfNull(existingProfiles);
        if (existingProfiles.Count == 0 || !Directory.Exists(ProfilesFolder))
        {
            return 0;
        }

        var removed = 0;
        try
        {
            foreach (var folder in Directory.EnumerateDirectories(ProfilesFolder))
            {
                if (!Guid.TryParseExact(Path.GetFileName(folder), "N", out var id) || existingProfiles.Contains(id))
                {
                    continue;
                }

                TryDelete(folder, "профиль браузера подключения, которого нет в настройках");
                if (!Directory.Exists(folder))
                {
                    removed++;
                }
            }

            foreach (var marker in Directory.EnumerateFiles(ProfilesFolder, "*.host"))
            {
                if (Guid.TryParseExact(Path.GetFileNameWithoutExtension(marker), "N", out var id) && !existingProfiles.Contains(id)
                    && !Directory.Exists(FolderOf(id)))
                {
                    TryDeleteFile(marker);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Verbose.Write("SignIn", "профили браузера удалённых подключений не проверены: " + ex.Message);
        }

        return removed;
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Verbose.Write("SignIn", "отметка профиля браузера не удалена: " + ex.Message);
        }
    }

    /// <summary>Подключение удалено: его профиль браузера (cookie и вход организации) больше не нужен.</summary>
    public void Delete(Guid profileId)
    {
        if (!Directory.Exists(ProfilesFolder)) { return; }
        var marker = FolderOf(profileId) + ".delete";
        try { File.WriteAllText(marker, ""); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Verbose.Write("SignIn", "Не удалось запланировать удаление профиля браузера: " + ex.Message);
        }
        DeleteMarked(marker);
    }

    private void RetryPendingDeletes()
    {
        if (!Directory.Exists(ProfilesFolder)) { return; }
        foreach (var marker in Directory.EnumerateFiles(ProfilesFolder, "*.delete")) { DeleteMarked(marker); }
    }

    private void DeleteMarked(string marker)
    {
        if (!Guid.TryParseExact(Path.GetFileNameWithoutExtension(marker), "N", out var id)) { return; }
        var folder = FolderOf(id);
        TryDelete(folder, "профиль браузера удаленного подключения");
        if (Directory.Exists(folder)) { return; }
        TryDeleteFile(HostMarkerOf(id));
        try { File.Delete(marker); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Verbose.Write("SignIn", "Отметка удаления профиля браузера осталась для следующей попытки: " + ex.Message);
        }
    }

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
