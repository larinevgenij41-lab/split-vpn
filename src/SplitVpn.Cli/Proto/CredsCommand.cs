using System.Text.Json;
using SplitVpn.Core.Net;
using SplitVpn.Core.Settings;
using SplitVpn.Windows.Security;

namespace SplitVpn.Cli.Proto;

/// <summary>Учётные данные прототипа: пароль вводится только в окне консоли и хранится через DPAPI.</summary>
internal static class CredsCommand
{
    public static Task<int> RunAsync(CliArgs args)
    {
        var action = args.Positional(0);
        return Task.FromResult(action switch
        {
            "set" => Set(args),
            "show" => Show(),
            "delete" => Delete(),
            "export" => Export(args),
            _ => Usage(),
        });
    }

    private static int Set(CliArgs args)
    {
        var server = args.Option("--server");
        var user = args.Option("--user");
        if (string.IsNullOrWhiteSpace(server))
        {
            return Usage();
        }

        if (string.IsNullOrWhiteSpace(user))
        {
            Console.Write($"Имя пользователя SSTP для {server}: ");
            user = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(user))
            {
                Console.WriteLine("Имя пользователя пустое — ничего не сохранено.");
                return 1;
            }
        }

        if (!ServerAddress.TryParse(server, out _))
        {
            Console.WriteLine("Неверный адрес сервера: ожидается «хост» или «хост:порт».");
            return 2;
        }

        ProtoContext.EnsureRoot();
        var password = ReadPassword(args, user, server);
        try
        {
            if (password.Count == 0)
            {
                Console.WriteLine("Пароль пустой — ничего не сохранено.");
                return 1;
            }

            var slot = int.TryParse(args.Option("--slot"), out var parsed) && parsed == 2 ? 2 : 1;
            var profile = new ProtoProfile(server.Trim(), user.Trim(), args.Option("--domain"));
            AtomicFile.WriteAllText(ProtoContext.ProfilePathFor(slot), JsonSerializer.Serialize(profile, JsonDefaults.Options));
            new SecretStore(ProtoContext.SecretPath).Save(ProtoContext.ProfileIdFor(slot), password.ToArray());
            Console.WriteLine($"Профиль и пароль прототипа {slot} сохранены.");
            return 0;
        }
        finally
        {
            password.Clear();
        }
    }

    /// <summary>
    /// Пароль из консоли или из одноразового файла (--password-file): файл удаляется сразу после чтения,
    /// поэтому пароль не попадает в командную строку и журнал.
    /// </summary>
    private static List<char> ReadPassword(CliArgs args, string user, string server)
    {
        var file = args.Option("--password-file");
        if (file is null)
        {
            Console.Write($"Пароль для {user}@{server} (ввод скрыт): ");
            return ReadMasked();
        }

        try
        {
            return [.. File.ReadAllText(file).TrimEnd('\r', '\n')];
        }
        finally
        {
            File.Delete(file);
        }
    }

    private static int Show()
    {
        foreach (var slot in new[] { 1, 2 })
        {
            if (!File.Exists(ProtoContext.ProfilePathFor(slot)))
            {
                continue;
            }

            var profile = ProtoContext.LoadProfile(slot);
            var hasSecret = new SecretStore(ProtoContext.SecretPath).Contains(ProtoContext.ProfileIdFor(slot));
            Console.WriteLine($"Слот {slot}: сервер {profile.Server}; пользователь задан: {!string.IsNullOrEmpty(profile.UserName)}; пароль сохранён: {hasSecret}");
        }

        return 0;
    }

    /// <summary>
    /// Только для автоматических испытаний интерфейса: пароль прототипа в одноразовый файл, доступный лишь
    /// администраторам и SYSTEM. Читающий сценарий обязан удалить файл сразу после чтения.
    /// </summary>
    private static int Export(CliArgs args)
    {
        if (args.Option("--file") is not { } file)
        {
            Console.WriteLine("creds export --file <файл>");
            return 2;
        }

        var password = ProtoContext.LoadPassword();
        try
        {
            var security = new System.Security.AccessControl.FileSecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            foreach (var sid in new[] { System.Security.Principal.WellKnownSidType.LocalSystemSid, System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid })
            {
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    new System.Security.Principal.SecurityIdentifier(sid, null),
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.AccessControlType.Allow));
            }

            using var stream = new FileInfo(file).Create(FileMode.Create, System.Security.AccessControl.FileSystemRights.Write, FileShare.None, 4096, FileOptions.None, security);
            using var writer = new StreamWriter(stream, new System.Text.UTF8Encoding(false));
            writer.Write(password);
            Console.WriteLine("Пароль записан в одноразовый файл; удалите его сразу после чтения.");
            return 0;
        }
        finally
        {
            Array.Clear(password);
        }
    }

    private static int Delete()
    {
        new SecretStore(ProtoContext.SecretPath).Delete(ProtoContext.ProfileId);
        File.Delete(ProtoContext.ProfilePath);
        Console.WriteLine("Профиль и пароль прототипа удалены.");
        return 0;
    }

    private static List<char> ReadMasked()
    {
        var buffer = new List<char>();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                return buffer;
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (buffer.Count > 0)
                {
                    buffer.RemoveAt(buffer.Count - 1);
                }

                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                buffer.Add(key.KeyChar);
                Console.Write('*');
            }
        }
    }

    private static int Usage()
    {
        Console.WriteLine("creds set --server <хост[:порт]> [--user <имя>] [--password-file <файл>] [--domain <домен>] | creds show | creds delete");
        return 2;
    }
}
