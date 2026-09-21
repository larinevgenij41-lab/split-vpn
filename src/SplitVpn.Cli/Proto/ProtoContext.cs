using System.Text.Json;
using SplitVpn.Core.Settings;
using SplitVpn.Windows.Security;

namespace SplitVpn.Cli.Proto;

internal sealed record ProtoProfile(string Server, string UserName, string? Domain);

/// <summary>Окружение прототипа: отдельный каталог, телефонная книга и секрет, не пересекающиеся с продуктом.</summary>
internal static class ProtoContext
{
    public const string EntryName = "SplitVpn Proto";

    public static readonly Guid ProfileId = new("8a2d4a4e-7c43-4b8b-9e7f-4f1c2a0b9d01");

    /// <summary>Второй сервер для спайка нескольких туннелей.</summary>
    public static readonly Guid ProfileId2 = new("8a2d4a4e-7c43-4b8b-9e7f-4f1c2a0b9d02");

    /// <summary>Имя записи телефонной книги по номеру слота.</summary>
    public static string EntryNameFor(int slot) => slot <= 1 ? EntryName : EntryName + " " + slot.ToString(System.Globalization.CultureInfo.InvariantCulture);

    public static Guid ProfileIdFor(int slot) => slot <= 1 ? ProfileId : ProfileId2;

    public static string ProfilePathFor(int slot) => slot <= 1 ? ProfilePath : Path.Combine(Root, "proto2.json");

    public static ProtoProfile LoadProfile(int slot)
    {
        var path = ProfilePathFor(slot);
        if (!File.Exists(path))
        {
            throw new InvalidOperationException($"Профиль прототипа {slot} не задан: выполните «creds set --slot {slot} --server <адрес> --user <имя>».");
        }

        return JsonSerializer.Deserialize<ProtoProfile>(File.ReadAllText(path), JsonDefaults.Options)
            ?? throw new InvalidOperationException($"Профиль прототипа {slot} повреждён.");
    }

    public static char[] LoadPassword(int slot)
    {
        return new SecretStore(SecretPath).TryLoad(ProfileIdFor(slot))
            ?? throw new InvalidOperationException($"Пароль прототипа {slot} не сохранён: выполните «creds set --slot {slot}».");
    }

    public static string Root { get; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SplitVpn.Dev");

    public static string Phonebook => Path.Combine(Root, "proto.pbk");

    public static string SecretPath => Path.Combine(Root, "secret.bin");

    public static string ProfilePath => Path.Combine(Root, "proto.json");

    public static string DnsBackupPath => Path.Combine(Root, "dns-backup.json");

    public static string GeoPath(CliArgs args) => args.Option("--geo") ?? Path.Combine(Root, "ru.txt");

    public static string ReportDirectory(CliArgs args) => args.Option("--report-dir") ?? Path.Combine(Root, "reports");

    public static ProtoProfile LoadProfile()
    {
        if (!File.Exists(ProfilePath))
        {
            throw new InvalidOperationException("Профиль прототипа не задан: выполните «creds set --server <адрес> --user <имя>».");
        }

        return JsonSerializer.Deserialize<ProtoProfile>(File.ReadAllText(ProfilePath), JsonDefaults.Options)
            ?? throw new InvalidOperationException("Профиль прототипа повреждён.");
    }

    public static char[] LoadPassword()
    {
        return new SecretStore(SecretPath).TryLoad(ProfileId)
            ?? throw new InvalidOperationException("Пароль прототипа не сохранён: выполните «creds set».");
    }

    public static void EnsureRoot()
    {
        Directory.CreateDirectory(Root);
        SecretStore.RestrictToSystemAndAdministrators(Root);
    }
}
