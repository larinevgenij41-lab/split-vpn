namespace SplitVpn.Service;

/// <summary>Расположение данных службы. Каталог доступен только SYSTEM и Administrators.</summary>
public sealed record ServicePaths(string Root)
{
    public const string ServiceName = "SplitVpn";
    public const string EntryName = "Раздельный VPN";
    public const string ImageName = "SplitVpn.Service.exe";

    public static ServicePaths Default { get; } = new(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SplitVpn"));

    public string Settings => Path.Combine(Root, "settings.json");

    public string State => Path.Combine(Root, "state.json");

    public string Secrets => Path.Combine(Root, "secrets.bin");

    public string Phonebook => Path.Combine(Root, "splitvpn.pbk");

    public string DnsBackup => Path.Combine(Root, "dns-backup.json");

    public string Geo => Path.Combine(Root, "geo");

    /// <summary>Версии списка обхода блокировок: отдельно от RU-базы, чтобы откат касался только своего списка.</summary>
    public string Bypass => Path.Combine(Root, "bypass");

    public string Logs => Path.Combine(Root, "logs");
}
