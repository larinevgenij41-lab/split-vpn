using System.Text.Json;
using SplitVpn.Core.Settings;
using SplitVpn.Windows.Recovery;
using SplitVpn.Windows.Wfp;

namespace SplitVpn.Cli.Proto;

/// <summary>Аварийное восстановление сети для окружения разработки (прототип и продукт).</summary>
internal static class RecoverCommand
{
    public static async Task<int> RunAsync(CliArgs args)
    {
        var productPhonebook = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SplitVpn", "splitvpn.pbk");
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var report = await NetworkRecovery.RunAsync(new RecoveryOptions
        {
            ServiceDirectory = PrototypeServiceDirectory(programFiles),
            AdditionalServiceDirectories = ProductServiceDirectories(programFiles, NetworkRecovery.RegisteredServiceDirectory(ServiceCommands.ServiceName)),
            Phonebooks = [ProtoContext.Phonebook, productPhonebook],
            WfpIdentities = [WfpIdentity.Prototype, WfpIdentity.Product],
            DnsBackupPath = Path.Combine(Path.GetDirectoryName(productPhonebook)!, "dns-backup.json"),
            AdditionalDnsBackupPath = ProtoContext.DnsBackupPath,
        }, CancellationToken.None);

        Console.WriteLine(JsonSerializer.Serialize(report, JsonDefaults.Options));
        return report.Success ? 0 : 1;
    }

    /// <summary>Каталог службы прототипа (развёртывание разработчика).</summary>
    internal static string PrototypeServiceDirectory(string programFiles) => Path.Combine(programFiles, "SplitVpn.Dev", "service");

    /// <summary>
    /// Каталоги установленного продукта, где лежат его помощники (рядом с файлом службы): по регистрации службы, если она
    /// есть, и всегда каталог установки по умолчанию (installer/Package.wxs) — на случай, если регистрация уже снята,
    /// а помощник ещё работает. Повторы снимает <see cref="NetworkRecovery.StopHelpers(IReadOnlyList{string})"/>.
    /// </summary>
    internal static IReadOnlyList<string> ProductServiceDirectories(string programFiles, string? registeredDirectory)
    {
        var installDirectory = Path.Combine(programFiles, "SplitVpn");
        return registeredDirectory is null ? [installDirectory] : [registeredDirectory, installDirectory];
    }
}
