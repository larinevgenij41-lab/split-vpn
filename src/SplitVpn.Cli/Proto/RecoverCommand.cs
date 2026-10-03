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
        var report = await NetworkRecovery.RunAsync(new RecoveryOptions
        {
            Phonebooks = [ProtoContext.Phonebook, productPhonebook],
            WfpIdentities = [WfpIdentity.Prototype, WfpIdentity.Product],
            DnsBackupPath = ProtoContext.DnsBackupPath,
        }, CancellationToken.None);

        Console.WriteLine(JsonSerializer.Serialize(report, JsonDefaults.Options));
        return report.Success ? 0 : 1;
    }
}
