using System.Text;
using SplitVpn.Cli;
using SplitVpn.Cli.Proto;

Console.OutputEncoding = Encoding.UTF8;

var commands = new Dictionary<string, Func<CliArgs, Task<int>>>(StringComparer.OrdinalIgnoreCase)
{
    ["inspect"] = InspectCommand.RunAsync,
    ["geo-fetch"] = GeoCommands.FetchAsync,
    ["compile-stats"] = GeoCommands.CompileStatsAsync,
    ["creds"] = CredsCommand.RunAsync,
    ["recover"] = RecoverCommand.RunAsync,
    ["s0-tunnel"] = TunnelDiagScenario.RunAsync,
    ["s1-scale"] = ScaleScenario.RunAsync,
    ["s2-entry"] = RasScenario.EntryAsync,
    ["s2-dial"] = RasScenario.DialAsync,
    ["s2-adopt"] = RasScenario.AdoptAsync,
    ["s3-split"] = SplitScenario.RunAsync,
    ["s4-dns"] = DnsScenario.RunAsync,
    ["s5-apply"] = PersistScenario.ApplyAsync,
    ["s6-multi"] = MultiTunnelScenario.RunAsync,
    ["s5-check"] = PersistScenario.CheckAsync,
    ["status"] = ServiceCommands.StatusAsync,
    ["events"] = ServiceCommands.EventsAsync,
    ["adapters"] = ServiceCommands.AdaptersAsync,
    ["settings"] = ServiceCommands.SettingsAsync,
    ["profile"] = ServiceCommands.ProfileAsync,
    ["password"] = ServiceCommands.PasswordAsync,
    ["connect"] = ServiceCommands.ConnectAsync,
    ["disconnect"] = ServiceCommands.DisconnectAsync,
    ["recover-network"] = ServiceCommands.RecoverNetworkAsync,
    ["check"] = ServiceCommands.CheckAsync,
    ["test-profile"] = ServiceCommands.TestProfileAsync,
    ["tunnels"] = ServiceCommands.TunnelsAsync,
    ["sign-in"] = ServiceCommands.SignInAsync,
    ["geo"] = ServiceCommands.GeoAsync,
    ["update"] = ServiceCommands.UpdateAsync,
    ["report"] = ServiceCommands.ReportAsync,
    ["ipc-probe-bad"] = ServiceCommands.ProbeBadAsync,
    ["wfp-groups"] = DevCommands.WfpGroupsAsync,
    ["wfp-delete-one"] = DevCommands.WfpDeleteOneAsync,
    ["secret-scan"] = DevCommands.SecretScanAsync,
    ["release-keygen"] = ReleaseCommands.KeygenAsync,
    ["release-sign"] = ReleaseCommands.SignAsync,
    ["release-verify"] = ReleaseCommands.VerifyAsync,
};

if (args.Length == 0 || !commands.TryGetValue(args[0], out var command))
{
    Console.WriteLine("splitvpn-cli — утилита разработки «Раздельный VPN»");
    Console.WriteLine("Диагностика:");
    Console.WriteLine("  inspect [--json <файл>]              адаптеры, маршруты, основной адаптер, конфликты, объекты WFP");
    Console.WriteLine("  geo-fetch [--out <каталог>]           скачать и проверить RU-базу Loyalsoldier");
    Console.WriteLine("  compile-stats [--file <ru.txt>]       размер политики: диапазоны, маршруты, фильтры");
    Console.WriteLine("Прототип (КТ1, с повышением):");
    Console.WriteLine("  creds set --server <адрес> --user <имя> | creds show | creds delete");
    Console.WriteLine("  s0-tunnel     что доступно через туннель и страна выхода (без маршрутов и фильтров)");
    Console.WriteLine("  s1-scale      масштаб маршрутов и фильтров (без блокировок)");
    Console.WriteLine("  s2-entry      создать запись RAS и сравнить с профилем пользователя");
    Console.WriteLine("  s2-dial       дозвон своей записью; s2-adopt — подхват и HangUp из нового процесса");
    Console.WriteLine("  s3-split      разделение с общесистемной защитой, обрыв и повтор");
    Console.WriteLine("  s4-dns        DNS-посредник, loopback на адаптере, возврат DHCP-DNS");
    Console.WriteLine("  s5-apply      persistent/static объекты WFP без влияния на трафик; s5-check — проверка и recover");
    Console.WriteLine("  recover       аварийное восстановление сети (прототип и продукт)");
    Console.WriteLine("Общие опции: --geo <ru.txt>, --report-dir <каталог>");
    Console.WriteLine("Служба (IPC, без повышения):");
    Console.WriteLine("  status [--json] | events [--since N] [--last N] | adapters");
    Console.WriteLine("  settings get [--out <файл>] | settings set --file <файл>");
    Console.WriteLine("  profile set --name <имя> --server <хост:порт> --user <имя> [--password-file <файл>]");
    Console.WriteLine("  password --password-file <файл> [--profile <id>]");
    Console.WriteLine("  connect | disconnect [--keep-protection] | recover-network");
    Console.WriteLine("  check <IP или домен> | test-profile [--profile <id>]");
    Console.WriteLine("  geo update|rollback|accept|reject|clear-skipped|import --file <ru.txt> [--list geo|bypass]");
    Console.WriteLine("  update [status]|check|download|install|skip [--version <версия>]");
    Console.WriteLine("  report [--out <файл>] [--no-mask] | ipc-probe-bad");
    Console.WriteLine("Выпуск релиза (только разработка):");
    Console.WriteLine("  release-keygen --out <файл> [--kid <id>]   создать ключ подписи манифеста обновлений");
    Console.WriteLine("  release-sign --manifest <файл> --key <файл>");
    Console.WriteLine("  release-verify --manifest <файл> --signature <файл> [--package <msi>]");
    return 2;
}

try
{
    return await command(new CliArgs(args.Skip(1).ToArray()));
}
catch (Exception ex)
{
    Console.Error.WriteLine("Ошибка: " + ex.Message);
    return 1;
}
