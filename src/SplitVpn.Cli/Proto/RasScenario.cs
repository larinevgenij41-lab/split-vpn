using SplitVpn.Core.Net;
using SplitVpn.Core.State;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Cli.Proto;

/// <summary>S2. Своя запись RAS: создание, дозвон (в том числе от SYSTEM), проекция, подхват из другого процесса.</summary>
internal static class RasScenario
{
    public static readonly TimeSpan DialTimeout = TimeSpan.FromSeconds(60);

    /// <summary>Создать запись в своей телефонной книге и сравнить с рабочим профилем пользователя.</summary>
    public static async Task<int> EntryAsync(CliArgs args)
    {
        var report = new ScenarioReport("s2-entry");
        var profile = ProtoContext.LoadProfile();
        try
        {
            ProtoContext.EnsureRoot();
            RasPhonebook.Save(ProtoContext.Phonebook, new RasEntrySpec(ProtoContext.EntryName, profile.Server));
            var ours = RasPhonebook.Describe(ProtoContext.Phonebook, ProtoContext.EntryName);
            report.Check("Запись создана в своей телефонной книге", ours.Count > 0, ProtoContext.Phonebook);
            var reference = args.Option("--compare") ?? "SSTP Germany";
            if (RasPhonebook.Exists(null, reference))
            {
                var theirs = RasPhonebook.Describe(null, reference);
                foreach (var key in ours.Keys.Where(k => theirs.GetValueOrDefault(k) != ours[k]))
                {
                    report.Note($"отличие {key}: наша {ours[key]}, «{reference}» {theirs.GetValueOrDefault(key)}");
                }
            }
            else
            {
                report.Note($"Профиль «{reference}» не найден в телефонной книге пользователя — сравнение пропущено.");
            }
        }
        catch (Exception ex)
        {
            report.Fail("Создание записи", ex);
        }

        return await report.SaveAsync(args, [profile.UserName, profile.Server]);
    }

    /// <summary>Дозвон без маршрутов по умолчанию; соединение остаётся после выхода процесса.</summary>
    public static async Task<int> DialAsync(CliArgs args)
    {
        var report = new ScenarioReport("s2-dial");
        var profile = ProtoContext.LoadProfile();
        var password = ProtoContext.LoadPassword();
        try
        {
            RasPhonebook.Save(ProtoContext.Phonebook, new RasEntrySpec(ProtoContext.EntryName, profile.Server));
            var routesBefore = NetInventory.ReadRoutesV4().Select(r => r.Destination + "→" + Ipv4.Format(r.NextHop)).ToHashSet();
            var connection = await DialAndDescribeAsync(report, profile, password);
            if (connection is null)
            {
                return await report.SaveAsync(args, [profile.UserName, profile.Server]);
            }

            var added = NetInventory.ReadRoutesV4().Select(r => r.Destination + "→" + Ipv4.Format(r.NextHop)).Where(r => !routesBefore.Contains(r)).ToList();
            report.Measure("routesAddedByRas", added);
            report.Check("RAS не поставил маршрут по умолчанию", !added.Any(r => r.StartsWith("0.0.0.0/0", StringComparison.Ordinal) || r.StartsWith("0.0.0.0/1", StringComparison.Ordinal)), string.Join(", ", added));
            if (args.Flag("--hangup"))
            {
                await RasClient.HangUpAsync(connection.Value, CancellationToken.None);
                report.Note("Соединение разорвано в том же процессе.");
            }
            else
            {
                report.Note("Процесс завершается без HangUp: проверка подхвата — «proto s2-adopt».");
            }
        }
        catch (Exception ex)
        {
            report.Fail("Дозвон", ex);
        }
        finally
        {
            Array.Clear(password);
        }

        return await report.SaveAsync(args, [profile.UserName, profile.Server]);
    }

    /// <summary>Новый процесс находит соединение своей телефонной книги, проверяет состояние и разрывает его.</summary>
    public static async Task<int> AdoptAsync(CliArgs args)
    {
        var report = new ScenarioReport("s2-adopt");
        try
        {
            var ours = RasClient.EnumerateConnections()
                .Where(c => string.Equals(c.Phonebook, ProtoContext.Phonebook, StringComparison.OrdinalIgnoreCase))
                .ToList();
            report.Check("Соединение пережило завершение дозвонившего процесса", ours.Count == 1, $"найдено {ours.Count}");
            foreach (var connection in ours)
            {
                var status = RasClient.GetStatus(connection.Handle);
                report.Check("Подхваченное соединение в состоянии Connected", status.Status == RasConnectionStatus.Connected, status.ToString());
                await RasClient.HangUpAsync(connection.Handle, CancellationToken.None);
                report.Check("HangUp освободил соединение", RasClient.GetStatus(connection.Handle).Status == RasConnectionStatus.Gone, "дескриптор недействителен");
            }
        }
        catch (Exception ex)
        {
            report.Fail("Подхват", ex);
        }

        return await report.SaveAsync(args, []);
    }

    /// <summary>Дозвон с проверкой проекции и туннельного интерфейса; общий для S2–S4.</summary>
    public static async Task<RasConnectionHandle?> DialAndDescribeAsync(ScenarioReport report, ProtoProfile profile, char[] password)
    {
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var result = await RasClient.DialAsync(ProtoContext.Phonebook, ProtoContext.EntryName, profile.UserName, password, profile.Domain, DialTimeout, CancellationToken.None);
        report.Measure("dialSeconds", Math.Round(stopwatch.Elapsed.TotalSeconds, 1));
        if (!report.Check("SSTP подключился через свою запись", result.Success, result.Success ? "Connected" : $"код {result.ErrorCode}: {result.ErrorText}; категория {RasErrorClassifier.Classify((int)result.ErrorCode).Category}"))
        {
            return null;
        }

        var handle = result.Handle!.Value;
        var projection = RasClient.GetProjection(handle);
        report.Measure("vpnClientAddress", Ipv4.Format(projection.ClientAddress));
        report.Measure("vpnServerAddress", Ipv4.Format(projection.ServerAddress));
        var tunnel = FindTunnel(projection.ClientAddress);
        if (report.Check("Найден PPP-интерфейс туннеля", tunnel is not null, tunnel is null ? "нет интерфейса с адресом проекции" : $"{tunnel.Name}, luid {tunnel.Luid}, index {tunnel.InterfaceIndex}"))
        {
            var dns = InterfaceDnsOps.Read(tunnel!.InterfaceGuid, ipv6: false);
            report.Measure("tunnelDns", new { dns.NameServer, dns.ProfileNameServer, registry = tunnel.DnsServers.Select(Ipv4.Format) });
        }

        return handle;
    }

    public static AdapterCandidate? FindTunnel(uint clientAddress)
    {
        return NetInventory.Capture().Adapters.FirstOrDefault(a => a.Addresses.Contains(clientAddress));
    }
}
