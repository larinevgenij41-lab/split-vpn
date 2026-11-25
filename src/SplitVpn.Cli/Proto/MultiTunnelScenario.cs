using SplitVpn.Core.Net;
using SplitVpn.Windows.Diagnostics;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.Operations;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Cli.Proto;

/// <summary>
/// S6. Два туннеля одновременно: две записи телефонной книги, два дозвона, проба с привязкой к адресу
/// каждого туннеля и подхват обоих соединений из нового процесса. Это проверка гипотезы v2 на живом
/// оборудовании; служба при этом должна быть остановлена, иначе она снимет пробные маршруты.
/// </summary>
internal static class MultiTunnelScenario
{
    private static readonly TimeSpan DialTimeout = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(6);

    /// <summary>s6-multi [--target 1.1.1.1:443]: поднять оба туннеля и проверить выход через каждый.</summary>
    public static async Task<int> RunAsync(CliArgs args)
    {
        var report = new ScenarioReport("s6-multi");
        var target = ParseTarget(args.Option("--target") ?? "1.1.1.1:443");
        var first = ProtoContext.LoadProfile(1);
        var second = ProtoContext.LoadProfile(2);
        var secrets = new[] { first.UserName, first.Server, second.UserName, second.Server };
        if (!ProtoContext.RequireServiceStopped(report))
        {
            return await report.SaveAsync(args, secrets);
        }

        ProtoContext.EnsureRoot();
        var connections = new List<(string Entry, RasConnectionHandle Handle, AdapterCandidate Adapter)>();
        // Соединение, уже набранное, но ещё не попавшее в список: его тоже нужно разорвать при сбое или Ctrl+C.
        RasConnectionHandle? pending = null;
        try
        {
            await RunStepsAsync();
        }
        catch (Exception ex)
        {
            report.Fail("Спайк двух туннелей", ex);
        }

        // Очистка ровно один раз — и после ранней остановки, и после сбоя.
        return await FinishAsync(report, args, connections, secrets, pending);

        async Task RunStepsAsync()
        {
            foreach (var (profile, slot) in new[] { (first, 1), (second, 2) })
            {
                var entry = ProtoContext.EntryNameFor(slot);
                RasPhonebook.Save(ProtoContext.Phonebook, new RasEntrySpec(entry, profile.Server));
                var password = ProtoContext.LoadPassword(slot);
                RasDialResult result;
                try
                {
                    result = await RasClient.DialAsync(ProtoContext.Phonebook, entry, profile.UserName, password, profile.Domain, DialTimeout, CancellationToken.None);
                }
                finally
                {
                    Array.Clear(password);
                }

                pending = result.Handle;
                report.Check($"Туннель {slot} подключён", result.Success, result.ErrorText + " код " + result.ErrorCode);
                if (!result.Success || result.Handle is not { } handle)
                {
                    return;
                }

                var projection = RasClient.GetProjection(handle);
                var adapter = NetInventory.Capture().Adapters.FirstOrDefault(a => a.Addresses.Contains(projection.ClientAddress));
                report.Check($"Интерфейс туннеля {slot} найден", adapter is not null, Ipv4.Format(projection.ClientAddress));
                if (adapter is null)
                {
                    return;
                }

                connections.Add((entry, handle, adapter));
                pending = null;
                report.Note($"туннель {slot}: адрес {Ipv4.Format(projection.ClientAddress)}, интерфейс {adapter.Name}, LUID {adapter.Luid}");
            }

            report.Check("Туннели на разных интерфейсах", connections[0].Adapter.Luid != connections[1].Adapter.Luid,
                $"{connections[0].Adapter.Name} / {connections[1].Adapter.Name}");
            await ProbeEachAsync(report, connections, target);
            CheckAdoption(report, connections);
        }
    }

    /// <summary>Проба цели через каждый туннель: временный маршрут /32 и сокет, привязанный к его адресу.</summary>
    private static async Task ProbeEachAsync(
        ScenarioReport report,
        List<(string Entry, RasConnectionHandle Handle, AdapterCandidate Adapter)> connections,
        (uint Address, ushort Port) target)
    {
        var probes = new SystemProbeOps();
        foreach (var (index, connection) in connections.Index())
        {
            var route = new RouteKey(new Ipv4Cidr(target.Address, 32), 0, connection.Adapter.Luid);
            var applied = RouteOps.Reconcile([route]);
            report.Check($"Маршрут пробы на туннель {index + 1} поставлен", applied.Failed == 0, string.Join("; ", applied.Errors));
            var local = connection.Adapter.Addresses.Count > 0 ? connection.Adapter.Addresses[0] : (uint?)null;
            var result = await probes.TcpAsync(target.Address, target.Port, local, ProbeTimeout, CancellationToken.None);
            report.Check(
                $"Проба через туннель {index + 1} ушла с его адреса",
                result.Connected && result.LocalAddress == local,
                $"соединение {result.Connected}, локальный адрес {(result.LocalAddress is { } l ? Ipv4.Format(l) : "нет")}, ошибка {result.Error}");
        }

        RouteOps.Reconcile([]);
    }

    /// <summary>Подхват: оба соединения видны как записи своей телефонной книги.</summary>
    private static void CheckAdoption(ScenarioReport report, List<(string Entry, RasConnectionHandle Handle, AdapterCandidate Adapter)> connections)
    {
        var own = RasClient.EnumerateConnections()
            .Where(c => string.Equals(Path.GetFullPath(c.Phonebook), Path.GetFullPath(ProtoContext.Phonebook), StringComparison.OrdinalIgnoreCase))
            .ToList();
        report.Check("Оба соединения видны для подхвата", own.Count == connections.Count, "найдено " + own.Count);
        foreach (var (entry, _, _) in connections)
        {
            report.Check($"Запись «{entry}» среди активных", own.Any(c => string.Equals(c.EntryName, entry, StringComparison.OrdinalIgnoreCase)),
                string.Join(", ", own.Select(c => c.EntryName)));
        }
    }

    private static async Task<int> FinishAsync(
        ScenarioReport report,
        CliArgs args,
        List<(string Entry, RasConnectionHandle Handle, AdapterCandidate Adapter)> connections,
        string[] secrets,
        RasConnectionHandle? pending = null)
    {
        // Спайк всегда заканчивается снятыми маршрутами и разорванными соединениями. Каждый шаг очистки
        // защищён отдельно: сбой одного не отменяет остальные.
        report.BeginCleanup();
        var clean = true;
        try
        {
            RouteOps.Reconcile([]);
        }
        catch (Exception ex)
        {
            clean = false;
            report.Fail("Снятие маршрутов пробы", ex);
        }

        foreach (var handle in connections.Select(c => c.Handle).Concat(pending is { } dialed ? [dialed] : []))
        {
            try
            {
                await RasClient.HangUpAsync(handle, CancellationToken.None);
            }
            catch (Exception ex)
            {
                clean = false;
                report.Fail("Разрыв соединения", ex);
            }
        }

        foreach (var slot in new[] { 1, 2 })
        {
            try
            {
                RasPhonebook.Delete(ProtoContext.Phonebook, ProtoContext.EntryNameFor(slot));
            }
            catch (Exception ex)
            {
                clean = false;
                report.Fail($"Удаление записи {slot}", ex);
            }
        }

        report.Note(clean ? "соединения разорваны, записи удалены, маршруты сняты" : "очистка выполнена не полностью — см. ошибки");
        return await report.SaveAsync(args, secrets);
    }

    private static (uint Address, ushort Port) ParseTarget(string text)
    {
        var parts = text.Split(':');
        if (parts.Length != 2 || !Ipv4.TryParse(parts[0], out var address) || !ushort.TryParse(parts[1], out var port))
        {
            throw new FormatException("Цель пробы задаётся как IP:порт, например 1.1.1.1:443.");
        }

        return (address, port);
    }
}
