using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using SplitVpn.Core.Net;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Net;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Cli.Proto;

/// <summary>
/// S0. Что доступно через туннель: DNS и TCP к набору адресов строго через PPP-интерфейс (IP_UNICAST_IF)
/// и страна выхода. Маршруты и фильтры не меняются.
/// </summary>
internal static class TunnelDiagScenario
{
    private static readonly string[] DnsServers = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "198.51.100.50", "77.88.8.8"];

    private static readonly string[] TcpTargets = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "104.16.132.229", "142.250.74.46", "77.88.55.242", "5.255.255.242"];

    public static async Task<int> RunAsync(CliArgs args)
    {
        var report = new ScenarioReport("s0-tunnel");
        var profile = ProtoContext.LoadProfile();
        var password = ProtoContext.LoadPassword();
        RasConnectionHandle? connection = null;
        try
        {
            RasPhonebook.Save(ProtoContext.Phonebook, new RasEntrySpec(ProtoContext.EntryName, profile.Server));
            connection = await RasScenario.DialAndDescribeAsync(report, profile, password);
            var tunnel = connection is null ? null : RasScenario.FindTunnel(RasClient.GetProjection(connection.Value).ClientAddress);
            if (tunnel is null)
            {
                return await report.SaveAsync(args, [profile.UserName, profile.Server]);
            }

            var index = tunnel.InterfaceIndex;
            if (args.Flag("--with-routes"))
            {
                AddTunnelRoutes(report, tunnel);
            }

            foreach (var server in DnsServers)
            {
                var stopwatch = Stopwatch.StartNew();
                var answer = await BootstrapResolver.ResolveAsync("example.com", [Ipv4.Parse(server)], index, CancellationToken.None);
                report.Measure("dns " + server, answer.Count > 0 ? $"{answer.Count} адр. за {stopwatch.ElapsedMilliseconds} мс" : "нет ответа");
            }

            foreach (var target in TcpTargets)
            {
                report.Measure("tcp443 " + target, await TcpViaAsync(target, 443, index));
            }

            report.Measure("exit", await ExitInfoAsync(index));
        }
        catch (Exception ex)
        {
            report.Fail("Диагностика туннеля", ex);
        }
        finally
        {
            Array.Clear(password);
            var cleanup = RouteOps.RemoveAllMarked();
            report.Measure("cleanupRoutesRemoved", cleanup.Removed);
            if (connection is { } handle)
            {
                await RasClient.HangUpAsync(handle, CancellationToken.None);
            }
        }

        return await report.SaveAsync(args, [profile.UserName, profile.Server]);
    }

    /// <summary>/1 через туннель и прямой /32 к российскому DNS сервера через основной адаптер.</summary>
    private static void AddTunnelRoutes(ScenarioReport report, AdapterCandidate tunnel)
    {
        var primary = ProtoNet.PrimaryAdapter(NetInventory.Capture());
        var codes = new[]
        {
            RouteOps.Add(new RouteKey(Ipv4Cidr.Parse("0.0.0.0/1"), 0, tunnel.Luid)),
            RouteOps.Add(new RouteKey(Ipv4Cidr.Parse("128.0.0.0/1"), 0, tunnel.Luid)),
            RouteOps.Add(new RouteKey(Ipv4Cidr.Parse("198.51.100.0/24"), primary.DefaultGateway!.Value, primary.Luid)),
        };
        report.Check("Маршруты /1 через туннель и прямой 198.51.100.0/24 через основной адаптер", codes.All(c => c == 0), string.Join(", ", codes));
    }

    private static async Task<string> TcpViaAsync(string target, int port, uint interfaceIndex)
    {
        using var socket = UnicastSocket.CreateTcp(interfaceIndex);
        var stopwatch = Stopwatch.StartNew();
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await socket.ConnectAsync(IPAddress.Parse(target), port, cts.Token);
            return $"соединение за {stopwatch.ElapsedMilliseconds} мс с {socket.LocalEndPoint}";
        }
        catch (OperationCanceledException)
        {
            return "таймаут";
        }
        catch (SocketException ex)
        {
            return ex.SocketErrorCode.ToString();
        }
    }

    /// <summary>Внешний IP и страна выхода по ответу ipinfo.io, запрос строго через туннель.</summary>
    private static async Task<string> ExitInfoAsync(uint interfaceIndex)
    {
        var addresses = await BootstrapResolver.ResolveAsync("ipinfo.io", [Ipv4.Parse("198.51.100.50"), Ipv4.Parse("77.88.8.8")], interfaceIndex, CancellationToken.None);
        if (addresses.Count == 0)
        {
            return "не удалось разрешить ipinfo.io через туннель";
        }

        using var socket = UnicastSocket.CreateTcp(interfaceIndex);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await socket.ConnectAsync(Ipv4.ToAddress(addresses[0]), 443, cts.Token);
        await using var network = new NetworkStream(socket, ownsSocket: false);
        await using var tls = new SslStream(network);
        await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = "ipinfo.io" }, cts.Token);
        var request = Encoding.ASCII.GetBytes("GET /json HTTP/1.1\r\nHost: ipinfo.io\r\nUser-Agent: SplitVpn-dev\r\nConnection: close\r\n\r\n");
        await tls.WriteAsync(request, cts.Token);
        using var reader = new StreamReader(tls, Encoding.UTF8);
        var response = await reader.ReadToEndAsync(cts.Token);
        var body = response[(response.IndexOf("\r\n\r\n", StringComparison.Ordinal) + 4)..];
        return string.Join(" ", body.Split('\n').Where(l => l.Contains("\"ip\"", StringComparison.Ordinal) || l.Contains("\"country\"", StringComparison.Ordinal) || l.Contains("\"city\"", StringComparison.Ordinal) || l.Contains("\"org\"", StringComparison.Ordinal)).Select(l => l.Trim()));
    }
}
