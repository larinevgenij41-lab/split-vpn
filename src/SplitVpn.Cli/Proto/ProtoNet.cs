using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using SplitVpn.Core.Geo;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Windows.Net;

namespace SplitVpn.Cli.Proto;

internal enum ProbeOutcome
{
    Connected,
    Blocked,
    Refused,
    Timeout,
    Error,
}

internal sealed record ProbeResult(ProbeOutcome Outcome, string? LocalAddress, double Milliseconds, string? Error);

/// <summary>Сетевые пробы и выборки для проверок прототипа.</summary>
internal static class ProtoNet
{
    public static readonly uint[] ForeignTargets = [Ipv4.Parse("1.1.1.1"), Ipv4.Parse("8.8.8.8")];

    public static readonly uint[] RussianTargets = [Ipv4.Parse("77.88.55.242"), Ipv4.Parse("5.255.255.242")];

    /// <summary>Маршруты 0.0.0.0/1 и 128.0.0.0/1 через туннель: без них IP_UNICAST_IF к туннелю даёт NetworkUnreachable.</summary>
    public static IReadOnlyList<uint> AddHalfRoutes(ulong tunnelLuid)
    {
        return [RouteOps.Add(new RouteKey(Ipv4Cidr.Parse("0.0.0.0/1"), 0, tunnelLuid)), RouteOps.Add(new RouteKey(Ipv4Cidr.Parse("128.0.0.0/1"), 0, tunnelLuid))];
    }

    public static AdapterCandidate PrimaryAdapter(NetSnapshot snapshot)
    {
        return PrimaryAdapterSelector.Select(snapshot.Adapters, null, false).Adapter
            ?? throw new InvalidOperationException("Нет основного адаптера с маршрутом по умолчанию.");
    }

    public static RangeSet LoadGeo(string path)
    {
        var validation = GeoValidator.Validate(GeoListParser.Parse(File.ReadAllText(path)));
        if (!validation.IsValid)
        {
            throw new InvalidOperationException("RU-база не прошла проверку: " + string.Join(" ", validation.Problems));
        }

        return validation.V4;
    }

    /// <summary>TCP-подключение с таймаутом; при блокировке WFP connect сразу возвращает WSAEACCES.</summary>
    public static async Task<ProbeResult> TcpAsync(uint remote, int port, uint? bindLocal, TimeSpan timeout)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        var stopwatch = Stopwatch.StartNew();
        try
        {
            if (bindLocal is { } local)
            {
                socket.Bind(new IPEndPoint(Ipv4.ToAddress(local), 0));
            }

            using var cts = new CancellationTokenSource(timeout);
            await socket.ConnectAsync(new IPEndPoint(Ipv4.ToAddress(remote), port), cts.Token);
            var localEndpoint = (IPEndPoint?)socket.LocalEndPoint;
            return new ProbeResult(ProbeOutcome.Connected, localEndpoint?.Address.ToString(), stopwatch.Elapsed.TotalMilliseconds, null);
        }
        catch (OperationCanceledException)
        {
            return new ProbeResult(ProbeOutcome.Timeout, null, stopwatch.Elapsed.TotalMilliseconds, "таймаут");
        }
        catch (SocketException ex)
        {
            var outcome = ex.SocketErrorCode switch
            {
                SocketError.AccessDenied => ProbeOutcome.Blocked,
                SocketError.ConnectionRefused => ProbeOutcome.Refused,
                _ => ProbeOutcome.Error,
            };
            return new ProbeResult(outcome, null, stopwatch.Elapsed.TotalMilliseconds, ex.SocketErrorCode.ToString());
        }
    }

    /// <summary>Отправка UDP-датаграммы: разрешение ALE проверяется на первой отправке.</summary>
    public static async Task<ProbeResult> UdpSendAsync(uint remote, int port, uint? bindLocal)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        var stopwatch = Stopwatch.StartNew();
        try
        {
            if (bindLocal is { } local)
            {
                socket.Bind(new IPEndPoint(Ipv4.ToAddress(local), 0));
            }

            await socket.SendToAsync(new byte[32], new IPEndPoint(Ipv4.ToAddress(remote), port));
            return new ProbeResult(ProbeOutcome.Connected, ((IPEndPoint?)socket.LocalEndPoint)?.Address.ToString(), stopwatch.Elapsed.TotalMilliseconds, null);
        }
        catch (SocketException ex)
        {
            var outcome = ex.SocketErrorCode == SocketError.AccessDenied ? ProbeOutcome.Blocked : ProbeOutcome.Error;
            return new ProbeResult(outcome, null, stopwatch.Elapsed.TotalMilliseconds, ex.SocketErrorCode.ToString());
        }
    }

    public static IReadOnlyList<uint> SampleRanges(RangeSet set, int count, Random random)
    {
        var result = new List<uint>(count);
        for (var i = 0; i < count && set.Count > 0; i++)
        {
            var range = set[random.Next(set.Count)];
            result.Add((uint)(range.Start + (ulong)random.NextInt64(0, (long)range.Size)));
        }

        return result;
    }

    /// <summary>Случайные публичные адреса вне прямого, локального и зарезервированного пространства.</summary>
    public static IReadOnlyList<uint> SampleForeign(CompiledPolicy policy, int count, Random random)
    {
        var result = new List<uint>(count);
        while (result.Count < count)
        {
            var address = (uint)random.NextInt64(0x01000000, 0xE0000000);
            var decision = policy.Classify(address);
            if (decision is { Decision: Decision.Vpn, Source: DecisionSource.Default })
            {
                result.Add(address);
            }
        }

        return result;
    }

    /// <summary>Доля адресов, лучший маршрут к которым идёт через ожидаемый интерфейс.</summary>
    public static (int Matched, int Total, IReadOnlyList<string> Examples) VerifyRoutes(IEnumerable<uint> addresses, ulong expectedLuid)
    {
        var total = 0;
        var matched = 0;
        var examples = new List<string>();
        foreach (var address in addresses)
        {
            total++;
            var route = RouteOps.FindBestRoute(address);
            if (route?.InterfaceLuid == expectedLuid)
            {
                matched++;
            }
            else if (examples.Count < 5)
            {
                examples.Add($"{Ipv4.Format(address)} → {(route is null ? "нет маршрута" : route.Destination + " luid " + route.InterfaceLuid)}");
            }
        }

        return (matched, total, examples);
    }

    public static async Task<double[]> LoopbackConnectLatencyAsync(int count)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start(count);
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var accept = Task.Run(async () =>
        {
            for (var i = 0; i < count; i++)
            {
                using var client = await listener.AcceptTcpClientAsync();
            }
        });

        var samples = new double[count];
        for (var i = 0; i < count; i++)
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            var stopwatch = Stopwatch.StartNew();
            await socket.ConnectAsync(IPAddress.Loopback, port);
            samples[i] = stopwatch.Elapsed.TotalMilliseconds;
        }

        await accept;
        Array.Sort(samples);
        return samples;
    }

    public static double Percentile(double[] sorted, double p) => sorted.Length == 0 ? 0 : sorted[(int)Math.Min(sorted.Length - 1, Math.Round(p * (sorted.Length - 1)))];
}
