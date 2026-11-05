using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.OpenConnect;

namespace OcSpike;

/// <summary>
/// Стенд КТ3: этот процесс играет роль службы — запускает SplitVpn.OpenConnect.exe с анонимными трубами,
/// показывает окно SSO, отвечает на запрос адреса шлюза, через заданное время отправляет Stop.
/// </summary>
internal static partial class Program
{
    private static int RunHelperDrive()
    {
        var helper = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, @"..\..\..\..\..\..\src\SplitVpn.OpenConnect\bin\Release\net10.0-windows10.0.19041.0\win-x64\SplitVpn.OpenConnect.exe"));
        Report["helper"] = helper;
        using var toHelper = new AnonymousPipeServerStream(PipeDirection.Out, HandleInheritability.Inheritable);
        using var fromHelper = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable);
        var start = new ProcessStartInfo(helper)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add("--pipes");
        start.ArgumentList.Add(toHelper.GetClientHandleAsString());
        start.ArgumentList.Add(fromHelper.GetClientHandleAsString());
        using var process = Process.Start(start)!;
        toHelper.DisposeLocalCopyOfClientHandle();
        fromHelper.DisposeLocalCopyOfClientHandle();
        process.ErrorDataReceived += (_, e) => { if (e.Data is not null) Log("[helper stderr] " + e.Data); };
        process.BeginErrorReadLine();

        var events = new JsonArray();
        Report["helperEvents"] = events;
        var writeLock = new object();
        void Send(HelperCommand command)
        {
            lock (writeLock)
            {
                FrameCodec.WriteAsync(toHelper, HelperContract.Serialize(command), CancellationToken.None).GetAwaiter().GetResult();
            }
        }

        Send(new StartCommand("https://avpn.example.org/", _opt.Group ?? "", _opt.UserAgent, !_opt.NoDtls, null, _opt.IfName, null, null));
        var stopAt = DateTime.UtcNow + TimeSpan.FromSeconds(_opt.RunSeconds);
        var established = false;
        BlockingCollection<Navigation>? navigations = null;
        Guid ssoRequest = default;
        var stopSent = false;

        var reader = Task.Run(() =>
        {
            while (true)
            {
                var payload = FrameCodec.ReadAsync(fromHelper, CancellationToken.None).GetAwaiter().GetResult();
                if (payload is null)
                {
                    return;
                }

                var helperEvent = HelperContract.TryDeserializeEvent(payload);
                if (helperEvent is not LogEvent and not StatsEvent)
                {
                    events.Add($"{DateTime.Now:HH:mm:ss} {helperEvent?.GetType().Name}");
                }

                switch (helperEvent)
                {
                    case LogEvent log:
                        Log($"[helper {log.Level}] {log.Text}");
                        break;
                    case SsoOpenEvent open:
                        ssoRequest = open.RequestId;
                        navigations = new BlockingCollection<Navigation>();
                        var queue = navigations;
                        var ui = new Thread(() =>
                        {
                            Application.EnableVisualStyles();
                            _window = new SsoWindow(open.Uri, queue, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SplitVpn", "OcSpike", "WebView2"));
                            Application.Run(_window);
                        });
                        ui.SetApartmentState(ApartmentState.STA);
                        ui.IsBackground = true;
                        ui.Start();
                        Task.Run(() =>
                        {
                            foreach (var nav in queue.GetConsumingEnumerable())
                            {
                                if (nav.Closed)
                                {
                                    Send(new WebviewClosedCommand(open.RequestId));
                                    return;
                                }

                                // Как в пульте: cookie только хоста шлюза.
                                var cookies = new Uri(nav.Uri).Host == open.GatewayHost
                                    ? nav.Cookies.Select(c => new SsoCookie(c.Name, c.Value)).ToList()
                                    : [];
                                Send(new WebviewLoadCommand(open.RequestId, nav.Uri, cookies));
                            }
                        });
                        break;
                    case SsoResultEvent result when result.RequestId == ssoRequest:
                        Log($"[drive] SSO: {(result.Done ? "принят" : result.Error)}");
                        _window?.CloseByCode();
                        navigations?.CompleteAdding();
                        break;
                    case ResolveHostEvent resolve:
                        var address = Dns.GetHostAddresses(resolve.Host).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)?.ToString();
                        Log($"[drive] адрес {resolve.Host} -> {address}");
                        Send(new ResolveReplyCommand(resolve.Host, address));
                        break;
                    case AuthFormEvent form:
                        Log($"[drive] форма шлюза: {string.Join(", ", form.Fields.Select(f => f.Name))} — отмена");
                        Send(new FormReplyCommand(form.RequestId, new Dictionary<string, string>(), true));
                        break;
                    case EstablishedEvent up:
                        established = true;
                        Report["established"] = new JsonObject
                        {
                            ["luid"] = up.Luid,
                            ["interface"] = up.InterfaceName,
                            ["address"] = up.Session.Address,
                            ["mtu"] = up.Session.Mtu,
                            ["dns"] = string.Join(",", up.Session.Dns),
                            ["splitDns"] = string.Join(",", up.Session.SplitDns),
                            ["includes"] = up.Session.IncludeCidrs().Count,
                            ["sessionTimeout"] = up.Session.SessionTimeoutSeconds,
                            ["dtls"] = up.Session.DtlsActive,
                        };
                        Report["adapterAddress"] = PowerShell($"Get-NetIPAddress -InterfaceAlias '{up.InterfaceName}' -AddressFamily IPv4 | ForEach-Object {{ $_.IPAddress + '/' + $_.PrefixLength }}");
                        Report["adapterMtu"] = PowerShell($"(Get-NetIPInterface -InterfaceAlias '{up.InterfaceName}' -AddressFamily IPv4).NlMtu");
                        Report["adapterRoutes"] = PowerShell($"Get-NetRoute -InterfaceAlias '{up.InterfaceName}' -AddressFamily IPv4 | ForEach-Object {{ $_.DestinationPrefix + ' m' + $_.RouteMetric }}");
                        break;
                    case StatsEvent stats:
                        Report["lastStats"] = $"tx {stats.BytesSent} rx {stats.BytesReceived} dtls {stats.DtlsActive}";
                        break;
                    case TerminatedEvent terminated:
                        Report["terminated"] = $"{terminated.Kind}: {terminated.Text}";
                        Log($"[drive] завершено: {terminated.Kind} — {terminated.Text}");
                        break;
                }
            }
        });

        while (!reader.IsCompleted && DateTime.UtcNow < stopAt + TimeSpan.FromMinutes(5))
        {
            if (!stopSent && (DateTime.UtcNow >= stopAt || (!established && DateTime.UtcNow >= stopAt + TimeSpan.FromMinutes(3))))
            {
                Log("[drive] Stop");
                Send(new StopCommand());
                stopSent = true;
            }

            Thread.Sleep(500);
        }

        process.WaitForExit(20000);
        Report["helperExitCode"] = process.HasExited ? process.ExitCode : -999;
        Report["adapterAfterExit"] = PowerShell($"Get-NetAdapter -IncludeHidden -Name '{_opt.IfName}' -ErrorAction SilentlyContinue | ForEach-Object Status");
        return established ? 0 : 5;
    }
}
