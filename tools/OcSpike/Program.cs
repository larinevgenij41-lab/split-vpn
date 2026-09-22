using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Numerics;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace OcSpike;

/// <summary>
/// Стенд КТ0: SSO во встроенном браузере, туннель через libopenconnect + Wintun,
/// проверка адреса, маршрутов, DNS, DTLS, повторного подключения по cookie.
/// Пишет журнал и JSON-отчёт в D:\VPN\logs\oc-spike-*.
/// </summary>
internal static unsafe partial class Program
{
    private static readonly string LogDir = @"D:\VPN\logs";
    private static readonly string Stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
    private static readonly string SessionFile = Path.Combine(LogDir, "oc-spike-session.bin");
    private static readonly JsonObject Report = new();
    private static readonly object LogLock = new();
    private static StreamWriter? _log;

    private static Options _opt = new();
    private static nint _vpninfo;
    private static int _formCalls;
    private static OcStats _lastStats;
    private static SsoWindow? _window;

    [STAThread]
    private static int Main(string[] args)
    {
        DisableQuickEdit();
        Directory.CreateDirectory(LogDir);
        _log = new StreamWriter(Path.Combine(LogDir, $"oc-spike-{Stamp}.log"), false, new UTF8Encoding(false)) { AutoFlush = true };
        _opt = Options.Parse(args);
        Report["startedAt"] = DateTime.Now.ToString("O");
        Report["options"] = JsonSerializer.SerializeToNode(_opt);
        try
        {
            return Run();
        }
        catch (Exception ex)
        {
            Log("ОШИБКА: " + ex);
            Report["exception"] = ex.Message;
            return 1;
        }
        finally
        {
            Report["finishedAt"] = DateTime.Now.ToString("O");
            File.WriteAllText(Path.Combine(LogDir, $"oc-spike-{Stamp}.json"),
                Report.ToJsonString(new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));
            if (!_opt.NoPause)
            {
                Console.WriteLine("Готово. Нажмите Enter, чтобы закрыть окно.");
                Console.ReadLine();
            }
        }
    }

    private static int Run()
    {
        var ocDir = Path.Combine(AppContext.BaseDirectory, "openconnect");
        SetDllDirectoryW(ocDir);

        Report["leftoverAdaptersAtStart"] = PowerShell($"Get-NetAdapter -IncludeHidden | Where-Object Name -like 'SplitVpn AC*' | ForEach-Object {{ $_.Name + ' / ' + $_.Status + ' / ' + $_.InterfaceDescription }}");

        if (Oc.InitSsl() != 0)
            throw new InvalidOperationException("openconnect_init_ssl");
        Report["openconnectVersion"] = Oc.Str(Oc.GetVersion());
        Log("libopenconnect " + Report["openconnectVersion"]);

        var callbacks = new ShimCallbacks
        {
            Validate = &OnValidate,
            Form = &OnForm,
            Log = &OnLog,
            Webview = &OnWebview,
            Resolve = _opt.ResolveOverride ? &OnResolve : null,
            SetupTun = &OnSetupTun,
            Reconnected = &OnReconnected,
            Stats = &OnStats,
        };
        var ctx = Oc.ShimNew(_opt.UserAgent, &callbacks, 0);
        if (ctx == 0)
            throw new InvalidOperationException("ocshim_new");
        if (_opt.HelperDrive)
        {
            Oc.ShimFree(ctx);
            return RunHelperDrive();
        }
        if (_opt.PauseTest)
        {
            Oc.ShimFree(ctx);
            return RunPauseTest(callbacks);
        }
        if (_opt.ReuseMatrix)
        {
            Oc.ShimFree(ctx);
            return RunReuseMatrix(callbacks);
        }
        _vpninfo = Oc.ShimVpninfo(ctx);

        try
        {
            return Connect(ctx);
        }
        finally
        {
            Oc.ShimFree(ctx);
            Report["adaptersAfterFree"] = PowerShell($"Get-NetAdapter -IncludeHidden | Where-Object Name -like 'SplitVpn AC*' | ForEach-Object {{ $_.Name + ' / ' + $_.Status }}");
        }
    }

    private static int Connect(nint ctx)
    {
        Oc.SetLogLevel(_vpninfo, _opt.Debug ? Oc.PrgDebug : Oc.PrgInfo);
        Check(Oc.SetProtocol(_vpninfo, "anyconnect"), "set_protocol");
        Check(Oc.SetUserAgent(_vpninfo, _opt.UserAgent), "set_useragent");
        Check(Oc.SetReportedOs(_vpninfo, "win"), "set_reported_os");
        Check(Oc.ParseUrl(_vpninfo, _opt.Url), "parse_url");

        var saved = _opt.Reuse ? LoadSession() : null;
        if (saved is not null)
        {
            var url = saved.ConnectUrl ?? _opt.Url;
            _resolvePin = (saved.DnsName ?? new Uri(url).Host, saved.Host);
            Log($"Повторное подключение по сохранённому cookie: {url}, {_resolvePin.Value.Name} -> {saved.Host}");
            Check(Oc.ParseUrl(_vpninfo, url), "parse_url(connect_url)");
            Check(Oc.SetCookie(_vpninfo, saved.Cookie), "set_cookie");
            Report["auth"] = "reused-cookie";
        }
        else
        {
            var sw = Stopwatch.StartNew();
            var rc = Oc.ObtainCookie(_vpninfo);
            Report["obtainCookie"] = new JsonObject { ["rc"] = rc, ["seconds"] = sw.Elapsed.TotalSeconds, ["formCalls"] = _formCalls };
            if (rc != 0)
            {
                Log($"obtain_cookie вернул {rc}");
                return 2;
            }
            Report["auth"] = "obtained";
        }

        var host = Oc.Str(Oc.GetHostname(_vpninfo)) ?? "";
        var dnsName = Oc.Str(Oc.GetDnsName(_vpninfo));
        var connectUrl = Oc.Str(Oc.GetConnectUrl(_vpninfo));
        Report["dnsNameAfterAuth"] = dnsName;
        Report["connectUrlAfterAuth"] = connectUrl;
        var cookie = Oc.Str(Oc.GetCookie(_vpninfo)) ?? "";
        Report["hostnameAfterAuth"] = host;
        Report["cookieLength"] = cookie.Length;
        Report["authExpiration"] = Oc.GetAuthExpiration(_vpninfo);

        var sw2 = Stopwatch.StartNew();
        var cstp = Oc.MakeCstpConnection(_vpninfo);
        Report["makeCstp"] = new JsonObject { ["rc"] = cstp, ["seconds"] = sw2.Elapsed.TotalSeconds };
        if (cstp != 0)
        {
            Log($"make_cstp_connection вернул {cstp}");
            if (saved is not null)
                Report["reuseFailed"] = true;
            return 3;
        }

        var peerHash = Oc.Str(Oc.GetPeerCertHash(_vpninfo)) ?? "";
        Report["peerCertHash"] = peerHash;
        Report["cstpCipher"] = Oc.Str(Oc.GetCstpCipher(_vpninfo));
        if (saved is not null)
            Report["peerHashMatchesSaved"] = saved.PeerCertHash == peerHash;
        if (_opt.SaveSession)
            SaveSession(new SavedSession(cookie, host, peerHash, Oc.Str(Oc.GetConnectUrl(_vpninfo)), Oc.Str(Oc.GetDnsName(_vpninfo))));

        if (_opt.NoDtls)
            Oc.DisableDtls(_vpninfo);
        else
            Report["setupDtls"] = Oc.SetupDtls(_vpninfo, 60);

        var info = ReadIpInfo();
        Report["ipInfo"] = info;

        var cmd = Oc.SetupCmdPipe(_vpninfo);
        var before = PowerShell("Get-NetRoute -AddressFamily IPv4 | Measure-Object | ForEach-Object Count");
        var tun = Oc.SetupTunDevice(_vpninfo, null, _opt.IfName);
        Report["setupTun"] = tun;
        if (tun != 0)
            return 4;

        var index = PowerShell($"(Get-NetAdapter -IncludeHidden -Name '{_opt.IfName}').ifIndex").Trim();
        Report["ifIndex"] = index;
        Report["adapter"] = PowerShell($"Get-NetAdapter -IncludeHidden -Name '{_opt.IfName}' | ForEach-Object {{ $_.InterfaceDescription + ' / ' + $_.Status + ' / LUID ' + $_.NetLuid }}");
        Report["addressesBeforeConfig"] = PowerShell($"Get-NetIPAddress -InterfaceIndex {index} -ErrorAction SilentlyContinue | ForEach-Object {{ $_.IPAddress + '/' + $_.PrefixLength }}");
        Report["dnsOnAdapterBeforeConfig"] = PowerShell($"(Get-DnsClientServerAddress -InterfaceIndex {index} -AddressFamily IPv4).ServerAddresses -join ','");

        ConfigureInterface(index, info);
        Report["routesOnTunnelAfterConfig"] = PowerShell($"Get-NetRoute -InterfaceIndex {index} -AddressFamily IPv4 | ForEach-Object {{ $_.DestinationPrefix + ' m' + $_.RouteMetric }}");
        Report["routeCountBeforeTun"] = before;
        Report["routeCountAfterConfig"] = PowerShell("Get-NetRoute -AddressFamily IPv4 | Measure-Object | ForEach-Object Count");

        var loop = new Thread(() =>
        {
            var rc = Oc.Mainloop(_vpninfo, 60, 10);
            Log($"mainloop завершён: {rc}");
            Report["mainloopRc"] = rc;
        }) { IsBackground = true, Name = "oc-mainloop" };
        loop.Start();

        Thread.Sleep(TimeSpan.FromSeconds(5));
        Report["dtlsCipherAfter5s"] = Oc.Str(Oc.GetDtlsCipher(_vpninfo));
        if (_opt.Routes)
            Probe(info);

        WaitForExit(cmd, loop);
        RemoveOurRoutes(index);
        Report["statsAtExit"] = new JsonObject { ["rxBytes"] = _lastStats.RxBytes, ["txBytes"] = _lastStats.TxBytes };
        Report["adapterAfterStop"] = PowerShell($"Get-NetAdapter -IncludeHidden -Name '{_opt.IfName}' -ErrorAction SilentlyContinue | ForEach-Object {{ $_.Status }}");
        return 0;
    }

    private static void WaitForExit(nint cmd, Thread loop)
    {
        var until = DateTime.UtcNow + TimeSpan.FromSeconds(_opt.RunSeconds);
        Console.WriteLine($"Туннель поднят. q — выход с logout, d — detach, k — аварийное завершение процесса. Автовыход ({_opt.Exit}) через {_opt.RunSeconds} с.");
        byte exitCmd = _opt.Exit == "logout" ? Oc.CmdCancel : Oc.CmdDetach;
        while (DateTime.UtcNow < until && loop.IsAlive)
        {
            Oc.ShimSendCmd(cmd, Oc.CmdStats);
            if (Console.KeyAvailable)
            {
                var key = Console.ReadKey(true).KeyChar;
                if (key == 'q') { exitCmd = Oc.CmdCancel; break; }
                if (key == 'd') { exitCmd = Oc.CmdDetach; break; }
                if (key == 'k') KillSelf();
            }
            if (_opt.KillAfter > 0 && DateTime.UtcNow > until - TimeSpan.FromSeconds(_opt.RunSeconds - _opt.KillAfter))
                KillSelf();
            Thread.Sleep(1000);
        }
        Report["exitCommand"] = exitCmd == Oc.CmdCancel ? "cancel(logout)" : "detach";
        Oc.ShimSendCmd(cmd, exitCmd);
        loop.Join(TimeSpan.FromSeconds(20));
    }

    private static void KillSelf()
    {
        Report["killedSelf"] = true;
        File.WriteAllText(Path.Combine(LogDir, $"oc-spike-{Stamp}.json"), Report.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        Log("Аварийное завершение процесса (проверка судьбы адаптера Wintun)");
        Environment.FailFast("oc-spike kill test");
    }

    private static JsonObject ReadIpInfo()
    {
        OcIpInfo* ip;
        OcVpnOption* cstp;
        OcVpnOption* dtls;
        Check(Oc.GetIpInfo(_vpninfo, &ip, &cstp, &dtls), "get_ip_info");
        var result = new JsonObject
        {
            ["addr"] = Oc.Str(ip->Addr),
            ["netmask"] = Oc.Str(ip->Netmask),
            ["addr6"] = Oc.Str(ip->Addr6),
            ["dns"] = new JsonArray(new[] { Oc.Str(ip->Dns0), Oc.Str(ip->Dns1), Oc.Str(ip->Dns2) }.Where(d => d is not null).Select(d => (JsonNode)d!).ToArray()),
            ["domain"] = Oc.Str(ip->Domain),
            ["proxyPac"] = Oc.Str(ip->ProxyPac),
            ["mtu"] = ip->Mtu,
            ["gatewayAddr"] = Oc.Str(ip->GatewayAddr),
            ["splitDns"] = Routes(ip->SplitDns),
            ["splitIncludes"] = Routes(ip->SplitIncludes),
            ["splitExcludes"] = Routes(ip->SplitExcludes),
        };
        var options = new JsonObject();
        for (var o = cstp; o != null; o = o->Next)
        {
            var name = Oc.Str(o->Option) ?? "";
            options[name] = name.Contains("DTLS-Session", StringComparison.OrdinalIgnoreCase) || name.Contains("Key", StringComparison.OrdinalIgnoreCase) || name.Contains("Post-Auth-XML", StringComparison.OrdinalIgnoreCase)
                ? "<скрыто>" : Oc.Str(o->Value);
        }
        result["cstpOptions"] = options;
        return result;
    }

    private static JsonArray Routes(OcSplitInclude* head)
    {
        var list = new JsonArray();
        for (var r = head; r != null; r = r->Next)
            list.Add(Oc.Str(r->Route));
        return list;
    }

    private static void ConfigureInterface(string index, JsonObject info)
    {
        var addr = (string)info["addr"]!;
        var mtu = (int)info["mtu"]!;
        var script = new StringBuilder();
        script.AppendLine($"New-NetIPAddress -InterfaceIndex {index} -IPAddress {addr} -PrefixLength 32 -PolicyStore ActiveStore -SkipAsSource $false | Out-Null");
        script.AppendLine($"Set-NetIPInterface -InterfaceIndex {index} -AddressFamily IPv4 -NlMtuBytes {mtu} -InterfaceMetric 9000 -PolicyStore ActiveStore");
        script.AppendLine($"Disable-NetAdapterBinding -Name '{_opt.IfName}' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue");
        if (_opt.Routes)
        {
            var prefixes = ((JsonArray)info["splitIncludes"]!).Select(n => ToPrefix((string)n!)).ToList();
            prefixes.AddRange(((JsonArray)info["dns"]!).Select(d => (string)d! + "/32"));
            foreach (var p in prefixes.Distinct())
                script.AppendLine($"New-NetRoute -DestinationPrefix {p} -InterfaceIndex {index} -NextHop 0.0.0.0 -RouteMetric 3917 -PolicyStore ActiveStore -ErrorAction Continue | Out-Null");
            Report["routesAdded"] = prefixes.Distinct().Count();
        }
        Report["configureOutput"] = PowerShell(script.ToString());
    }

    private static void RemoveOurRoutes(string index)
    {
        if (!_opt.Routes)
            return;
        PowerShell($"Get-NetRoute -InterfaceIndex {index} -ErrorAction SilentlyContinue | Where-Object RouteMetric -eq 3917 | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue");
    }

    private static string ToPrefix(string route)
    {
        var parts = route.Split('/');
        if (parts.Length == 2 && parts[1].Contains('.'))
        {
            var mask = BitConverter.ToUInt32(IPAddress.Parse(parts[1]).GetAddressBytes().Reverse().ToArray());
            return $"{parts[0]}/{BitOperations.PopCount(mask)}";
        }
        return route;
    }

    private static void Probe(JsonObject info)
    {
        var probes = new JsonObject();
        var dns = ((JsonArray)info["dns"]!).Select(d => (string)d!).FirstOrDefault();
        var domain = ((string?)info["domain"] ?? "").Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries);
        if (dns is not null)
        {
            probes["tcp53"] = TcpProbe(dns, 53);
            foreach (var d in domain.Take(4))
                probes["dns:" + d] = PowerShell($"Resolve-DnsName -Name {d} -Server {dns} -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue | Select-Object -First 3 | ForEach-Object {{ $_.Type.ToString() + ' ' + $_.IPAddress + $_.NameHost + $_.PrimaryServer }}");
            probes["corp:avpn.example.org"] = PowerShell($"Resolve-DnsName -Name avpn.example.org -Server {dns} -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue | Where-Object Type -eq A | ForEach-Object IPAddress");
            var pac = (string?)info["proxyPac"];
            if (pac is not null)
            {
                var pacHost = new Uri(pac).Host;
                probes["corp:" + pacHost] = PowerShell($"Resolve-DnsName -Name {pacHost} -Server {dns} -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue | Where-Object Type -eq A | ForEach-Object IPAddress");
                probes["public:" + pacHost] = PowerShell($"Resolve-DnsName -Name {pacHost} -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue | Where-Object Type -eq A | ForEach-Object IPAddress");
                probes["pacRouteCheck"] = PowerShell($"$a = (Resolve-DnsName -Name {pacHost} -Server {dns} -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue | Where-Object Type -eq A | Select-Object -First 1).IPAddress; if ($a) {{ (Find-NetRoute -RemoteIPAddress $a | Select-Object -First 1).InterfaceAlias }}");
                probes["pacFetch"] = FetchPac(pac, dns);
            }
        }
        probes["route:10.0.16.21"] = PowerShell("(Find-NetRoute -RemoteIPAddress 10.0.16.21 | Select-Object -First 1).InterfaceAlias");
        probes["route:1.1.1.1"] = PowerShell("(Find-NetRoute -RemoteIPAddress 1.1.1.1 | Select-Object -First 1).InterfaceAlias");
        probes["route:gateway"] = PowerShell("$g=(Resolve-DnsName avpn.example.org -Type A -DnsOnly | Select-Object -First 1).IPAddress; $g + ' via ' + (Find-NetRoute -RemoteIPAddress $g | Select-Object -First 1).InterfaceAlias");
        probes["dnsOnAdapter"] = PowerShell($"(Get-DnsClientServerAddress -InterfaceAlias '{_opt.IfName}' -AddressFamily IPv4).ServerAddresses -join ','");
        probes["nrpt"] = PowerShell("Get-DnsClientNrptPolicy -ErrorAction SilentlyContinue | Measure-Object | ForEach-Object Count");
        Report["probes"] = probes;
    }

    private static string FetchPac(string pac, string dns)
    {
        try
        {
            var host = new Uri(pac).Host;
            var address = PowerShell($"(Resolve-DnsName -Name {host} -Server {dns} -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue | Where-Object Type -eq A | Select-Object -First 1).IPAddress").Trim();
            if (address.Length == 0)
                return "не разрешилось корпоративным DNS";
            using var handler = new SocketsHttpHandler
            {
                ConnectCallback = (context, token) =>
                {
                    var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                    socket.Connect(IPAddress.Parse(address), context.DnsEndPoint.Port);
                    return ValueTask.FromResult<Stream>(new NetworkStream(socket, ownsSocket: true));
                },
            };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
            var text = client.GetStringAsync(pac).GetAwaiter().GetResult();
            var proxies = Regex.Matches(text, @"PROXY\s+([A-Za-z0-9\.\-]+:\d+)").Select(m => m.Groups[1].Value).Distinct().Take(10);
            return $"ok {text.Length} байт; PROXY: {string.Join(", ", proxies)}";
        }
        catch (Exception ex)
        {
            return "ошибка: " + ex.GetType().Name + ": " + ex.Message;
        }
    }

    private static string TcpProbe(string host, int port)
    {
        try
        {
            using var client = new TcpClient();
            var sw = Stopwatch.StartNew();
            return client.ConnectAsync(host, port).Wait(TimeSpan.FromSeconds(3)) ? $"ok {sw.ElapsedMilliseconds} мс" : "таймаут";
        }
        catch (Exception ex)
        {
            return "ошибка: " + ex.Message;
        }
    }

    // ---- колбэки libopenconnect ----

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int OnValidate(nint priv, byte* reason)
    {
        var text = Oc.Str(reason);
        Log("validate_peer_cert: сертификат сервера не прошёл проверку: " + text);
        Report["peerCertRejected"] = text;
        return -1;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnLog(nint priv, int level, byte* message)
    {
        Log($"[oc{level}] " + Redact(Oc.Str(message)?.TrimEnd() ?? ""));

    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int OnResolve(nint priv, byte* node, byte* address, int length)
    {
        var name = Oc.Str(node) ?? "";
        try
        {
            var ip = _resolvePin is { } pin && string.Equals(pin.Name, name, StringComparison.OrdinalIgnoreCase) ? pin.Address : Dns.GetHostAddresses(name).First(a => a.AddressFamily == AddressFamily.InterNetwork).ToString();
            Log($"[resolve] {name} -> {ip} (через колбэк службы)");
            var bytes = Encoding.ASCII.GetBytes(ip);
            if (bytes.Length > length)
                return -1;
            Marshal.Copy(bytes, 0, (nint)address, bytes.Length);
            var list = Report["resolveCallbacks"] as JsonArray ?? new JsonArray();
            list.Add($"{name} -> {ip}");
            Report["resolveCallbacks"] = list;
            return 0;
        }
        catch (Exception ex)
        {
            Log($"[resolve] {name}: {ex.Message}");
            return -1;
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnSetupTun(nint priv)
    {
        Log("[event] setup_tun");
        Report["setupTunCallback"] = true;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnReconnected(nint priv)
    {
        Log("[event] reconnected");
        var count = (int?)Report["reconnects"] ?? 0;
        Report["reconnects"] = count + 1;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnStats(nint priv, OcStats* stats)
    {
        _lastStats = *stats;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int OnForm(nint priv, OcAuthForm* form)
    {
        _formCalls++;
        var described = DescribeForm(form);
        var forms = Report["forms"] as JsonArray ?? new JsonArray();
        forms.Add(described);
        Report["forms"] = forms;
        Log("[form] " + described.ToJsonString());

        if (Oc.Str(form->AuthId) == "success")
            return Oc.FormOk;

        if (form->AuthgroupOpt != null)
        {
            var select = form->AuthgroupOpt;
            var wanted = _opt.Group ?? AskChoice(select, "Группа подключения");
            if (wanted is null)
                return Oc.FormCancelled;
            var index = FindChoice(select, wanted);
            if (index < 0)
            {
                Log("Группа не найдена: " + wanted);
                return Oc.FormErr;
            }
            Oc.SetOptionValue(&select->Form, Oc.Str(select->Choices[index]->Name)!);
            if (index != form->AuthgroupSelection && !_groupSwitched)
            {
                _groupSwitched = true;
                return Oc.FormNewGroup;
            }
        }

        for (var o = form->Opts; o != null; o = o->Next)
        {
            if ((o->Flags & 0x0001) != 0 || (OcFormOpt*)form->AuthgroupOpt == o)
                continue;
            var name = Oc.Str(o->Name) ?? "";
            var label = Oc.Str(o->Label) ?? name;
            switch (o->Type)
            {
                case Oc.OptText:
                    var text = name.StartsWith("user", StringComparison.OrdinalIgnoreCase) && _opt.User is not null ? _opt.User : Ask(label, secret: false);
                    Oc.SetOptionValue(o, text);
                    break;
                case Oc.OptPassword:
                    Oc.SetOptionValue(o, Ask(label, secret: true));
                    break;
                case Oc.OptSelect:
                    var choice = AskChoice((OcFormOptSelect*)o, label);
                    if (choice is null)
                        return Oc.FormCancelled;
                    Oc.SetOptionValue(o, choice);
                    break;
            }
        }
        return Oc.FormOk;
    }

    private static bool _groupSwitched;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int OnWebview(nint priv, byte* uri)
    {
        var start = Oc.Str(uri) ?? "";
        Log("[sso] webview запрошен: " + RedactUri(start));
        Report["ssoStartHost"] = new Uri(start).Host;
        var queue = new BlockingCollection<Navigation>();
        var ready = new ManualResetEventSlim();
        var ui = new Thread(() =>
        {
            Application.EnableVisualStyles();
            _window = new SsoWindow(start, queue, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SplitVpn", "OcSpike", "WebView2"));
            ready.Set();
            Application.Run(_window);
        });
        ui.SetApartmentState(ApartmentState.STA);
        ui.IsBackground = true;
        ui.Start();
        ready.Wait();

        var deadline = DateTime.UtcNow + TimeSpan.FromMinutes(5);
        var steps = new JsonArray();
        Report["ssoSteps"] = steps;
        try
        {
            while (true)
            {
                var remaining = deadline - DateTime.UtcNow;
                if (remaining <= TimeSpan.Zero || !queue.TryTake(out var nav, remaining))
                {
                    Log("[sso] таймаут входа");
                    return -138;
                }
                if (nav.Closed)
                {
                    Log("[sso] окно закрыто пользователем");
                    return -125;
                }
                var rc = LoadChanged(nav);
                steps.Add($"{RedactUri(nav.Uri)} cookies={nav.Cookies.Count} rc={rc}");
                Log($"[sso] load_changed rc={rc}");
                if (rc == -Oc.EAGAIN)
                    continue;
                return rc;
            }
        }
        finally
        {
            _window?.CloseByCode();
        }
    }

    private static int LoadChanged(Navigation nav)
    {
        var allocations = new List<nint>();
        nint Utf8(string s)
        {
            var p = Marshal.StringToCoTaskMemUTF8(s);
            allocations.Add(p);
            return p;
        }
        try
        {
            var cookies = (byte**)NativeMemory.AllocZeroed((nuint)(nav.Cookies.Count * 2 + 1), (nuint)sizeof(nint));
            for (var i = 0; i < nav.Cookies.Count; i++)
            {
                cookies[i * 2] = (byte*)Utf8(nav.Cookies[i].Name);
                cookies[i * 2 + 1] = (byte*)Utf8(nav.Cookies[i].Value);
            }
            var result = new OcWebviewResult { Uri = (byte*)Utf8(nav.Uri), Cookies = cookies, Headers = null };
            var rc = Oc.WebviewLoadChanged(_vpninfo, &result);
            NativeMemory.Free(cookies);
            return rc;
        }
        finally
        {
            foreach (var p in allocations)
                Marshal.FreeCoTaskMem(p);
        }
    }

    // ---- вспомогательное ----

    private static JsonObject DescribeForm(OcAuthForm* form)
    {
        var opts = new JsonArray();
        for (var o = form->Opts; o != null; o = o->Next)
        {
            var item = new JsonObject { ["type"] = o->Type, ["name"] = Oc.Str(o->Name), ["label"] = Oc.Str(o->Label), ["flags"] = o->Flags };
            if (o->Type == Oc.OptSelect)
            {
                var s = (OcFormOptSelect*)o;
                var choices = new JsonArray();
                for (var i = 0; i < s->NrChoices; i++)
                    choices.Add($"{Oc.Str(s->Choices[i]->Name)} | {Oc.Str(s->Choices[i]->Label)}");
                item["choices"] = choices;
            }
            opts.Add(item);
        }
        return new JsonObject
        {
            ["authId"] = Oc.Str(form->AuthId),
            ["method"] = Oc.Str(form->Method),
            ["action"] = RedactUri(Oc.Str(form->Action) ?? ""),
            ["banner"] = Oc.Str(form->Banner),
            ["message"] = Oc.Str(form->Message),
            ["error"] = Oc.Str(form->Error),
            ["authgroupSelection"] = form->AuthgroupSelection,
            ["opts"] = opts,
        };
    }

    private static int FindChoice(OcFormOptSelect* select, string wanted)
    {
        for (var i = 0; i < select->NrChoices; i++)
        {
            var c = select->Choices[i];
            if (string.Equals(Oc.Str(c->Name), wanted, StringComparison.OrdinalIgnoreCase)
                || string.Equals(Oc.Str(c->Label), wanted, StringComparison.OrdinalIgnoreCase))
                return i;
        }
        return -1;
    }

    private static string? AskChoice(OcFormOptSelect* select, string label)
    {
        Console.WriteLine(label + ":");
        for (var i = 0; i < select->NrChoices; i++)
            Console.WriteLine($"  {i + 1}. {Oc.Str(select->Choices[i]->Label)} ({Oc.Str(select->Choices[i]->Name)})");
        Console.Write("Номер: ");
        var line = Console.ReadLine();
        return int.TryParse(line, out var n) && n >= 1 && n <= select->NrChoices ? Oc.Str(select->Choices[n - 1]->Name) : null;
    }

    private static string Ask(string label, bool secret)
    {
        Console.Write(label + ": ");
        if (!secret)
            return Console.ReadLine() ?? "";
        var sb = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(true);
            if (key.Key == ConsoleKey.Enter)
                break;
            if (key.Key == ConsoleKey.Backspace && sb.Length > 0)
                sb.Length--;
            else if (!char.IsControl(key.KeyChar))
                sb.Append(key.KeyChar);
        }
        Console.WriteLine();
        return sb.ToString();
    }

    private static void Check(int rc, string what)
    {
        if (rc != 0)
            throw new InvalidOperationException($"{what} вернул {rc}");
    }

    internal static void Log(string message)
    {
        var line = $"{DateTime.Now:HH:mm:ss.fff} {message}";
        lock (LogLock)
            _log?.WriteLine(line);
        // Подробности протокола — только в файл: запись в консоль блокируется режимом выделения
        // и останавливает поток mainloop вместе с пересылкой пакетов.
        if (!message.StartsWith("[oc2]", StringComparison.Ordinal) && !message.StartsWith("[oc3]", StringComparison.Ordinal))
            ThreadPool.QueueUserWorkItem(static l => Console.WriteLine(l), line, preferLocal: false);
    }

    private static string Redact(string text)
    {
        text = CookieValue().Replace(text, "$1=<скрыто>");
        text = DtlsSession().Replace(text, "$1<скрыто>");
        return TokenXml().Replace(text, "<$1><скрыто></$1>");
    }

    internal static string RedactUri(string uri)
    {
        var q = uri.IndexOf('?');
        return q < 0 ? uri : uri[..q] + "?<параметры скрыты>";
    }

    private static string PowerShell(string script)
    {
        var psi = new ProcessStartInfo("powershell.exe", "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
        };
        using var p = Process.Start(psi)!;
        p.StandardInput.WriteLine("[Console]::OutputEncoding = [Text.Encoding]::UTF8");
        p.StandardInput.WriteLine(script);
        p.StandardInput.Close();
        var output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();
        return output.Trim();
    }

    private sealed record SavedSession(string Cookie, string Host, string PeerCertHash, string? ConnectUrl = null, string? DnsName = null);

    private static (string Name, string Address)? _resolvePin;

    private static void SaveSession(SavedSession session)
    {
        var data = ProtectedData.Protect(JsonSerializer.SerializeToUtf8Bytes(session), null, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(SessionFile, data);
        Log("Сеанс сохранён (DPAPI CurrentUser)");
    }

    private static SavedSession? LoadSession()
    {
        if (!File.Exists(SessionFile))
            return null;
        var data = ProtectedData.Unprotect(File.ReadAllBytes(SessionFile), null, DataProtectionScope.CurrentUser);
        return JsonSerializer.Deserialize<SavedSession>(data);
    }

    [GeneratedRegex(@"(webvpn[a-z_]*|acSamlv2Token|acSamlv2Error|SAMLResponse)=[^;\s""&]+", RegexOptions.IgnoreCase)]
    private static partial Regex CookieValue();

    [GeneratedRegex(@"(X-DTLS-Session-ID:s*|X-DTLS-Master-Secret:s*)S+", RegexOptions.IgnoreCase)]
    private static partial Regex DtlsSession();

    [GeneratedRegex(@"<(sso-token|session-token|opaque[^>]*)>[^<]*</[^>]+>", RegexOptions.IgnoreCase)]
    private static partial Regex TokenXml();

    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetDllDirectoryW(string path);

    private static void DisableQuickEdit()
    {
        var input = GetStdHandle(-10);
        if (GetConsoleMode(input, out var mode))
            SetConsoleMode(input, (mode & ~0x0040u) | 0x0080u);
    }

    [LibraryImport("kernel32.dll")]
    private static partial nint GetStdHandle(int handle);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetConsoleMode(nint handle, out uint mode);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetConsoleMode(nint handle, uint mode);
}

internal sealed class Options
{
    public string Url { get; set; } = "https://avpn.example.org";
    public string? Group { get; set; }
    public string? User { get; set; }
    public string UserAgent { get; set; } = "AnyConnect Windows 4.10.06090";
    public string IfName { get; set; } = "SplitVpn AC spike";
    public bool Debug { get; set; }
    public bool NoDtls { get; set; }
    public bool Routes { get; set; }
    public bool Reuse { get; set; }
    public bool SaveSession { get; set; }
    public bool ResolveOverride { get; set; } = true;
    public bool NoPause { get; set; }
    public int RunSeconds { get; set; } = 90;
    public int KillAfter { get; set; }
    public string Exit { get; set; } = "detach";
    public bool ReuseMatrix { get; set; }
    public bool PauseTest { get; set; }
    public bool HelperDrive { get; set; }

    public static Options Parse(string[] args)
    {
        var o = new Options();
        for (var i = 0; i < args.Length; i++)
        {
            string Next() => args[++i];
            switch (args[i])
            {
                case "--url": o.Url = Next(); break;
                case "--group": o.Group = Next(); break;
                case "--user": o.User = Next(); break;
                case "--ua": o.UserAgent = Next(); break;
                case "--ifname": o.IfName = Next(); break;
                case "--debug": o.Debug = true; break;
                case "--no-dtls": o.NoDtls = true; break;
                case "--routes": o.Routes = true; break;
                case "--reuse": o.Reuse = true; break;
                case "--save-session": o.SaveSession = true; break;
                case "--no-resolve-override": o.ResolveOverride = false; break;
                case "--no-pause": o.NoPause = true; break;
                case "--run-seconds": o.RunSeconds = int.Parse(Next()); break;
                case "--kill-after": o.KillAfter = int.Parse(Next()); break;
                case "--exit": o.Exit = Next(); break;
                case "--reuse-matrix": o.ReuseMatrix = true; break;
                case "--pause-test": o.PauseTest = true; break;
                case "--helper": o.HelperDrive = true; break;
                default: throw new ArgumentException("Неизвестный параметр " + args[i]);
            }
        }
        return o;
    }
}
