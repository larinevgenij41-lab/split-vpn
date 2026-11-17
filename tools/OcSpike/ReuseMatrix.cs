using System.Text.Json.Nodes;

namespace OcSpike;

/// <summary>
/// Опыт: почему CONNECT по сохранённому cookie получает 401.
/// Каждый вариант — после собственного свежего входа, чтобы неудача одного не портила сессию другому.
/// </summary>
internal static unsafe partial class Program
{
    private static readonly string[] Variants = ["A-host-ip-full-cookie", "B-host-name-full-cookie", "C-host-name-webvpn-only"];

    private static int RunReuseMatrix(ShimCallbacks callbacks)
    {
        var results = new JsonArray();
        Report["reuseMatrix"] = results;
        foreach (var variant in Variants)
        {
            var row = new JsonObject { ["variant"] = variant };
            results.Add(row);
            Log($"===== вариант {variant}: свежий вход");

            var first = Oc.ShimNew(_opt.UserAgent, &callbacks, 0);
            _vpninfo = Oc.ShimVpninfo(first);
            _groupSwitched = false;
            string cookie, ip, dnsName;
            try
            {
                Prepare(_opt.Url);
                row["obtain"] = Oc.ObtainCookie(_vpninfo);
                if ((int)row["obtain"]! != 0)
                    continue;
                cookie = Oc.Str(Oc.GetCookie(_vpninfo)) ?? "";
                ip = Oc.Str(Oc.GetHostname(_vpninfo)) ?? "";
                dnsName = Oc.Str(Oc.GetDnsName(_vpninfo)) ?? "";
                row["firstCstp"] = Oc.MakeCstpConnection(_vpninfo);
                row["cookieHasStrap"] = cookie.Contains("openconnect_strapkey=", StringComparison.Ordinal);
                row["cookieAfterCstpSame"] = (Oc.Str(Oc.GetCookie(_vpninfo)) ?? "") == cookie;
            }
            finally
            {
                // Закрытие без BYE: quit_reason не выставлен, как при OC_CMD_DETACH
                Oc.ShimFree(first);
            }
            Thread.Sleep(2000);

            Log($"===== вариант {variant}: подключение по cookie");
            var second = Oc.ShimNew(_opt.UserAgent, &callbacks, 0);
            _vpninfo = Oc.ShimVpninfo(second);
            try
            {
                switch (variant[0])
                {
                    case 'A':
                        Prepare(_opt.Url);
                        row["setHostname"] = Oc.SetHostname(_vpninfo, ip);
                        row["setCookie"] = Oc.SetCookie(_vpninfo, cookie);
                        break;
                    case 'B':
                        _resolvePin = (dnsName, ip);
                        Prepare(_opt.Url);
                        row["setCookie"] = Oc.SetCookie(_vpninfo, cookie);
                        break;
                    default:
                        _resolvePin = (dnsName, ip);
                        Prepare(_opt.Url);
                        var webvpn = cookie.Split("; ").First(p => p.StartsWith("webvpn=", StringComparison.Ordinal));
                        row["setCookie"] = Oc.SetCookie(_vpninfo, webvpn);
                        break;
                }
                row["reuseCstp"] = Oc.MakeCstpConnection(_vpninfo);
                Log($"===== вариант {variant}: CONNECT по cookie rc={row["reuseCstp"]}");
            }
            finally
            {
                _resolvePin = null;
                Oc.ShimFree(second);
            }
            Thread.Sleep(2000);
        }
        return 0;
    }

    private static void Prepare(string url)
    {
        Oc.SetLogLevel(_vpninfo, _opt.Debug ? Oc.PrgDebug : Oc.PrgInfo);
        Check(Oc.SetProtocol(_vpninfo, "anyconnect"), "set_protocol");
        Check(Oc.SetUserAgent(_vpninfo, _opt.UserAgent), "set_useragent");
        Check(Oc.SetReportedOs(_vpninfo, "win"), "set_reported_os");
        Check(Oc.ParseUrl(_vpninfo, url), "parse_url");
    }
}
