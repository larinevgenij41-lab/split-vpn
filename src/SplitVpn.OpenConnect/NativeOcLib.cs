using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.OpenConnect;
using SplitVpn.OpenConnect.Native;

namespace SplitVpn.OpenConnect;

/// <summary>libopenconnect через ocshim. Один экземпляр на процесс помощника.</summary>
internal sealed unsafe class NativeOcLib : IOcLib
{
    private const int ReconnectTimeoutSeconds = 60;
    private const int ReconnectIntervalSeconds = 10;
    private const int DtlsAttemptPeriodSeconds = 60;

    private GCHandle _self;
    private IOcCallbacks? _callbacks;
    private nint _ctx;
    private nint _vpninfo;
    private nint _commandSocket;

    public string Version => OcNative.Utf8(OcNative.GetVersion()) ?? "";

    public bool DtlsActive => _vpninfo != 0 && OcNative.GetDtlsCipher(_vpninfo) != null;

    public void Create(IOcCallbacks callbacks, string userAgent, bool verbose)
    {
        OcNative.HardenPkcs11();
        if (OcNative.InitSsl() != 0)
        {
            throw new InvalidOperationException("openconnect_init_ssl завершился с ошибкой");
        }

        _callbacks = callbacks;
        _self = GCHandle.Alloc(this);
        var table = new ShimCallbacks
        {
            Validate = &OnValidate,
            Form = &OnForm,
            Log = &OnLog,
            Webview = &OnWebview,
            Resolve = &OnResolve,
            SetupTun = &OnSetupTun,
            Reconnected = &OnReconnected,
            Stats = &OnStats,
        };
        _ctx = OcNative.ShimNew(userAgent, &table, GCHandle.ToIntPtr(_self));
        if (_ctx == 0)
        {
            throw new InvalidOperationException("ocshim_new завершился с ошибкой");
        }

        _vpninfo = OcNative.ShimVpninfo(_ctx);
        OcNative.SetLogLevel(_vpninfo, verbose ? OcCodes.PrgDebug : OcCodes.PrgInfo);
        Check(OcNative.SetProtocol(_vpninfo, "anyconnect"), "openconnect_set_protocol");
        Check(OcNative.SetUserAgent(_vpninfo, userAgent), "openconnect_set_useragent");
        Check(OcNative.SetReportedOs(_vpninfo, "win"), "openconnect_set_reported_os");
    }

    public int ParseUrl(string url) => OcNative.ParseUrl(_vpninfo, url);

    public int SetClientCertificate(string certificateUrl, string keyUrl) => OcNative.SetClientCert(_vpninfo, certificateUrl, keyUrl);

    public int ObtainCookie() => OcNative.ObtainCookie(_vpninfo);

    public int MakeCstpConnection() => OcNative.MakeCstpConnection(_vpninfo);

    public int SetupDtls() => OcNative.SetupDtls(_vpninfo, DtlsAttemptPeriodSeconds);

    public int DisableDtls() => OcNative.DisableDtls(_vpninfo);

    public int SetupTunDevice(string interfaceName) => OcNative.SetupTunDevice(_vpninfo, null, interfaceName);

    public SessionInfo ReadSession()
    {
        OcIpInfo* ip;
        OcVpnOption* cstp;
        OcVpnOption* dtls;
        if (OcNative.GetIpInfo(_vpninfo, &ip, &cstp, &dtls) != 0 || ip == null)
        {
            throw new InvalidOperationException("openconnect_get_ip_info завершился с ошибкой");
        }

        int? sessionTimeout = null;
        for (var option = cstp; option != null; option = option->Next)
        {
            if (OcNative.Utf8(option->Option) == "X-CSTP-Session-Timeout"
                && int.TryParse(OcNative.Utf8(option->Value), NumberStyles.None, CultureInfo.InvariantCulture, out var seconds))
            {
                sessionTimeout = seconds;
            }
        }

        return new SessionInfo
        {
            Address = OcNative.Utf8(ip->Addr) ?? "",
            Netmask = OcNative.Utf8(ip->Netmask) ?? "",
            Mtu = ip->Mtu,
            Dns = new[] { OcNative.Utf8(ip->Dns0), OcNative.Utf8(ip->Dns1), OcNative.Utf8(ip->Dns2) }.OfType<string>().ToList(),
            SplitDns = Routes(ip->SplitDns),
            SplitIncludes = Routes(ip->SplitIncludes),
            SplitExcludes = Routes(ip->SplitExcludes),
            ProxyPac = OcNative.Utf8(ip->ProxyPac),
            SessionTimeoutSeconds = sessionTimeout,
            DtlsActive = DtlsActive,
        };
    }

    public void SetupCommandPipe()
    {
        _commandSocket = OcNative.SetupCmdPipe(_vpninfo);
        if (_commandSocket == -1)
        {
            throw new InvalidOperationException("openconnect_setup_cmd_pipe завершился с ошибкой");
        }
    }

    public int Mainloop() => OcNative.Mainloop(_vpninfo, ReconnectTimeoutSeconds, ReconnectIntervalSeconds);

    public void SendCommand(byte command)
    {
        if (_commandSocket is not (0 or -1))
        {
            _ = OcNative.ShimSendCmd(_commandSocket, command);
        }
    }

    public int WebviewLoadChanged(string uri, IReadOnlyList<SsoCookie> cookies)
    {
        var strings = new List<nint>();
        nint Utf8(string value)
        {
            var pointer = Marshal.StringToCoTaskMemUTF8(value);
            strings.Add(pointer);
            return pointer;
        }

        var array = (byte**)NativeMemory.AllocZeroed((nuint)(cookies.Count * 2 + 1), (nuint)sizeof(nint));
        try
        {
            for (var i = 0; i < cookies.Count; i++)
            {
                array[i * 2] = (byte*)Utf8(cookies[i].Name);
                array[i * 2 + 1] = (byte*)Utf8(cookies[i].Value);
            }

            var result = new OcWebviewResult { Uri = (byte*)Utf8(uri), Cookies = array, Headers = null };
            return OcNative.WebviewLoadChanged(_vpninfo, &result);
        }
        finally
        {
            NativeMemory.Free(array);
            foreach (var pointer in strings)
            {
                // Токен SSO не должен оставаться в памяти дольше вызова.
                var length = System.Text.Encoding.UTF8.GetByteCount(Marshal.PtrToStringUTF8(pointer) ?? "");
                new Span<byte>((byte*)pointer, length).Clear();
                Marshal.FreeCoTaskMem(pointer);
            }
        }
    }

    public void Dispose()
    {
        if (_ctx != 0)
        {
            OcNative.ShimFree(_ctx);
            _ctx = 0;
            _vpninfo = 0;
        }

        if (_self.IsAllocated)
        {
            _self.Free();
        }
    }

    private static List<string> Routes(OcSplitInclude* head)
    {
        var list = new List<string>();
        for (var route = head; route != null; route = route->Next)
        {
            if (OcNative.Utf8(route->Route) is { } text)
            {
                list.Add(text);
            }
        }

        return list;
    }

    private static void Check(int code, string what)
    {
        if (code != 0)
        {
            throw new InvalidOperationException($"{what} вернул {code}");
        }
    }

    private static IOcCallbacks Callbacks(nint priv) => ((NativeOcLib)GCHandle.FromIntPtr(priv).Target!)._callbacks!;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int OnValidate(nint priv, byte* reason) => Guard(() => Callbacks(priv).ValidatePeerCertificate(OcNative.Utf8(reason) ?? ""), -1);

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnLog(nint priv, int level, byte* message) => Guard(() =>
    {
        Callbacks(priv).Log(level, OcNative.Utf8(message)?.TrimEnd() ?? "");
        return 0;
    }, 0);

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int OnWebview(nint priv, byte* uri) => Guard(() => Callbacks(priv).OpenWebview(OcNative.Utf8(uri) ?? ""), -OcCodes.Einval);

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int OnResolve(nint priv, byte* node, byte* address, int length) => Guard(() =>
    {
        var resolved = Callbacks(priv).Resolve(OcNative.Utf8(node) ?? "");
        if (resolved is null)
        {
            return -1;
        }

        var bytes = System.Text.Encoding.ASCII.GetBytes(resolved);
        if (bytes.Length > length)
        {
            return -1;
        }

        Marshal.Copy(bytes, 0, (nint)address, bytes.Length);
        return 0;
    }, -1);

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnSetupTun(nint priv)
    {
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnReconnected(nint priv) => Guard(() =>
    {
        Callbacks(priv).Reconnected();
        return 0;
    }, 0);

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnStats(nint priv, OcStats* stats)
    {
        var copy = *stats;
        Guard(() =>
        {
            Callbacks(priv).Stats(copy.TxBytes, copy.RxBytes);
            return 0;
        }, 0);
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int OnForm(nint priv, OcAuthForm* form) => Guard(() => Callbacks(priv).ProcessForm(ReadForm(form)), OcCodes.FormErr);

    private static OcForm ReadForm(OcAuthForm* form)
    {
        var fields = new List<OcField>();
        OcField? group = null;
        for (var option = form->Opts; option != null; option = option->Next)
        {
            var field = ReadField(option, (OcFormOpt*)form->AuthgroupOpt == option);
            fields.Add(field);
            if ((OcFormOpt*)form->AuthgroupOpt == option)
            {
                group = field;
            }
        }

        return new OcForm
        {
            AuthId = OcNative.Utf8(form->AuthId),
            Banner = OcNative.Utf8(form->Banner),
            Message = OcNative.Utf8(form->Message),
            Error = OcNative.Utf8(form->Error),
            Fields = fields,
            Group = group,
            GroupSelection = form->AuthgroupSelection,
        };
    }

    private static OcField ReadField(OcFormOpt* option, bool isGroup)
    {
        var kind = option->Type switch
        {
            OcNative.OptText => OcFieldKind.Text,
            OcNative.OptPassword => OcFieldKind.Password,
            OcNative.OptSelect => OcFieldKind.Select,
            OcNative.OptHidden => OcFieldKind.Hidden,
            OcNative.OptSsoToken or OcNative.OptSsoUser => OcFieldKind.SsoToken,
            _ => OcFieldKind.Other,
        };
        var choices = new List<AuthChoiceDto>();
        if (kind == OcFieldKind.Select)
        {
            var select = (OcFormOptSelect*)option;
            for (var i = 0; i < select->NrChoices; i++)
            {
                choices.Add(new AuthChoiceDto(OcNative.Utf8(select->Choices[i]->Name) ?? "", OcNative.Utf8(select->Choices[i]->Label) ?? ""));
            }
        }

        var pointer = (nint)option;
        return new OcField(
            OcNative.Utf8(option->Name) ?? "",
            OcNative.Utf8(option->Label) ?? OcNative.Utf8(option->Name) ?? "",
            kind,
            (option->Flags & OcNative.OptIgnore) != 0 && !isGroup,
            choices,
            value => _ = OcNative.SetOptionValue((OcFormOpt*)pointer, value));
    }

    /// <summary>Исключение не должно пересечь границу нативного колбэка: процесс упадёт без журнала.</summary>
    private static T Guard<T>(Func<T> action, T fallback)
    {
        try
        {
            return action();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Ошибка в колбэке libopenconnect: " + ex);
            return fallback;
        }
    }
}
