using System.Runtime.InteropServices;

namespace OcSpike;

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct OcFormOpt
{
    public OcFormOpt* Next;
    public int Type;
    public byte* Name;
    public byte* Label;
    public byte* Value;
    public uint Flags;
    public void* Reserved;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct OcChoice
{
    public byte* Name;
    public byte* Label;
    public byte* AuthType;
    public byte* OverrideName;
    public byte* OverrideLabel;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct OcFormOptSelect
{
    public OcFormOpt Form;
    public int NrChoices;
    public OcChoice** Choices;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct OcAuthForm
{
    public byte* Banner;
    public byte* Message;
    public byte* Error;
    public byte* AuthId;
    public byte* Method;
    public byte* Action;
    public OcFormOpt* Opts;
    public OcFormOptSelect* AuthgroupOpt;
    public int AuthgroupSelection;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct OcSplitInclude
{
    public byte* Route;
    public OcSplitInclude* Next;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct OcIpInfo
{
    public byte* Addr;
    public byte* Netmask;
    public byte* Addr6;
    public byte* Netmask6;
    public byte* Dns0, Dns1, Dns2;
    public byte* Nbns0, Nbns1, Nbns2;
    public byte* Domain;
    public byte* ProxyPac;
    public int Mtu;
    public OcSplitInclude* SplitDns;
    public OcSplitInclude* SplitIncludes;
    public OcSplitInclude* SplitExcludes;
    public byte* GatewayAddr;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct OcVpnOption
{
    public byte* Option;
    public byte* Value;
    public OcVpnOption* Next;
}

[StructLayout(LayoutKind.Sequential)]
internal struct OcStats
{
    public ulong TxPkts, TxBytes, RxPkts, RxBytes;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct OcWebviewResult
{
    public byte* Uri;
    public byte** Cookies;
    public byte** Headers;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct ShimCallbacks
{
    public delegate* unmanaged[Cdecl]<nint, byte*, int> Validate;
    public delegate* unmanaged[Cdecl]<nint, OcAuthForm*, int> Form;
    public delegate* unmanaged[Cdecl]<nint, int, byte*, void> Log;
    public delegate* unmanaged[Cdecl]<nint, byte*, int> Webview;
    public delegate* unmanaged[Cdecl]<nint, byte*, byte*, int, int> Resolve;
    public delegate* unmanaged[Cdecl]<nint, void> SetupTun;
    public delegate* unmanaged[Cdecl]<nint, void> Reconnected;
    public delegate* unmanaged[Cdecl]<nint, OcStats*, void> Stats;
}

internal static unsafe partial class Oc
{
    private const string Lib = "libopenconnect-5.dll";
    private const string Shim = "ocshim.dll";

    public const int PrgErr = 0, PrgInfo = 1, PrgDebug = 2, PrgTrace = 3;
    public const int OptText = 1, OptPassword = 2, OptSelect = 3, OptHidden = 4, OptToken = 5, OptSsoToken = 6, OptSsoUser = 7;
    public const int FormErr = -1, FormOk = 0, FormCancelled = 1, FormNewGroup = 2;
    public const byte CmdCancel = (byte)'x', CmdPause = (byte)'p', CmdDetach = (byte)'d', CmdStats = (byte)'s';
    public const int EAGAIN = 11, EINVAL = 22, EPERM = 1;

    [LibraryImport(Shim, EntryPoint = "ocshim_new", StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint ShimNew(string useragent, ShimCallbacks* callbacks, nint priv);

    [LibraryImport(Shim, EntryPoint = "ocshim_vpninfo")]
    public static partial nint ShimVpninfo(nint ctx);

    [LibraryImport(Shim, EntryPoint = "ocshim_send_cmd")]
    public static partial int ShimSendCmd(nint socket, byte cmd);

    [LibraryImport(Shim, EntryPoint = "ocshim_free")]
    public static partial void ShimFree(nint ctx);

    [LibraryImport(Lib, EntryPoint = "openconnect_init_ssl")]
    public static partial int InitSsl();

    [LibraryImport(Lib, EntryPoint = "openconnect_get_version")]
    public static partial byte* GetVersion();

    [LibraryImport(Lib, EntryPoint = "openconnect_set_loglevel")]
    public static partial void SetLogLevel(nint vpninfo, int level);

    [LibraryImport(Lib, EntryPoint = "openconnect_set_protocol", StringMarshalling = StringMarshalling.Utf8)]
    public static partial int SetProtocol(nint vpninfo, string protocol);

    [LibraryImport(Lib, EntryPoint = "openconnect_set_useragent", StringMarshalling = StringMarshalling.Utf8)]
    public static partial int SetUserAgent(nint vpninfo, string useragent);

    [LibraryImport(Lib, EntryPoint = "openconnect_set_reported_os", StringMarshalling = StringMarshalling.Utf8)]
    public static partial int SetReportedOs(nint vpninfo, string os);

    [LibraryImport(Lib, EntryPoint = "openconnect_parse_url", StringMarshalling = StringMarshalling.Utf8)]
    public static partial int ParseUrl(nint vpninfo, string url);

    [LibraryImport(Lib, EntryPoint = "openconnect_set_option_value", StringMarshalling = StringMarshalling.Utf8)]
    public static partial int SetOptionValue(OcFormOpt* opt, string value);

    [LibraryImport(Lib, EntryPoint = "openconnect_obtain_cookie")]
    public static partial int ObtainCookie(nint vpninfo);

    [LibraryImport(Lib, EntryPoint = "openconnect_get_cookie")]
    public static partial byte* GetCookie(nint vpninfo);

    [LibraryImport(Lib, EntryPoint = "openconnect_set_cookie", StringMarshalling = StringMarshalling.Utf8)]
    public static partial int SetCookie(nint vpninfo, string cookie);

    [LibraryImport(Lib, EntryPoint = "openconnect_get_hostname")]
    public static partial byte* GetHostname(nint vpninfo);

    [LibraryImport(Lib, EntryPoint = "openconnect_set_hostname", StringMarshalling = StringMarshalling.Utf8)]
    public static partial int SetHostname(nint vpninfo, string hostname);

    [LibraryImport(Lib, EntryPoint = "openconnect_get_dnsname")]
    public static partial byte* GetDnsName(nint vpninfo);

    [LibraryImport(Lib, EntryPoint = "openconnect_get_connect_url")]
    public static partial byte* GetConnectUrl(nint vpninfo);

    [LibraryImport(Lib, EntryPoint = "openconnect_get_peer_cert_hash")]
    public static partial byte* GetPeerCertHash(nint vpninfo);

    [LibraryImport(Lib, EntryPoint = "openconnect_get_auth_expiration")]
    public static partial long GetAuthExpiration(nint vpninfo);

    [LibraryImport(Lib, EntryPoint = "openconnect_make_cstp_connection")]
    public static partial int MakeCstpConnection(nint vpninfo);

    [LibraryImport(Lib, EntryPoint = "openconnect_setup_dtls")]
    public static partial int SetupDtls(nint vpninfo, int attemptPeriod);

    [LibraryImport(Lib, EntryPoint = "openconnect_disable_dtls")]
    public static partial int DisableDtls(nint vpninfo);

    [LibraryImport(Lib, EntryPoint = "openconnect_setup_tun_device", StringMarshalling = StringMarshalling.Utf8)]
    public static partial int SetupTunDevice(nint vpninfo, string? vpncScript, string ifname);

    [LibraryImport(Lib, EntryPoint = "openconnect_get_ip_info")]
    public static partial int GetIpInfo(nint vpninfo, OcIpInfo** info, OcVpnOption** cstpOptions, OcVpnOption** dtlsOptions);

    [LibraryImport(Lib, EntryPoint = "openconnect_get_cstp_cipher")]
    public static partial byte* GetCstpCipher(nint vpninfo);

    [LibraryImport(Lib, EntryPoint = "openconnect_get_dtls_cipher")]
    public static partial byte* GetDtlsCipher(nint vpninfo);

    [LibraryImport(Lib, EntryPoint = "openconnect_setup_cmd_pipe")]
    public static partial nint SetupCmdPipe(nint vpninfo);

    [LibraryImport(Lib, EntryPoint = "openconnect_mainloop")]
    public static partial int Mainloop(nint vpninfo, int reconnectTimeout, int reconnectInterval);

    [LibraryImport(Lib, EntryPoint = "openconnect_webview_load_changed")]
    public static partial int WebviewLoadChanged(nint vpninfo, OcWebviewResult* result);

    public static string? Str(byte* p) => p == null ? null : Marshal.PtrToStringUTF8((nint)p);
}
