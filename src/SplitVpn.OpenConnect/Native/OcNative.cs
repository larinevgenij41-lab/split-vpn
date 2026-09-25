using System.Runtime.InteropServices;

namespace SplitVpn.OpenConnect.Native;

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

/// <summary>Таблица колбэков ocshim: порядок полей совпадает с struct ocshim_callbacks.</summary>
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

/// <summary>
/// Вызовы libopenconnect и прослойки ocshim. Библиотеки лежат рядом с exe и загружаются стандартным
/// поиском Windows из каталога приложения.
/// </summary>
internal static unsafe partial class OcNative
{
    private const string Library = "libopenconnect-5.dll";
    private const string Shim = "ocshim.dll";

    public const int OptText = 1, OptPassword = 2, OptSelect = 3, OptHidden = 4, OptToken = 5, OptSsoToken = 6, OptSsoUser = 7;
    public const uint OptIgnore = 0x0001;
    public const byte CmdCancel = (byte)'x', CmdStats = (byte)'s';

    private const string GnuTls = "libgnutls-30.dll";

    [LibraryImport(Library, EntryPoint = "openconnect_get_version")]
    public static partial byte* GetVersion();

    [LibraryImport(Library, EntryPoint = "openconnect_init_ssl")]
    public static partial int InitSsl();

    [LibraryImport(GnuTls, EntryPoint = "gnutls_global_init")]
    private static partial int GnuTlsGlobalInit();

    // gnutls_pkcs11_init(flags, deploy_file); GNUTLS_PKCS11_FLAG_MANUAL == 0 — модули не загружать.
    [LibraryImport(GnuTls, EntryPoint = "gnutls_pkcs11_init")]
    private static partial int GnuTlsPkcs11Init(uint flags, nint deployFile);

    /// <summary>
    /// Инициализирует PKCS#11 в ручном режиме до <see cref="InitSsl"/>. Иначе openconnect_init_ssl
    /// вызывает gnutls_pkcs11_init(GNUTLS_PKCS11_FLAG_AUTO) и подхватывает модули по вкомпилированным
    /// в p11-kit путям сборки MSYS2 (например, «\ucrt64\etc\pkcs11\modules»), а корень системного
    /// диска доступен на запись любому пользователю — это дало бы выполнение кода в процессе помощника
    /// от LocalSystem. Смарткарты и аппаратные токены программа не использует: клиентский сертификат
    /// берётся из хранилища Windows, поэтому отключение автозагрузки модулей ничего не ломает.
    /// gnutls хранит счётчик инициализации, поэтому повторный вызов с флагом AUTO внутри
    /// openconnect_init_ssl становится пустой операцией. Best-effort: при отсутствии библиотеки молчим.
    /// </summary>
    public static void HardenPkcs11()
    {
        try
        {
            _ = GnuTlsGlobalInit();
            _ = GnuTlsPkcs11Init(0, 0);
        }
        catch (DllNotFoundException)
        {
        }
        catch (EntryPointNotFoundException)
        {
        }
    }

    [LibraryImport(Shim, EntryPoint = "ocshim_version")]
    public static partial int ShimVersion();

    [LibraryImport(Shim, EntryPoint = "ocshim_new", StringMarshalling = StringMarshalling.Utf8)]
    public static partial nint ShimNew(string useragent, ShimCallbacks* callbacks, nint priv);

    [LibraryImport(Shim, EntryPoint = "ocshim_vpninfo")]
    public static partial nint ShimVpninfo(nint ctx);

    [LibraryImport(Shim, EntryPoint = "ocshim_send_cmd")]
    public static partial int ShimSendCmd(nint socket, byte cmd);

    [LibraryImport(Shim, EntryPoint = "ocshim_free")]
    public static partial void ShimFree(nint ctx);

    [LibraryImport(Library, EntryPoint = "openconnect_set_loglevel")]
    public static partial void SetLogLevel(nint vpninfo, int level);

    [LibraryImport(Library, EntryPoint = "openconnect_set_protocol", StringMarshalling = StringMarshalling.Utf8)]
    public static partial int SetProtocol(nint vpninfo, string protocol);

    [LibraryImport(Library, EntryPoint = "openconnect_set_useragent", StringMarshalling = StringMarshalling.Utf8)]
    public static partial int SetUserAgent(nint vpninfo, string useragent);

    [LibraryImport(Library, EntryPoint = "openconnect_set_reported_os", StringMarshalling = StringMarshalling.Utf8)]
    public static partial int SetReportedOs(nint vpninfo, string os);

    [LibraryImport(Library, EntryPoint = "openconnect_parse_url", StringMarshalling = StringMarshalling.Utf8)]
    public static partial int ParseUrl(nint vpninfo, string url);

    [LibraryImport(Library, EntryPoint = "openconnect_set_client_cert", StringMarshalling = StringMarshalling.Utf8)]
    public static partial int SetClientCert(nint vpninfo, string cert, string? sslKey);

    [LibraryImport(Library, EntryPoint = "openconnect_set_option_value", StringMarshalling = StringMarshalling.Utf8)]
    public static partial int SetOptionValue(OcFormOpt* opt, string value);

    [LibraryImport(Library, EntryPoint = "openconnect_obtain_cookie")]
    public static partial int ObtainCookie(nint vpninfo);

    [LibraryImport(Library, EntryPoint = "openconnect_make_cstp_connection")]
    public static partial int MakeCstpConnection(nint vpninfo);

    [LibraryImport(Library, EntryPoint = "openconnect_setup_dtls")]
    public static partial int SetupDtls(nint vpninfo, int attemptPeriod);

    [LibraryImport(Library, EntryPoint = "openconnect_disable_dtls")]
    public static partial int DisableDtls(nint vpninfo);

    [LibraryImport(Library, EntryPoint = "openconnect_setup_tun_device", StringMarshalling = StringMarshalling.Utf8)]
    public static partial int SetupTunDevice(nint vpninfo, string? vpncScript, string ifname);

    [LibraryImport(Library, EntryPoint = "openconnect_get_ip_info")]
    public static partial int GetIpInfo(nint vpninfo, OcIpInfo** info, OcVpnOption** cstpOptions, OcVpnOption** dtlsOptions);

    [LibraryImport(Library, EntryPoint = "openconnect_get_dtls_cipher")]
    public static partial byte* GetDtlsCipher(nint vpninfo);

    [LibraryImport(Library, EntryPoint = "openconnect_setup_cmd_pipe")]
    public static partial nint SetupCmdPipe(nint vpninfo);

    [LibraryImport(Library, EntryPoint = "openconnect_mainloop")]
    public static partial int Mainloop(nint vpninfo, int reconnectTimeout, int reconnectInterval);

    [LibraryImport(Library, EntryPoint = "openconnect_webview_load_changed")]
    public static partial int WebviewLoadChanged(nint vpninfo, OcWebviewResult* result);

    public static string? Utf8(byte* pointer) => pointer == null ? null : Marshal.PtrToStringUTF8((nint)pointer);
}
