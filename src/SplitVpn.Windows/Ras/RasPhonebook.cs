using System.Globalization;
using SplitVpn.Core.Settings;
using SplitVpn.Windows.Native;
using Windows.Win32;
using Windows.Win32.NetworkManagement.Rras;
using static SplitVpn.Windows.Ras.RasConstants;

namespace SplitVpn.Windows.Ras;

public sealed record RasEntrySpec(string EntryName, string Server, uint? DnsServer = null)
{
    public VpnProtocol Protocol { get; init; } = VpnProtocol.Sstp;
    public AuthMethod AuthMethod { get; init; } = AuthMethod.MsChapV2;
    public IpsecAuthentication IpsecAuthentication { get; init; }
}

/// <summary>Запись VPN в собственном файле телефонной книги приложения.</summary>
public static unsafe class RasPhonebook
{
    /// <summary>Создаёт или перезаписывает запись. Пароли в телефонную книгу не пишутся.</summary>
    public static void Save(string phonebookPath, RasEntrySpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(phonebookPath))!);
        var entry = Build(spec);
        var code = PInvoke.RasSetEntryProperties(phonebookPath, spec.EntryName, entry, (uint)sizeof(RASENTRYW), default, 0);
        NativeCallException.ThrowIfFailed(code, "RasSetEntryProperties");
    }

    public static bool Exists(string? phonebookPath, string entryName) => TryRead(phonebookPath, entryName, out _) == ErrorSuccess;

    /// <summary>Имена всех записей своей телефонной книги: по ним чистятся записи удалённых профилей.</summary>
    public static IReadOnlyList<string> EnumerateEntryNames(string phonebookPath)
    {
        if (!File.Exists(phonebookPath))
        {
            return [];
        }

        var count = 8;
        while (true)
        {
            var buffer = new RASENTRYNAMEW[count];
            buffer[0].dwSize = (uint)sizeof(RASENTRYNAMEW);
            var size = (uint)(sizeof(RASENTRYNAMEW) * count);
            var code = PInvoke.RasEnumEntries(null, phonebookPath, ref buffer[0], ref size, out var returned);
            if (code == ErrorBufferTooSmall)
            {
                count = (int)(size / sizeof(RASENTRYNAMEW)) + 1;
                continue;
            }

            NativeCallException.ThrowIfFailed(code, "RasEnumEntries");
            return buffer.Take((int)returned).Select(e => e.szEntryName.AsReadOnlySpan().SliceAtNull().ToString()).ToList();
        }
    }

    public static void Delete(string phonebookPath, string entryName)
    {
        var code = PInvoke.RasDeleteEntry(phonebookPath, entryName);
        if (code is not ErrorSuccess and not ErrorCannotFindPhonebookEntry)
        {
            throw new NativeCallException("RasDeleteEntry", code);
        }
    }

    /// <summary>Сводка ключевых полей записи — для сравнения своей записи с рабочим профилем пользователя.</summary>
    public static IReadOnlyDictionary<string, string> Describe(string? phonebookPath, string entryName)
    {
        var code = TryRead(phonebookPath, entryName, out var e);
        NativeCallException.ThrowIfFailed(code, "RasGetEntryProperties");
        return new SortedDictionary<string, string>(StringComparer.Ordinal)
        {
            ["dwType"] = Hex(e.dwType),
            ["dwfOptions"] = Hex(e.dwfOptions),
            ["dwfOptions2"] = Hex(e.dwfOptions2),
            ["dwfOptions3"] = Hex(e.dwfOptions3),
            ["dwVpnStrategy"] = Hex(e.dwVpnStrategy),
            ["dwEncryptionType"] = Hex(e.dwEncryptionType),
            ["dwfNetProtocols"] = Hex(e.dwfNetProtocols),
            ["dwFramingProtocol"] = Hex(e.dwFramingProtocol),
            ["dwCustomAuthKey"] = Hex(e.dwCustomAuthKey),
            ["dwRedialCount"] = Hex(e.dwRedialCount),
            ["dwIdleDisconnectSeconds"] = Hex(e.dwIdleDisconnectSeconds),
            ["dwIPv4InterfaceMetric"] = Hex(e.dwIPv4InterfaceMetric),
            ["szDeviceType"] = e.szDeviceType.AsReadOnlySpan().SliceAtNull().ToString(),
            ["szDeviceName"] = e.szDeviceName.AsReadOnlySpan().SliceAtNull().ToString(),
            ["szLocalPhoneNumber"] = e.szLocalPhoneNumber.AsReadOnlySpan().SliceAtNull().ToString(),
            ["ipaddrDns"] = string.Create(CultureInfo.InvariantCulture, $"{e.ipaddrDns.a}.{e.ipaddrDns.b}.{e.ipaddrDns.c}.{e.ipaddrDns.d}"),
        };
    }

    internal static RASENTRYW Build(RasEntrySpec spec)
    {
        if (!VpnProtocols.Supports(spec.Protocol, spec.AuthMethod) || !VpnProtocols.TryParseServer(spec.Server, spec.Protocol, out var server))
        {
            throw new InvalidOperationException("Недопустимые параметры VPN-записи.");
        }

        var entry = new RASENTRYW
        {
            dwSize = (uint)sizeof(RASENTRYW),
            dwType = RasetVpn,
            dwVpnStrategy = spec.Protocol switch { VpnProtocol.Sstp => VsSstpOnly, VpnProtocol.L2tpIpsec => 3, VpnProtocol.Ikev2 => 7, _ => 1 },
            dwEncryptionType = spec.AuthMethod is AuthMethod.Pap or AuthMethod.Chap ? 0u : EtRequire,
            dwFramingProtocol = RasfpPpp,
            dwfNetProtocols = RasnpIp,
            dwIdleDisconnectSeconds = RasidsDisabled,
            dwRedialCount = 0,
            dwfOptions = AuthenticationOptions(spec.AuthMethod),
            dwCustomAuthKey = VpnProtocols.IsEap(spec.AuthMethod) ? EapConfiguration.TypeId(spec.AuthMethod) : 0,
            dwfOptions2 = Raseo2DontUseRasCredentials
                | Raseo2DisableClassBasedStaticRoute
                | Raseo2DontNegotiateMultilink
                | Raseo2DisableNbtOverIp
                | Raseo2SecureFileAndPrint
                | Raseo2SecureClientForMsNet,
        };

        if (spec.Protocol == VpnProtocol.L2tpIpsec && spec.IpsecAuthentication == IpsecAuthentication.PreSharedKey)
        {
            entry.dwfOptions2 |= PInvoke.RASEO2_UsePreSharedKey;
        }

        if (spec.AuthMethod == AuthMethod.MachineCertificate)
        {
            entry.dwfOptions2 |= PInvoke.RASEO2_RequireMachineCertificates;
        }

        // Маршрут по умолчанию через VPN RAS не ставит: маршрутами управляет служба.
        Copy(server.ForPhonebook, entry.szLocalPhoneNumber.AsSpan());
        Copy(DeviceTypeVpn, entry.szDeviceType.AsSpan());
        Copy(spec.Protocol switch
        {
            VpnProtocol.Sstp => DeviceNameSstp, VpnProtocol.L2tpIpsec => "WAN Miniport (L2TP)",
            VpnProtocol.Ikev2 => "WAN Miniport (IKEv2)", _ => "WAN Miniport (PPTP)",
        }, entry.szDeviceName.AsSpan());
        if (spec.DnsServer is { } dns)
        {
            entry.dwfOptions |= RaseoSpecificNameServers;
            entry.ipaddrDns = new RASIPADDR { a = (byte)(dns >> 24), b = (byte)(dns >> 16), c = (byte)(dns >> 8), d = (byte)dns };
        }

        return entry;
    }

    private static uint AuthenticationOptions(AuthMethod method) => method switch
    {
        // PAP/CHAP не вырабатывают MPPE-ключи; шифрование обеспечивается SSTP TLS или обязательным IPsec.
        AuthMethod.Pap => PInvoke.RASEO_RequirePAP,
        AuthMethod.Chap => PInvoke.RASEO_RequireCHAP,
        AuthMethod.MachineCertificate => RaseoRequireDataEncryption,
        AuthMethod.MsChapV2 => RaseoRequireDataEncryption | RaseoRequireMsChap2,
        _ => RaseoRequireDataEncryption | PInvoke.RASEO_RequireEAP,
    };

    public static void SetPreSharedKey(string phonebook, string entryName, ReadOnlySpan<char> key)
    {
        var credentials = new RASCREDENTIALSW { dwSize = (uint)sizeof(RASCREDENTIALSW), dwMask = PInvoke.RASCM_PreSharedKey };
        try
        {
            if (key.Length > 256 || key.Contains('\0')) { throw new InvalidOperationException("Недопустимый ключ IPsec."); }
            key.CopyTo(credentials.szPassword.AsSpan());
            NativeCallException.ThrowIfFailed(PInvoke.RasSetCredentials(phonebook, entryName, credentials, key.IsEmpty), "RasSetCredentials PSK");
        }
        finally { credentials.szPassword.AsSpan().Clear(); }
    }

    public static void SetEapConfiguration(string phonebook, string entryName, byte[] config)
    {
        fixed (byte* data = config)
        fixed (char* book = phonebook)
        fixed (char* name = entryName)
        {
            NativeCallException.ThrowIfFailed(PInvoke.RasSetCustomAuthData(book, name, data, (uint)config.Length), "RasSetCustomAuthData");
        }
    }

    private static uint TryRead(string? phonebookPath, string entryName, out RASENTRYW entry)
    {
        entry = new RASENTRYW { dwSize = (uint)sizeof(RASENTRYW) };
        var size = (uint)sizeof(RASENTRYW);
        uint deviceInfoSize = 0;
        return PInvoke.RasGetEntryProperties(phonebookPath, entryName, ref entry, ref size, default, ref deviceInfoSize);
    }

    private static void Copy(string value, Span<char> target)
    {
        if (value.Length >= target.Length)
        {
            throw new ArgumentException("Значение не помещается в поле RAS.", nameof(value));
        }

        target.Clear();
        value.AsSpan().CopyTo(target);
    }

    private static string Hex(uint value) => string.Create(CultureInfo.InvariantCulture, $"0x{value:X8}");
}
