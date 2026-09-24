namespace SplitVpn.Windows.Ras;

/// <summary>Константы ras.h, которых нет в метаданных как перечислений.</summary>
internal static class RasConstants
{
    public const uint RaseoSpecificNameServers = 0x00000004;
    public const uint RaseoRemoteDefaultGateway = 0x00000010;
    public const uint RaseoModemLights = 0x00000100;
    public const uint RaseoRequireDataEncryption = 0x00001000;
    public const uint RaseoUseLogonCredentials = 0x00004000;
    public const uint RaseoPreviewUserPw = 0x01000000;
    public const uint RaseoPreviewDomain = 0x02000000;
    public const uint RaseoShowDialingProgress = 0x04000000;
    public const uint RaseoRequireMsChap2 = 0x20000000;

    public const uint Raseo2SecureFileAndPrint = 0x00000001;
    public const uint Raseo2SecureClientForMsNet = 0x00000002;
    public const uint Raseo2DontNegotiateMultilink = 0x00000004;
    public const uint Raseo2DontUseRasCredentials = 0x00000008;
    public const uint Raseo2DisableNbtOverIp = 0x00000040;
    public const uint Raseo2ReconnectIfDropped = 0x00000100;
    public const uint Raseo2Ipv6RemoteDefaultGateway = 0x00002000;
    public const uint Raseo2RegisterIpWithDns = 0x00004000;
    public const uint Raseo2DisableClassBasedStaticRoute = 0x00080000;
    public const uint Raseo2CacheCredentials = 0x02000000;

    public const uint RasnpIp = 0x00000004;
    public const uint RasfpPpp = 1;
    public const uint RasetVpn = 2;
    public const uint EtRequire = 1;
    public const uint VsSstpOnly = 5;
    public const uint RasidsDisabled = 0xFFFFFFFF;

    public const uint RasApiVersionCurrent = 4;
    public const uint NotifierTypeRasDialFunc2 = 2;

    public const uint ErrorSuccess = 0;
    public const uint ErrorInvalidHandle = 6;
    public const uint ErrorBufferTooSmall = 603;
    public const uint ErrorAlreadyDisconnecting = 617;
    public const uint ErrorPortNotOpen = 618;
    public const uint ErrorPortDisconnected = 619;
    public const uint ErrorCannotFindPhonebookEntry = 623;
    public const uint ErrorNoConnection = 668;

    /// <summary>Границы кодов ras.h (RASBASE…RASBASEEND): их расшифровывает RasGetErrorString, а не FormatMessage.</summary>
    public const uint RasErrorFirst = 600;
    public const uint RasErrorLast = 950;

    public const string DeviceTypeVpn = "vpn";
    public const string DeviceNameSstp = "WAN Miniport (SSTP)";
}
