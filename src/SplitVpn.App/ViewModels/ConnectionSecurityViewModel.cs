using CommunityToolkit.Mvvm.ComponentModel;
using SplitVpn.Core.Settings;

namespace SplitVpn.App.ViewModels;

public sealed record SecurityChoice<T>(T Value, string Name)
{
    public override string ToString() => Name;
}

/// <summary>Общие поля безопасности для редактора подключения и мастера.</summary>
public sealed partial class ConnectionSecurityViewModel : ObservableObject
{
    private static readonly SecurityChoice<VpnProtocol>[] AllProtocols =
    [new(VpnProtocol.Sstp, "SSTP"), new(VpnProtocol.L2tpIpsec, "L2TP/IPsec"), new(VpnProtocol.Ikev2, "IKEv2"), new(VpnProtocol.Pptp, "PPTP (устаревший)"),
        new(VpnProtocol.AnyConnect, "Cisco AnyConnect (вход через SSO)")];

    /// <summary>AnyConnect не бывает опорным подключением: мастер, который создаёт опорное, его не предлагает.</summary>
    public bool AllowAnyConnect { get; init; } = true;

    public IReadOnlyList<SecurityChoice<VpnProtocol>> Protocols => AllowAnyConnect ? AllProtocols : AllProtocols.Where(p => p.Value != VpnProtocol.AnyConnect).ToList();

    public static IReadOnlyList<SecurityChoice<IpsecAuthentication>> IpsecMethods { get; } =
    [new(IpsecAuthentication.PreSharedKey, "Общий ключ (PSK)"), new(IpsecAuthentication.MachineCertificate, "Сертификат компьютера")];

    private static readonly SecurityChoice<AuthMethod>[] AllMethods =
    [new(AuthMethod.MsChapV2, "MS-CHAPv2"), new(AuthMethod.EapMsChapV2, "EAP-MSCHAPv2"), new(AuthMethod.PeapMsChapV2, "PEAP / EAP-MSCHAPv2"),
        new(AuthMethod.EapTls, "EAP-TLS (сертификат)"), new(AuthMethod.TtlsMsChapV2, "EAP-TTLS / MSCHAPv2"), new(AuthMethod.TtlsPap, "EAP-TTLS / PAP"),
        new(AuthMethod.Pap, "PAP (совместимость)"), new(AuthMethod.Chap, "CHAP (совместимость)"), new(AuthMethod.MachineCertificate, "Сертификат компьютера (IKEv2)"),
        new(AuthMethod.GatewayForm, "Как попросит шлюз: SSO, пароль или сертификат")];

    [ObservableProperty] private VpnProtocol _protocol;
    [ObservableProperty] private AuthMethod _authMethod;
    [ObservableProperty] private IpsecAuthentication _ipsecAuthentication;
    [ObservableProperty] private string _domain = "";
    [ObservableProperty] private string _serverNames = "";
    [ObservableProperty] private string _trustedRoots = "";
    [ObservableProperty] private string _clientCertificateThumbprint = "";
    [ObservableProperty] private string _preSharedKey = "";
    [ObservableProperty] private bool _clearPreSharedKey;
    [ObservableProperty] private string _anyConnectGroup = "";
    [ObservableProperty] private string _anyConnectCertificate = "";
    [ObservableProperty] private bool _useDtls = true;
    [ObservableProperty] private bool _applyServerProxy;
    [ObservableProperty] private string _userAgent = AnyConnectSettings.DefaultUserAgent;

    public bool CanClearSavedKey { get; init; } = true;

    public IReadOnlyList<SecurityChoice<AuthMethod>> AuthMethods => AllMethods.Where(m => VpnProtocols.Supports(Protocol, m.Value)).ToList();
    public bool NeedsPassword => VpnProtocols.NeedsPassword(AuthMethod);
    public bool IsL2tp => Protocol == VpnProtocol.L2tpIpsec;
    public bool IsAnyConnect => Protocol == VpnProtocol.AnyConnect;
    public bool IsRas => !IsAnyConnect;
    public bool NeedsPsk => IsL2tp && IpsecAuthentication == IpsecAuthentication.PreSharedKey;
    public bool NeedsTrust => VpnProtocols.NeedsServerValidation(AuthMethod);
    public bool NeedsClientCertificate => AuthMethod == AuthMethod.EapTls;
    public bool NeedsMachineCertificate => AuthMethod == AuthMethod.MachineCertificate || (IsL2tp && IpsecAuthentication == IpsecAuthentication.MachineCertificate);
    public string ProtocolHint => VpnProtocols.ServerHint(Protocol) + (Protocol == VpnProtocol.Pptp ? " PPTP имеет устаревшую защиту; используйте только для совместимости." : "");
    public string CompatibilityHint => VpnProtocols.Supports(Protocol, AuthMethod) ? ""
        : "Прежний способ входа несовместим с выбранным протоколом. Выберите новый способ входа.";
    public string Summary => VpnProtocols.Name(Protocol) + " · " + VpnProtocols.AuthName(AuthMethod);

    partial void OnProtocolChanged(VpnProtocol oldValue, VpnProtocol newValue)
    {
        OnPropertyChanged(nameof(AuthMethods));
        // У AnyConnect один способ входа, у RAS-протоколов его нет: при переходе между ними выбор делается сам.
        if ((oldValue == VpnProtocol.AnyConnect || newValue == VpnProtocol.AnyConnect) && !VpnProtocols.Supports(newValue, AuthMethod))
        {
            AuthMethod = AuthMethods[0].Value;
        }

        NotifyOptions();
    }

    partial void OnAuthMethodChanged(AuthMethod value) => NotifyOptions();
    partial void OnIpsecAuthenticationChanged(IpsecAuthentication value) => NotifyOptions();

    private void NotifyOptions()
    {
        OnPropertyChanged(nameof(Summary));
        foreach (var property in new[] { nameof(NeedsPassword), nameof(IsL2tp), nameof(NeedsPsk), nameof(NeedsTrust), nameof(NeedsClientCertificate),
            nameof(NeedsMachineCertificate), nameof(ProtocolHint), nameof(CompatibilityHint), nameof(IsAnyConnect), nameof(IsRas) }) { OnPropertyChanged(property); }
    }

    public void Load(ConnectionProfile profile)
    {
        Protocol = profile.Protocol; AuthMethod = profile.AuthMethod; IpsecAuthentication = profile.IpsecAuthentication;
        Domain = profile.Domain ?? ""; ServerNames = profile.Eap.ServerNames;
        TrustedRoots = string.Join(Environment.NewLine, profile.Eap.TrustedRootThumbprints);
        ClientCertificateThumbprint = profile.Eap.ClientCertificateThumbprint;
        AnyConnectGroup = profile.AnyConnect.Group; AnyConnectCertificate = profile.AnyConnect.ClientCertificateThumbprint;
        UseDtls = profile.AnyConnect.UseDtls; ApplyServerProxy = profile.AnyConnect.ApplyServerProxy; UserAgent = profile.AnyConnect.UserAgent;
        ClearSecrets();
    }

    public ConnectionProfile Apply(ConnectionProfile profile) => profile with
    {
        Protocol = Protocol, AuthMethod = AuthMethod, IpsecAuthentication = IpsecAuthentication, Domain = Domain.Trim(),
        Eap = new EapSettings
        {
            ServerNames = ServerNames.Trim(),
            TrustedRootThumbprints = TrustedRoots.Split(['\r', '\n', ';'], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .Select(VpnProtocols.NormalizeThumbprint).Distinct().ToList(),
            ClientCertificateThumbprint = VpnProtocols.NormalizeThumbprint(ClientCertificateThumbprint),
        },
        // Цель карточки «Сети шлюза» меняется на доске маршрутизации: здесь она остаётся как в профиле.
        AnyConnect = profile.AnyConnect with
        {
            Group = AnyConnectGroup.Trim(),
            ClientCertificateThumbprint = VpnProtocols.NormalizeThumbprint(AnyConnectCertificate),
            UseDtls = UseDtls,
            ApplyServerProxy = ApplyServerProxy,
            UserAgent = UserAgent.Trim(),
        },
    };

    public void ClearSecrets() { PreSharedKey = ""; ClearPreSharedKey = false; }
}
