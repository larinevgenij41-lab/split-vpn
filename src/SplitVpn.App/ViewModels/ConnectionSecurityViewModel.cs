using System.IO;
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
        new(VpnProtocol.AnyConnect, "Cisco AnyConnect (вход через SSO)"), new(VpnProtocol.SshVpn, "VPN поверх SSH (только TCP)")];

    /// <summary>AnyConnect не бывает опорным подключением: мастер, который создаёт опорное, его не предлагает.</summary>
    public bool AllowAnyConnect { get; init; } = true;

    /// <summary>«VPN поверх SSH» настраивается на странице «Подключения»: мастеру первого запуска он не нужен.</summary>
    public bool AllowSshVpn { get; init; } = true;

    public IReadOnlyList<SecurityChoice<VpnProtocol>> Protocols => AllProtocols
        .Where(p => (AllowAnyConnect || p.Value != VpnProtocol.AnyConnect) && (AllowSshVpn || p.Value != VpnProtocol.SshVpn)).ToList();

    public static IReadOnlyList<SecurityChoice<IpsecAuthentication>> IpsecMethods { get; } =
    [new(IpsecAuthentication.PreSharedKey, "Общий ключ (PSK)"), new(IpsecAuthentication.MachineCertificate, "Сертификат компьютера")];

    private static readonly SecurityChoice<AuthMethod>[] AllMethods =
    [new(AuthMethod.MsChapV2, "MS-CHAPv2"), new(AuthMethod.EapMsChapV2, "EAP-MSCHAPv2"), new(AuthMethod.PeapMsChapV2, "PEAP / EAP-MSCHAPv2"),
        new(AuthMethod.EapTls, "EAP-TLS (сертификат)"), new(AuthMethod.TtlsMsChapV2, "EAP-TTLS / MSCHAPv2"), new(AuthMethod.TtlsPap, "EAP-TTLS / PAP"),
        new(AuthMethod.Pap, "PAP (совместимость)"), new(AuthMethod.Chap, "CHAP (совместимость)"), new(AuthMethod.MachineCertificate, "Сертификат компьютера (IKEv2)"),
        new(AuthMethod.GatewayForm, "Как попросит шлюз: SSO, пароль или сертификат"), new(AuthMethod.SshKey, "Ключ SSH")];

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
    [ObservableProperty] private string _sshHostKey = "";
    [ObservableProperty] private string _sshKeyStatus = SshKeyKept;

    private const string SshKeyKept = "Файл не выбран. Если ключ уже загружен, он остаётся прежним; для нового подключения выберите файл.";

    /// <summary>Содержимое выбранного файла ключа SSH: уходит службе при сохранении и в интерфейсе не показывается.</summary>
    public string? PendingSshKey { get; private set; }

    /// <summary>Выбор файла закрытого ключа SSH. Файл читается сразу и проверяется: формат OpenSSH, без пароля.</summary>
    [CommunityToolkit.Mvvm.Input.RelayCommand]
    private void ChooseSshKey()
    {
        var dialog = new Microsoft.Win32.OpenFileDialog { Title = "Закрытый ключ SSH", Filter = "Все файлы|*.*", CheckFileExists = true };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        LoadSshKeyFile(dialog.FileName);
    }

    /// <summary>Ключ ушёл в службу: в памяти приложения он больше не нужен. Выбранный после отправки остаётся.</summary>
    internal void SshKeySaved(string? sent)
    {
        if (sent is not null && ReferenceEquals(PendingSshKey, sent))
        {
            PendingSshKey = null;
            SshKeyStatus = "Ключ загружен в службу.";
        }
    }

    internal void LoadSshKeyFile(string path)
    {
        try
        {
            PendingSshKey = Core.SshTunnel.SshPrivateKey.ReadFile(path);
            SshKeyStatus = "Выбран файл «" + Path.GetFileName(path) + "»: ключ будет загружен в службу при сохранении.";
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            PendingSshKey = null;
            SshKeyStatus = "Файл ключа не прочитан: " + ex.Message;
        }
    }

    /// <summary>
    /// Раскрыт блок "Параметры входа и безопасности". Своё свойство, а не привязка к <see cref="RequiresSecurityDetails"/>:
    /// щелчок по заголовку заменил бы такую привязку, и блок перестал бы раскрываться сам для L2TP/PSK и EAP.
    /// Раскрывается сам, когда параметры нужны, и сам не сворачивается. Правкой профиля не является.
    /// </summary>
    [ObservableProperty] private bool _detailsExpanded;

    public bool CanClearSavedKey { get; init; } = true;

    /// <summary>Возвращает раскрытие блока к нужному профилю: при открытии другого профиля в редакторе.</summary>
    public void ResetDetailsExpanded() => DetailsExpanded = RequiresSecurityDetails;

    public IReadOnlyList<SecurityChoice<AuthMethod>> AuthMethods => AllMethods.Where(m => VpnProtocols.Supports(Protocol, m.Value)).ToList();
    public bool NeedsPassword => VpnProtocols.NeedsPassword(AuthMethod);
    public bool IsL2tp => Protocol == VpnProtocol.L2tpIpsec;
    public bool IsAnyConnect => Protocol == VpnProtocol.AnyConnect;
    public bool IsSsh => Protocol == VpnProtocol.SshVpn;
    public bool IsRas => VpnProtocols.UsesRas(Protocol);
    public bool NeedsPsk => IsL2tp && IpsecAuthentication == IpsecAuthentication.PreSharedKey;
    public bool RequiresSecurityDetails => NeedsPsk || NeedsTrust || NeedsClientCertificate || NeedsMachineCertificate || IsSsh || CompatibilityHint.Length > 0;
    public bool NeedsTrust => VpnProtocols.NeedsServerValidation(AuthMethod);
    public bool NeedsClientCertificate => AuthMethod == AuthMethod.EapTls;
    public bool NeedsMachineCertificate => AuthMethod == AuthMethod.MachineCertificate || (IsL2tp && IpsecAuthentication == IpsecAuthentication.MachineCertificate);
    public string ProtocolHint => VpnProtocols.ServerHint(Protocol) + (Protocol == VpnProtocol.Pptp ? " PPTP имеет устаревшую защиту; используйте только для совместимости." : "");
    public string ServerPlaceholder => Protocol switch
    {
        VpnProtocol.Sstp => "vpn.example.org:443",
        VpnProtocol.AnyConnect => "https://vpn.example.org/group",
        VpnProtocol.SshVpn => "vpn.example.org:22",
        _ => "vpn.example.org",
    };
    public string CompatibilityHint => VpnProtocols.Supports(Protocol, AuthMethod) ? ""
        : "Прежний способ входа несовместим с выбранным протоколом. Выберите новый способ входа.";
    public string Summary => VpnProtocols.Name(Protocol) + " · " + VpnProtocols.AuthName(AuthMethod);

    partial void OnProtocolChanged(VpnProtocol oldValue, VpnProtocol newValue)
    {
        if (oldValue == VpnProtocol.SshVpn && newValue != oldValue)
        {
            PendingSshKey = null;
            SshKeyStatus = SshKeyKept;
        }

        OnPropertyChanged(nameof(AuthMethods));
        // У AnyConnect и «VPN поверх SSH» по одному способу входа, у RAS-протоколов их нет: при переходе выбор делается сам.
        if ((!VpnProtocols.UsesRas(oldValue) || !VpnProtocols.UsesRas(newValue)) && !VpnProtocols.Supports(newValue, AuthMethod))
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
        OnPropertyChanged(nameof(RequiresSecurityDetails));
        OnPropertyChanged(nameof(ServerPlaceholder));
        foreach (var property in new[] { nameof(NeedsPassword), nameof(IsL2tp), nameof(NeedsPsk), nameof(NeedsTrust), nameof(NeedsClientCertificate),
            nameof(NeedsMachineCertificate), nameof(ProtocolHint), nameof(CompatibilityHint), nameof(IsAnyConnect), nameof(IsRas), nameof(IsSsh) }) { OnPropertyChanged(property); }
        if (RequiresSecurityDetails)
        {
            DetailsExpanded = true;
        }
    }

    public void Load(ConnectionProfile profile)
    {
        Protocol = profile.Protocol; AuthMethod = profile.AuthMethod; IpsecAuthentication = profile.IpsecAuthentication;
        Domain = profile.Domain ?? ""; ServerNames = profile.Eap.ServerNames;
        TrustedRoots = string.Join(Environment.NewLine, profile.Eap.TrustedRootThumbprints);
        ClientCertificateThumbprint = profile.Eap.ClientCertificateThumbprint;
        AnyConnectGroup = profile.AnyConnect.Group; AnyConnectCertificate = profile.AnyConnect.ClientCertificateThumbprint;
        UseDtls = profile.AnyConnect.UseDtls; ApplyServerProxy = profile.AnyConnect.ApplyServerProxy; UserAgent = profile.AnyConnect.UserAgent;
        SshHostKey = profile.SshVpn.HostKey;
        ClearSecrets();
        ResetDetailsExpanded();
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
        // Строка из known_hosts может нести комментарий в конце: в профиль идёт только «тип ключ».
        SshVpn = profile.SshVpn with
        {
            HostKey = Core.SshTunnel.SshHostKey.TryParse(SshHostKey, out var hostKey) ? hostKey.Text : SshHostKey.Trim(),
        },
    };

    public void ClearSecrets() { PreSharedKey = ""; ClearPreSharedKey = false; PendingSshKey = null; SshKeyStatus = SshKeyKept; }
}
