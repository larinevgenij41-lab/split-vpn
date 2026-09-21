using System.ComponentModel;
using System.Globalization;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.OpenConnect;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Operations;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Coordination;

/// <summary>
/// Туннели AnyConnect. Сеанс шлюза живёт в процессе-помощнике и не переносится между процессами, поэтому
/// помощник запускается только по действию пользователя («Подключить», «Войти»): без него вход в SSO
/// некому показать. После любого завершения сеанса туннель ждёт нового входа.
/// </summary>
public sealed partial class Coordinator
{
    private static readonly TimeSpan SignInPromptLifetime = TimeSpan.FromMinutes(5);
    private const int MaxFormFields = 32;
    private const int MaxFormValueLength = 1024;

    /// <summary>Туннель AnyConnect без сеанса: запустить помощника, если пользователь разрешил вход.</summary>
    private void EnsureAnyConnect(TunnelFacts tunnel)
    {
        if (tunnel.AnyConnect is not null)
        {
            return;
        }

        var approved = Facts.SignInApproved.Contains(tunnel.ProfileId);
        tunnel.PasswordRequired = !approved && tunnel.BlockingError == ErrorCategory.None;
        if (!approved || tunnel.BlockingError != ErrorCategory.None || Facts.Primary is null || _deps.Time.GetUtcNow() < tunnel.NextDialAt
            || _settings.Profile(tunnel.ProfileId) is not { } profile)
        {
            return;
        }

        StartAnyConnect(tunnel, profile);
    }

    private void StartAnyConnect(TunnelFacts tunnel, ConnectionProfile profile)
    {
        if (!AnyConnectGateway.TryParse(profile.Server, out var gateway))
        {
            tunnel.BlockingError = ErrorCategory.Other;
            tunnel.LastErrorText = $"«{tunnel.Name}»: неверный адрес шлюза AnyConnect.";
            return;
        }

        var generation = ++tunnel.DialGeneration;
        var profileId = tunnel.ProfileId;
        IAnyConnectSession session;
        try
        {
            // Очередь неограниченная: запись не ждёт и не отказывает, пока служба работает.
            session = _deps.AnyConnect.Start(helperEvent => TryEnqueue("Helper:" + helperEvent.GetType().Name, () => OnHelperEventAsync(profileId, generation, helperEvent, CancellationToken.None)));
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or Win32Exception or UnauthorizedAccessException)
        {
            tunnel.BlockingError = ErrorCategory.Other;
            tunnel.LastErrorCategory = ErrorCategory.Other;
            tunnel.LastErrorText = $"«{tunnel.Name}»: помощник AnyConnect не запустился: {ex.Message}";
            Journal("Ошибка", tunnel.LastErrorText);
            return;
        }

        // События помощника обрабатываются в очереди актора, то есть уже после этого присваивания.
        tunnel.AnyConnect = new AnyConnectLink(session, generation);
        tunnel.PasswordRequired = false;
        tunnel.SignIn = null;
        var settings = profile.AnyConnect;
        session.Send(new StartCommand(
            gateway.Url,
            settings.Group,
            settings.UserAgent,
            settings.UseDtls,
            settings.ClientCertificateThumbprint.Length > 0 ? settings.ClientCertificateThumbprint : null,
            InterfaceNameFor(profile),
            string.IsNullOrWhiteSpace(profile.UserName) ? null : profile.UserName,
            LoadGatewayPassword(profile)));
        Journal("Сведения", $"Подключение к «{profile.Name}» (AnyConnect, шлюз {gateway.Host}).");
    }

    /// <summary>Имя адаптера Wintun: постоянное для профиля.</summary>
    internal static string InterfaceNameFor(ConnectionProfile profile) => "SplitVpn AC " + profile.Id.ToString("N")[..8];

    /// <summary>Пароль для формы шлюза: сохранённый или запомненный до перезапуска службы; без него шлюз спросит.</summary>
    private string? LoadGatewayPassword(ConnectionProfile profile)
    {
        var chars = Facts.MemoryPasswordProfile == profile.Id && Facts.MemoryPassword is { } memory
            ? memory.ToArray()
            : profile.SavePassword ? _deps.Secrets.TryLoad(profile.Id) : null;
        if (chars is null)
        {
            return null;
        }

        var password = new string(chars);
        Array.Clear(chars);
        return password;
    }

    internal async Task OnHelperEventAsync(Guid profileId, int generation, HelperEvent helperEvent, CancellationToken cancellationToken)
    {
        if (Facts.Tunnels.GetValueOrDefault(profileId) is not { AnyConnect: { } link } tunnel || link.Generation != generation)
        {
            // Событие прежнего процесса: сеанс уже остановлен службой.
            return;
        }

        switch (helperEvent)
        {
            case HelloEvent hello when hello.Contract != HelperContract.Version:
                StopAnyConnect(tunnel);
                tunnel.BlockingError = ErrorCategory.Other;
                tunnel.LastErrorText = $"«{tunnel.Name}»: версия помощника AnyConnect не совпадает со службой — переустановите программу.";
                Journal("Ошибка", tunnel.LastErrorText);
                break;
            case HelloEvent hello:
                link.ClientVersion = hello.OpenConnectVersion;
                _deps.Logger.LogInformation("Помощник AnyConnect {Name}: {Version}", tunnel.Name, hello.OpenConnectVersion);
                break;
            case SsoOpenEvent open:
                tunnel.SignIn = new SignInPromptDto
                {
                    RequestId = open.RequestId,
                    Kind = SignInKind.Browser,
                    GatewayHost = open.GatewayHost,
                    Uri = open.Uri,
                    ExpiresUtc = _deps.Time.GetUtcNow() + SignInPromptLifetime,
                };
                tunnel.PasswordRequired = true;
                Journal("Сведения", $"«{tunnel.Name}»: требуется вход через браузер.");
                break;
            case SsoResultEvent result:
                OnSsoResult(tunnel, result);
                break;
            case AuthFormEvent form:
                tunnel.SignIn = new SignInPromptDto
                {
                    RequestId = form.RequestId,
                    Kind = SignInKind.Form,
                    GatewayHost = GatewayHostOf(tunnel),
                    Title = form.Title,
                    Message = form.Message,
                    Error = form.Error,
                    Fields = form.Fields,
                    ExpiresUtc = _deps.Time.GetUtcNow() + SignInPromptLifetime,
                };
                tunnel.PasswordRequired = true;
                Journal("Сведения", $"«{tunnel.Name}»: шлюз запрашивает данные входа.");
                break;
            case ResolveHostEvent resolve:
                await ResolveGatewayAsync(tunnel, link, resolve.Host, cancellationToken);
                break;
            case EstablishedEvent up:
                await OnAnyConnectEstablishedAsync(tunnel, link, up, cancellationToken);
                break;
            case IpInfoChangedEvent changed:
                ApplySession(tunnel, changed.Session);
                Journal("Сведения", $"«{tunnel.Name}»: шлюз изменил параметры сеанса после переподключения.");
                await ReconcileAsync(cancellationToken);
                break;
            case StatsEvent stats:
                tunnel.Statistics = new RasStatistics(stats.BytesSent, stats.BytesReceived, _deps.Time.GetUtcNow() - (tunnel.SessionStartedUtc ?? _deps.Time.GetUtcNow()));
                if (tunnel.Session is { } session && session.DtlsActive != stats.DtlsActive)
                {
                    tunnel.Session = session with { DtlsActive = stats.DtlsActive };
                }

                break;
            case ReconnectingEvent reconnecting:
                Journal("Предупреждение", $"«{tunnel.Name}»: связь со шлюзом прервалась, переподключение ({reconnecting.Reason}).");
                break;
            case LogEvent log:
                // Сообщения библиотеки без секретов (их вырезает помощник) — в файл журнала службы: по ним разбирают сбои входа.
                _deps.Logger.Log(log.Level switch { "error" => LogLevel.Warning, "info" => LogLevel.Information, _ => LogLevel.Debug },
                    "AnyConnect {Name}: {Text}", tunnel.Name, log.Text.TrimEnd());
                break;
            case TerminatedEvent terminated:
                await OnAnyConnectTerminatedAsync(tunnel, link, terminated, cancellationToken);
                break;
        }
    }

    private void OnSsoResult(TunnelFacts tunnel, SsoResultEvent result)
    {
        if (tunnel.SignIn?.RequestId != result.RequestId)
        {
            return;
        }

        // Окно закрывается по исчезновению запроса; при ошибке следом придёт Terminated с причиной.
        tunnel.SignIn = null;
        tunnel.PasswordRequired = false;
        if (!result.Done)
        {
            _deps.Logger.LogWarning("AnyConnect {Name}: SSO не принят: {Error}", tunnel.Name, result.Error);
        }
    }

    /// <summary>
    /// Адрес шлюза для libopenconnect. До ответа адрес попадает в серверные адреса: политика, фильтры и маршрут /32
    /// через основной адаптер готовы раньше, чем помощник откроет соединение.
    /// </summary>
    private async Task ResolveGatewayAsync(TunnelFacts tunnel, AnyConnectLink link, string host, CancellationToken cancellationToken)
    {
        IReadOnlyList<uint> addresses;
        if (Ipv4.TryParse(host, out var literal))
        {
            addresses = [literal];
        }
        else if (string.Equals(host, GatewayHostOf(tunnel), StringComparison.OrdinalIgnoreCase) && tunnel.ServerAddresses.Count > 0)
        {
            addresses = tunnel.ServerAddresses;
        }
        else
        {
            addresses = await ResolveHelperHostAsync(host, cancellationToken);
        }

        var added = addresses.Where(a => !tunnel.ServerAddresses.Contains(a) && !link.ResolvedAddresses.Contains(a)).ToList();
        if (added.Count > 0)
        {
            link.ResolvedAddresses.AddRange(added);
            Journal("Сведения", $"«{tunnel.Name}»: узел шлюза {host} — " + string.Join(", ", added.Select(Ipv4.Format)));
            // Сверка ловит системные ошибки сама: сбой применения не должен уронить очередь актора.
            await ReconcileAsync(cancellationToken);
        }

        link.Session.Send(new ResolveReplyCommand(host, addresses.Count > 0 ? Ipv4.Format(addresses[0]) : null));
    }

    private async Task<IReadOnlyList<uint>> ResolveHelperHostAsync(string host, CancellationToken cancellationToken)
    {
        if (Facts.Primary is not { } primary)
        {
            return [];
        }

        try
        {
            var addresses = await _deps.Resolver.ResolveAsync(host, ServiceDnsAddresses(), primary.InterfaceIndex, cancellationToken);
            if (addresses.Count > 0)
            {
                _deps.DnsProxy.Pin(host, addresses);
            }

            return addresses;
        }
        catch (Exception ex) when (ex is SocketException or IOException or InvalidOperationException or TimeoutException)
        {
            _deps.Logger.LogWarning(ex, "Не удалось разрешить узел шлюза AnyConnect");
            return [];
        }
    }

    private async Task OnAnyConnectEstablishedAsync(TunnelFacts tunnel, AnyConnectLink link, EstablishedEvent up, CancellationToken cancellationToken)
    {
        link.Established = true;
        link.Luid = up.Luid;
        tunnel.Adapter = _deps.Inventory.Capture().Adapters.FirstOrDefault(a => a.Luid == up.Luid);
        ApplySession(tunnel, up.Session);
        tunnel.SessionStartedUtc = _deps.Time.GetUtcNow();
        tunnel.Statistics = null;
        tunnel.EverConnected = true;
        tunnel.Verified = false;
        tunnel.SignIn = null;
        tunnel.PasswordRequired = false;
        // Счётчики повторов и текст ошибки снимает проверка готовности (она идёт сразу после этой сверки).
        var networks = up.Session.IncludeCidrs().Count;
        Journal("Сведения", string.Create(CultureInfo.InvariantCulture,
            $"«{tunnel.Name}» подключён (AnyConnect): адрес {up.Session.Address}, сетей шлюза {networks}, {(up.Session.DtlsActive ? "DTLS" : "TLS")}."));
        if (networks == 0)
        {
            Journal("Предупреждение", $"«{tunnel.Name}»: шлюз не прислал ни одной сети — через это подключение ничего не пойдёт.");
        }

        if (up.Session.TooWideIncludes() is { Count: > 0 } tooWide)
        {
            Journal("Предупреждение", string.Create(CultureInfo.InvariantCulture,
                $"«{tunnel.Name}»: сети шлюза шире /8 отброшены ({string.Join(", ", tooWide)}) — они забрали бы заметную часть интернета."));
        }

        await ReconcileAsync(cancellationToken);
    }

    private static void ApplySession(TunnelFacts tunnel, SessionInfo session)
    {
        tunnel.Session = session;
        tunnel.VpnDns = session.DnsAddresses();
    }

    private async Task OnAnyConnectTerminatedAsync(TunnelFacts tunnel, AnyConnectLink link, TerminatedEvent terminated, CancellationToken cancellationToken)
    {
        var wasUp = link.Established;
        link.Session.Dispose();
        tunnel.AnyConnect = null;
        tunnel.SignIn = null;
        Facts.SignInApproved.Remove(tunnel.ProfileId);
        if (wasUp)
        {
            tunnel.ResetConnection(_deps.Time.GetUtcNow());
        }

        tunnel.VpnDns = [];
        var (category, blocking, fallback) = terminated.Kind switch
        {
            TerminationKind.Cancelled => (ErrorCategory.None, false, null),
            TerminationKind.CertificateRejected => (ErrorCategory.Certificate, true, "сертификат шлюза не прошёл проверку"),
            TerminationKind.HostScanRequired => (ErrorCategory.Authentication, true, "шлюз требует проверку состояния компьютера (HostScan), которую программа не выполняет"),
            TerminationKind.AuthRejected => (ErrorCategory.Authentication, false, "шлюз отклонил вход"),
            TerminationKind.SessionExpired => (ErrorCategory.Authentication, false, "сеанс на шлюзе завершён или истёк"),
            TerminationKind.NetworkError => (ErrorCategory.ServerUnreachable, false, "шлюз недоступен"),
            _ => (ErrorCategory.Other, false, "внутренняя ошибка помощника"),
        };

        if (fallback is null)
        {
            Journal("Сведения", wasUp ? $"Сеанс «{tunnel.Name}» завершён." : $"Вход в «{tunnel.Name}» отменён.");
        }
        else
        {
            // Текст помощника уже называет причину; общая формулировка — только если он пуст.
            var reason = string.IsNullOrWhiteSpace(terminated.Text) ? fallback : terminated.Text.Trim().TrimEnd('.');
            tunnel.LastErrorCategory = category;
            tunnel.LastErrorText = $"«{tunnel.Name}»: {reason}";
            tunnel.BlockingError = blocking ? category : ErrorCategory.None;
            Journal("Ошибка", tunnel.LastErrorText + (blocking
                ? ". Повторы остановлены до действия пользователя."
                : wasUp ? ". Сети шлюза недоступны до нового входа." : "."));
        }

        tunnel.PasswordRequired = tunnel.BlockingError == ErrorCategory.None;
        Facts.AppliedFilters.Remove(FilterGroup.Runtime);
        await ReconcileAsync(cancellationToken);
    }

    /// <summary>Останавливает помощника: Stop (BYE на шлюзе) и закрытие канала. События процесса больше не принимаются.</summary>
    private static void StopAnyConnect(TunnelFacts tunnel)
    {
        if (tunnel.AnyConnect is not { } link)
        {
            return;
        }

        link.StopRequested = true;
        link.Session.Send(new StopCommand());
        link.Session.Dispose();
        tunnel.AnyConnect = null;
        tunnel.SignIn = null;
        tunnel.Session = null;
    }

    /// <summary>
    /// Остановка службы: сначала туннели AnyConnect опускаются и политика применяется без сетей шлюза, потом
    /// помощники получают Stop. Сеанс не переживёт службу, поэтому новая служба попросит войти заново.
    /// </summary>
    internal void ShutdownAnyConnect()
    {
        var sessions = Facts.Tunnels.Values.Where(t => t.AnyConnect is not null).ToList();
        if (sessions.Count == 0)
        {
            return;
        }

        foreach (var tunnel in sessions)
        {
            tunnel.AnyConnect!.Established = false;
            tunnel.ResetConnection(_deps.Time.GetUtcNow());
        }

        try
        {
            EnsureRoutesSafe();
        }
        catch (Exception ex) when (ex is Windows.Native.NativeCallException or InvalidOperationException or IOException)
        {
            _deps.Logger.LogWarning(ex, "Не удалось применить политику перед остановкой AnyConnect");
        }

        foreach (var tunnel in sessions)
        {
            StopAnyConnect(tunnel);
        }

        Journal("Сведения", "Служба останавливается: сеансы AnyConnect завершены.");
    }

    private string GatewayHostOf(TunnelFacts tunnel) =>
        AnyConnectGateway.TryParse(_settings.Profile(tunnel.ProfileId)?.Server, out var gateway) ? gateway.Host : "";

    private static bool AnyConnectEndpointChanged(ConnectionProfile before, ConnectionProfile after) =>
        after.Protocol == VpnProtocol.AnyConnect
        && (before.Protocol != after.Protocol
            || before.AnyConnect.Group != after.AnyConnect.Group
            || before.AnyConnect.ClientCertificateThumbprint != after.AnyConnect.ClientCertificateThumbprint
            || before.AnyConnect.UseDtls != after.AnyConnect.UseDtls
            || before.AnyConnect.UserAgent != after.AnyConnect.UserAgent);

    /// <summary>Сети шлюзов с установленным сеансом — в цель карточки «Сети сервера».</summary>
    private List<ServerNetworks> GatewayNetworks()
    {
        var result = new List<ServerNetworks>();
        foreach (var tunnel in Facts.Tunnels.Values.Where(t => t is { IsUp: true, Session: not null, Protocol: VpnProtocol.AnyConnect }))
        {
            if (_settings.Profile(tunnel.ProfileId) is { } profile)
            {
                result.Add(new ServerNetworks(AppSettings.ServerNetworksTarget(profile), tunnel.Session!.IncludeCidrs()));
            }
        }

        return result;
    }

    /// <summary>
    /// DNS-серверы поднятых туннелей идут через свой туннель: иначе широкая сеть шлюза (10.0.0.0/8) перехватила бы
    /// DNS другого подключения. Пока сеанса AnyConnect нет, слой не нужен и политика не меняется.
    /// </summary>
    private List<TunnelHost> TunnelHosts()
    {
        if (!Facts.Tunnels.Values.Any(t => t.AnyConnect is { Established: true }))
        {
            return [];
        }

        return Facts.Tunnels.Values.Where(t => t.Luid is not null)
            .SelectMany(t => t.VpnDns.Select(address => new TunnelHost(t.ProfileId, address)))
            .Distinct()
            .ToList();
    }

    /// <summary>
    /// Суффиксы split DNS шлюза и хост PAC разрешаются DNS-серверами шлюза. Адреса не закрепляются: трафик идёт
    /// по политике, поэтому публичный сайт в том же домене не уводится в туннель. Правило пользователя важнее.
    /// </summary>
    private void AddGatewayDomainRoutes(List<DomainRoute> routes)
    {
        foreach (var tunnel in Facts.Tunnels.Values.Where(t => t is { IsUp: true, Session: not null, Protocol: VpnProtocol.AnyConnect, VpnDns.Count: > 0 }))
        {
            if (_settings.Profile(tunnel.ProfileId) is not { } profile || TunnelDnsRoute(tunnel) is not { } dns)
            {
                continue;
            }

            var session = tunnel.Session!;
            // Однословные суффиксы («local») не берём: они совпали бы с mDNS и именами локальной сети.
            var names = session.SplitDns.Select(SettingsSerializer.NormalizeSuffix)
                .Where(s => s.Contains('.', StringComparison.Ordinal) && SettingsSerializer.IsValidSuffix(s));
            if (Uri.TryCreate(session.ProxyPac, UriKind.Absolute, out var pac) && pac.HostNameType == UriHostNameType.Dns)
            {
                names = names.Append(pac.IdnHost.ToLowerInvariant());
            }

            var target = AppSettings.ServerNetworksTarget(profile);
            foreach (var suffix in names.Distinct().Where(s => routes.TrueForAll(r => r.Suffix != s)).ToList())
            {
                routes.Add(new DomainRoute(suffix, target, dns, PinAddresses: false));
            }
        }
    }

    /// <summary>
    /// Имя шлюза AnyConnect, когда опорного туннеля нет. Без этого посредник уходит в offline, имя шлюза
    /// не разрешается — и вход в дополнительный туннель невозможен именно тогда, когда он нужнее всего:
    /// опорное подключение лежит. Сам адрес шлюза и так пропускается фильтрами как адрес VPN-сервера,
    /// поэтому разрешение его имени напрямую ничего не открывает сверх уже разрешённого. Адреса не
    /// закрепляются: трафик по-прежнему идёт по политике.
    /// </summary>
    private void AddGatewayHostRoutes(List<DomainRoute> routes)
    {
        if (DnsAnchor is not null || Facts.Primary is not { } primary)
        {
            return;
        }

        var direct = new DnsRoute(ServiceDnsAddresses().Select(Endpoint).ToList(), primary.InterfaceIndex);
        foreach (var profile in _settings.ActiveProfiles.Where(p => p.Protocol == VpnProtocol.AnyConnect))
        {
            if (!AnyConnectGateway.TryParse(profile.Server, out var gateway))
            {
                continue;
            }

            var suffix = SettingsSerializer.NormalizeSuffix(gateway.Host);
            if (suffix.Length == 0 || Ipv4.TryParse(suffix, out _) || routes.Exists(r => r.Suffix == suffix))
            {
                continue;
            }

            routes.Add(new DomainRoute(suffix, RouteTarget.Direct, direct, PinAddresses: false));
        }
    }

    private SignInPromptDto? SignInPromptOf(TunnelFacts tunnel)
    {
        if (tunnel.Protocol != VpnProtocol.AnyConnect || _state.Intent != Intent.Connected || _state.ProtectionSuspended)
        {
            return null;
        }

        if (tunnel.SignIn is { } prompt)
        {
            return prompt;
        }

        return tunnel is { AnyConnect: null, PasswordRequired: true, BlockingError: ErrorCategory.None }
            ? new SignInPromptDto { Kind = SignInKind.Required, GatewayHost = GatewayHostOf(tunnel), Error = tunnel.LastErrorText }
            : null;
    }

    private ServerNetworksDto? ServerNetworksOf(TunnelFacts tunnel)
    {
        if (tunnel is not { IsUp: true, Session: { } session })
        {
            return null;
        }

        return new ServerNetworksDto
        {
            Networks = session.IncludeCidrs().Select(c => c.ToString()).ToList(),
            Dns = session.Dns,
            DnsSuffixes = session.SplitDns,
            ProxyPac = session.ProxyPac,
            ApplyProxy = _settings.Profile(tunnel.ProfileId)?.AnyConnect.ApplyServerProxy == true,
            ClientVersion = tunnel.AnyConnect?.ClientVersion,
            Mtu = session.Mtu,
            DtlsActive = session.DtlsActive,
            SessionExpiresUtc = session.SessionTimeoutSeconds is > 0 and var seconds && tunnel.SessionStartedUtc is { } started
                ? started.AddSeconds(seconds)
                : null,
        };
    }

    private async Task<IpcResponse> BeginSignInAsync(Guid profileId, CancellationToken cancellationToken)
    {
        if (_settings.Profile(profileId) is not { Protocol: VpnProtocol.AnyConnect } profile)
        {
            return IpcResponse.Failure(IpcErrorCodes.NotFound, "Подключение AnyConnect не найдено.");
        }

        if (profile.Role == ProfileRole.Off)
        {
            var assigned = await SetProfileRoleAsync(profileId, ProfileRole.Secondary, cancellationToken);
            if (!assigned.Ok)
            {
                return assigned;
            }
        }

        Facts.SignInApproved.Add(profileId);
        if (Facts.Tunnels.GetValueOrDefault(profileId) is { } tunnel)
        {
            tunnel.BlockingError = ErrorCategory.None;
            tunnel.ExternallyDisconnected = false;
            tunnel.NextDialAt = _deps.Time.GetUtcNow();
            RetryFromScratch(tunnel);
        }

        if (_state.Intent != Intent.Connected || _state.ProtectionSuspended)
        {
            return await ChangeIntentAsync(Intent.Connected, cancellationToken);
        }

        await ReconcileAsync(cancellationToken);
        return IpcResponse.Success(BuildStatus());
    }

    private IpcResponse CancelSignIn(CancelSignInRequest request)
    {
        Facts.SignInApproved.Remove(request.ProfileId);
        if (Facts.Tunnels.GetValueOrDefault(request.ProfileId) is { AnyConnect: { Established: false } link } tunnel)
        {
            if (tunnel.SignIn is { } prompt && prompt.RequestId == request.RequestId)
            {
                // Помощник сам завершит вход с итогом Cancelled.
                link.Session.Send(prompt.Kind == SignInKind.Form
                    ? new FormReplyCommand(prompt.RequestId, new Dictionary<string, string>(), Cancel: true)
                    : new WebviewClosedCommand(prompt.RequestId));
                tunnel.SignIn = null;
            }
            else if (request.RequestId == Guid.Empty)
            {
                StopAnyConnect(tunnel);
                tunnel.PasswordRequired = true;
                Journal("Сведения", $"Вход в «{tunnel.Name}» отменён.");
            }
        }

        return IpcResponse.Success(BuildStatus());
    }

    private IpcResponse ForwardSsoNavigation(SsoNavigationRequest request)
    {
        if (!TryGetPrompt(request.ProfileId, request.RequestId, SignInKind.Browser, out var tunnel))
        {
            return IpcResponse.Failure(IpcErrorCodes.NotFound, "Запрос входа устарел.");
        }

        if (request.Cookies.Count > 64 || request.Uri.Length > 8192)
        {
            return IpcResponse.Failure(IpcErrorCodes.BadRequest, "Слишком большой ответ браузера.");
        }

        tunnel.AnyConnect!.Session.Send(new WebviewLoadCommand(request.RequestId, request.Uri, request.Cookies));
        return IpcResponse.Success();
    }

    private IpcResponse SubmitAuthForm(SubmitAuthFormRequest request)
    {
        if (!TryGetPrompt(request.ProfileId, request.RequestId, SignInKind.Form, out var tunnel))
        {
            return IpcResponse.Failure(IpcErrorCodes.NotFound, "Запрос входа устарел.");
        }

        if (request.Values.Count > MaxFormFields
            || request.Values.Any(v => v.Key.Length > 256 || v.Value.Length > MaxFormValueLength || v.Value.Contains('\0', StringComparison.Ordinal)))
        {
            return IpcResponse.Failure(IpcErrorCodes.InvalidSettings, "Недопустимые значения формы входа.");
        }

        tunnel.AnyConnect!.Session.Send(new FormReplyCommand(request.RequestId, request.Values, request.Cancel));
        tunnel.SignIn = null;
        tunnel.PasswordRequired = false;
        if (request.Cancel)
        {
            Facts.SignInApproved.Remove(request.ProfileId);
        }

        return IpcResponse.Success(BuildStatus());
    }

    private bool TryGetPrompt(Guid profileId, Guid requestId, SignInKind kind, out TunnelFacts tunnel)
    {
        tunnel = Facts.Tunnels.GetValueOrDefault(profileId)!;
        return tunnel is { AnyConnect: not null, SignIn: { } prompt } && prompt.RequestId == requestId && prompt.Kind == kind;
    }
}
