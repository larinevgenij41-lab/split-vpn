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

    /// <summary>
    /// Узлы кластера шлюза, о которых спрашивал помощник: их имена есть в журнале. Отчёт читает набор
    /// вне очереди актора, поэтому он потокобезопасный.
    /// </summary>
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, byte> _gatewayNodeHosts = new(StringComparer.OrdinalIgnoreCase);
    private const int MaxFormFields = 32;
    private const int MaxFormValueLength = 1024;

    /// <summary>
    /// За сколько помощник должен поднять сеанс, пока он работает сам — без ответа пользователя на запрос входа.
    /// Иначе он считается зависшим (нет ответа шлюза, ожидание внешнего браузера HPKE без колбэка) и останавливается.
    /// </summary>
    internal static readonly TimeSpan AnyConnectEstablishDeadline = TimeSpan.FromSeconds(90);

    /// <summary>
    /// Сколько ждать выхода прежнего помощника профиля перед запуском нового: 2 с на дописывание канала, его
    /// собственный срок выхода 15 с и 3 с на конец процесса после принудительного завершения. Дольше не ждём —
    /// завис сам процесс, и ожидание не поможет.
    /// </summary>
    internal static readonly TimeSpan HelperExitWait = TimeSpan.FromSeconds(20);

    /// <summary>
    /// Помощники, которых служба уже отпустила, а процесс ещё не вышел: адаптер Wintun с именем профиля занят ими,
    /// и новый помощник того же профиля не смог бы его создать.
    /// </summary>
    private readonly Dictionary<Guid, HelperExit> _helperExits = [];

    /// <summary>Выход отпущенного помощника и его ожидание, ограниченное <see cref="HelperExitWait"/>.</summary>
    private sealed record HelperExit(Task Exited, Task Waited)
    {
        public bool Over => Exited.IsCompleted || Waited.IsCompleted;
    }

    /// <summary>Туннель AnyConnect без сеанса: запустить помощника, если пользователь разрешил вход.</summary>
    private void EnsureAnyConnect(TunnelFacts tunnel)
    {
        if (tunnel.AnyConnect is { } running)
        {
            // Срок подъёма проверяет таймер; сверка лишь подстраховывает его и в очереди актора проверку не повторяет.
            if (!running.Established && _deps.Time.GetUtcNow() >= EstablishDeadline(tunnel, running))
            {
                QueueDeadlineCheck(tunnel.ProfileId, running.Generation);
            }

            return;
        }

        var approved = Facts.SignInApproved.Contains(tunnel.ProfileId);
        tunnel.PasswordRequired = !approved && tunnel.BlockingError == ErrorCategory.None;
        if (!approved || tunnel.BlockingError != ErrorCategory.None || Facts.Primary is null || _deps.Time.GetUtcNow() < tunnel.NextDialAt
            || _settings.Profile(tunnel.ProfileId) is not { } profile)
        {
            return;
        }

        if (PreviousHelperExiting(tunnel.ProfileId))
        {
            return;
        }

        StartAnyConnect(tunnel, profile);
    }

    /// <summary>
    /// Прежний помощник профиля ещё не вышел: новый запустится, как только он выйдет (или истечёт <see cref="HelperExitWait"/>),
    /// — об этом позаботится продолжение, поставленное в <see cref="ReleaseHelper"/>.
    /// </summary>
    private bool PreviousHelperExiting(Guid profileId) =>
        _helperExits.TryGetValue(profileId, out var exit) && !exit.Over;

    /// <summary>
    /// Закрывает канал помощника и запоминает его выход. Когда процесс выйдет (или выйдет срок ожидания), очередь
    /// актора получает сверку: запуск нового помощника, отложенный в <see cref="EnsureAnyConnect"/>, не ждёт минутной сверки.
    /// </summary>
    private void ReleaseHelper(Guid profileId, IAnyConnectSession session)
    {
        session.Dispose();
        var exited = session.Exited;
        if (exited.IsCompleted)
        {
            _helperExits.Remove(profileId);
            return;
        }

        var exit = new HelperExit(exited, Task.WhenAny(exited, Task.Delay(HelperExitWait, _deps.Time)));
        _helperExits[profileId] = exit;
        _ = exit.Waited.ContinueWith(
            _ => TryEnqueue("AnyConnectHelperExited", () => OnHelperExitedAsync(profileId, exit)),
            CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }

    private async Task OnHelperExitedAsync(Guid profileId, HelperExit exit)
    {
        if (!_helperExits.TryGetValue(profileId, out var current) || !ReferenceEquals(current, exit))
        {
            return;
        }

        _helperExits.Remove(profileId);
        if (Facts.SignInApproved.Contains(profileId) && Facts.Tunnels.GetValueOrDefault(profileId) is { AnyConnect: null }
            && _state is { Intent: Intent.Connected, ProtectionSuspended: false })
        {
            await ReconcileAsync(CancellationToken.None);
        }
    }

    private void StartAnyConnect(TunnelFacts tunnel, ConnectionProfile profile)
    {
        if (!AnyConnectGateway.TryParse(profile.Server, out var gateway))
        {
            tunnel.BlockingError = ErrorCategory.Other;
            tunnel.LastErrorText = $"«{tunnel.Name}»: неверный адрес шлюза AnyConnect.";
            return;
        }

        var generation = tunnel.DialGeneration = ++_attemptGeneration;
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
        var link = new AnyConnectLink(session, generation) { ProgressUtc = _deps.Time.GetUtcNow() };
        tunnel.AnyConnect = link;
        tunnel.SessionServerAddresses = tunnel.ServerAddresses.ToArray();
        tunnel.AnyConnectStartedUtc = _deps.Time.GetUtcNow();
        tunnel.PasswordRequired = false;
        tunnel.SignIn = null;
        var settings = profile.AnyConnect;
        // Копию, которая лежала в хранилище SYSTEM до первого запуска помощника с этим сертификатом, сделала не служба:
        // её служба не запоминает и потом не удаляет. Проверка — до команды помощнику, иначе он успел бы скопировать сам.
        var foreignCopy = settings.ClientCertificateThumbprint.Length > 0 && IsForeignCertificateCopy(settings.ClientCertificateThumbprint);
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
        ArmEstablishDeadline(tunnel, link);
        if (settings.ClientCertificateThumbprint.Length > 0 && !foreignCopy)
        {
            RecordCertificateCopy(settings.ClientCertificateThumbprint);
        }
    }

    /// <summary>Имя адаптера Wintun: постоянное для профиля.</summary>
    internal static string InterfaceNameFor(ConnectionProfile profile) => "SplitVpn AC " + profile.Id.ToString("N")[..8];

    /// <summary>Пароль для формы шлюза: сохранённый или запомненный до перезапуска службы; без него шлюз спросит.</summary>
    private string? LoadGatewayPassword(ConnectionProfile profile)
    {
        var chars = Facts.MemoryPasswords.TryGetValue(profile.Id, out var memory)
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
                ArmEstablishDeadline(tunnel, link);
                Journal("Сведения", $"«{tunnel.Name}»: требуется вход через браузер.");
                break;
            case SsoResultEvent result:
                OnSsoResult(tunnel, link, result);
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
                ArmEstablishDeadline(tunnel, link);
                Journal("Сведения", $"«{tunnel.Name}»: шлюз запрашивает данные входа.");
                break;
            case ResolveHostEvent resolve:
                await ResolveGatewayAsync(tunnel, link, resolve.Host, resolve.Port, cancellationToken);
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

    private void OnSsoResult(TunnelFacts tunnel, AnyConnectLink link, SsoResultEvent result)
    {
        if (tunnel.SignIn?.RequestId != result.RequestId)
        {
            return;
        }

        // Окно закрывается по исчезновению запроса; при ошибке следом придёт Terminated с причиной.
        tunnel.SignIn = null;
        tunnel.PasswordRequired = false;
        ResumeEstablishDeadline(tunnel, link);
        if (!result.Done)
        {
            _deps.Logger.LogWarning("AnyConnect {Name}: SSO не принят: {Error}", tunnel.Name, result.Error);
        }
    }

    /// <summary>
    /// Адрес шлюза для libopenconnect. До ответа адрес попадает в серверные адреса: политика, фильтры и маршрут /32
    /// через основной адаптер готовы раньше, чем помощник откроет соединение.
    /// </summary>
    private async Task ResolveGatewayAsync(TunnelFacts tunnel, AnyConnectLink link, string host, int port, CancellationToken cancellationToken)
    {
        // Каждый узел шлюза получает маршрут мимо туннеля и разрешение в фильтрах защиты. Шлюз или помощник,
        // перебирающий узлы без конца, открыл бы так прямой путь куда угодно: число узлов и портов ограничено.
        // Узел, заданный IP-адресом, считается наравне с именем: иначе шлюз, перенаправляющий на адреса, открыл бы
        // прямой путь к любому их числу. Не считаются только сам шлюз и его уже известные адреса.
        var gatewayHost = GatewayHostOf(tunnel);
        var isLiteral = Ipv4.TryParse(host, out var literal);
        var isGateway = string.Equals(host, gatewayHost, StringComparison.OrdinalIgnoreCase)
            || (isLiteral && tunnel.ServerAddresses.Contains(literal));
        if (!isGateway && !link.NodeHosts.Contains(host))
        {
            if (link.NodeHosts.Count >= MaxGatewayNodes)
            {
                Journal("Предупреждение", $"«{tunnel.Name}»: шлюз перенаправил на слишком много узлов; узел {host} не открыт.");
                link.Session.Send(new ResolveReplyCommand(host, null, []));
                return;
            }

            link.NodeHosts.Add(host);
            if (!isLiteral && !SameParentDomain(host, gatewayHost))
            {
                Journal("Предупреждение", $"«{tunnel.Name}»: узел шлюза {host} вне домена {gatewayHost}; соединение с ним идёт мимо туннеля.");
            }
        }

        // Перенаправление может вести на узел с другим портом: фильтры открываются и для него, иначе соединение заблокировано.
        var portAdded = port is > 0 and <= ushort.MaxValue && port != tunnel.ServerPort
            && (link.GatewayTcpPorts.Contains((ushort)port) || link.GatewayTcpPorts.Count < MaxGatewayNodes)
            && link.GatewayTcpPorts.Add((ushort)port);
        if (portAdded)
        {
            Journal("Сведения", string.Create(CultureInfo.InvariantCulture, $"«{tunnel.Name}»: узел шлюза {host} работает на порту {port}."));
        }

        IReadOnlyList<uint> addresses;
        if (isLiteral)
        {
            addresses = [literal];
        }
        else if (string.Equals(host, GatewayHostOf(tunnel), StringComparison.OrdinalIgnoreCase) && tunnel.ServerAddresses.Count > 0)
        {
            addresses = tunnel.ServerAddresses;
        }
        else
        {
            // Узел кластера шлюза попадает в журнал: маскированный отчёт должен скрыть и его.
            _gatewayNodeHosts.TryAdd(host, 0);
            // Имя с сотней адресов открыло бы сотню прямых путей: адресов одного узла берётся не больше предела.
            addresses = (await ResolveHelperHostAsync(host, cancellationToken)).Take(MaxGatewayNodes).ToList();
        }

        var added = addresses.Where(a => !tunnel.ServerAddresses.Contains(a) && !link.ResolvedAddresses.Contains(a)).ToList();
        if (added.Count > 0)
        {
            link.ResolvedAddresses.AddRange(added);
            Journal("Сведения", $"«{tunnel.Name}»: узел шлюза {host} — " + string.Join(", ", added.Select(Ipv4.Format)));
        }

        if (added.Count > 0 || portAdded)
        {
            // Сверка ловит системные ошибки сама: сбой применения не должен уронить очередь актора.
            await ReconcileAsync(cancellationToken);
        }

        // Все адреса: маршруты /32 и фильтры открыты к каждому, и помощник возьмёт следующий, если первый не отвечает.
        link.Session.Send(new ResolveReplyCommand(host, addresses.Count > 0 ? Ipv4.Format(addresses[0]) : null, addresses.Select(Ipv4.Format).ToList()));
    }

    private async Task<IReadOnlyList<uint>> ResolveHelperHostAsync(string host, CancellationToken cancellationToken)
    {
        if (Facts.Primary is not { } primary)
        {
            return [];
        }

        // Разрешение идёт на очереди актора: общий предел не даёт медленным DNS-серверам (по 3 с на каждый)
        // задержать все остальные работы службы. Не успел — помощник получит пустой ответ и сообщит об ошибке.
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        limit.CancelAfter(HelperResolveLimit);
        try
        {
            var addresses = await _deps.Resolver.ResolveAsync(host, ServiceDnsAddresses(), primary.InterfaceIndex, limit.Token)
                .WaitAsync(limit.Token);
            if (addresses.Count > 0)
            {
                _deps.DnsProxy.Pin(host, addresses, ServerResolveInterval);
            }

            return addresses;
        }
        catch (Exception ex) when (ex is SocketException or IOException or InvalidOperationException or TimeoutException
            || (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested))
        {
            _deps.Logger.LogWarning(ex, "Не удалось разрешить узел шлюза AnyConnect");
            return [];
        }
    }

    /// <summary>Сколько узлов кластера и дополнительных портов шлюза открывается за один сеанс помощника.</summary>
    private const int MaxGatewayNodes = 8;

    /// <summary>Совпадают ли два последних уровня имён: узлы кластера обычно в домене самого шлюза.</summary>
    private static bool SameParentDomain(string host, string gateway)
    {
        static string Parent(string name)
        {
            var labels = name.TrimEnd('.').Split('.');
            return labels.Length >= 2 ? labels[^2] + "." + labels[^1] : name;
        }

        return gateway.Length > 0 && string.Equals(Parent(host), Parent(gateway), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Предел разрешения узла шлюза на очереди актора.</summary>
    private static readonly TimeSpan HelperResolveLimit = TimeSpan.FromSeconds(8);

    private async Task OnAnyConnectEstablishedAsync(TunnelFacts tunnel, AnyConnectLink link, EstablishedEvent up, CancellationToken cancellationToken)
    {
        link.Established = true;
        link.Luid = up.Luid;
        // Адаптер находит снимок сети сверки ниже — по LUID сеанса (RefreshTunnelAdapters): отдельный снимок здесь
        // лишь удваивал время на очереди актора.
        tunnel.Adapter = null;
        ApplySession(tunnel, up.Session);
        tunnel.SessionStartedUtc = _deps.Time.GetUtcNow();
        tunnel.Statistics = null;
        tunnel.EverConnected = true;
        tunnel.ResetVerification();
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

        // DTLS идёт на порт, назначенный шлюзом: без разрешения фильтров сеанс остался бы на TLS.
        if (tunnel.AnyConnect is { } link && session.DtlsPort is > 0 and <= ushort.MaxValue and var dtls && dtls != tunnel.ServerPort)
        {
            link.GatewayUdpPorts.Add((ushort)dtls);
        }
    }

    private async Task OnAnyConnectTerminatedAsync(TunnelFacts tunnel, AnyConnectLink link, TerminatedEvent terminated, CancellationToken cancellationToken)
    {
        var wasUp = link.Established;
        ReleaseHelper(tunnel.ProfileId, link.Session);
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
    private void StopAnyConnect(TunnelFacts tunnel)
    {
        if (tunnel.AnyConnect is not { } link)
        {
            return;
        }

        link.Session.Send(new StopCommand());
        ReleaseHelper(tunnel.ProfileId, link.Session);
        tunnel.AnyConnect = null;
        tunnel.SignIn = null;
        tunnel.Session = null;
    }

    /// <summary>
    /// Остановка службы: сначала туннели AnyConnect опускаются и политика применяется без сетей шлюза, потом
    /// помощники получают Stop. Сеанс не переживёт службу, поэтому новая служба попросит войти заново.
    /// Возвращает задачу, которая завершится, когда все помощники вышли: служба должна её дождаться — выход
    /// процесса службы закрывает Job, и помощник был бы убит раньше, чем попрощается со шлюзом. Это касается и
    /// помощников, отпущенных раньше (срок подъёма, смена настроек, завершённый сеанс), которые ещё не вышли.
    /// </summary>
    internal Task ShutdownAnyConnect()
    {
        var exits = _helperExits.Values.Select(e => e.Exited).Where(t => !t.IsCompleted).ToList();
        var sessions = Facts.Tunnels.Values.Where(t => t.AnyConnect is not null).ToList();
        if (sessions.Count == 0)
        {
            return Task.WhenAll(exits);
        }

        exits.AddRange(sessions.Select(t => t.AnyConnect!.Session.Exited));

        foreach (var tunnel in sessions)
        {
            tunnel.AnyConnect!.Established = false;
            tunnel.ResetConnection(_deps.Time.GetUtcNow());
        }

        try
        {
            // При выходе из системы и выключении Windows к этому моменту уже убрала интерфейсы туннелей RAS: прежний
            // снимок сети вёл бы к тысячам маршрутов на несуществующий интерфейс (ошибка 1168).
            RefreshTunnelAdapters(_deps.Inventory.Capture());
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
        return Task.WhenAll(exits);
    }

    private string GatewayHostOf(TunnelFacts tunnel) =>
        AnyConnectGateway.TryParse(_settings.Profile(tunnel.ProfileId)?.Server, out var gateway) ? gateway.Host : "";

    /// <summary>
    /// Сети шлюзов с установленным сеансом — в цель карточки «Сети сервера». Без сеанса сетей шлюза нет: адреса
    /// идут по обычным правилам, как до первого входа.
    /// </summary>
    private List<ServerNetworks> GatewayNetworks()
    {
        var result = new List<ServerNetworks>();
        foreach (var tunnel in Facts.Tunnels.Values.Where(t => t is { IsUp: true, Session: not null, Protocol: VpnProtocol.AnyConnect }))
        {
            if (_settings.Profile(tunnel.ProfileId) is { } profile)
            {
                result.Add(new ServerNetworks(
                    AppSettings.ServerNetworksTarget(profile),
                    tunnel.Session!.IncludeCidrs(),
                    profile.AnyConnect.UserRulesOverrideServerNetworks));
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
    /// Без сеанса правил нет: имена разрешаются по общим правилам, как до первого входа.
    /// </summary>
    private void AddGatewayDomainRoutes(List<DomainRoute> routes)
    {
        foreach (var tunnel in Facts.Tunnels.Values.Where(t => t is { IsUp: true, Session: not null, Protocol: VpnProtocol.AnyConnect, VpnDns.Count: > 0 }))
        {
            if (_settings.Profile(tunnel.ProfileId) is not { } profile || TunnelDnsRoute(tunnel) is not { } dns)
            {
                continue;
            }

            var target = AppSettings.ServerNetworksTarget(profile);
            foreach (var suffix in GatewayDnsNames(tunnel.Session!).Where(s => routes.TrueForAll(r => r.Suffix != s)))
            {
                routes.Add(new DomainRoute(suffix, target, dns, PinAddresses: false));
            }
        }
    }

    /// <summary>Имена, которые разрешает DNS шлюза: суффиксы split DNS (или домен по умолчанию) и хост PAC.</summary>
    private static List<string> GatewayDnsNames(SessionInfo session)
    {
        // Однословные суффиксы («local») не берём: они совпали бы с mDNS и именами локальной сети.
        var names = session.DnsSuffixes().Select(SettingsSerializer.NormalizeSuffix).Where(IsGatewayDnsName);
        if (Uri.TryCreate(session.ProxyPac, UriKind.Absolute, out var pac) && pac.HostNameType == UriHostNameType.Dns)
        {
            names = names.Append(pac.IdnHost.ToLowerInvariant());
        }

        return names.Distinct(StringComparer.Ordinal).ToList();
    }

    /// <summary>Не однословное и не публичная зона вроде com.ru: иначе DNS шлюза разрешал бы чужие сайты всей зоны.</summary>
    private static bool IsGatewayDnsName(string name) =>
        name.Contains('.', StringComparison.Ordinal) && SettingsSerializer.IsValidSuffix(name) && Core.Dns.PublicSuffixes.IsSearchListSuffix(name);

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

            // Только само имя шлюза: его поддомены (внутренние имена компании) не должны уходить к DNS провайдера.
            routes.Add(new DomainRoute(suffix, RouteTarget.Direct, direct, PinAddresses: false, ExactName: true));
        }
    }

    private SignInPromptDto? SignInPromptOf(TunnelFacts tunnel)
    {
        // Положенный пользователем туннель входа не ждёт: «Требуется вход» на нём звало бы поднять то, что он только что отключил.
        if (tunnel.Protocol != VpnProtocol.AnyConnect || tunnel.Paused || _state.Intent != Intent.Connected || _state.ProtectionSuspended)
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
            DnsSuffixes = session.DnsSuffixes(),
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
                ResumeEstablishDeadline(tunnel, link);
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
        ResumeEstablishDeadline(tunnel, tunnel.AnyConnect);
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

    // ---- срок подъёма сеанса ----

    /// <summary>
    /// Когда сеанс должен быть поднят. Пока пользователь отвечает на запрос входа, срок не идёт: он считается от
    /// ответа, а если ответа нет — от истечения запроса (помощник к тому времени должен был сам завершить вход).
    /// </summary>
    private static DateTimeOffset EstablishDeadline(TunnelFacts tunnel, AnyConnectLink link)
    {
        var from = tunnel.SignIn is { } prompt && prompt.ExpiresUtc > link.ProgressUtc ? prompt.ExpiresUtc : link.ProgressUtc;
        return from + AnyConnectEstablishDeadline;
    }

    /// <summary>Таймер проверки срока: по нему, а не по минутной сверке, зависший помощник останавливается вовремя.</summary>
    private void ArmEstablishDeadline(TunnelFacts tunnel, AnyConnectLink link)
    {
        var delay = EstablishDeadline(tunnel, link) - _deps.Time.GetUtcNow();
        var profileId = tunnel.ProfileId;
        var generation = link.Generation;
        _ = Task.Delay(delay > TimeSpan.Zero ? delay : TimeSpan.Zero, _deps.Time).ContinueWith(
            _ => QueueDeadlineCheck(profileId, generation),
            CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }

    /// <summary>Пользователь ответил на запрос входа: помощник снова работает сам, и срок начинается заново.</summary>
    private void ResumeEstablishDeadline(TunnelFacts tunnel, AnyConnectLink link)
    {
        link.ProgressUtc = _deps.Time.GetUtcNow();
        ArmEstablishDeadline(tunnel, link);
    }

    private void QueueDeadlineCheck(Guid profileId, int generation) =>
        TryEnqueue("AnyConnectDeadline", () => CheckEstablishDeadlineAsync(profileId, generation, CancellationToken.None));

    /// <summary>
    /// Помощник не поднял сеанс в срок: он останавливается, а туннель ведёт себя как после сетевой ошибки шлюза —
    /// ждёт нового входа. Пока открыт запрос входа и срок не вышел, проверка просто переносится.
    /// </summary>
    internal async Task CheckEstablishDeadlineAsync(Guid profileId, int generation, CancellationToken cancellationToken)
    {
        if (Facts.Tunnels.GetValueOrDefault(profileId) is not { AnyConnect: { Established: false } link } tunnel || link.Generation != generation)
        {
            return;
        }

        if (_deps.Time.GetUtcNow() < EstablishDeadline(tunnel, link))
        {
            ArmEstablishDeadline(tunnel, link);
            return;
        }

        link.Session.Send(new StopCommand());
        var seconds = ((int)AnyConnectEstablishDeadline.TotalSeconds).ToString(CultureInfo.InvariantCulture);
        await OnAnyConnectTerminatedAsync(tunnel, link,
            new TerminatedEvent(TerminationKind.NetworkError, $"шлюз не ответил за {seconds} с, помощник остановлен"), cancellationToken);
    }

    // ---- копии клиентских сертификатов ----

    /// <summary>Начало сверки: удалить копии клиентских сертификатов, которые больше не нужны.</summary>
    private void MaintainAnyConnect() => ReleaseUnusedCertificateCopies();

    /// <summary>Отпечатки клиентских сертификатов, выбранных сейчас в профилях AnyConnect (в том числе выключенных).</summary>
    private HashSet<string> SelectedClientCertificates() =>
        _settings.Profiles
            .Where(p => p.Protocol == VpnProtocol.AnyConnect && p.AnyConnect.ClientCertificateThumbprint.Length > 0)
            .Select(p => VpnProtocols.NormalizeThumbprint(p.AnyConnect.ClientCertificateThumbprint))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Сертификаты, которые помощники по запросу службы скопировали в хранилище SYSTEM. Список хранится в состоянии
    /// службы: сертификат могут снять с подключения перед перезапуском службы, и копию надо удалить и после него.
    /// В файлах прежних версий списка нет — тогда он пуст: копии прежних версий не отличить от сделанных не службой,
    /// поэтому они остаются в хранилище.
    /// </summary>
    private HashSet<string> CertificateCopies() =>
        (_state.AnyConnectCertificateCopies ?? [])
            .OfType<string>()
            .Where(VpnProtocols.IsThumbprint)
            .Select(VpnProtocols.NormalizeThumbprint)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>Копия сертификата уже есть в хранилище SYSTEM, а служба её не запоминала: её сделал не помощник службы.</summary>
    private bool IsForeignCertificateCopy(string thumbprint) =>
        VpnProtocols.IsThumbprint(thumbprint)
        && !CertificateCopies().Contains(VpnProtocols.NormalizeThumbprint(thumbprint))
        && _deps.AnyConnect.HasCertificateCopy(thumbprint);

    /// <summary>Помощник получил сертификат: он сделает копию, и служба должна помнить о ней до удаления.</summary>
    private void RecordCertificateCopy(string thumbprint)
    {
        if (!VpnProtocols.IsThumbprint(thumbprint))
        {
            return;
        }

        var copies = CertificateCopies();
        if (copies.Add(VpnProtocols.NormalizeThumbprint(thumbprint)) || _state.AnyConnectCertificateCopies is null)
        {
            SaveCertificateCopies(copies);
        }
    }

    /// <summary>
    /// Помощник копирует сертификат компьютера в хранилище учётной записи SYSTEM и не удаляет копию при выходе: ею
    /// пользуются другие помощники. Когда сертификат больше не выбран ни в одном профиле (профиль удалён или выбран
    /// другой сертификат), копию удаляет служба — только копии из своего списка, другие сертификаты хранилища
    /// не трогаются. Неудачное удаление не повторяется: сертификат уходит из списка, как и после удачного.
    /// </summary>
    private void ReleaseUnusedCertificateCopies()
    {
        var selected = SelectedClientCertificates();
        var copies = CertificateCopies();
        var unused = copies.Where(t => !selected.Contains(t)).ToList();
        foreach (var thumbprint in unused)
        {
            copies.Remove(thumbprint);
            try
            {
                var removed = _deps.AnyConnect.RemoveCertificateCopies(thumbprint);
                if (removed > 0)
                {
                    _deps.Logger.LogInformation("Удалена копия клиентского сертификата {Thumbprint}: он больше не выбран ни в одном подключении", thumbprint);
                }
            }
            catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or UnauthorizedAccessException or InvalidOperationException)
            {
                _deps.Logger.LogWarning(ex, "Не удалось удалить копию клиентского сертификата {Thumbprint}", thumbprint);
            }
        }

        // Файл прежней версии получает список при первой сверке; пустой список ради одной записи в файл не пишется.
        if (unused.Count > 0 || (_state.AnyConnectCertificateCopies is null && copies.Count > 0))
        {
            SaveCertificateCopies(copies);
        }
    }

    private void SaveCertificateCopies(IEnumerable<string> copies)
    {
        _state = _state with { AnyConnectCertificateCopies = copies.Order(StringComparer.Ordinal).ToList() };
        try
        {
            _deps.Stores.SaveState(_state);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Список остаётся в памяти и попадёт в файл со следующей записью состояния.
            _deps.Logger.LogWarning(ex, "Не удалось сохранить список копий клиентских сертификатов AnyConnect");
        }
    }
}
