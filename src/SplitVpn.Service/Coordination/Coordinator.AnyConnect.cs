using System.ComponentModel;
using System.Globalization;
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
    /// вне очереди актора, поэтому он потокобезопасный. Значение - номер последнего события журнала, после которого имя
    /// ещё может в нём встречаться: имя, ушедшее из журнала, маскировать незачем, и набор подрезается
    /// (<see cref="RememberGatewayNodeHost"/>), как и прежние личные значения настроек.
    /// </summary>
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, long> _gatewayNodeHosts = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Предел набора имён узлов шлюза: каждое имя участвует в маскировании каждого отчёта.</summary>
    internal const int MaxGatewayNodeHosts = 512;

    /// <summary>Имена узлов шлюза, которые маскирует отчёт (для проверок).</summary>
    internal IReadOnlyCollection<string> GatewayNodeHosts => _gatewayNodeHosts.Keys.ToList();

    /// <summary>
    /// Запоминает имя узла шлюза для маскирования отчёта и подрезает набор: имена, чьё последнее упоминание ушло из
    /// журнала событий, забываются. Сверх предела (помощник спрашивает о множестве имён, а журнал стоит) первыми
    /// уходят давние имена, которых в журнале нет; имена, ещё упомянутые в журнале, остаются.
    /// </summary>
    internal void RememberGatewayNodeHost(string host)
    {
        var retained = _deps.Journal.Since(0);
        if (!_gatewayNodeHosts.TryAdd(host, retained.Count == 0 ? 0 : retained[^1].Id))
        {
            return;
        }

        var oldest = retained.Count == 0 ? long.MaxValue : retained[0].Id;
        foreach (var item in _gatewayNodeHosts.Where(item => item.Value < oldest && !string.Equals(item.Key, host, StringComparison.OrdinalIgnoreCase)).ToList())
        {
            var lastReference = retained.LastOrDefault(e => e.Text.Contains(item.Key, StringComparison.OrdinalIgnoreCase));
            if (lastReference is null) _gatewayNodeHosts.TryRemove(item.Key, out _);
            else _gatewayNodeHosts[item.Key] = lastReference.Id;
        }

        var excess = _gatewayNodeHosts.Count - MaxGatewayNodeHosts;
        if (excess <= 0)
        {
            return;
        }

        var candidates = _gatewayNodeHosts.Where(item => !string.Equals(item.Key, host, StringComparison.OrdinalIgnoreCase))
            .OrderBy(item => item.Value).Select(item => item.Key).ToList();
        foreach (var name in candidates.Where(name => !retained.Any(e => e.Text.Contains(name, StringComparison.OrdinalIgnoreCase))))
        {
            if (excess <= 0) break;
            if (_gatewayNodeHosts.TryRemove(name, out _)) excess--;
        }

        // Все оставшиеся ещё в журнале: предел всё равно соблюдается, уходят самые давние.
        foreach (var name in candidates)
        {
            if (excess <= 0) break;
            if (_gatewayNodeHosts.TryRemove(name, out _)) excess--;
        }
    }

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

        // Всё, что может не получиться (пароль из secrets.bin, который держит антивирус, хранилище сертификатов), - до
        // запуска процесса: иначе помощник оставался бы без команды Start, срок подъёма не взводился, и через минуты
        // туннель падал бы с ложной причиной «шлюз не ответил». Сбой - не ошибка настроек: вход не отменяется,
        // следующая сверка попробует снова.
        var settings = profile.AnyConnect;
        StartCommand start;
        bool foreignCopy;
        try
        {
            // Копию, которая лежала в хранилище SYSTEM до первого запуска помощника с этим сертификатом, сделала не
            // служба: её служба не запоминает и потом не удаляет. Проверка — до команды помощнику, иначе он успел бы
            // скопировать сам.
            foreignCopy = settings.ClientCertificateThumbprint.Length > 0 && IsForeignCertificateCopy(settings.ClientCertificateThumbprint);
            start = new StartCommand(
                gateway.Url,
                settings.Group,
                settings.UserAgent,
                settings.UseDtls,
                settings.ClientCertificateThumbprint.Length > 0 ? settings.ClientCertificateThumbprint : null,
                InterfaceNameFor(profile),
                string.IsNullOrWhiteSpace(profile.UserName) ? null : profile.UserName,
                LoadGatewayPassword(profile));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            ReportAnyConnectStartFailure(tunnel, $"«{tunnel.Name}»: не удалось подготовить вход в шлюз AnyConnect (пароль или сертификат не прочитаны): {ex.Message}. Повтор на следующей сверке.");
            return;
        }

        var generation = tunnel.DialGeneration = ++_attemptGeneration;
        var profileId = tunnel.ProfileId;
        IAnyConnectSession session;
        try
        {
            // Очередь неограниченная: запись не ждёт и не отказывает, пока служба работает.
            session = _deps.AnyConnect.Start(helperEvent =>
            {
                if (helperEvent is LogEvent log)
                {
                    _deps.Logger.Log(log.Level switch { "error" => LogLevel.Warning, "info" => LogLevel.Information, _ => LogLevel.Debug },
                        "AnyConnect {Name}: {Text}", profile.Name, Core.Diagnostics.LogText.SingleLine(log.Text.TrimEnd()));
                    return;
                }
                TryEnqueue("Helper:" + helperEvent.GetType().Name, () => OnHelperEventAsync(profileId, generation, helperEvent, CancellationToken.None));
            });
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or Win32Exception or UnauthorizedAccessException)
        {
            ClearPassword(start);
            tunnel.BlockingError = ErrorCategory.Other;
            tunnel.LastErrorCategory = ErrorCategory.Other;
            tunnel.LastErrorText = $"«{tunnel.Name}»: помощник AnyConnect не запустился: {ex.Message}";
            Journal("Ошибка", tunnel.LastErrorText);
            return;
        }

        // События помощника обрабатываются в очереди актора, то есть уже после этого присваивания.
        tunnel.HelperStarts++;
        var link = new AnyConnectLink(session, generation) { ProgressUtc = _deps.Time.GetUtcNow() };
        tunnel.AnyConnect = link;
        try
        {
            tunnel.SessionServerAddresses = tunnel.ServerAddresses.ToArray();
            tunnel.AnyConnectStartedUtc = _deps.Time.GetUtcNow();
            tunnel.PasswordRequired = false;
            tunnel.SignIn = null;
            session.Send(start);
            Journal("Сведения", $"Подключение к «{profile.Name}» (AnyConnect, шлюз {gateway.Host}).");
            ArmEstablishDeadline(tunnel, link);
            if (settings.ClientCertificateThumbprint.Length > 0 && !foreignCopy)
            {
                RecordCertificateCopy(settings.ClientCertificateThumbprint);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Помощник без команды Start и без срока подъёма висел бы до ложного «шлюз не ответил»: он отпускается
            // сразу, а туннель ждёт следующей сверки с настоящей причиной в тексте ошибки.
            link.DeadlineTimer?.Dispose();
            ReleaseHelper(profileId, session);
            tunnel.AnyConnect = null;
            ReportAnyConnectStartFailure(tunnel, $"«{tunnel.Name}»: помощник AnyConnect не получил команду входа: {ex.Message}. Повтор на следующей сверке.");
        }
        finally
        {
            // Команда уже в трубе (или не ушла вовсе): пароль в памяти службы больше не нужен.
            ClearPassword(start);
        }
    }

    private static void ClearPassword(StartCommand start)
    {
        if (start.Password is { } password)
        {
            Array.Clear(password);
        }
    }

    /// <summary>
    /// Запуск помощника сорвался не по вине настроек (файл паролей занят, хранилище недоступно). Вход, одобренный
    /// пользователем (<see cref="CoordinatorFacts.SignInApproved"/>), не снимается: следующая сверка попробует снова.
    /// Попытка завершилась, не начавшись: при подъёме по очереди следующие туннели её не ждут (как и у SSH и RAS).
    /// </summary>
    private void ReportAnyConnectStartFailure(TunnelFacts tunnel, string text)
    {
        tunnel.DialSettled = true;
        tunnel.LastErrorCategory = ErrorCategory.Other;
        tunnel.LastErrorCode = null;
        if (tunnel.LastErrorText != text)
        {
            Journal("Ошибка", text);
        }

        tunnel.LastErrorText = text;
    }

    /// <summary>Имя адаптера Wintun: постоянное для профиля.</summary>
    internal static string InterfaceNameFor(ConnectionProfile profile) => "SplitVpn AC " + profile.Id.ToString("N")[..8];

    /// <summary>
    /// Пароль для формы шлюза: сохранённый или запомненный до перезапуска службы; без него шлюз спросит. Массив, а не
    /// строка: его очищают сразу после отправки команды помощнику (неизменяемая строка оставалась бы в памяти службы).
    /// </summary>
    private char[]? LoadGatewayPassword(ConnectionProfile profile) =>
        Facts.MemoryPasswords.TryGetValue(profile.Id, out var memory)
            ? memory.ToArray()
            : profile.SavePassword ? _deps.Secrets.TryLoad(profile.Id) : null;

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
            case SsoOpenEvent open when open.Uri is null || open.Uri.Length > HelperLimits.MaxSsoUri:
                // Обрезанный адрес вход не откроет, а целиком он уходил бы в каждый ответ о состоянии.
                await RejectGatewaySessionAsync(tunnel, link, string.Create(CultureInfo.InvariantCulture,
                    $"шлюз прислал слишком длинный адрес страницы входа ({open.Uri?.Length ?? 0} символов при пределе {HelperLimits.MaxSsoUri})"), cancellationToken);
                break;
            case SsoOpenEvent open:
                tunnel.SignIn = new SignInPromptDto
                {
                    RequestId = open.RequestId,
                    Kind = SignInKind.Browser,
                    GatewayHost = HelperLimits.Truncate(open.GatewayHost, HelperLimits.MaxDnsNameLength) ?? "",
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
            case AuthFormEvent received:
                // Тексты и поля шлюза хранятся и уходят в каждый ответ о состоянии: только в пределах HelperLimits.
                var form = received.Capped();
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
            case EstablishedEvent up when GatewayTunnelAddressProblem(tunnel, up.Session) is { } problem:
                await RejectGatewaySessionAsync(tunnel, link, problem, cancellationToken);
                break;
            case EstablishedEvent up:
                await OnAnyConnectEstablishedAsync(tunnel, link, up, cancellationToken);
                break;
            case IpInfoChangedEvent changed when GatewayTunnelAddressProblem(tunnel, changed.Session) is { } problem:
                await RejectGatewaySessionAsync(tunnel, link, problem, cancellationToken);
                break;
            case IpInfoChangedEvent changed:
                ApplySession(tunnel, changed.Session);
                tunnel.ResetVerification();
                tunnel.NextVerifyAt = _deps.Time.GetUtcNow();
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
                Journal("Сведения", $"«{tunnel.Name}»: {reconnecting.Reason}");
                break;
            case LogEvent log:
                // Сообщения библиотеки без секретов (их вырезает помощник) — в файл журнала службы: по ним разбирают сбои входа.
                _deps.Logger.Log(log.Level switch { "error" => LogLevel.Warning, "info" => LogLevel.Information, _ => LogLevel.Debug },
                    "AnyConnect {Name}: {Text}", tunnel.Name, Core.Diagnostics.LogText.SingleLine(log.Text.TrimEnd()));
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
    private async Task ResolveGatewayAsync(TunnelFacts tunnel, AnyConnectLink link, string host, int port, CancellationToken cancellationToken, IReadOnlyList<uint>? resolved = null)
    {
        // Каждый узел шлюза получает маршрут мимо туннеля и разрешение в фильтрах защиты. Шлюз или помощник,
        // перебирающий узлы без конца, открыл бы так прямой путь куда угодно: число узлов и портов ограничено.
        // Узел, заданный IP-адресом, считается наравне с именем: иначе шлюз, перенаправляющий на адреса, открыл бы
        // прямой путь к любому их числу. Не считаются только сам шлюз и его уже известные адреса.
        var gatewayHost = GatewayHostOf(tunnel);
        var isLiteral = Ipv4.TryParse(host, out var literal);
        var isGateway = string.Equals(host, gatewayHost, StringComparison.OrdinalIgnoreCase)
            || (isLiteral && tunnel.ServerAddresses.Contains(literal));
        if (!isGateway && !isLiteral)
        {
            // Имя узла попадает в журнал и тогда, когда узел отклонён (предел узлов или портов): маскированный отчёт
            // должен скрыть его до первой записи.
            RememberGatewayNodeHost(host);
        }

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
        if (port < 0 || port > ushort.MaxValue || port != 0 && port != tunnel.ServerPort
            && !link.GatewayTcpPorts.Contains((ushort)port) && link.GatewayTcpPorts.Count >= MaxGatewayNodes)
        {
            Journal("Предупреждение", $"«{tunnel.Name}»: порт узла {host} превышает ограничения шлюза.");
            link.Session.Send(new ResolveReplyCommand(host, null, []));
            return;
        }

        var portAdded = port is > 0 and <= ushort.MaxValue && port != tunnel.ServerPort
            && (link.GatewayTcpPorts.Contains((ushort)port) || link.GatewayTcpPorts.Count < MaxGatewayNodes)
            && link.GatewayTcpPorts.Add((ushort)port);
        if (portAdded)
        {
            Journal("Сведения", string.Create(CultureInfo.InvariantCulture, $"«{tunnel.Name}»: узел шлюза {host} работает на порту {port}."));
        }

        var removed = false;
        IReadOnlyList<uint> addresses;
        if (isLiteral)
        {
            // Адрес из профиля - выбор пользователя; адрес, на который перенаправил шлюз, проверяется.
            addresses = isGateway ? [literal] : FilterGatewayNodeAddresses(tunnel, host, [literal]);
            if (addresses.Count == 0)
            {
                Journal("Ошибка", $"«{tunnel.Name}»: шлюз перенаправил на недопустимый адрес {host}; узел не открыт.");
                link.Session.Send(new ResolveReplyCommand(host, null, []));
                return;
            }
        }
        else if (string.Equals(host, GatewayHostOf(tunnel), StringComparison.OrdinalIgnoreCase) && tunnel.ServerAddresses.Count > 0)
        {
            addresses = tunnel.ServerAddresses;
        }
        else
        {
            // Узел кластера шлюза попадает в журнал: маскированный отчёт должен скрыть и его.
            RememberGatewayNodeHost(host);
            // Имя с сотней адресов открыло бы сотню прямых путей: адресов одного узла берётся не больше предела.
            if (resolved is null && Facts.Primary is { } primary)
            {
                var servers = ServiceDnsAddresses();
                var interfaceIndex = primary.InterfaceIndex;
                _ = ResolveAndReplyAsync();
                return;

                async Task ResolveAndReplyAsync()
                {
                    var answer = await ResolveHelperHostAsync(host, servers, interfaceIndex, cancellationToken);
                    await EnqueueAsync("ResolveGateway", async () =>
                    {
                        if (Facts.Tunnels.GetValueOrDefault(tunnel.ProfileId)?.AnyConnect == link)
                            await ResolveGatewayAsync(tunnel, link, host, port, cancellationToken, answer);
                    });
                }
            }

            if (!link.NodeAddresses.TryGetValue(host, out var known)) link.NodeAddresses[host] = known = [];
            // Узлы кластера проверяются до предела: недопустимые адреса не должны вытеснять годные.
            var usable = resolved is { Count: > 0 } && !isGateway ? FilterGatewayNodeAddresses(tunnel, host, resolved) : resolved;
            var allDropped = resolved is { Count: > 0 } && usable is { Count: 0 };
            if (allDropped)
            {
                // Прежние адреса узла тоже не отдаются: имя теперь ведёт только на недопустимые.
                Journal("Ошибка", $"«{tunnel.Name}»: у узла шлюза {host} нет допустимых адресов; узел не открыт.");
            }

            resolved = usable;
            if (resolved is { Count: > 0 } || allDropped)
            {
                var fresh = (resolved ?? []).Distinct().Take(MaxGatewayNodes).ToList();
                var stale = known.Except(fresh).ToList();
                known.Clear();
                known.UnionWith(fresh);
                foreach (var address in stale.Where(a => !link.NodeAddresses.Values.Any(node => node.Contains(a))))
                    removed |= link.ResolvedAddresses.Remove(address);
                addresses = fresh;
            }
            else
            {
                addresses = known.ToList();
            }
        }

        var added = addresses.Where(a => !tunnel.ServerAddresses.Contains(a) && !link.ResolvedAddresses.Contains(a)).ToList();
        if (added.Count > 0)
        {
            link.ResolvedAddresses.AddRange(added);
            Journal("Сведения", $"«{tunnel.Name}»: узел шлюза {host} — " + string.Join(", ", added.Select(Ipv4.Format)));
        }

        if (removed || added.Count > 0 || portAdded || resolved is not null)
        {
            // Сверка ловит системные ошибки сама: сбой применения не должен уронить очередь актора.
            await ReconcileAsync(cancellationToken);
        }
        if (!isLiteral && addresses.Count > 0)
        {
            _deps.DnsProxy.Pin(host, addresses, ServerResolveInterval);
        }

        // Все адреса: маршруты /32 и фильтры открыты к каждому, и помощник возьмёт следующий, если первый не отвечает.
        if (addresses.Count > 1)
        {
            var offset = (int)((tunnel.HelperStarts - 1) % (uint)addresses.Count);
            addresses = addresses.Skip(offset).Concat(addresses.Take(offset)).ToList();
        }
        link.Session.Send(new ResolveReplyCommand(host, addresses.Count > 0 ? Ipv4.Format(addresses[0]) : null, addresses.Select(Ipv4.Format).ToList()));
    }

    private async Task<IReadOnlyList<uint>> ResolveHelperHostAsync(string host, IReadOnlyList<uint> servers, uint interfaceIndex, CancellationToken cancellationToken)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        limit.CancelAfter(HelperResolveLimit);
        try
        {
            return await _deps.Resolver.ResolveAsync(host, servers, interfaceIndex, limit.Token)
                .WaitAsync(limit.Token);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            // Любой сбой, а не только сетевой: задача разрешения запущена без наблюдателя, и неожиданное исключение
            // (например, ArgumentException на имени узла, присланном шлюзом) терялось бы вместе с ответом - помощник
            // ждал бы его до своего срока. Пустой список - ответ «узел не разрешился». Отмена при остановке службы
            // уходит дальше: отвечать уже некому.
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
            if (labels.Length < 2) return name;
            var parent = labels[^2] + "." + labels[^1];
            return labels.Length > 2 && !Core.Dns.PublicSuffixes.IsSearchListSuffix(parent)
                ? labels[^3] + "." + parent : parent;
        }

        return gateway.Length > 0 && string.Equals(Parent(host), Parent(gateway), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Предел разрешения узла шлюза на очереди актора.</summary>
    private static readonly TimeSpan HelperResolveLimit = TimeSpan.FromSeconds(8);

    private async Task OnAnyConnectEstablishedAsync(TunnelFacts tunnel, AnyConnectLink link, EstablishedEvent up, CancellationToken cancellationToken)
    {
        link.DeadlineTimer?.Dispose();
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
        var networks = FormattedNetworks(up.Session).Count;
        Journal("Сведения", string.Create(CultureInfo.InvariantCulture,
            $"«{tunnel.Name}» подключён (AnyConnect): адрес {up.Session.Address}, сетей шлюза {networks}, {(up.Session.DtlsActive ? "DTLS" : "TLS")}."));
        // Отклонённый слой тоже даёт пустой список сетей: «шлюз не прислал сетей» тогда было бы неправдой.
        if (up.Session.RejectedIncludes() is { } rejected)
        {
            Journal("Предупреждение", $"«{tunnel.Name}»: сети шлюза отброшены целиком — {rejected}. "
                + "Через подключение действуют пользовательские правила.");
        }
        else if (networks == 0)
        {
            Journal("Предупреждение", $"«{tunnel.Name}»: шлюз не прислал сетей. Через подключение действуют пользовательские правила.");
        }

        if (up.Session.TooWideIncludes() is { Count: > 0 } tooWide)
        {
            Journal("Предупреждение", string.Create(CultureInfo.InvariantCulture,
                $"«{tunnel.Name}»: сети шлюза шире /8 отброшены ({string.Join(", ", tooWide)}) — они забрали бы заметную часть интернета."));
        }

        await ReconcileAsync(cancellationToken);
    }

    /// <summary>Причина отказа от сетей шлюза по сеансу: считается один раз, а статус строится часто.</summary>
    private readonly System.Runtime.CompilerServices.ConditionalWeakTable<SessionInfo, System.Runtime.CompilerServices.StrongBox<string?>> _rejectedIncludes = new();

    /// <summary>
    /// Сети шлюза отброшены целиком (<see cref="SessionInfo.RejectedIncludes"/>): предупреждение на главной, а не
    /// только строка в журнале - иначе подключение выглядело бы рабочим, а корпоративные сети шли бы мимо него.
    /// </summary>
    private IEnumerable<StatusWarning> GatewayNetworkWarnings()
    {
        foreach (var tunnel in Facts.Tunnels.Values.Where(t => t is { IsUp: true, Session: not null }))
        {
            if (_rejectedIncludes.GetValue(tunnel.Session!, s => new(s.RejectedIncludes())).Value is { } rejected)
            {
                yield return new StatusWarning("gateway-networks-rejected",
                    $"«{tunnel.Name}»: сети шлюза отброшены целиком ({rejected}). Через подключение действуют только пользовательские правила.", null);
            }

            if (tunnel.AnyConnect is { DnsLanConflicts.Count: > 0 } link)
            {
                yield return new StatusWarning("gateway-dns-lan", $"«{tunnel.Name}»: {DnsLanConflictText(link.DnsLanConflicts)}", null);
            }

            if (tunnel.AnyConnect is { DnsRuleConflicts.Count: > 0 } ruled)
            {
                yield return new StatusWarning("gateway-dns-rule", $"«{tunnel.Name}»: {DnsRuleConflictText(ruled.DnsRuleConflicts)}", null);
            }

            if (tunnel.Session!.Ipv6NotDisabled)
            {
                yield return new StatusWarning("gateway-ipv6",
                    $"«{tunnel.Name}»: не удалось отключить IPv6 в туннеле AnyConnect. Подключение работает только по IPv4: трафик IPv6 через него блокируется.", null);
            }

            if (tunnel.Session!.Truncated is { Count: > 0 } truncated)
            {
                yield return new StatusWarning("gateway-session-truncated",
                    $"«{tunnel.Name}»: шлюз прислал слишком много данных сеанса, лишнее отброшено ({string.Join("; ", truncated)}).", null);
            }
        }
    }

    private void ApplySession(TunnelFacts tunnel, SessionInfo received)
    {
        // Параметры шлюза уходят в каждый ответ о состоянии: служба держит их в тех же пределах, что и помощник.
        var session = received.Capped();
        tunnel.AnyConnect!.ParametersReceivedUtc = _deps.Time.GetUtcNow();
        tunnel.AnyConnect.GatewayUdpPorts.Clear();
        tunnel.Session = session;
        foreach (var item in session.Truncated)
        {
            Journal("Предупреждение", $"«{tunnel.Name}»: шлюз прислал слишком много данных сеанса, лишнее отброшено — {item}.");
        }

        RefreshGatewayDns(tunnel, RangeSet.From(OnLinkPrefixes()));

        // DTLS идёт на порт, назначенный шлюзом: без разрешения фильтров сеанс остался бы на TLS.
        if (tunnel.AnyConnect is { } link && session.DtlsPort is > 0 and <= ushort.MaxValue and var dtls && dtls != tunnel.ServerPort)
        {
            link.GatewayUdpPorts.Add((ushort)dtls);
        }
    }

    /// <summary>
    /// DNS шлюзов AnyConnect без адресов локальной сети. Шлюз, назвавший своим DNS адрес из сети адаптера
    /// (X-CSTP-DNS: 192.168.1.10), иначе получил бы запросы имён, отправленные узлу домашней сети, а политика
    /// увела бы этот узел в туннель. Локальная сеть важнее: адрес убирается из DNS туннеля, о чём говорит
    /// предупреждение. Сеть адаптера меняется со сменой сети, поэтому сверка повторяет отбор перед сборкой политики.
    /// </summary>
    private void RefreshGatewayDns()
    {
        if (!Facts.Tunnels.Values.Any(t => t is { Protocol: VpnProtocol.AnyConnect, Session: not null }))
        {
            return;
        }

        var onLink = RangeSet.From(OnLinkPrefixes());
        foreach (var tunnel in Facts.Tunnels.Values.Where(t => t is { Protocol: VpnProtocol.AnyConnect, Session: not null, AnyConnect: not null }))
        {
            RefreshGatewayDns(tunnel, onLink);
        }
    }

    private void RefreshGatewayDns(TunnelFacts tunnel, RangeSet onLink)
    {
        if (tunnel is not { Session: { } session, AnyConnect: { } link })
        {
            return;
        }

        var all = session.DnsAddresses();
        var conflicts = all.Where(onLink.Contains).ToList();
        // «Ручные правила важнее сетей шлюза»: адрес DNS, который правило пользователя направило в другую цель (напрямую,
        // в другой туннель, «Блокировать»), не уводится в этот туннель ради DNS - он убирается из DNS туннеля.
        var ruled = _settings.Profile(tunnel.ProfileId) is { AnyConnect.UserRulesOverrideServerNetworks: true }
            ? all.Except(conflicts).Where(a => DnsRuleConflict(a, tunnel.ProfileId)).ToList()
            : [];
        tunnel.VpnDns = conflicts.Count == 0 && ruled.Count == 0 ? all : all.Except(conflicts).Except(ruled).ToList();
        if (!ruled.SequenceEqual(link.DnsRuleConflicts))
        {
            link.DnsRuleConflicts = ruled;
            if (ruled.Count > 0)
            {
                Journal("Предупреждение", $"«{tunnel.Name}»: {DnsRuleConflictText(ruled)}");
            }
        }

        if (conflicts.SequenceEqual(link.DnsLanConflicts))
        {
            return;
        }

        link.DnsLanConflicts = conflicts;
        if (conflicts.Count > 0)
        {
            Journal("Предупреждение", $"«{tunnel.Name}»: {DnsLanConflictText(conflicts)}");
        }
    }

    /// <summary>
    /// Действующее ручное правило для адреса (то, что ложится в политике последним: по приоритету, затем самое узкое)
    /// направляет его не в этот туннель.
    /// </summary>
    private bool DnsRuleConflict(uint address, Guid tunnel)
    {
        var (rules, _) = ParsedRules();
        var rule = rules.Where(r => r.Cidr.Contains(address))
            .OrderBy(r => r.Priority).ThenBy(r => r.Cidr.PrefixLength).LastOrDefault();
        return rule is not null && rule.Target != RouteTarget.Tunnel(tunnel);
    }

    private static string DnsLanConflictText(IReadOnlyList<uint> conflicts) =>
        $"адрес DNS-сервера шлюза {string.Join(", ", conflicts.Select(Ipv4.Format))} совпадает с локальной сетью — "
        + "запросы имён к нему не отправляются, этот адрес остаётся в локальной сети.";

    private static string DnsRuleConflictText(IReadOnlyList<uint> conflicts) =>
        $"адрес DNS-сервера шлюза {string.Join(", ", conflicts.Select(Ipv4.Format))} попадает под ручное правило с другой целью — "
        + "запросы имён к нему не отправляются, адрес идёт по правилу. Чтобы DNS шлюза работал, измените правило "
        + "или снимите галочку «Ручные правила важнее сетей шлюза».";

    /// <summary>
    /// Почему адрес туннеля, выданный шлюзом, нельзя принять; null — адрес годится. Адаптер получает его как /32 с
    /// принудительным Preferred: адрес маршрутизатора, узла локальной сети, DNS, сервера VPN или другого туннеля
    /// перехватил бы трафик к нему у всей машины.
    /// </summary>
    internal string? GatewayTunnelAddressProblem(TunnelFacts tunnel, SessionInfo session)
    {
        if (session.TunnelAddressProblem() is { } problem)
        {
            return problem;
        }

        var address = Ipv4.Parse(session.Address);
        var text = Ipv4.Format(address);
        if (Facts.Primary is { } primary)
        {
            if (primary.DefaultGateway == address)
            {
                return $"шлюз выдал адрес туннеля {text}, совпадающий с адресом маршрутизатора локальной сети";
            }

            if (primary.Addresses.Contains(address)
                || primary.OnLinkPrefixes.Any(p => p.PrefixLength >= PolicyCompiler.MinOnLinkPrefix && p.Contains(address)))
            {
                return $"шлюз выдал адрес туннеля {text} из локальной сети основного адаптера «{primary.Name}»";
            }
        }

        if (ServiceDnsAddresses().Contains(address))
        {
            return $"шлюз выдал адрес туннеля {text}, совпадающий с адресом DNS-сервера сети";
        }

        if (AllServerAddresses().Contains(address))
        {
            return $"шлюз выдал адрес туннеля {text}, совпадающий с адресом сервера VPN";
        }

        foreach (var other in Facts.Tunnels.Values.Where(t => !ReferenceEquals(t, tunnel)))
        {
            var otherAddress = other.Session is { } otherSession && Ipv4.TryParse(otherSession.Address ?? "", out var parsed) ? parsed : (uint?)null;
            if (otherAddress == address || other.Adapter?.Addresses.Contains(address) == true)
            {
                return $"шлюз выдал адрес туннеля {text}, который уже занят подключением «{other.Name}»";
            }
        }

        return null;
    }

    /// <summary>
    /// Сеанс шлюза отклонён из-за его данных (адрес туннеля, адрес страницы входа): помощник останавливается с BYE,
    /// а туннель получает блокирующую ошибку — повтор с тем же шлюзом дал бы то же самое.
    /// </summary>
    private async Task RejectGatewaySessionAsync(TunnelFacts tunnel, AnyConnectLink link, string reason, CancellationToken cancellationToken)
    {
        var wasUp = link.Established;
        StopAnyConnect(tunnel);
        Facts.SignInApproved.Remove(tunnel.ProfileId);
        if (wasUp)
        {
            tunnel.ResetConnection(_deps.Time.GetUtcNow());
        }

        tunnel.VpnDns = [];
        tunnel.DialSettled = true;
        tunnel.LastErrorCategory = ErrorCategory.Other;
        tunnel.LastErrorCode = null;
        tunnel.LastErrorText = $"«{tunnel.Name}»: {reason}. Подключение остановлено.";
        tunnel.BlockingError = ErrorCategory.Other;
        tunnel.PasswordRequired = false;
        Journal("Ошибка", tunnel.LastErrorText + " Повторы остановлены до действия пользователя.");
        Facts.AppliedFilters.Remove(FilterGroup.Runtime);
        await ReconcileAsync(cancellationToken);
    }

    /// <summary>
    /// Адреса узла шлюза, на который перенаправил шлюз, без недопустимых: каждый получает маршрут /32 мимо туннеля
    /// и разрешение в фильтрах защиты. Что отброшено — в журнал.
    /// </summary>
    private List<uint> FilterGatewayNodeAddresses(TunnelFacts tunnel, string host, IEnumerable<uint> candidates)
    {
        var serviceDns = ServiceDnsAddresses();
        var (rules, _) = ParsedRules();
        var kept = new List<uint>();
        var dropped = new List<string>();
        foreach (var address in candidates.Distinct())
        {
            if (GatewayNodeAddressProblem(address, Facts.Primary, serviceDns, rules) is { } reason)
            {
                dropped.Add($"{Ipv4.Format(address)} ({reason})");
            }
            else
            {
                kept.Add(address);
            }
        }

        if (dropped.Count > 0)
        {
            Journal("Предупреждение", $"«{tunnel.Name}»: у узла шлюза {host} отброшены адреса {string.Join(", ", dropped)} — прямой путь к ним открыл бы шлюз.");
        }

        return kept;
    }

    /// <summary>Почему адрес узла шлюза нельзя открыть напрямую; null — можно.</summary>
    internal static string? GatewayNodeAddressProblem(uint address, AdapterCandidate? primary, IReadOnlyCollection<uint> serviceDns, IReadOnlyList<UserRule> rules)
    {
        if (SpecialRanges.GatewayUnusable.Contains(address))
        {
            return "служебный диапазон";
        }

        if (primary is not null)
        {
            if (primary.DefaultGateway == address)
            {
                return "маршрутизатор локальной сети";
            }

            if (primary.Addresses.Contains(address)
                || primary.OnLinkPrefixes.Any(p => p.PrefixLength >= PolicyCompiler.MinOnLinkPrefix && p.Contains(address)))
            {
                return "локальная сеть";
            }
        }

        if (serviceDns.Contains(address))
        {
            return "DNS-сервер сети";
        }

        // Действует то правило, что ложится в политике последним: по приоритету, затем самое узкое.
        var rule = rules.Where(r => r.Cidr.Contains(address))
            .OrderBy(r => r.Priority).ThenBy(r => r.Cidr.PrefixLength).LastOrDefault();
        return rule?.Target.Kind == TargetKind.Block ? "запрещён правилом пользователя" : null;
    }

    private async Task OnAnyConnectTerminatedAsync(TunnelFacts tunnel, AnyConnectLink link, TerminatedEvent terminated, CancellationToken cancellationToken)
    {
        var wasUp = link.Established;
        link.DeadlineTimer?.Dispose();
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
            // Текст помощника идёт и в ответ о состоянии (LastErrorText): одной строкой, без управляющих символов.
            var reason = string.IsNullOrWhiteSpace(terminated.Text) ? fallback : Core.Diagnostics.LogText.SingleLine(terminated.Text.Trim().TrimEnd('.'));
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
        link.DeadlineTimer?.Dispose();
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
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Любой сбой (нет доступа, сокет, BFE) не должен отменять прощание помощников со шлюзом ниже.
            _deps.Logger.LogWarning(ex, "Не удалось применить политику перед остановкой AnyConnect");
        }

        foreach (var tunnel in sessions)
        {
            try
            {
                StopAnyConnect(tunnel);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _deps.Logger.LogWarning(ex, "Помощник AnyConnect {Name} не остановлен", tunnel.Name);
            }
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
            .SelectMany(t =>
            {
                var userRulesWin = t.Protocol == VpnProtocol.AnyConnect
                    && _settings.Profile(t.ProfileId) is { AnyConnect.UserRulesOverrideServerNetworks: true };
                return t.VpnDns.Select(address => new TunnelHost(t.ProfileId, address, userRulesWin));
            })
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
            foreach (var suffix in GatewayDnsNames(tunnel.Session!, profile.AnyConnect.ApplyServerProxy).Where(s => routes.TrueForAll(r =>
                !string.Equals(r.Suffix, s, StringComparison.OrdinalIgnoreCase)
                && (!r.PinAddresses || r.ExactName || !s.EndsWith("." + r.Suffix, StringComparison.OrdinalIgnoreCase)))))
            {
                var exact = !tunnel.Session!.DnsSuffixes().Select(SettingsSerializer.NormalizeSuffix).Contains(suffix, StringComparer.OrdinalIgnoreCase);
                routes.Add(new DomainRoute(suffix, target, dns, PinAddresses: false, ExactName: exact));
            }
        }
    }

    /// <summary>
    /// Имена, которые разрешает DNS шлюза: суффиксы split DNS (или домен по умолчанию) и хост PAC. Хост PAC — только
    /// когда прокси шлюза применяется (<paramref name="includePac"/>) и только годное имя: иначе шлюз, назвав PAC на
    /// публичной зоне или на чужом имени, увёл бы его разрешение к своему DNS.
    /// </summary>
    internal static List<string> GatewayDnsNames(SessionInfo session, bool includePac)
    {
        // Однословные суффиксы («local») не берём: они совпали бы с mDNS и именами локальной сети.
        var names = session.DnsSuffixes().Select(SettingsSerializer.NormalizeSuffix).Where(IsGatewayDnsName);
        if (includePac && Uri.TryCreate(session.ProxyPac, UriKind.Absolute, out var pac) && pac.HostNameType == UriHostNameType.Dns
            && SettingsSerializer.NormalizeSuffix(pac.IdnHost) is { } pacHost && IsGatewayDnsName(pacHost))
        {
            names = names.Append(pacHost);
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

    /// <summary>
    /// Сети шлюза строками — по сеансу один раз: разбор, проверка пределов и запись тысяч сетей иначе шли бы при каждом
    /// построении состояния, а оно строится после каждой работы очереди, в том числе после статистики каждые 2 с.
    /// </summary>
    private readonly System.Runtime.CompilerServices.ConditionalWeakTable<SessionInfo, IReadOnlyList<string>> _formattedNetworks = new();

    private IReadOnlyList<string> FormattedNetworks(SessionInfo session) =>
        _formattedNetworks.GetValue(session, s => s.IncludeCidrs().Select(c => c.ToString()).ToArray());

    /// <summary>Страница сетей шлюза поднятого туннеля: в состоянии их только первые <see cref="ServerNetworksDto.MaxStatusNetworks"/>.</summary>
    private IpcResponse ServerNetworksPage(GetServerNetworksRequest request)
    {
        if (request.Offset < 0)
        {
            return IpcResponse.Failure(IpcErrorCodes.BadRequest, "Неверная позиция в списке сетей шлюза.");
        }

        if (Facts.Tunnels.GetValueOrDefault(request.ProfileId) is not { IsUp: true, Session: { } session })
        {
            return IpcResponse.Failure(IpcErrorCodes.NotFound, "Сеанса шлюза нет: подключение не поднято.");
        }

        var networks = FormattedNetworks(session);
        var page = networks.Skip(request.Offset).Take(ServerNetworksPageDto.MaxPage).ToArray();
        return IpcResponse.Success(new ServerNetworksPageDto(Math.Min(request.Offset, networks.Count), networks.Count, page));
    }

    private ServerNetworksDto? ServerNetworksOf(TunnelFacts tunnel)
    {
        if (tunnel is not { IsUp: true, Session: { } session })
        {
            return null;
        }

        var networks = FormattedNetworks(session);
        return new ServerNetworksDto
        {
            Networks = networks.Count > ServerNetworksDto.MaxStatusNetworks ? networks.Take(ServerNetworksDto.MaxStatusNetworks).ToArray() : networks,
            NetworkCount = networks.Count,
            NetworksTruncated = networks.Count > ServerNetworksDto.MaxStatusNetworks,
            Dns = session.Dns,
            DnsSuffixes = session.DnsSuffixes(),
            ProxyPac = session.ProxyPac,
            ApplyProxy = _settings.Profile(tunnel.ProfileId)?.AnyConnect.ApplyServerProxy == true,
            ClientVersion = tunnel.AnyConnect?.ClientVersion,
            Mtu = session.Mtu,
            DtlsActive = session.DtlsActive,
            SessionExpiresUtc = session.SessionTimeoutSeconds is > 0 and var seconds && tunnel.AnyConnect?.ParametersReceivedUtc is { } started
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
            tunnel.Paused = false;
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
        if (request.RequestId != Guid.Empty
            && Facts.Tunnels.GetValueOrDefault(request.ProfileId)?.SignIn?.RequestId != request.RequestId)
        {
            return IpcResponse.Failure(IpcErrorCodes.NotFound, "Запрос входа устарел.");
        }
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
        link.DeadlineTimer?.Dispose();
        link.DeadlineTimer = _deps.Time.CreateTimer(_ => QueueDeadlineCheck(profileId, generation), null,
            delay > TimeSpan.Zero ? delay : TimeSpan.Zero, Timeout.InfiniteTimeSpan);
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
            // Из списка - до попытки: неудачное удаление не повторяется на каждой сверке (см. выше).
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
        if (unused.Any(t => !copies.Contains(t)) || (_state.AnyConnectCertificateCopies is null && copies.Count > 0))
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
