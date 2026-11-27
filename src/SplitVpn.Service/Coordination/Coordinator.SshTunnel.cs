using System.ComponentModel;
using System.Globalization;
using SplitVpn.Core.Diagnostics;
using SplitVpn.Core.Net;
using SplitVpn.Core.Protection;
using SplitVpn.Core.Settings;
using SplitVpn.Core.SshTunnel;
using SplitVpn.Core.State;
using SplitVpn.Windows.Operations;

namespace SplitVpn.Service.Coordination;

/// <summary>
/// «VPN поверх SSH». Туннель держит отдельный процесс движка: он создаёт адаптер и переносит TCP из него в одно
/// соединение SSH. Маршруты, DNS и защита - у службы, как для остальных туннелей. В отличие от AnyConnect вход
/// пользователя не нужен: после обрыва служба поднимает туннель сама, с растущей паузой.
/// </summary>
public sealed partial class Coordinator
{
    /// <summary>Как часто работающий туннель проверяется запросом DNS через него.</summary>
    internal static readonly TimeSpan SshHealthInterval = TimeSpan.FromSeconds(30);

    /// <summary>Пауза перед повторной проверкой после неудачной.</summary>
    internal static readonly TimeSpan SshHealthRetry = TimeSpan.FromSeconds(10);

    /// <summary>Сколько проверок подряд должно не пройти, чтобы движок перезапустился. Короткие обрывы он лечит сам.</summary>
    internal const int SshHealthFailureLimit = 2;

    /// <summary>
    /// Сколько проверок подряд туннель может молчать, пока движок считает соединение с сервером живым.
    /// Соединение TCP зависает, не закрываясь (перегруженный канал, потеря пакетов у провайдера): движок
    /// разрыва не видит, и без этого предела туннель оставался «подключённым» без единого ответа, а имена
    /// по его правилам не разрешались. Три проверки - около полутора минут тишины.
    /// </summary>
    internal const int SshStalledCheckLimit = 3;

    /// <summary>Сколько ждать выхода прежнего процесса движка перед запуском нового: имя адаптера у них общее.</summary>
    internal static readonly TimeSpan SshEngineExitWait = TimeSpan.FromSeconds(10);

    /// <summary>Выход прежних процессов движка по профилям.</summary>
    private sealed record SshExit(Task Exited, string Name, DateTimeOffset Deadline)
    {
        /// <summary>Срок ожидания; сдвигается при переводе часов назад (<see cref="ShiftDeadlines"/>).</summary>
        public DateTimeOffset Deadline { get; set; } = Deadline;
    }
    private readonly Dictionary<Guid, SshExit> _sshExits = [];

    /// <summary>
    /// Подготовка адаптера SSH завершилась (успешно или с ошибкой): сверка продолжает дозвон сразу, а не по тику.
    /// Ответ подготовки, которую уже сменила другая (туннель разорван, профиль выключен), ничего не меняет.
    /// </summary>
    private async Task OnSshInterfacePreparedAsync(Guid profileId, Task preparation)
    {
        if (Facts.Tunnels.GetValueOrDefault(profileId) is not { } tunnel || !ReferenceEquals(tunnel.SshInterfacePreparation, preparation))
        {
            return;
        }

        await ReconcileAsync(CancellationToken.None);
    }

    /// <summary>Подготовка адаптера SSH ещё идёт: дозваниваться рано, её завершение само назначит сверку.</summary>
    private static bool SshInterfacePreparing(TunnelFacts tunnel) => tunnel.SshInterfacePreparation is { IsCompleted: false };

    /// <summary>Туннель «VPN поверх SSH» без сеанса: запустить движок, если ничто не мешает.</summary>
    private void EnsureSshTunnel(TunnelFacts tunnel)
    {
        var now = _deps.Time.GetUtcNow();
        if (tunnel.Ssh is not null || tunnel.BlockingError != ErrorCategory.None || tunnel.ExternallyDisconnected || Facts.ProfileTestRunning
            || Facts.Primary is null || now < tunnel.NextDialAt || _settings.Profile(tunnel.ProfileId) is not { } profile)
        {
            return;
        }

        // Адрес адаптера общий для всех профилей. Проверяется настоящий выход прежнего процесса.
        if (_sshExits.Values.FirstOrDefault(previous => !previous.Exited.IsCompleted) is { } exit)
        {
            tunnel.DialSettled = true;
            tunnel.WaitingForSshExit = exit.Exited;
            if (now < exit.Deadline)
            {
                tunnel.NextDialAt = exit.Deadline;
                tunnel.LastErrorText = $"Ожидание выхода прежнего движка «{exit.Name}».";
            }
            else
            {
                Block(tunnel, ErrorCategory.Other,
                    $"прежний движок «{exit.Name}» не освободил адрес туннеля. Перезапустите службу или дождитесь выхода процесса");
            }
            return;
        }

        if (_deps.SshTunnel.EnginePath is null)
        {
            Block(tunnel, ErrorCategory.Other, "не найден движок «VPN поверх SSH» - переустановите программу");
            return;
        }

        if (!SshHostKey.TryParse(profile.SshVpn.HostKey, out var hostKey))
        {
            Block(tunnel, ErrorCategory.Other, "не задан или не распознан ключ сервера SSH - откройте «Подключения» и укажите его");
            return;
        }

        var interfaceName = SshTunnelDefaults.InterfaceName(profile.Id);
        try
        {
            if (tunnel.SshInterfacePreparation is null)
            {
                var started = tunnel.SshInterfacePreparation = _deps.SshTunnel.PrepareInterfaceAsync(interfaceName);
                if (!started.IsCompleted)
                {
                    // Пока подготовка идёт, DialDue этот туннель не видит (иначе полная сверка шла бы каждые 2 с
                    // до 30 с подряд): её завершение само назначает сверку, и дозвон продолжится сразу.
                    var preparedId = tunnel.ProfileId;
                    _ = started.ContinueWith(_ => TryEnqueue("SshInterfacePrepared", () => OnSshInterfacePreparedAsync(preparedId, started)),
                        CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                }
            }

            var preparation = tunnel.SshInterfacePreparation;
            if (!preparation.IsCompleted)
            {
                tunnel.DialStartedUtc ??= now;
                tunnel.LastErrorText = $"Ожидание освобождения адаптера {interfaceName}.";
                return;
            }

            tunnel.SshInterfacePreparation = null;
            preparation.GetAwaiter().GetResult();
        }
        catch (Exception ex) when (ex is IOException or Win32Exception or UnauthorizedAccessException)
        {
            tunnel.DialSettled = true;
            tunnel.LastErrorCategory = ErrorCategory.Other;
            tunnel.LastErrorText = $"«{tunnel.Name}»: {ex.Message}";
            ScheduleRetry(tunnel, now);
            Journal("Ошибка", tunnel.LastErrorText);
            return;
        }

        var key = _deps.Secrets.TryLoad(profile.Id, SecretKind.SshPrivateKey);
        if (key is null)
        {
            tunnel.LastErrorCode = null;
            tunnel.DialSettled = true;
            if (_deps.Secrets.IsStored(profile.Id, SecretKind.SshPrivateKey))
            {
                // Ключ сохранён, но сейчас не расшифровывается (DPAPI ещё не готов при загрузке Windows).
                RegisterUnreadableKey(tunnel, SecretKind.SshPrivateKey, "ключ SSH", "загрузите файл ключа заново");
                return;
            }

            Block(tunnel, ErrorCategory.Authentication, "требуется ключ SSH - откройте «Подключения» и загрузите файл ключа");
            return;
        }

        _keyUnreadable.Remove((profile.Id, SecretKind.SshPrivateKey));

        var server = SshEngineServer(tunnel)!.Value;
        var parameters = new SingBoxParameters
        {
            InterfaceName = interfaceName,
            Server = server,
            Port = tunnel.ServerPort,
            User = profile.UserName,
            HostKey = hostKey,
            DnsServers = SshUpstreamDns(),
            VerboseLog = _deps.Verbose?.UntilUtc is { } verboseUntil && verboseUntil > now,
        };
        var generation = tunnel.DialGeneration = ++_attemptGeneration;
        var profileId = tunnel.ProfileId;
        ISshTunnelSession session;
        try
        {
            var personalValues = SshPersonalValues(tunnel);
            var failureQueued = 0;
            session = _deps.SshTunnel.Start(parameters, key, engineEvent =>
            {
                if (engineEvent is SshTunnelLog log)
                {
                    var detailed = SshEngineLog.IsDetailed(log.Line);
                    if (!detailed || _deps.Verbose?.UntilUtc > _deps.Time.GetUtcNow())
                    {
                        _deps.Logger.Log(detailed ? LogLevel.Debug : LogLevel.Warning,
                            "Движок SSH {Name}: {Text}", profile.Name, Core.Diagnostics.LogText.SingleLine(Redactor.Redact(SshEngineLog.Plain(log.Line), personalValues)));
                    }

                    if (SshEngineLog.Classify(log.Line) == SshEngineFailure.None
                        || Interlocked.Exchange(ref failureQueued, 1) != 0)
                    {
                        return;
                    }
                }

                TryEnqueue("Ssh:" + engineEvent.GetType().Name, () => OnSshEventAsync(profileId, generation, engineEvent, CancellationToken.None));
            });
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or Win32Exception or UnauthorizedAccessException)
        {
            tunnel.DialSettled = true;
            tunnel.LastErrorCategory = ErrorCategory.Other;
            tunnel.LastErrorText = $"«{tunnel.Name}»: движок «VPN поверх SSH» не запустился: {ex.Message}";
            ScheduleRetry(tunnel, now);
            Journal("Ошибка", tunnel.LastErrorText);
            return;
        }
        finally
        {
            Array.Clear(key);
        }

        // События движка обрабатываются в очереди актора, то есть уже после этого присваивания.
        tunnel.Ssh = new SshTunnelLink(session, generation, server) { DnsServers = parameters.DnsServers };
        // Адрес сеанса один и тот же в настройках движка, в маршруте до сервера и в фильтре защиты: его смена
        // в DNS посреди сеанса не должна оставить движок без пути к серверу.
        tunnel.SessionServerAddresses = [server];
        tunnel.DialStartedUtc = now;
        tunnel.PasswordRequired = false;
        Journal("Сведения", $"Подключение к «{profile.Name}» (VPN поверх SSH).");
    }

    private void Block(TunnelFacts tunnel, ErrorCategory category, string reason)
    {
        tunnel.DialSettled = true;
        tunnel.BlockingError = category;
        tunnel.LastErrorCategory = category;
        tunnel.LastErrorCode = null;
        tunnel.LastErrorText = $"«{tunnel.Name}»: {reason}.";
        Journal("Ошибка", tunnel.LastErrorText + " Повторы остановлены до действия пользователя.");
    }

    internal async Task OnSshEventAsync(Guid profileId, int generation, SshTunnelEvent engineEvent, CancellationToken cancellationToken)
    {
        if (Facts.Tunnels.GetValueOrDefault(profileId) is not { Ssh: { } link } tunnel || link.Generation != generation)
        {
            // Событие прежнего процесса: сеанс уже остановлен службой.
            return;
        }

        switch (engineEvent)
        {
            case SshTunnelLog log:
                if (SshEngineLog.Classify(log.Line) is var failure and not SshEngineFailure.None)
                {
                    link.Failure = failure;
                }

                if (link.Failure != SshEngineFailure.None)
                {
                    // Сервер отказал уже поднятому туннелю (ключ отозван, ключ сервера сменился): ждать контроля незачем.
                    await FailSshTunnelAsync(tunnel, link, null, null, cancellationToken);
                }

                break;
            case SshTunnelReady ready:
                link.Ready = true;
                link.Luid = ready.Luid;
                // Адаптер находит снимок сети сверки ниже - по LUID сеанса (RefreshTunnelAdapters).
                tunnel.Adapter = null;
                tunnel.VpnDns = [];
                tunnel.SessionStartedUtc = _deps.Time.GetUtcNow();
                tunnel.Statistics = null;
                tunnel.DialSettled = true;
                tunnel.ResetVerification();
                tunnel.NextVerifyAt = _deps.Time.GetUtcNow();
                link.NextHealthAt = _deps.Time.GetUtcNow() + SshHealthInterval;
                // Счётчики повторов и текст ошибки снимает проверка готовности: только обмен данными через туннель
                // доказывает, что соединение SSH с сервером установлено.
                Journal("Сведения", $"«{tunnel.Name}»: адаптер туннеля создан, проверяется связь с сервером.");
                await ReconcileAsync(cancellationToken);
                break;
            case SshTunnelExited exited:
                await FailSshTunnelAsync(tunnel, link, exited.ExitCode, exited.Failure, cancellationToken);
                break;
        }
    }

    /// <summary>
    /// Сеанс движка кончился: процесс вышел сам или сервер отказал. Туннель снимается, его назначения до нового
    /// подъёма блокирует защита. Отказ входа и чужой ключ сервера останавливают повторы, остальное повторяется
    /// с растущей паузой.
    /// </summary>
    private async Task FailSshTunnelAsync(TunnelFacts tunnel, SshTunnelLink link, int? exitCode, string? reason, CancellationToken cancellationToken)
    {
        var now = _deps.Time.GetUtcNow();
        var wasUp = link.Ready;
        StopSshTunnel(tunnel);
        if (wasUp)
        {
            tunnel.ResetConnection(now);
        }

        tunnel.DialSettled = true;
        tunnel.LastErrorCode = null;
        if (link.Failure != SshEngineFailure.None)
        {
            tunnel.BlockingError = ErrorCategory.Authentication;
            tunnel.LastErrorCategory = ErrorCategory.Authentication;
            tunnel.LastErrorText = $"«{tunnel.Name}»: {SshEngineLog.Describe(link.Failure)}.";
            Journal("Ошибка", tunnel.LastErrorText + " Повторы остановлены до действия пользователя.");
        }
        else
        {
            tunnel.FailedDialsSinceResolve++;
            var delay = ScheduleRetry(tunnel, now);
            var cause = reason ?? (exitCode is { } code
                ? string.Create(CultureInfo.InvariantCulture, $"движок завершился (код {code})")
                : "движок завершился");
            tunnel.LastErrorCategory = wasUp ? ErrorCategory.Other : ErrorCategory.ServerUnreachable;
            tunnel.LastErrorText = string.Create(CultureInfo.InvariantCulture,
                $"«{tunnel.Name}»: {(wasUp ? "туннель оборвался" : "туннель не поднялся")}: {cause.TrimEnd('.')}. Повтор через {Math.Max(1, (int)delay.TotalSeconds)} с.");
            Journal("Ошибка", tunnel.LastErrorText);
        }

        Facts.AppliedFilters.Remove(FilterGroup.Runtime);
        await ReconcileAsync(cancellationToken);
    }

    /// <summary>
    /// Останавливает движок: процесс завершается, с ним исчезает адаптер. События процесса больше не принимаются.
    /// Через этот метод идут все разрывы сеанса (<see cref="HangUpAsync"/>): неудачная проверка, смена ключа и
    /// параметров, отключение пользователем. Без него туннель остался бы «поднятым» без адаптера.
    /// </summary>
    private void StopSshTunnel(TunnelFacts tunnel)
    {
        if (tunnel.Ssh is not { } link)
        {
            return;
        }

        tunnel.Ssh = null;
        link.Probes.Cancel();
        link.Probes.Dispose();
        var profileId = tunnel.ProfileId;
        link.Session.Dispose();
        var exited = link.Session.Exited;
        if (exited.IsCompleted)
        {
            _sshExits.Remove(profileId);
            return;
        }

        var exit = new SshExit(exited, tunnel.Name, _deps.Time.GetUtcNow() + SshEngineExitWait);
        _sshExits[profileId] = exit;
        _ = MonitorSshExitAsync(profileId, exit, link.Session);
    }

    private async Task MonitorSshExitAsync(Guid profileId, SshExit exit, ISshTunnelSession session)
    {
        try
        {
            await exit.Exited.WaitAsync(SshEngineExitWait, _deps.Time);
        }
        catch (TimeoutException)
        {
            _deps.Logger.LogWarning("Движок SSH {Name} не завершился, повтор остановки", exit.Name);
            session.Dispose();
            await EnqueueAsync("SshEngineExitTimeout", () => ReconcileAsync(CancellationToken.None));
            await exit.Exited;
        }
        await EnqueueAsync("SshEngineExited", () => OnSshEngineExitedAsync(profileId, exit));
    }

    private async Task OnSshEngineExitedAsync(Guid profileId, SshExit exit)
    {
        if (!_sshExits.TryGetValue(profileId, out var current) || !ReferenceEquals(current, exit))
        {
            return;
        }

        _sshExits.Remove(profileId);
        foreach (var waiting in Facts.Tunnels.Values.Where(t => t.WaitingForSshExit == exit.Exited))
        {
            waiting.WaitingForSshExit = null;
            waiting.BlockingError = ErrorCategory.None;
            waiting.LastErrorCategory = ErrorCategory.None;
            waiting.LastErrorText = null;
            waiting.NextDialAt = _deps.Time.GetUtcNow();
        }
        if (_state is { Intent: Intent.Connected, ProtectionSuspended: false })
        {
            await ReconcileAsync(CancellationToken.None);
        }
    }

    /// <summary>
    /// Проверка готовности туннеля SSH: запрос DNS по TCP через адаптер туннеля. Обычная проба (TCP-подключение
    /// к контрольному адресу) здесь ничего не доказывает: движок принимает соединение у себя и до сервера может
    /// его не донести. Ответ на запрос приходит только через живое соединение SSH.
    /// </summary>
    private void StartSshVerify(TunnelFacts tunnel)
    {
        if (TunnelDnsRoute(tunnel) is not { } route || Facts.Primary is null)
        {
            return;
        }

        var name = tunnel.Name;
        var profileId = tunnel.ProfileId;
        var token = tunnel.Ssh!.Probes.Token;
        tunnel.Verifying = true;
        var generation = tunnel.VerifyGeneration = ++_attemptGeneration;
        _ = Task.Run(async () =>
        {
            var alive = false;
            try
            {
                alive = await _deps.SshTunnel.ProbeAsync(route.Servers, route.InterfaceIndex, token);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { return; }
            catch (Exception ex)
            {
                // Сорванная проба - непройденная проба: очередь обязана получить ответ.
                _deps.Logger.LogWarning(ex, "Проверка готовности «{Name}» прервана", name);
            }

            await EnqueueAsync("VerifyFinished", () => OnVerifyFinishedAsync(profileId, generation, alive, russianOk: null, CancellationToken.None));
        });
    }

    /// <summary>
    /// Движок работает, а его адаптера в системе нет дольше <see cref="AdapterMissingTimeout"/> (адаптер удалён
    /// или сброшен драйвер): туннель без адаптера не несёт трафик и сам не восстановится. Движок перезапускается
    /// обычным порядком, с паузой.
    /// </summary>
    private async Task<bool> CheckSshAdaptersAsync(CancellationToken cancellationToken)
    {
        var now = _deps.Time.GetUtcNow();
        foreach (var tunnel in Facts.Tunnels.Values.Where(t => t.Ssh is { Ready: true }).ToList())
        {
            if (!tunnel.Ssh!.DnsServers.SequenceEqual(SshUpstreamDns()))
            {
                // Серверы DNS записаны в настройки движка при запуске: новый список требует нового процесса.
                Journal("Сведения", $"«{tunnel.Name}»: список «DNS через VPN» изменён, туннель перезапускается.");
                StopSshTunnel(tunnel);
                tunnel.ResetConnection(now);
                Facts.AppliedFilters.Remove(FilterGroup.Runtime);
                await ReconcileAsync(cancellationToken);
                continue;
            }

            if (HelperAdapterTimedOut(tunnel))
            {
                await FailSshTunnelAsync(tunnel, tunnel.Ssh, null, "адаптер туннеля не найден в системе или потерял адрес IPv4", cancellationToken);
            }
            else if (tunnel.Luid is { } luid && _deps.SshTunnel.GetCounters(luid) is { } counters)
            {
                tunnel.Statistics = new Windows.Ras.RasStatistics(counters.Sent, counters.Received, now - (tunnel.SessionStartedUtc ?? now));
            }
        }

        // Сверку при отказе назначает сам отказ.
        return false;
    }

    /// <summary>Серверы DNS за туннелем SSH: «DNS через VPN» из настроек, без них - общеизвестные.</summary>
    private List<uint> SshUpstreamDns()
    {
        var upstream = UpstreamDnsAddresses();
        return (upstream.Count > 0 ? upstream : FallbackUpstreams.ToList()).Take(SshTunnelDefaults.MaxDnsServers).ToList();
    }

    /// <summary>Подошёл срок контроля работающего туннеля SSH.</summary>
    private bool SshHealthDue(DateTimeOffset now) =>
        _state.Intent == Intent.Connected && !Facts.ProfileTestRunning
        && Facts.Tunnels.Values.Any(t => t is { Verified: true, Ssh: { Ready: true, HealthRunning: false } link } && now >= link.NextHealthAt);

    /// <summary>
    /// Контроль в работе. Процесс движка жив, даже когда соединение SSH с сервером оборвалось или зависло, поэтому
    /// раз в <see cref="SshHealthInterval"/> через туннель уходит запрос DNS. Признак «проверен» при этом не
    /// сбрасывается, чтобы статус не мигал. Проба идёт в фоновой задаче.
    /// </summary>
    private bool StartSshHealthChecks()
    {
        var now = _deps.Time.GetUtcNow();
        if (!SshHealthDue(now))
        {
            return false;
        }

        foreach (var tunnel in Facts.Tunnels.Values.Where(t => t is { Verified: true, Ssh: { Ready: true, HealthRunning: false } }).ToList())
        {
            var link = tunnel.Ssh!;
            if (now < link.NextHealthAt || TunnelDnsRoute(tunnel) is not { } route)
            {
                continue;
            }

            link.HealthRunning = true;
            var profileId = tunnel.ProfileId;
            var generation = link.Generation;
            var pathGeneration = link.PathGeneration;
            var token = link.Probes.Token;
            var name = tunnel.Name;
            _ = Task.Run(async () =>
            {
                var alive = false;
                try
                {
                    alive = await _deps.SshTunnel.ProbeAsync(route.Servers, route.InterfaceIndex, token);
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { return; }
                catch (Exception ex)
                {
                    _deps.Logger.LogWarning(ex, "Контроль связи «{Name}» прерван", name);
                }

                await EnqueueAsync("SshHealth", () => OnSshHealthAsync(profileId, generation, alive, CancellationToken.None, pathGeneration));
            });
        }

        // Сверка не нужна: результат придёт в очередь отдельным событием.
        return false;
    }

    internal async Task OnSshHealthAsync(Guid profileId, int generation, bool alive, CancellationToken cancellationToken, int? pathGeneration = null)
    {
        if (Facts.Tunnels.GetValueOrDefault(profileId) is not { Ssh: { } link } tunnel || link.Generation != generation)
        {
            return;
        }

        var now = _deps.Time.GetUtcNow();
        link.HealthRunning = false;
        if (pathGeneration.HasValue && pathGeneration != link.PathGeneration)
        {
            return;
        }

        if (alive)
        {
            link.HealthFailures = 0;
            link.StalledChecks = 0;
            link.NextHealthAt = now + SshHealthInterval;
            return;
        }

        if (++link.HealthFailures < SshHealthFailureLimit)
        {
            link.NextHealthAt = now + SshHealthRetry;
            _deps.Logger.LogInformation("«{Name}»: контроль связи не прошёл ({Attempt} из {Total}), повтор через {Delay} с",
                tunnel.Name, link.HealthFailures, SshHealthFailureLimit, (int)SshHealthRetry.TotalSeconds);
            return;
        }

        if (link.Session.HasEstablishedTransport() != false)
        {
            if (++link.StalledChecks < SshStalledCheckLimit)
            {
                link.HealthFailures = 0;
                link.NextHealthAt = now + SshHealthRetry;
                _deps.Logger.LogWarning("«{Name}»: DNS не ответил, отключение транспорта SSH не подтверждено ({Attempt} из {Total})",
                    tunnel.Name, link.StalledChecks, SshStalledCheckLimit);
                return;
            }

            await FailSshTunnelAsync(tunnel, link, null, "сервер SSH не отвечает: соединение зависло", cancellationToken);
            return;
        }

        await FailSshTunnelAsync(tunnel, link, null, "соединение с сервером SSH потеряно", cancellationToken);
    }

    /// <summary>
    /// Сеть сменилась: соединение SSH, скорее всего, оборвано - контроль не ждёт своего срока. Счёт неудач не
    /// обнуляется: при «моргающем» Wi-Fi уведомления приходят чаще, чем набираются две неудачи подряд, и мёртвое
    /// соединение иначе не перезапускалось бы никогда. Двойного счёта нет: ответ пробы, начатой до смены пути,
    /// отбрасывается по поколению пути (<see cref="OnSshHealthAsync"/>), засчитывается только новая проба.
    /// </summary>
    private void HastenSshHealth()
    {
        var now = _deps.Time.GetUtcNow();
        foreach (var link in Facts.Tunnels.Values.Select(t => t.Ssh).OfType<SshTunnelLink>().Where(l => l.Ready))
        {
            link.PathGeneration++;
            link.NextHealthAt = now;
        }
    }

    /// <summary>
    /// Остановка службы: туннели SSH опускаются, движки завершаются. Сеанс не переживает службу (процесс движка
    /// в её Job), новая служба поднимет туннель сама. Возвращает задачу выхода процессов.
    /// <para>
    /// Если применение политики перед остановкой AnyConnect не уложилось в срок и идёт в фоне, остановка SSH ждёт его конца:
    /// применение читает те же факты туннелей. Не дождались в пределах срока хоста — движок завершит закрытие Job при выходе
    /// службы (прощаться ему не с кем).
    /// </para>
    /// </summary>
    internal Task ShutdownSshTunnels() =>
        _shutdownApply.IsCompleted
            ? StopSshTunnelsForShutdown()
            : _shutdownApply.ContinueWith(_ => StopSshTunnelsForShutdown(),
                CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default).Unwrap();

    private Task StopSshTunnelsForShutdown()
    {
        var exits = new List<Task>();
        foreach (var tunnel in Facts.Tunnels.Values.Where(t => t.Ssh is not null).ToList())
        {
            exits.Add(tunnel.Ssh!.Session.Exited);
            StopSshTunnel(tunnel);
            tunnel.ResetConnection(_deps.Time.GetUtcNow());
        }

        if (exits.Count > 0)
        {
            Journal("Сведения", "Служба останавливается: туннели «VPN поверх SSH» завершены.");
        }

        return Task.WhenAll(exits);
    }

    /// <summary>Значения, которые из вывода движка скрываются: имя сервера и имя пользователя (адреса скрываются сами).</summary>
    private List<string?> SshPersonalValues(TunnelFacts tunnel)
    {
        var profile = _settings.Profile(tunnel.ProfileId);
        return [profile is null ? null : ServerHost(profile), profile?.UserName];
    }
}

/// <summary>Живой процесс движка «VPN поверх SSH». Поколение отсекает события прежних процессов.</summary>
internal sealed class SshTunnelLink(ISshTunnelSession session, int generation, uint serverAddress)
{
    public ISshTunnelSession Session { get; } = session;

    public int Generation { get; } = generation;

    /// <summary>Адрес сервера, на который настроен этот процесс: он же в маршруте до сервера и в фильтре защиты.</summary>
    public uint ServerAddress { get; } = serverAddress;

    /// <summary>Серверы DNS, записанные в настройки этого процесса; служба ходит к ним по служебным адресам туннеля.</summary>
    public IReadOnlyList<uint> DnsServers { get; init; } = [];

    /// <summary>Адаптер создан и настроен: туннель считается поднятым.</summary>
    public bool Ready { get; set; }

    public ulong Luid { get; set; }

    /// <summary>Причина отказа, которую движок назвал в своём выводе.</summary>
    public SshEngineFailure Failure { get; set; }

    public DateTimeOffset NextHealthAt { get; set; }

    public bool HealthRunning { get; set; }

    public CancellationTokenSource Probes { get; } = new();

    public int PathGeneration { get; set; }

    public int HealthFailures { get; set; }

    /// <summary>Сколько проверок подряд DNS через туннель молчал при живом на вид соединении с сервером.</summary>
    public int StalledChecks { get; set; }
}
