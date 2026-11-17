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

    /// <summary>Сколько ждать выхода прежнего процесса движка перед запуском нового: имя адаптера у них общее.</summary>
    internal static readonly TimeSpan SshEngineExitWait = TimeSpan.FromSeconds(10);

    /// <summary>Выход прежних процессов движка по профилям.</summary>
    private readonly Dictionary<Guid, Task> _sshExits = [];

    /// <summary>Туннель «VPN поверх SSH» без сеанса: запустить движок, если ничто не мешает.</summary>
    private void EnsureSshTunnel(TunnelFacts tunnel)
    {
        var now = _deps.Time.GetUtcNow();
        if (tunnel.Ssh is not null || tunnel.BlockingError != ErrorCategory.None || tunnel.ExternallyDisconnected || Facts.ProfileTestRunning
            || Facts.Primary is null || now < tunnel.NextDialAt || _settings.Profile(tunnel.ProfileId) is not { } profile)
        {
            return;
        }

        // Прежний процесс ещё не вышел: имя адаптера занято. Его выход сам назначит сверку.
        if (_sshExits.TryGetValue(tunnel.ProfileId, out var exit) && !exit.IsCompleted)
        {
            return;
        }

        _sshExits.Remove(tunnel.ProfileId);
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

        var key = _deps.Secrets.TryLoad(profile.Id, SecretKind.SshPrivateKey);
        if (key is null)
        {
            tunnel.LastErrorCode = null;
            tunnel.DialSettled = true;
            if (_deps.Secrets.IsStored(profile.Id, SecretKind.SshPrivateKey))
            {
                // Ключ сохранён, но сейчас не расшифровывается (DPAPI ещё не готов при загрузке Windows).
                tunnel.LastErrorCategory = ErrorCategory.Other;
                tunnel.LastErrorText = $"«{tunnel.Name}»: сохранённый ключ SSH сейчас не читается, повтор позже.";
                ScheduleRetry(tunnel, now);
                return;
            }

            Block(tunnel, ErrorCategory.Authentication, "требуется ключ SSH - откройте «Подключения» и загрузите файл ключа");
            return;
        }

        var server = tunnel.ServerAddresses[0];
        var parameters = new SingBoxParameters
        {
            InterfaceName = SshTunnelDefaults.InterfaceName(profile.Id),
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
            session = _deps.SshTunnel.Start(parameters, key, engineEvent =>
                TryEnqueue("Ssh:" + engineEvent.GetType().Name, () => OnSshEventAsync(profileId, generation, engineEvent, CancellationToken.None)));
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

                // В выводе движка встречаются адрес сервера и имя пользователя: в журнал - только после скрытия.
                _deps.Logger.LogWarning("Движок SSH {Name}: {Text}", tunnel.Name, Redactor.Redact(log.Line, SshPersonalValues(tunnel)));
                if (link.Failure != SshEngineFailure.None && link.Ready)
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
                tunnel.EverConnected = true;
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
        var profileId = tunnel.ProfileId;
        link.Session.Dispose();
        var exited = link.Session.Exited;
        if (exited.IsCompleted)
        {
            _sshExits.Remove(profileId);
            return;
        }

        var waited = Task.WhenAny(exited, Task.Delay(SshEngineExitWait, _deps.Time));
        _sshExits[profileId] = waited;
        _ = waited.ContinueWith(
            _ => TryEnqueue("SshEngineExited", () => OnSshEngineExitedAsync(profileId, waited)),
            CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }

    private async Task OnSshEngineExitedAsync(Guid profileId, Task waited)
    {
        if (!_sshExits.TryGetValue(profileId, out var current) || !ReferenceEquals(current, waited))
        {
            return;
        }

        _sshExits.Remove(profileId);
        if (Facts.Tunnels.GetValueOrDefault(profileId) is { Ssh: null } && _state is { Intent: Intent.Connected, ProtectionSuspended: false })
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
        var russianTargets = DirectRussianTargets();
        var primaryAddresses = Facts.Primary.Addresses;
        tunnel.Verifying = true;
        var generation = tunnel.VerifyGeneration = ++_attemptGeneration;
        _ = Task.Run(async () =>
        {
            var alive = false;
            var russianOk = true;
            try
            {
                alive = await _deps.SshTunnel.ProbeAsync(route.Servers, route.InterfaceIndex, CancellationToken.None);
                russianOk = russianTargets.Count == 0 || await ProbeAsync(russianTargets, primaryAddresses, CancellationToken.None);
            }
            catch (Exception ex)
            {
                // Сорванная проба - непройденная проба: очередь обязана получить ответ.
                _deps.Logger.LogWarning(ex, "Проверка готовности «{Name}» прервана", name);
            }

            await EnqueueAsync("VerifyFinished", () => OnVerifyFinishedAsync(profileId, generation, alive, russianOk, CancellationToken.None));
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

            if (tunnel.Adapter is not null)
            {
                tunnel.AdapterMissingSinceUtc = null;
                continue;
            }

            tunnel.AdapterMissingSinceUtc ??= now;
            if (now - tunnel.AdapterMissingSinceUtc.Value >= AdapterMissingTimeout)
            {
                await FailSshTunnelAsync(tunnel, tunnel.Ssh!, null, "адаптер туннеля не найден в системе", cancellationToken);
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
            var name = tunnel.Name;
            _ = Task.Run(async () =>
            {
                var alive = false;
                try
                {
                    alive = await _deps.SshTunnel.ProbeAsync(route.Servers, route.InterfaceIndex, CancellationToken.None);
                }
                catch (Exception ex)
                {
                    _deps.Logger.LogWarning(ex, "Контроль связи «{Name}» прерван", name);
                }

                await EnqueueAsync("SshHealth", () => OnSshHealthAsync(profileId, generation, alive, CancellationToken.None));
            });
        }

        // Сверка не нужна: результат придёт в очередь отдельным событием.
        return false;
    }

    internal async Task OnSshHealthAsync(Guid profileId, int generation, bool alive, CancellationToken cancellationToken)
    {
        if (Facts.Tunnels.GetValueOrDefault(profileId) is not { Ssh: { } link } tunnel || link.Generation != generation)
        {
            return;
        }

        var now = _deps.Time.GetUtcNow();
        link.HealthRunning = false;
        if (alive)
        {
            link.HealthFailures = 0;
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

        await FailSshTunnelAsync(tunnel, link, null, "сервер перестал отвечать через туннель", cancellationToken);
    }

    /// <summary>Сеть сменилась: соединение SSH, скорее всего, оборвано - контроль не ждёт своего срока.</summary>
    private void HastenSshHealth()
    {
        var now = _deps.Time.GetUtcNow();
        foreach (var link in Facts.Tunnels.Values.Select(t => t.Ssh).OfType<SshTunnelLink>().Where(l => l.Ready))
        {
            link.NextHealthAt = now;
        }
    }

    /// <summary>
    /// Остановка службы: туннели SSH опускаются, движки завершаются. Сеанс не переживает службу (процесс движка
    /// в её Job), новая служба поднимет туннель сама. Возвращает задачу выхода процессов.
    /// </summary>
    internal Task ShutdownSshTunnels()
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

    public int HealthFailures { get; set; }
}
