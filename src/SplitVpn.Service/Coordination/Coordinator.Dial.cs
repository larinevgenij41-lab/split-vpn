using Microsoft.Extensions.Logging;
using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Windows.Ras;
using SplitVpn.Windows.Operations;

namespace SplitVpn.Service.Coordination;

public sealed partial class Coordinator
{
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Сколько проб подряд должно не пройти, прежде чем живой сеанс разрывается. Сеанс RAS уже поднят,
    /// и частая причина молчания туннеля — сервер, который ещё не отпустил прежнюю сессию: разрыв и новый
    /// дозвон этот счёт только перезапускают, поэтому сначала мы пробуем тот же сеанс ещё раз.
    /// </summary>
    internal const int VerifyProbeAttempts = 3;

    /// <summary>Пауза между пробами одного сеанса. Кратна тику службы, поэтому на деле — от неё до тика сверху.</summary>
    internal static readonly TimeSpan VerifyProbeInterval = TimeSpan.FromSeconds(2);

    /// <summary>
    /// Наименьшая пауза перед дозвоном после исчерпанных проб. Обычный backoff начинается с секунды, но
    /// цикл «дозвон — пробы — разрыв» и так занимает десятки секунд: секундная пауза лишь молотит сеансы сервера.
    /// </summary>
    internal static readonly TimeSpan VerifyRetryFloor = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Сколько очередь ждёт зависший дозвон, прежде чем отпустить следующий туннель. Предел обязателен:
    /// таймаут дозвона RAS — 60 с, и без него недоступный сервер держал бы всю очередь минуту.
    /// </summary>
    internal static readonly TimeSpan SequentialDialWait = TimeSpan.FromSeconds(15);

    private async Task EnsureDialsAsync(CancellationToken cancellationToken)
    {
        if (Facts.Tunnels.Count == 0)
        {
            // Состояние «Ошибка», а не бесконечное «Подключение»: пользователь видит причину и может снять защиту.
            var text = "Не выбрано ни одного подключения: откройте «Подключения» и включите хотя бы одно.";
            if (Facts.ConfigError != text)
            {
                Journal("Ошибка", text);
            }

            Facts.ConfigError = text;
            return;
        }

        Facts.ConfigError = null;
        // Порядок списка, а не перечисления словаря: он виден пользователю и задаёт очерёдность подъёма.
        var ordered = ActiveProfiles
            .Select(p => Facts.Tunnels.GetValueOrDefault(p.Id))
            .OfType<TunnelFacts>()
            .ToList();
        var now = _deps.Time.GetUtcNow();
        for (var index = 0; index < ordered.Count; index++)
        {
            var tunnel = ordered[index];
            if (tunnel.IsUp)
            {
                if (!tunnel.Verified && !tunnel.Verifying && now >= tunnel.NextVerifyAt)
                {
                    StartVerify(tunnel);
                }

                continue;
            }

            // Положенный туннель не поднимаем ничем: AnyConnect идёт мимо CanStartDial, поэтому проверка здесь.
            if (tunnel.Paused || !PrecedingSettled(ordered, index, now))
            {
                continue;
            }

            if (tunnel.Protocol == VpnProtocol.AnyConnect)
            {
                EnsureAnyConnect(tunnel);
                continue;
            }

            if (CanStartDial(tunnel, out var profile, out var password))
            {
                StartDial(tunnel, profile, password);
            }
        }
    }

    /// <summary>
    /// При подъёме по очереди туннель ждёт всех, кто стоит перед ним в списке. Ожидание ограничено: хватает
    /// того, что предыдущий поднялся, отказался, положен пользователем или уже висит дольше отведённого срока, —
    /// иначе одно недоступное подключение не пускало бы остальные.
    /// </summary>
    private bool PrecedingSettled(List<TunnelFacts> ordered, int index, DateTimeOffset now) =>
        !_settings.SequentialDial
        || ordered.Take(index).All(t => t.IsUp || t.DialSettled || t.Paused
            || t.BlockingError != ErrorCategory.None
            // Ждёт человека — пароля или входа в шлюз. Очередь ждать его не должна: это может быть минутами.
            || t.PasswordRequired || t.SignIn is not null
            || (t.DialStartedUtc is { } started && now - started >= SequentialDialWait));

    private bool CanStartDial(TunnelFacts tunnel, out ConnectionProfile profile, out char[] password)
    {
        profile = null!;
        password = [];
        if (tunnel.Dialing || tunnel.Paused || Facts.ProfileTestRunning || tunnel.BlockingError != ErrorCategory.None || tunnel.ExternallyDisconnected
            || Facts.Primary is null || _deps.Time.GetUtcNow() < tunnel.NextDialAt)
        {
            return false;
        }

        if (_settings.Profile(tunnel.ProfileId) is not { } active)
        {
            return false;
        }

        var loaded = LoadPassword(active);
        if (VpnProtocols.NeedsPreSharedKey(active) && !_deps.Secrets.Contains(active.Id, SecretKind.PreSharedKey))
        {
            if (loaded is not null)
            {
                Array.Clear(loaded);
            }

            tunnel.BlockingError = ErrorCategory.Authentication;
            tunnel.LastErrorText = $"«{tunnel.Name}»: требуется ключ IPsec — откройте «Подключения» и сохраните его.";
            return false;
        }

        tunnel.PasswordRequired = loaded is null;
        if (loaded is null)
        {
            return false;
        }

        profile = active;
        password = loaded;
        return true;
    }

    private char[]? LoadPassword(ConnectionProfile profile)
    {
        if (!VpnProtocols.NeedsPassword(profile.AuthMethod)) { return []; }
        if (Facts.MemoryPasswordProfile == profile.Id && Facts.MemoryPassword is { } memory)
        {
            return memory.ToArray();
        }

        return profile.SavePassword ? _deps.Secrets.TryLoad(profile.Id) : null;
    }

    private void StartDial(TunnelFacts tunnel, ConnectionProfile profile, char[] password)
    {
        try
        {
            PrepareEntry(tunnel, profile);
        }
        catch (Exception ex) when (ex is InvalidOperationException or Windows.Native.NativeCallException)
        {
            Array.Clear(password);
            tunnel.BlockingError = VpnProtocols.NeedsServerValidation(profile.AuthMethod) || profile.AuthMethod == AuthMethod.MachineCertificate
                ? ErrorCategory.Certificate
                : ErrorCategory.Authentication;
            tunnel.LastErrorText = ex.Message;
            Journal("Ошибка", $"Не удалось подготовить «{tunnel.Name}»: {ex.Message}");
            return;
        }
        catch
        {
            Array.Clear(password);
            throw;
        }

        // Проба идёт параллельно дозвону и его не задерживает: к следующей попытке будут известны адреса
        // проверки отзыва сертификата, без которых Windows отклоняет исправный сертификат за kill switch.
        EnsureCertificateProbe(tunnel, "перед дозвоном");
        tunnel.Dialing = true;
        tunnel.DialStartedUtc = _deps.Time.GetUtcNow();
        var generation = ++tunnel.DialGeneration;
        Journal("Сведения", $"Подключение к «{profile.Name}» (попытка {tunnel.DialAttempt + 1}).");
        _ = Task.Run(async () =>
        {
            RasDialResult result;
            try
            {
                result = await _deps.Ras.DialAsync(tunnel.EntryName, profile.UserName, password, profile.Domain, CancellationToken.None);
            }
            catch (Exception ex)
            {
                result = new RasDialResult(false, null, 0, ex.Message);
            }
            finally
            {
                Array.Clear(password);
            }

            await EnqueueAsync("DialFinished", () => OnDialFinishedAsync(tunnel.ProfileId, result, generation, CancellationToken.None));
        });
    }

    /// <summary>
    /// Готовит запись телефонной книги под текущий профиль и запоминает отпечаток параметров входа:
    /// по нему при следующем запуске службы решается, можно ли подхватить живое соединение.
    /// </summary>
    private void PrepareEntry(TunnelFacts tunnel, ConnectionProfile profile)
    {
        var key = VpnProtocols.NeedsPreSharedKey(profile) ? _deps.Secrets.TryLoad(profile.Id, SecretKind.PreSharedKey) : null;
        try
        {
            _deps.Ras.SaveEntry(tunnel.EntryName, profile, key ?? []);
            tunnel.AppliedEntryServer = profile.Server;
            RememberFingerprint(tunnel, VpnProtocols.ConnectionKey(profile));
        }
        finally
        {
            if (key is not null)
            {
                Array.Clear(key);
            }
        }
    }

    internal async Task OnDialFinishedAsync(Guid profileId, RasDialResult result, int generation, CancellationToken cancellationToken)
    {
        if (Facts.Tunnels.GetValueOrDefault(profileId) is not { } tunnel)
        {
            if (result.Handle is { } orphan)
            {
                await _deps.Ras.HangUpAsync(orphan, cancellationToken);
            }

            return;
        }

        tunnel.Dialing = false;
        // Попытка завершилась — очередь отпускает следующий туннель независимо от того, чем она кончилась.
        tunnel.DialSettled = true;
        // Туннель положили, пока шёл дозвон: соединение разрывается, а не присоединяется.
        if (generation != tunnel.DialGeneration || _state.Intent != Intent.Connected || tunnel.Paused)
        {
            if (result.Handle is { } stale)
            {
                await _deps.Ras.HangUpAsync(stale, cancellationToken);
            }

            return;
        }

        if (result.Success && result.Handle is { } handle)
        {
            // Счётчик попыток и текст ошибки снимает только успешная проверка: дозвон, после которого в туннеле
            // нет интернета, возвращал бы паузу к секунде — это и есть цикл переподключений.
            AttachTunnel(tunnel, handle);
            Journal("Сведения", $"«{tunnel.Name}» подключён" + (tunnel.Adapter is { Addresses.Count: > 0 } a ? $", адрес {Ipv4.Format(a.Addresses[0])}" : "") + ".");
        }
        else
        {
            RegisterDialFailure(tunnel, result);
        }

        await ReconcileAsync(cancellationToken);
    }

    private void RegisterDialFailure(TunnelFacts tunnel, RasDialResult result)
    {
        var info = RasErrorClassifier.Classify((int)result.ErrorCode);
        tunnel.LastErrorCategory = info.Category;
        tunnel.LastErrorCode = (int)result.ErrorCode;
        tunnel.LastErrorText = $"«{tunnel.Name}»: {RasErrorClassifier.CategoryText(info.Category)}: {result.ErrorText} (код {result.ErrorCode})";
        tunnel.FailedDialsSinceResolve++;
        if (info.Category == ErrorCategory.Certificate)
        {
            // Отказ по сертификату: смотрим, что именно предъявляет сервер, — от этого зависит и текст
            // ошибки, и то, какие адреса проверки отзыва защите нужно открыть.
            EnsureCertificateProbe(tunnel, "отказ по сертификату", force: true);
            if (RevocationRetryDue(tunnel, result))
            {
                tunnel.RevocationRetryUsed = true;
                var wait = ScheduleRetry(tunnel, _deps.Time.GetUtcNow());
                Journal("Ошибка", $"{tunnel.LastErrorText}. Адреса проверки отзыва открыты защитой, повтор через {wait.TotalSeconds:F0} с.");
                return;
            }
        }

        if (!info.Retryable)
        {
            tunnel.BlockingError = info.Category;
            Journal("Ошибка", tunnel.LastErrorText + ". Повторы остановлены до действия пользователя.");
            return;
        }

        var delay = ScheduleRetry(tunnel, _deps.Time.GetUtcNow());
        Journal("Ошибка", $"{tunnel.LastErrorText}. Повтор через {delay.TotalSeconds:F0} с.");
    }

    /// <summary>
    /// Отказ из-за недоступной проверки отзыва, а адреса этой проверки защита уже открыла: причина
    /// отказа снята, и одна попытка даётся автоматически. Дальше повторы останавливаются, как обычно.
    /// </summary>
    private static bool RevocationRetryDue(TunnelFacts tunnel, RasDialResult result) =>
        !tunnel.RevocationRetryUsed
        && tunnel.RevocationHosts.Count > 0
        && (int)result.ErrorCode == ConnectionErrorGuide.RevocationOffline;

    /// <summary>
    /// Назначает время следующего дозвона по счётчику неудачных попыток. Счётчик растёт до успешной проверки,
    /// поэтому пауза увеличивается до предела профиля (Retry.MaxDelaySeconds) и там остаётся: повторы не
    /// прекращаются, но и не занимают службу каждую секунду.
    /// </summary>
    private TimeSpan ScheduleRetry(TunnelFacts tunnel, DateTimeOffset now, TimeSpan? floor = null)
    {
        var maxDelay = TimeSpan.FromSeconds(_settings.Profile(tunnel.ProfileId)?.Retry.MaxDelaySeconds ?? 60);
        var delay = Backoff.Delay(tunnel.DialAttempt++, maxDelay, _deps.Random);
        if (floor is { } least && delay < least)
        {
            delay = least;
        }

        tunnel.NextDialAt = now + delay;
        return delay;
    }

    /// <summary>
    /// Проверка готовности. Глубоко проверяется тот туннель, которому политика отдала контрольный
    /// иностранный адрес: проба уходит с его адреса, а российская цель — с адреса основного адаптера.
    /// Остальные туннели считаются готовыми, как только RAS отдал интерфейс с адресом: отдельной
    /// цели для них нет, а их трафик виден в «Проверить адрес».
    ///
    /// Пробы идут в фоновой задаче, как и дозвон: пять секунд таймаута на цель — это пять секунд, которые
    /// очередь актора иначе простояла бы, не отвечая ни интерфейсу, ни тикам, ни помощнику AnyConnect.
    /// </summary>
    private void StartVerify(TunnelFacts tunnel)
    {
        if (tunnel.Adapter is not { Addresses.Count: > 0 } adapter || Facts.Primary is null)
        {
            return;
        }

        if (!OwnsForeignTarget(tunnel))
        {
            MarkVerified(tunnel);
            Journal("Сведения", $"«{tunnel.Name}» готов: адрес {Ipv4.Format(adapter.Addresses[0])}.");
            return;
        }

        // В фоновую задачу уходят только значения: Facts и настройки принадлежат очереди актора.
        var name = tunnel.Name;
        var profileId = tunnel.ProfileId;
        var foreignTarget = _settings.CheckTargets.Foreign;
        var russianTarget = RussianCheckNeeded() ? _settings.CheckTargets.Russian : null;
        var tunnelAddresses = adapter.Addresses;
        var primaryAddresses = Facts.Primary.Addresses;
        tunnel.Verifying = true;
        var generation = ++tunnel.VerifyGeneration;
        _ = Task.Run(async () =>
        {
            var foreign = false;
            var russianOk = true;
            try
            {
                foreign = await ProbeAsync(foreignTarget, tunnelAddresses, CancellationToken.None);
                russianOk = russianTarget is null || await ProbeAsync(russianTarget, primaryAddresses, CancellationToken.None);
            }
            catch (Exception ex)
            {
                // Сорванная проба — это непройденная проба: очередь обязана получить ответ, иначе туннель
                // навсегда останется с поднятым Verifying и перестанет проверяться.
                _deps.Logger.LogWarning(ex, "Проверка готовности «{Name}» прервана", name);
            }

            await EnqueueAsync("VerifyFinished", () => OnVerifyFinishedAsync(profileId, generation, foreign, russianOk, CancellationToken.None));
        });
    }

    /// <summary>
    /// Ответ пробы вернулся в очередь актора. Первая непройденная проба живой сеанс не рвёт: пока попытки
    /// не исчерпаны, пробуем тот же сеанс снова — сервер мог просто не успеть отпустить прежнюю сессию,
    /// и тогда новый дозвон только перезапустил бы её таймаут.
    /// </summary>
    internal async Task OnVerifyFinishedAsync(Guid profileId, int generation, bool foreign, bool russianOk, CancellationToken cancellationToken)
    {
        if (Facts.Tunnels.GetValueOrDefault(profileId) is not { } tunnel)
        {
            return;
        }

        tunnel.Verifying = false;
        if (generation != tunnel.VerifyGeneration || _state.Intent != Intent.Connected || !tunnel.IsUp || tunnel.Verified)
        {
            return;
        }

        if (foreign)
        {
            // Российская цель идёт напрямую: её недоступность туннель не чинит, разрыв только оборвал бы связь.
            // Пользователь видит это предупреждением статуса, а туннель считается проверенным.
            Facts.RussianTargetUnreachable = !russianOk;
            MarkVerified(tunnel);
            Journal("Сведения", russianOk
                ? "Проверка маршрутов пройдена: подключено."
                : $"Проверка маршрутов пройдена: подключено. Российская контрольная цель {_settings.CheckTargets.Russian} недоступна напрямую.");
        }
        else if (++tunnel.VerifyProbeFailures < VerifyProbeAttempts)
        {
            // Состояние туннеля не изменилось и ошибку пользователю показывать рано: следующую пробу
            // запустит обычный тик, когда придёт срок.
            tunnel.NextVerifyAt = _deps.Time.GetUtcNow() + VerifyProbeInterval;
            _deps.Logger.LogInformation("«{Name}»: проба {Attempt} из {Total} не прошла, сеанс сохранён, повтор через {Delay} с",
                tunnel.Name, tunnel.VerifyProbeFailures, VerifyProbeAttempts, (int)VerifyProbeInterval.TotalSeconds);
            return;
        }
        else
        {
            await RegisterVerificationFailureAsync(tunnel, cancellationToken);
        }

        await ReconcileAsync(cancellationToken);
    }

    /// <summary>Проверка пройдена: счётчики повторов и текст ошибки снимаются только здесь.</summary>
    private static void MarkVerified(TunnelFacts tunnel)
    {
        tunnel.Verified = true;
        tunnel.ResetRetries();
        tunnel.LastErrorText = null;
        tunnel.LastErrorCategory = ErrorCategory.None;
        tunnel.LastErrorCode = null;
    }

    /// <summary>
    /// В туннеле нет интернета: соединение разрывается, следующий дозвон — с растущей паузой. Текст ошибки
    /// держится до успешной проверки и называет число неудач подряд, время следующей попытки и, если детектор
    /// её нашёл, вероятную причину (чужое VPN-подключение Windows или чужие маршруты на туннеле).
    /// </summary>
    private async Task RegisterVerificationFailureAsync(TunnelFacts tunnel, CancellationToken cancellationToken)
    {
        var now = _deps.Time.GetUtcNow();
        tunnel.VerifyFailures++;
        tunnel.LastErrorCategory = ErrorCategory.NoInternetInTunnel;
        tunnel.LastErrorCode = null;
        var delay = ScheduleRetry(tunnel, now, VerifyRetryFloor);
        tunnel.LastErrorText = $"«{tunnel.Name}»: {RasErrorClassifier.VerificationText(tunnel.VerifyFailures, delay)}.{ConflictCause(tunnel, now)}";
        Journal("Ошибка", tunnel.LastErrorText);
        await HangUpAsync(tunnel, "проверка не пройдена", cancellationToken);
    }

    /// <summary>
    /// Вероятная причина неудачной проверки по детектору конфликтов. Детектор запускается сразу, но не чаще
    /// раза в 5 минут на туннель: он опрашивает RAS, таблицу маршрутов и WFP, как при обычной проверке по тику.
    /// </summary>
    private string ConflictCause(TunnelFacts tunnel, DateTimeOffset now)
    {
        if (now - tunnel.LastConflictProbeUtc >= ConflictCheckInterval)
        {
            tunnel.LastConflictProbeUtc = now;
            CheckConflicts(now, force: true);
        }

        var conflict = Facts.ConflictWarnings.FirstOrDefault(w => w.Code == "foreign-vpn")
            ?? Facts.ConflictWarnings.FirstOrDefault(w => w.Code == "foreign-routes" && w.Subject == tunnel.Name);
        return conflict switch
        {
            { Code: "foreign-vpn", Subject: { Length: > 0 } name } =>
                $" Возможная причина: активно VPN-подключение Windows «{name}» — отключите его в «Сетевых подключениях».",
            { Code: "foreign-routes" } routes => " Возможная причина: " + Uncapitalize(routes.Text),
            _ => "",
        };
    }

    private static string Uncapitalize(string text) =>
        text.Length == 0 ? text : char.ToLowerInvariant(text[0]) + text[1..];

    /// <summary>Контрольный иностранный адрес назначен именно этому туннелю.</summary>
    private bool OwnsForeignTarget(TunnelFacts tunnel)
    {
        if (!TryParseTarget(_settings.CheckTargets.Foreign, out var address, out _))
        {
            return false;
        }

        var classification = Facts.Policy?.Classify(address);
        return classification is { Decision: Decision.Vpn } vpn && vpn.Tunnel == tunnel.ProfileId;
    }

    /// <summary>Российская цель проверяется, только когда она идёт напрямую.</summary>
    private bool RussianCheckNeeded()
    {
        if (!TryParseTarget(_settings.CheckTargets.Russian, out var address, out _))
        {
            return false;
        }

        return Facts.Policy?.Classify(address).Decision == Decision.Direct;
    }

    private async Task<bool> ProbeAsync(string target, IReadOnlyList<uint> expectedLocal, CancellationToken cancellationToken)
    {
        if (!TryParseTarget(target, out var address, out var port))
        {
            return true;
        }

        var bind = expectedLocal.Count > 0 ? expectedLocal[0] : (uint?)null;
        var result = await _deps.Probes.TcpAsync(address, port, bind, ProbeTimeout, cancellationToken);
        _deps.Logger.LogInformation("Проверка {Target}: соединение {Connected}, локальный адрес {Local}, ожидались {Expected}, ошибка {Error}",
            target, result.Connected, result.LocalAddress is { } l ? Ipv4.Format(l) : null, string.Join(",", expectedLocal.Select(Ipv4.Format)), result.Error);
        return result.Connected && result.LocalAddress is { } local && expectedLocal.Contains(local);
    }

    private static bool TryParseTarget(string target, out uint address, out ushort port)
    {
        address = 0;
        port = 0;
        var parts = (target ?? "").Split(':');
        return parts.Length == 2 && Ipv4.TryParse(parts[0], out address) && ushort.TryParse(parts[1], out port);
    }
}
