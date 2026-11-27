using System.Globalization;
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
    /// Сколько после обрыва, которого сервер не видел (пропал Wi-Fi, сеть оборвалась), новый сеанс ждёт трафика, не
    /// переподключаясь. Сервер держит прежний сеанс до своей проверки связи - у pppd сервера NL это до 4 пропущенных
    /// эхо по 30 с, 2-2,5 мин, - и новому сеансу с тем же постоянным адресом трафик в это время не идёт. Разрыв и новый
    /// дозвон этот срок не сокращают (разбор 09.11.2026: три сеанса подряд молчали ~125 с от обрыва).
    /// </summary>
    internal static readonly TimeSpan ServerHoldWindow = TimeSpan.FromMinutes(3);

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
        // Wi-Fi только что подключился: новые туннели ждут, уже начатые подъёмы и поднятые туннели идут как обычно.
        var held = WifiDialHeld(now);
        for (var index = 0; index < ordered.Count; index++)
        {
            var tunnel = ordered[index];
            if (tunnel.IsUp)
            {
                if (tunnel.Protocol == VpnProtocol.Sstp && now - tunnel.LastCertificateProbeUtc >= CertificateProbeInterval) EnsureCertificateProbe(tunnel, "контроль действующего сеанса");
                if (!tunnel.Verified && !tunnel.Verifying && now >= tunnel.NextVerifyAt)
                {
                    StartVerify(tunnel);
                }

                continue;
            }

            // Положенный туннель не поднимаем ничем: AnyConnect идёт мимо CanStartDial, поэтому проверка здесь.
            if (tunnel.Paused || tunnel.ServerAddresses.Count == 0 || !PrecedingSettled(ordered, index, now))
            {
                continue;
            }

            try
            {
                StartTunnel(tunnel, held, now);
            }
            catch (Exception ex) when (!IsShutdown(ex, cancellationToken))
            {
                RegisterStartFailure(tunnel, ex);
            }
        }
    }

    /// <summary>Подъём одного туннеля без сеанса: свой путь у AnyConnect, SSH и RAS.</summary>
    private void StartTunnel(TunnelFacts tunnel, bool held, DateTimeOffset now)
    {
        if (tunnel.Protocol == VpnProtocol.AnyConnect)
        {
            if (!held || tunnel.AnyConnect is not null)
            {
                EnsureAnyConnect(tunnel);
            }

            return;
        }

        if (tunnel.Protocol == VpnProtocol.SshVpn)
        {
            if (!held)
            {
                EnsureSshTunnel(tunnel);
            }

            return;
        }

        // Свои соединения RAS на этом проходе не перечислились: сеанс записи может быть жив, а дозвон поверх него
        // дал бы второй сеанс или ошибку 756. Дозвон - на следующей сверке, остальные туннели поднимаются. Так же
        // ждёт туннель, чей сеанс с прежними параметрами входа не разорвался: его запись ещё занята. И туннель, чей
        // прежний сеанс RAS ещё отпускает после разрыва (IsReleasing): дозвон начнётся по событию его завершения.
        if (_rasConnectionsUnknown || _rasLeftoverNotHungUp.Contains(tunnel.ProfileId) || IsReleasing(tunnel.ProfileId))
        {
            // Ожидание считается зависшей попыткой: при подъёме по очереди следующие туннели (в том числе AnyConnect
            // и SSH, которым RAS не нужен) ждут его не дольше SequentialDialWait, а не до восстановления RAS.
            tunnel.DialStartedUtc ??= now;
            return;
        }

        if (!held && CanStartDial(tunnel, out var profile, out var password))
        {
            StartDial(tunnel, profile, password);
        }
    }

    /// <summary>
    /// Подъём туннеля прервался неожиданным исключением (COMException при разборе EAP XML, CryptographicException
    /// хранилища сертификатов и подобные). Сбой касается только этого туннеля: попытка считается завершённой - очередь
    /// идёт дальше, - а повтор идёт по обычной растущей паузе. Наружу сбой не уходит: иначе туннели ниже по списку не
    /// поднимались бы, пока он повторяется, а каждая сверка заново перестраивала бы защиту.
    /// </summary>
    private void RegisterStartFailure(TunnelFacts tunnel, Exception ex)
    {
        tunnel.DialSettled = true;
        tunnel.LastErrorCategory = ErrorCategory.Other;
        tunnel.LastErrorCode = null;
        tunnel.LastErrorText = $"«{tunnel.Name}»: подключение не началось: {ex.GetType().Name}: {ex.Message}";
        var delay = ScheduleRetry(tunnel, _deps.Time.GetUtcNow());
        _deps.Logger.LogError(ex, "Подъём «{Name}» прерван неожиданной ошибкой", tunnel.Name);
        Journal("Ошибка", $"{tunnel.LastErrorText}. Повтор через {delay.TotalSeconds:F0} с.");
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
            // Отключён через меню сети Windows: служба сама его не поднимает, и ждать его нечего.
            || t.ExternallyDisconnected
            // Ждёт человека — пароля или входа в шлюз. Очередь ждать его не должна: это может быть минутами.
            || t.PasswordRequired || t.SignIn is not null
            || (t.ServerAddresses.Count == 0 && ((!t.ServerResolving && t.NextServerResolveAt != default)
                || (t.ServerResolveStartedUtc is { } resolving && now - resolving >= SequentialDialWait)))
            || (t.DialStartedUtc is { } started && now - started >= SequentialDialWait)
            // Помощник AnyConnect, зависший до входа или подъёма туннеля, держит очередь не дольше того же срока.
            || (t.AnyConnect is { Established: false } && t.AnyConnectStartedUtc is { } helperStarted && now - helperStarted >= SequentialDialWait));

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

        if (VpnProtocols.NeedsPreSharedKey(active) && !_deps.Secrets.IsStored(active.Id, SecretKind.PreSharedKey))
        {
            Block(tunnel, ErrorCategory.Authentication, "требуется ключ IPsec - откройте «Подключения» и сохраните его");
            return false;
        }
        var loaded = LoadPassword(active);
        if (loaded is null && active.SavePassword && _deps.Secrets.IsStored(active.Id))
        {
            var seen = _deps.Time.GetTimestamp();
            // Срок считается от первого сбоя серии. Прежняя отметка старше срока - след прерванной серии (туннель
            // отключали, VPN выключали): разовый сбой через часы начинает новый счёт, а не сразу просит пароль.
            var first = _passwordUnreadable.TryGetValue(active.Id, out var mark) && _deps.Time.GetElapsedTime(mark.Last, seen) < UnreadablePasswordGrace
                ? mark.First
                : seen;
            _passwordUnreadable[active.Id] = new UnreadableSighting(first, seen);
            if (_deps.Time.GetElapsedTime(first, seen) < UnreadablePasswordGrace)
            {
                // Пароль сохранён, но сейчас не расшифровывается (DPAPI ещё не готов при загрузке Windows): это не
                // «нужен пароль», ждать ввода от пользователя нельзя - повтор по своей паузе, как с ключом IPsec.
                tunnel.PasswordRequired = false;
                tunnel.LastErrorCode = null;
                tunnel.LastErrorCategory = ErrorCategory.Other;
                tunnel.LastErrorText = $"«{tunnel.Name}»: сохранённый пароль сейчас не читается, повтор позже.";
                tunnel.DialSettled = true;
                var nowUtc = _deps.Time.GetUtcNow();
                // Пауза короче срока: иначе отметка успевала бы устареть до повтора, и счёт начинался бы заново без конца.
                if (ScheduleRetry(tunnel, nowUtc) > UnreadablePasswordRetryLimit)
                {
                    tunnel.NextDialAt = nowUtc + UnreadablePasswordRetryLimit;
                }

                return false;
            }

            // Пароль не читается дольше срока: сбой не временный (значение не удалось отложить, постоянный код DPAPI).
            // Повторять дальше бессмысленно - пользователь вводит пароль заново, как будто его нет.
            if (!tunnel.PasswordRequired)
            {
                tunnel.LastErrorText = $"«{tunnel.Name}»: сохранённый пароль не читается - введите его заново.";
                Journal("Ошибка", tunnel.LastErrorText);
            }
        }
        else
        {
            _passwordUnreadable.Remove(active.Id);
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

    /// <summary>
    /// Сколько сохранённый, но нечитаемый пароль ждёт расшифровки повторами. Дольше - сбой не временный, и туннель
    /// просит пароль: иначе он повторял бы «пароль сейчас не читается» вечно, а ввести пароль было негде.
    /// </summary>
    internal static readonly TimeSpan UnreadablePasswordGrace = TimeSpan.FromMinutes(2);

    /// <summary>Наибольшая пауза между попытками прочитать пароль в пределах срока: заметно короче срока.</summary>
    private static readonly TimeSpan UnreadablePasswordRetryLimit = UnreadablePasswordGrace / 2;

    /// <summary>Профиль - когда его сохранённый пароль не прочитался впервые в текущей серии и когда в последний раз.</summary>
    private readonly Dictionary<Guid, UnreadableSighting> _passwordUnreadable = [];

    /// <summary>То же для сохранённых ключей (IPsec, SSH): профиль и вид ключа - первый и последний сбой чтения серии.</summary>
    private readonly Dictionary<(Guid ProfileId, SecretKind Kind), UnreadableSighting> _keyUnreadable = [];

    /// <summary>
    /// Сохранённый ключ сейчас не прочитался (DPAPI, LSA или RPC ещё не готовы при загрузке Windows): попытка завершена,
    /// повтор - по своей паузе, но не реже <see cref="UnreadablePasswordRetryLimit"/>, чтобы серия сбоев не прерывалась.
    /// Ключ не читается дольше <see cref="UnreadablePasswordGrace"/> - сбой не временный, и текст ошибки говорит, что
    /// ключ нужно сохранить заново. Повторы при этом не прекращаются, в отличие от пароля: ввести ключ на главной
    /// негде, а остановленный туннель за kill switch оставался бы без связи, даже если чтение потом наладится.
    /// </summary>
    private void RegisterUnreadableKey(TunnelFacts tunnel, SecretKind kind, string what, string action)
    {
        var seen = _deps.Time.GetTimestamp();
        // Отметки удалённых профилей не копятся.
        foreach (var gone in _keyUnreadable.Keys.Where(k => !Facts.Tunnels.ContainsKey(k.ProfileId)).ToList())
        {
            _keyUnreadable.Remove(gone);
        }

        var id = (tunnel.ProfileId, kind);
        var first = _keyUnreadable.TryGetValue(id, out var mark) && _deps.Time.GetElapsedTime(mark.Last, seen) < UnreadablePasswordGrace
            ? mark.First
            : seen;
        _keyUnreadable[id] = new UnreadableSighting(first, seen);
        tunnel.LastErrorCode = null;
        tunnel.LastErrorCategory = ErrorCategory.Other;
        tunnel.DialSettled = true;
        var nowUtc = _deps.Time.GetUtcNow();
        if (ScheduleRetry(tunnel, nowUtc) > UnreadablePasswordRetryLimit)
        {
            tunnel.NextDialAt = nowUtc + UnreadablePasswordRetryLimit;
        }

        if (_deps.Time.GetElapsedTime(first, seen) < UnreadablePasswordGrace)
        {
            tunnel.LastErrorText = $"«{tunnel.Name}»: сохранённый {what} сейчас не читается, повтор позже.";
            return;
        }

        var text = $"«{tunnel.Name}»: сохранённый {what} не читается дольше {UnreadablePasswordGrace.TotalMinutes:F0} мин - откройте «Подключения» и {action}. Повторы продолжаются.";
        if (tunnel.LastErrorText != text)
        {
            Journal("Ошибка", text);
        }

        tunnel.LastErrorText = text;
    }


    private char[]? LoadPassword(ConnectionProfile profile)
    {
        if (!VpnProtocols.NeedsPassword(profile.AuthMethod)) { return []; }
        if (Facts.MemoryPasswords.TryGetValue(profile.Id, out var memory))
        {
            return memory.ToArray();
        }

        return profile.SavePassword ? _deps.Secrets.TryLoad(profile.Id) : null;
    }

    /// <summary>
    /// Дозвон RAS. Неожиданное исключение до запуска задачи дозвона (чтение ключа IPsec, проба сертификата, журнал)
    /// затирает пароль и снимает <see cref="TunnelFacts.Dialing"/>: иначе пароль оставался бы в памяти, а туннель
    /// навсегда числился бы «в дозвоне» без задачи, которая этот признак сняла бы. Сбой уходит в <see cref="RegisterStartFailure"/>.
    /// </summary>
    private void StartDial(TunnelFacts tunnel, ConnectionProfile profile, char[] password)
    {
        try
        {
            StartDialCore(tunnel, profile, password);
        }
        catch
        {
            // Запуск задачи дозвона - последний шаг StartDialCore: исключение значит, что задачи нет и пароль ей не передан.
            Array.Clear(password);
            tunnel.Dialing = false;
            throw;
        }
    }

    private void StartDialCore(TunnelFacts tunnel, ConnectionProfile profile, char[] password)
    {
        var key = VpnProtocols.NeedsPreSharedKey(profile) ? _deps.Secrets.TryLoad(profile.Id, SecretKind.PreSharedKey) : null;
        if (VpnProtocols.NeedsPreSharedKey(profile) && key is null)
        {
            Array.Clear(password);
            tunnel.LastErrorCode = null;
            if (_deps.Secrets.IsStored(profile.Id, SecretKind.PreSharedKey))
            {
                // Ключ сохранён, но сейчас не расшифровывается (LSA или RPC ещё не готовы при загрузке Windows):
                // это не «ключа нет», и блокировать подключение до действия пользователя нельзя.
                // Попытка завершилась, не начавшись: при подъёме по очереди следующие туннели её не ждут,
                // а этот повторяет по своей паузе.
                RegisterUnreadableKey(tunnel, SecretKind.PreSharedKey, "ключ IPsec", "сохраните его заново");
                return;
            }

            tunnel.BlockingError = ErrorCategory.Authentication;
            tunnel.LastErrorCategory = ErrorCategory.Authentication;
            tunnel.LastErrorText = $"«{tunnel.Name}»: требуется ключ IPsec — откройте «Подключения» и сохраните его.";
            return;
        }

        _keyUnreadable.Remove((profile.Id, SecretKind.PreSharedKey));
        tunnel.SessionServerAddresses = tunnel.ServerAddresses.ToArray();
        // DNS прежнего сеанса к новому не относится: сервер мог смениться или перестать выдавать DNS.
        tunnel.VpnDns = [];
        try
        {
            PrepareEntry(tunnel, profile, key);
        }
        catch (Exception ex) when (IsTransientPrepareError(ex))
        {
            // Телефонная книга занята или временно недоступна: это не ошибка настроек, повтор по обычной паузе.
            // Попытка завершилась: при подъёме по очереди следующий туннель её не ждёт.
            Array.Clear(password);
            tunnel.DialSettled = true;
            tunnel.LastErrorCategory = ErrorCategory.Other;
            tunnel.LastErrorCode = ex is Windows.Native.NativeCallException native ? unchecked((int)native.Code) : null;
            tunnel.LastErrorText = $"«{tunnel.Name}»: не удалось подготовить запись подключения: {ex.Message}";
            var delay = ScheduleRetry(tunnel, _deps.Time.GetUtcNow());
            Journal("Ошибка", $"{tunnel.LastErrorText}. Повтор через {delay.TotalSeconds:F0} с.");
            return;
        }
        catch (Exception ex) when (ex is InvalidOperationException or Windows.Native.NativeCallException)
        {
            Array.Clear(password);
            // Сертификат компьютера для IPsec (L2TP) - тоже сертификат: подсказка про пароль здесь ни при чём.
            tunnel.BlockingError = VpnProtocols.NeedsServerValidation(profile.AuthMethod) || profile.AuthMethod == AuthMethod.MachineCertificate
                || (profile.Protocol == VpnProtocol.L2tpIpsec && profile.IpsecAuthentication == IpsecAuthentication.MachineCertificate)
                ? ErrorCategory.Certificate
                : ErrorCategory.Authentication;
            // Код прошлой ошибки дозвона здесь не относится: подсказка строилась бы по нему.
            tunnel.LastErrorCategory = tunnel.BlockingError;
            tunnel.LastErrorCode = null;
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
        var generation = tunnel.DialGeneration = ++_attemptGeneration;
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
    /// Коды временных сбоев подготовки записи: 621-624 - телефонная книга не открывается, не загружается, запись
    /// не находится или не пишется; 5, 32, 33 - файл недоступен, занят или заблокирован другим процессом
    /// (антивирус, служба RAS); 8, 14, 1450 - не хватает памяти или системных ресурсов. Служба RAS недоступна или
    /// перезапускается (<see cref="Windows.Ras.RasClient.RasUnavailable"/>, <see cref="Windows.Ras.RasClient.RpcUnavailable"/>) —
    /// тоже временно.
    /// </summary>
    private static readonly HashSet<uint> TransientPrepareCodes = [5, 8, 14, 32, 33, 621, 622, 623, 624, 1450];

    /// <summary>
    /// Сбой подготовки записи проходит сам: это не ошибка сертификата или входа, и останавливать повторы до
    /// действия пользователя нельзя - за kill switch он остался бы без связи.
    /// </summary>
    internal static bool IsTransientPrepareError(Exception ex) => ex switch
    {
        IOException or UnauthorizedAccessException => true,
        Windows.Native.NativeCallException native => TransientPrepareCodes.Contains(native.Code)
            || Windows.Ras.RasClient.RasUnavailable(native.Code) || Windows.Ras.RasClient.RpcUnavailable(native.Code),
        _ => false,
    };

    /// <summary>
    /// Готовит запись телефонной книги под текущий профиль и запоминает отпечаток параметров входа:
    /// по нему при следующем запуске службы решается, можно ли подхватить живое соединение.
    /// </summary>
    private void PrepareEntry(TunnelFacts tunnel, ConnectionProfile profile, char[]? key = null)
    {
        key ??= VpnProtocols.NeedsPreSharedKey(profile) ? _deps.Secrets.TryLoad(profile.Id, SecretKind.PreSharedKey) : null;
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

        if (generation != tunnel.DialGeneration)
        {
            if (result.Handle is { } stale)
            {
                tunnel.LastOwnHangUpUtc = _deps.Time.GetUtcNow();
                await HangUpConnectionAsync(stale, new PendingRelease(tunnel.ProfileId, tunnel.EntryName, tunnel.Name, Tracked: false), cancellationToken);
            }

            return;
        }

        tunnel.Dialing = false;
        // Попытка завершилась — очередь отпускает следующий туннель независимо от того, чем она кончилась.
        tunnel.DialSettled = true;
        // Туннель положили, пока шёл дозвон: соединение разрывается, а не присоединяется.
        if (_state.Intent != Intent.Connected || tunnel.Paused)
        {
            if (result.Handle is { } stale)
            {
                tunnel.LastOwnHangUpUtc = _deps.Time.GetUtcNow();
                await HangUpConnectionAsync(stale, new PendingRelease(tunnel.ProfileId, tunnel.EntryName, tunnel.Name, Tracked: false), cancellationToken);
            }

            // «Отключить» посреди дозвона: снятие защиты оставило записи телефонной книги (с ключами IPsec), пока шёл
            // дозвон. Теперь он закончен - повтор снятия (оно идемпотентно) удаляет их, не дожидаясь периодической сверки.
            if (_state.Intent == Intent.Off)
            {
                await ReconcileAsync(cancellationToken);
            }

            return;
        }

        if (result.Success && result.Handle is { } handle)
        {
            // Счётчик попыток и текст ошибки снимает только успешная проверка: дозвон, после которого в туннеле
            // нет интернета, возвращал бы паузу к секунде — это и есть цикл переподключений.
            if (TryAttachTunnel(tunnel, handle) is { } failure)
            {
                await RegisterDeadOnArrivalAsync(tunnel, handle, failure, cancellationToken);
            }
            else
            {
                Journal("Сведения", $"«{tunnel.Name}» подключён" + (tunnel.Adapter is { Addresses.Count: > 0 } a ? $", адрес {Ipv4.Format(a.Addresses[0])}" : "") + ".");
            }
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

        if (result.ErrorCode == LcpTerminatedCode && tunnel.LcpTerminatedRetries < LcpTerminatedAutoRetries)
        {
            // 734 бывает и при обрыве ненадёжного канала: один такой обрыв не должен оставлять пользователя
            // без сети до нажатия «Подключить».
            tunnel.LcpTerminatedRetries++;
            var wait = ScheduleRetry(tunnel, _deps.Time.GetUtcNow());
            Journal("Ошибка", $"{tunnel.LastErrorText}. Повтор {tunnel.LcpTerminatedRetries} из {LcpTerminatedAutoRetries} через {wait.TotalSeconds:F0} с.");
            return;
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
    /// Дозвон прошёл, но сеанс не присоединился ни с одной попытки: обычно он умер, пока результат ждал очереди
    /// актора, и сведения о нём не читаются. Остаток соединения отпускается, а попытка считается неудачной и идёт по
    /// обычной растущей паузе - иначе сервер, рвущий сеансы сразу после подъёма, получал бы новый дозвон на каждом
    /// тике. Адрес сервера при этом рабочий: счётчик для повторного разрешения имени не растёт.
    /// </summary>
    private async Task RegisterDeadOnArrivalAsync(TunnelFacts tunnel, RasConnectionHandle handle, Windows.Native.NativeCallException ex, CancellationToken cancellationToken)
    {
        if (tunnel.Connection == handle)
        {
            // Сбой после присоединения: модель не должна держать мёртвое соединение.
            tunnel.Connection = null;
            tunnel.Adapter = null;
            tunnel.SessionStartedUtc = null;
        }

        await ReleaseDeadConnectionAsync(tunnel, handle, cancellationToken);
        tunnel.LastErrorCategory = ErrorCategory.Other;
        tunnel.LastErrorCode = unchecked((int)ex.Code);
        tunnel.LastErrorText = $"«{tunnel.Name}»: соединение разорвано сразу после подключения: {ex.Message}";
        var delay = ScheduleRetry(tunnel, _deps.Time.GetUtcNow());
        Journal("Ошибка", $"{tunnel.LastErrorText}. Повтор через {delay.TotalSeconds:F0} с.");
    }

    /// <summary>
    /// Сколько раз подряд пробуется присоединить сеанс. Снимок сети, прочитанный во время смены интерфейсов сразу
    /// после дозвона, может не прочитаться (GetIfTable2 и подобные), а следующее чтение обычно проходит: живой сеанс
    /// не должен разрываться из-за одного неудачного чтения.
    /// </summary>
    internal const int AttachAttempts = 3;

    /// <summary>
    /// Присоединяет сеанс, повторяя попытку сразу, без паузы. Повтор безопасен: AttachTunnel ничего не меняет до
    /// вызовов, которые могут не пройти (сведения о сеансе и снимок сети). Возвращает сбой последней попытки, если
    /// не удалась ни одна, иначе null.
    /// </summary>
    private Windows.Native.NativeCallException? TryAttachTunnel(TunnelFacts tunnel, RasConnectionHandle handle)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                AttachTunnel(tunnel, handle);
                return null;
            }
            catch (Windows.Native.NativeCallException ex) when (attempt < AttachAttempts)
            {
                _deps.Logger.LogWarning(ex, "Сеанс {Name} не присоединён (попытка {Attempt} из {Attempts}): повтор", tunnel.Name, attempt, AttachAttempts);
            }
            catch (Windows.Native.NativeCallException ex)
            {
                return ex;
            }
        }
    }

    /// <summary>
    /// Отказ из-за недоступной проверки отзыва, а адреса этой проверки защита уже открыла: причина
    /// отказа снята, и одна попытка даётся автоматически. Дальше повторы останавливаются, как обычно.
    /// </summary>
    private static bool RevocationRetryDue(TunnelFacts tunnel, RasDialResult result) =>
        !tunnel.RevocationRetryUsed
        && tunnel.RevocationHosts.Count > 0
        && ConnectionErrorGuide.IsRevocationCheckFailure((int)result.ErrorCode);

    /// <summary>ERROR_PPP_LCP_TERMINATED: согласование PPP (LCP) прервано.</summary>
    internal const uint LcpTerminatedCode = 734;

    /// <summary>Сколько повторов даётся после отказа 734, прежде чем он считается отказом входа.</summary>
    internal const int LcpTerminatedAutoRetries = 2;

    private const int MinRetryDelaySeconds = 5;
    private const int MaxRetryDelaySeconds = 3600;

    /// <summary>
    /// Назначает время следующего дозвона по счётчику неудачных попыток. Счётчик растёт до успешной проверки,
    /// поэтому пауза увеличивается до предела профиля (Retry.MaxDelaySeconds) и там остаётся: повторы не
    /// прекращаются, но и не занимают службу каждую секунду. Предел из файла настроек ограничен 5 с - 1 ч:
    /// ноль дозванивался бы дважды в секунду (блокировка учётной записи на сервере), огромное значение
    /// фактически прекращало бы повторы.
    /// </summary>
    private TimeSpan ScheduleRetry(TunnelFacts tunnel, DateTimeOffset now, TimeSpan? floor = null)
    {
        var maxDelay = TimeSpan.FromSeconds(Math.Clamp(_settings.Profile(tunnel.ProfileId)?.Retry.MaxDelaySeconds ?? 60, MinRetryDelaySeconds, MaxRetryDelaySeconds));
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
        // Сеанс, ждущий повтора разрыва, уже не прошёл проверку: новая проба засчитала бы ту же неудачу снова.
        if (tunnel.Adapter is not { IsUp: true, Addresses.Count: > 0 } adapter || Facts.Primary is null || tunnel.HangUpPending)
        {
            return;
        }

        // «VPN поверх SSH» проверяется своим способом и всегда: до ветки «нет контрольных целей», иначе туннель
        // с мёртвым соединением SSH засчитался бы готовым без пробы.
        if (tunnel.Protocol == VpnProtocol.SshVpn)
        {
            StartSshVerify(tunnel);
            return;
        }

        // В фоновую задачу уходят только значения: Facts и настройки принадлежат очереди актора.
        var foreignTargets = ForeignTargetsOf(tunnel);
        if (foreignTargets.Count == 0 && _settings.DefaultTarget.IsGroup(out var groupId)
            && _settings.Group(groupId) is { Mode: BalanceMode.Failover } group && group.Members.Contains(tunnel.ProfileId)
            && !string.IsNullOrWhiteSpace(_settings.CheckTargets.Foreign))
        {
            // Групповые маршруты ещё на другом участнике. Для пробы годится только DNS, для которого
            // политика выбрала этот туннель или Windows уже установила маршрут /32 через его адаптер.
            foreignTargets.AddRange(tunnel.VpnDns.Where(address =>
                Facts.Policy?.Classify(address) is { Decision: Decision.Vpn } vpn && vpn.Tunnel == tunnel.ProfileId
                || _snapshot?.RoutesV4.Any(r => r.InterfaceLuid == adapter.Luid && r.Destination == new Ipv4Cidr(address, 32)) == true)
                .Select(address => new CheckTarget(address, 53)));
        }
        if (foreignTargets.Count == 0)
        {
            MarkVerified(tunnel);
            Journal("Сведения", $"«{tunnel.Name}» готов: адрес {Ipv4.Format(adapter.Addresses[0])}.");
            return;
        }

        var name = tunnel.Name;
        var profileId = tunnel.ProfileId;
        var russianTargets = DirectRussianTargets();
        tunnel.VerificationCancellation?.Dispose();
        tunnel.VerificationCancellation = new CancellationTokenSource();
        var probeToken = tunnel.VerificationCancellation.Token;
        var tunnelAddresses = adapter.Addresses;
        var primaryAddresses = Facts.Primary.Addresses;
        tunnel.Verifying = true;
        var generation = tunnel.VerifyGeneration = ++_attemptGeneration;
        _ = Task.Run(async () =>
        {
            var foreign = false;
            var russianOk = true;
            try
            {
                foreign = await ProbeAsync(foreignTargets, tunnelAddresses, probeToken);
                russianOk = russianTargets.Count == 0 || await ProbeAsync(russianTargets, primaryAddresses, probeToken);
            }
            catch (OperationCanceledException) when (probeToken.IsCancellationRequested) { return; }
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
    /// <param name="russianOk">Ответила ли российская контрольная цель напрямую; null - проба её не проверяла (туннель SSH),
    /// и предупреждение, выставленное пробой другого туннеля, остаётся как есть.</param>
    internal async Task OnVerifyFinishedAsync(Guid profileId, int generation, bool foreign, bool? russianOk, CancellationToken cancellationToken)
    {
        if (Facts.Tunnels.GetValueOrDefault(profileId) is not { } tunnel || generation != tunnel.VerifyGeneration)
        {
            return;
        }

        tunnel.Verifying = false;
        if (_state.Intent != Intent.Connected || !tunnel.IsUp || tunnel.Verified || tunnel.HangUpPending)
        {
            return;
        }

        if (foreign)
        {
            // Российская цель идёт напрямую: её недоступность туннель не чинит, разрыв только оборвал бы связь.
            // Пользователь видит это предупреждением статуса, а туннель считается проверенным.
            if (russianOk is { } checkedRussian)
            {
                Facts.RussianTargetUnreachable = !checkedRussian;
                _russianTargetCheckedBy = tunnel.ProfileId;
            }

            MarkVerified(tunnel);
            Journal("Сведения", russianOk != false
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
        else if (!HangUpOpensFallback(tunnel) && ServerHoldLeft(tunnel) is { } left)
        {
            // Пробы исчерпаны, но после обрыва сервер, вероятно, ещё держит прежний сеанс: новый дозвон получил бы тот же
            // отказ, а разрыв лишь добавил бы сеансов на сервере. Тот же сеанс пробуется дальше, пока не выйдет срок.
            tunnel.NextVerifyAt = _deps.Time.GetUtcNow() + VerifyProbeInterval;
            if (tunnel.VerifyProbeFailures == VerifyProbeAttempts)
            {
                Journal("Сведения", string.Create(CultureInfo.InvariantCulture,
                    $"«{tunnel.Name}»: трафик через туннель пока не идёт. После обрыва сервер, вероятно, ещё держит прежний сеанс: ждём до {left.TotalSeconds:F0} с, не переподключаясь."));
            }
            else
            {
                _deps.Logger.LogInformation("«{Name}»: проба {Attempt} не прошла, сервер, вероятно, держит прежний сеанс (ещё до {Left} с), сеанс сохранён",
                    tunnel.Name, tunnel.VerifyProbeFailures, (int)left.TotalSeconds);
            }

            return;
        }
        else
        {
            await RegisterVerificationFailureAsync(tunnel, cancellationToken);
        }

        await ReconcileAsync(cancellationToken);
    }

    /// <summary>Туннель, чья проба последней проверила российскую цель (<see cref="CoordinatorFacts.RussianTargetUnreachable"/>).</summary>
    private Guid? _russianTargetCheckedBy;

    /// <summary>
    /// Предупреждение о российской цели держится, пока жив проверенный сеанс туннеля, чья проба его выставила. Туннель
    /// разорван, положен, выключен или удалён, VPN отключён - снимается: иначе после такого туннеля (например, когда
    /// остался только SSH, который российскую цель не проверяет) оно висело бы до перезапуска службы. Новый сеанс
    /// выставит его заново своей пробой.
    /// </summary>
    private void ClearStaleRussianTargetWarning()
    {
        if (!Facts.RussianTargetUnreachable)
        {
            return;
        }

        if (_state.Intent != Intent.Connected || _russianTargetCheckedBy is not { } id
            || Facts.Tunnels.GetValueOrDefault(id) is not { Verified: true })
        {
            Facts.RussianTargetUnreachable = false;
            _russianTargetCheckedBy = null;
        }
    }

    /// <summary>
    /// Сколько ещё сервер может держать сеанс, оборванный без разрыва с нашей стороны; null - такого обрыва не было
    /// или срок <see cref="ServerHoldWindow"/> вышел.
    /// </summary>
    private TimeSpan? ServerHoldLeft(TunnelFacts tunnel)
    {
        if (tunnel.UncleanDropUtc is not { } dropped)
        {
            return null;
        }

        var left = dropped + ServerHoldWindow - _deps.Time.GetUtcNow();
        return left > TimeSpan.Zero ? left : null;
    }

    /// <summary>
    /// Разрыв молчащего сеанса даст его трафику другой путь: в группе поднят другой участник (резерв или
    /// распределение) либо при обрыве «остального интернета» настройка разрешает весь трафик напрямую. Тогда ждать
    /// сервер на молчащем сеансе нельзя: пока туннель числится поднятым, ни резерв, ни режим обрыва не включаются.
    /// </summary>
    private bool HangUpOpensFallback(TunnelFacts tunnel)
    {
        bool OtherUp(IEnumerable<Guid> members) =>
            members.Any(id => id != tunnel.ProfileId && Facts.Tunnels.GetValueOrDefault(id)?.Luid is not null);

        var usedGroups = _settings.DomainRules.Select(r => r.Target)
            .Concat(_settings.Rules.Select(r => r.Target))
            .Concat(GatewayNetworks().Where(n => n.Cidrs.Count > 0).Select(n => n.Target))
            .Append(_settings.DefaultTarget)
            .Append(_geo.HasBase ? _settings.GeoTarget : _settings.DefaultTarget)
            .Append(BypassTarget)
            .Where(t => t.Kind == TargetKind.Group).Select(t => t.Id).ToHashSet();
        if (_settings.Groups.Any(group => usedGroups.Contains(group.Id)
            && group.Members.Contains(tunnel.ProfileId) && OtherUp(group.Members)))
        {
            return true;
        }

        var carriers = DefaultCarriers;
        return _settings.OutageMode == OutageMode.AllowAll && carriers.Contains(tunnel.ProfileId) && !OtherUp(carriers);
    }

    /// <summary>Проверка пройдена: счётчики повторов и текст ошибки снимаются только здесь.</summary>
    private static void MarkVerified(TunnelFacts tunnel)
    {
        tunnel.Verified = true;
        tunnel.EverConnected = true;
        tunnel.UncleanDropUtc = null;
        tunnel.VerifyFailures = 0;
        // Повтор после открытия адресов проверки отзыва даётся заново: следующий обрыв через несколько дней
        // может снова упереться в недоступную проверку отзыва, и без повтора туннель стоял бы до вмешательства.
        tunnel.RevocationRetryUsed = false;
        tunnel.LcpTerminatedRetries = 0;
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
        if (tunnel.Ssh is not null)
        {
            tunnel.FailedDialsSinceResolve++;
        }

        tunnel.VerifyFailures++;
        tunnel.LastErrorCategory = ErrorCategory.NoInternetInTunnel;
        tunnel.LastErrorCode = null;
        var delay = ScheduleRetry(tunnel, now, VerifyRetryFloor);
        tunnel.LastErrorText = $"«{tunnel.Name}»: {RasErrorClassifier.VerificationText(tunnel.VerifyFailures, delay)}.{ConflictCause(tunnel, now)}";
        Journal("Ошибка", tunnel.LastErrorText);
        // Неудача засчитана здесь один раз: отказ RasHangUp не должен вести к новой пробе и новому счёту на
        // каждой сверке - разрыв повторит сверка, а DialAttempt и VerifyFailures больше не растут.
        await HangUpOrDeferAsync(tunnel, "проверка не пройдена", cancellationToken);
    }

    /// <summary>
    /// Вероятная причина неудачной проверки по детектору конфликтов. Детектор запускается сразу, но не чаще
    /// раза в 5 минут на туннель: он опрашивает RAS, таблицу маршрутов и WFP, как при обычной проверке по тику.
    /// Детектор работает в фоне: здесь причина — по прошлому результату, а свежий результат допишет её
    /// к тексту ошибки (<see cref="AppendConflictCauses"/>).
    /// </summary>
    private string ConflictCause(TunnelFacts tunnel, DateTimeOffset now)
    {
        if (now - tunnel.LastConflictProbeUtc >= ConflictCheckInterval)
        {
            tunnel.LastConflictProbeUtc = now;
            CheckConflicts(now, force: true);
        }

        return ConflictCauseText(tunnel);
    }

    /// <summary>Свежий результат детектора: туннелям с непройденной проверкой без названной причины она дописывается.</summary>
    private void AppendConflictCauses()
    {
        foreach (var tunnel in Facts.Tunnels.Values.Where(t => t.LastErrorCategory == ErrorCategory.NoInternetInTunnel
            && t.LastErrorText is { } text && !text.Contains("Возможная причина", StringComparison.Ordinal)))
        {
            if (ConflictCauseText(tunnel) is { Length: > 0 } cause)
            {
                tunnel.LastErrorText += cause;
            }
        }
    }

    private string ConflictCauseText(TunnelFacts tunnel)
    {
        // Подключение Windows к серверу этого же туннеля - самая вероятная причина; остальные чужие - общая.
        var conflict = Facts.ConflictWarnings.FirstOrDefault(w => w.Code == "foreign-vpn" && w.SameServerProfileId == tunnel.ProfileId)
            ?? Facts.ConflictWarnings.FirstOrDefault(w => w.Code == "foreign-vpn")
            ?? Facts.ConflictWarnings.FirstOrDefault(w => w.Code == "foreign-routes" && w.Subject == tunnel.Name);
        return conflict switch
        {
            { Code: "foreign-vpn", Subject: { Length: > 0 } name, SameServerProfileId: { } same } when same == tunnel.ProfileId =>
                $" Возможная причина: VPN-подключение Windows «{name}» идёт к тому же серверу — отключите его и его автоматическое подключение в «Сетевых подключениях».",
            { Code: "foreign-vpn", Subject: { Length: > 0 } name } =>
                $" Возможная причина: активно VPN-подключение Windows «{name}» — отключите его в «Сетевых подключениях».",
            { Code: "foreign-routes" } routes => " Возможная причина: " + Uncapitalize(routes.Text),
            _ => "",
        };
    }

    private static string Uncapitalize(string text) =>
        text.Length == 0 ? text : char.ToLowerInvariant(text[0]) + text[1..];

    /// <summary>
    /// Контрольные иностранные цели, которые политика отдала этому туннелю. Пусто - туннель глубоко не
    /// проверяется. Цели другого туннеля или прямого выхода в пробу не берутся: с адреса этого туннеля они не
    /// ответили бы, и проба рвала бы рабочий туннель.
    /// </summary>
    private List<CheckTarget> ForeignTargetsOf(TunnelFacts tunnel) =>
        ParseTargets(_settings.CheckTargets.Foreign, ReportSkippedTargets)
            .Where(target => Facts.Policy?.Classify(target.Address) is { Decision: Decision.Vpn } vpn && vpn.Tunnel == tunnel.ProfileId)
            .ToList();

    /// <summary>Российские цели проверяются, только когда они идут напрямую.</summary>
    private List<CheckTarget> DirectRussianTargets() =>
        ParseTargets(_settings.CheckTargets.Russian, ReportSkippedTargets)
            .Where(target => Facts.Policy?.Classify(target.Address).Decision == Decision.Direct)
            .ToList();

    /// <summary>Что показала проба одной цели через ожидаемый адрес.</summary>
    private enum ProbeVerdict
    {
        /// <summary>Таймаут, недоступность или ответ не через ожидаемый адрес.</summary>
        Failed,

        /// <summary>Удалённая сторона ответила сбросом (RST) на ожидаемый адрес.</summary>
        Refused,

        /// <summary>Соединение установлено с ожидаемого адреса.</summary>
        Connected,
    }

    /// <summary>
    /// Путь работает, если хоть одна цель соединилась или ответила сбросом: ответ прошёл туннель туда и обратно.
    /// Сервер VPN может отклонять саму контрольную цель (запрет DoH к 1.1.1.1:443), и разрыв живого туннеля по кругу
    /// оставил бы без связи. Сброс даёт и сервер, потерявший выход в интернет, - тогда другая цель молчит; но молчать
    /// может и цель, которую сервер просто не выпускает (порт 80 только через прокси). Разрыв этого не исправил бы,
    /// поэтому такой туннель считается рабочим, а в журнал службы пишется предупреждение. Цели проверяются одновременно.
    /// </summary>
    private async Task<bool> ProbeAsync(IReadOnlyList<CheckTarget> targets, IReadOnlyList<uint> expectedLocal, CancellationToken cancellationToken)
    {
        var bind = expectedLocal.Count > 0 ? expectedLocal[0] : (uint?)null;
        using var done = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var pending = targets.ToDictionary(target => ProbeOneAsync(target, bind, expectedLocal, done.Token), target => target);
        var refused = new List<CheckTarget>();
        var silent = new List<CheckTarget>();
        try
        {
            while (pending.Count > 0)
            {
                var finished = await Task.WhenAny(pending.Keys);
                var target = pending[finished];
                pending.Remove(finished);
                switch (await finished)
                {
                    case ProbeVerdict.Connected:
                        return true;
                    case ProbeVerdict.Refused:
                        refused.Add(target);
                        break;
                    default:
                        silent.Add(target);
                        break;
                }
            }
        }
        finally
        {
            // Ответ уже есть: остальные пробы не нужны, их сокеты закрываются.
            await done.CancelAsync();
        }

        if (refused.Count > 0 && silent.Count > 0)
        {
            _deps.Logger.LogWarning("Проверка: {Refused} ответили сбросом, {Silent} не ответили - возможно, у сервера VPN нет выхода в интернет",
                string.Join(", ", refused), string.Join(", ", silent));
        }

        return refused.Count > 0;
    }

    private async Task<ProbeVerdict> ProbeOneAsync(CheckTarget target, uint? bind, IReadOnlyList<uint> expectedLocal, CancellationToken cancellationToken)
    {
        TcpProbeResult result;
        try
        {
            result = await _deps.Probes.TcpAsync(target.Address, target.Port, bind, ProbeTimeout, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return ProbeVerdict.Failed;
        }

        _deps.Logger.LogInformation("Проверка {Target}: соединение {Connected}, отказ удалённой стороны {Refused}, локальный адрес {Local}, ожидались {Expected}, ошибка {Error}",
            target, result.Connected, result.Refused, result.LocalAddress is { } l ? Ipv4.Format(l) : null, string.Join(",", expectedLocal.Select(Ipv4.Format)), result.Error);

        // Ответ засчитывается, только если он вернулся на адрес, с которого шла проба.
        if (result.LocalAddress is not { } local || !expectedLocal.Contains(local))
        {
            return ProbeVerdict.Failed;
        }

        return result.Connected ? ProbeVerdict.Connected : result.Refused ? ProbeVerdict.Refused : ProbeVerdict.Failed;
    }

    /// <summary>Контрольная цель «IP:порт».</summary>
    internal readonly record struct CheckTarget(uint Address, ushort Port)
    {
        public override string ToString() => string.Create(CultureInfo.InvariantCulture, $"{Ipv4.Format(Address)}:{Port}");
    }

    /// <summary>
    /// Цели из настройки: одна «IP:порт» или несколько через запятую, точку с запятой или пробел
    /// («1.1.1.1:443, 1.1.1.1:80»). Неразобранные пропускаются, из разобранных берутся первые
    /// <see cref="SettingsValidator.MaxCheckTargets"/>: пробы идут одновременно. Пропущенное получает <paramref name="skipped"/>.
    /// </summary>
    internal static List<CheckTarget> ParseTargets(string? targets, Action<string, IReadOnlyList<string>, int>? skipped = null)
    {
        var result = new List<CheckTarget>();
        var rejected = new List<string>();
        foreach (var item in CheckTargetList.Split(targets))
        {
            if (CheckTargetList.TryParse(item, out var address, out var port))
            {
                result.Add(new CheckTarget(address, port));
            }
            else
            {
                rejected.Add(item);
            }
        }

        result = result.Distinct().ToList();
        if (result.Count > SettingsValidator.MaxCheckTargets)
        {
            rejected.AddRange(result.Skip(SettingsValidator.MaxCheckTargets).Select(t => t.ToString()));
            result = result.Take(SettingsValidator.MaxCheckTargets).ToList();
        }

        if (rejected.Count > 0)
        {
            skipped?.Invoke(targets ?? "", rejected, result.Count);
        }

        return result;
    }

    /// <summary>Списки целей, о пропусках в которых журнал уже предупредил: по одной записи на значение настройки.</summary>
    private readonly HashSet<string> _reportedCheckTargets = new(StringComparer.Ordinal);

    /// <summary>
    /// Часть контрольных целей не применяется (опечатка, сверх предела): запись в журнал событий, а не тихое
    /// сокращение — без целей туннель считается проверенным без пробы связи.
    /// </summary>
    private void ReportSkippedTargets(string targets, IReadOnlyList<string> skipped, int used)
    {
        if (!_reportedCheckTargets.Add(targets))
        {
            return;
        }

        var list = string.Join(", ", skipped.Select(s => "«" + Core.Diagnostics.LogText.SingleLine(s) + "»"));
        Journal("Предупреждение", used == 0
            ? $"Контрольные цели «{Core.Diagnostics.LogText.SingleLine(targets)}» не разобраны ({list}): проверка связи по ним не выполняется. Укажите цели вида 1.1.1.1:443 в настройках."
            : $"Контрольные цели {list} пропущены: нужен вид 1.1.1.1:443 и не больше {SettingsValidator.MaxCheckTargets} целей. Проверка связи идёт по остальным.");
    }
}
