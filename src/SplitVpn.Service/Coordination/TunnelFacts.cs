using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.OpenConnect;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Windows.Operations;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Coordination;

/// <summary>Что служба знает про один туннель. У каждого профиля своя запись телефонной книги RAS.</summary>
internal sealed class TunnelFacts(Guid profileId, string entryName)
{
    public Guid ProfileId { get; } = profileId;

    public string EntryName { get; } = entryName;

    public string Name { get; set; } = "";

    public ProfileRole Role { get; set; }

    /// <summary>Адрес сервера, который сейчас записан в телефонной книге.</summary>
    public string? AppliedEntryServer { get; set; }

    public ushort ServerPort { get; set; } = ServerAddress.DefaultPort;

    public VpnProtocol Protocol { get; set; } = VpnProtocol.Sstp;

    public IReadOnlyList<uint> ServerAddresses { get; set; } = [];

    /// <summary>Адреса в начале дозвона: сохраняются до конца сеанса, независимо от обновления DNS.</summary>
    public IReadOnlyList<uint> SessionServerAddresses { get; set; } = [];

    public DateTimeOffset ServerResolvedUtc { get; set; }

    public DateTimeOffset NextServerResolveAt { get; set; }

    public bool ServerResolving { get; set; }

    public DateTimeOffset? ServerResolveStartedUtc { get; set; }

    public RasConnectionHandle? Connection { get; set; }

    public AdapterCandidate? Adapter { get; set; }

    public IReadOnlyList<uint> VpnDns { get; set; } = [];

    public DateTimeOffset? SessionStartedUtc { get; set; }

    public RasStatistics? Statistics { get; set; }

    public bool Verified { get; set; }

    public bool EverConnected { get; set; }

    public bool Dialing { get; set; }

    /// <summary>
    /// Пользователь положил этот туннель вручную, не трогая настройки. Живёт до общего «Подключить»
    /// и до перезапуска службы: в настройках такого признака нет, роль профиля остаётся прежней.
    /// </summary>
    public bool Paused { get; set; }

    /// <summary>Дозвон хотя бы раз завершился в нынешнем цикле подключения — успехом или отказом.</summary>
    public bool DialSettled { get; set; }

    /// <summary>Когда начался последний дозвон: по нему очередь отпускает туннель, который завис.</summary>
    public DateTimeOffset? DialStartedUtc { get; set; }

    public int DialGeneration { get; set; }

    /// <summary>Неудачные попытки подряд: растёт до успешной проверки и задаёт паузу перед следующим дозвоном.</summary>
    public int DialAttempt { get; set; }

    /// <summary>Проверки готовности, не пройденные подряд: сбрасывается только успешной проверкой или командой пользователя.</summary>
    public int VerifyFailures { get; set; }

    /// <summary>Проба готовности идёт в фоновой задаче: очередь актора её не ждёт.</summary>
    public bool Verifying { get; set; }

    /// <summary>Поколение проверки: ответ пробы прежнего сеанса не применяется к нынешнему.</summary>
    public int VerifyGeneration { get; set; }

    /// <summary>
    /// Пробы текущего сеанса, не прошедшие подряд. Сеанс RAS живой, и сервер мог просто не успеть
    /// отпустить прежнюю сессию, поэтому первая неудачная проба его не рвёт: рвёт только исчерпанный счёт.
    /// </summary>
    public int VerifyProbeFailures { get; set; }

    /// <summary>Время следующей пробы готовности внутри текущего сеанса.</summary>
    public DateTimeOffset NextVerifyAt { get; set; }

    /// <summary>Когда для этого туннеля последний раз запускался детектор конфликтов (неудачная проверка).</summary>
    public DateTimeOffset LastConflictProbeUtc { get; set; }

    /// <summary>Что сервер предъявил по TLS в последней пробе; null — пробы не было или сервер не отвечает по TLS.</summary>
    public ServerCertificateFacts? ServerCertificate { get; set; }

    /// <summary>
    /// Узлы, к которым Windows ходит за списком отзыва сертификата сервера. Защита обязана их пропускать,
    /// иначе исправный сертификат отклоняется. Набор переживает перезапуск службы (кеш серверов).
    /// </summary>
    public IReadOnlyList<string> RevocationHosts { get; set; } = [];

    /// <summary>
    /// Повтор после открытия адресов проверки отзыва уже использован. Одна попытка даётся сама: адрес
    /// открылся только что, и прежний отказ к ней не относится. Дальше — обычная остановка повторов.
    /// </summary>
    public bool RevocationRetryUsed { get; set; }

    public bool CertificateProbeRunning { get; set; }

    public int CertificateProbeGeneration { get; set; }

    public DateTimeOffset LastCertificateProbeUtc { get; set; }

    public int FailedDialsSinceResolve { get; set; }

    public DateTimeOffset NextDialAt { get; set; }

    public ErrorCategory BlockingError { get; set; }

    public ErrorCategory LastErrorCategory { get; set; }

    public string? LastErrorText { get; set; }

    public int? LastErrorCode { get; set; }

    public bool PasswordRequired { get; set; }

    /// <summary>VPN разорван другой программой или из меню сети Windows; сбрасывается командой пользователя.</summary>
    public bool ExternallyDisconnected { get; set; }

    /// <summary>Сеанс помощника AnyConnect: от запуска процесса до его завершения.</summary>
    public AnyConnectLink? AnyConnect { get; set; }

    /// <summary>Параметры сеанса шлюза AnyConnect (сети, DNS, суффиксы); null — сеанса нет.</summary>
    public SessionInfo? Session { get; set; }

    /// <summary>Текущий запрос входа помощника: окно SSO или форма шлюза.</summary>
    public SignInPromptDto? SignIn { get; set; }

    /// <summary>Туннель поднят: соединение RAS или установленный сеанс AnyConnect.</summary>
    public bool IsUp => Connection is not null || AnyConnect is { Established: true };

    /// <summary>Есть что разрывать: соединение RAS или живой процесс-помощник.</summary>
    public bool HasSession => IsUp || AnyConnect is not null;

    /// <summary>Туннель поднят и интерфейс найден: только тогда на него можно ставить маршруты.</summary>
    public ulong? Luid => IsUp ? Adapter?.Luid : null;

    /// <summary>Проверенный сеанс не короче этого времени считается устойчивым: только он сбрасывает счётчики попыток.</summary>
    public static readonly TimeSpan StableSession = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Сеанс был проверен и продержался достаточно долго. Обрыв такого сеанса — случайность, и следующий
    /// дозвон начинается заново; обрыв короткого сеанса означает, что подключение не работает, и пауза растёт.
    /// </summary>
    public bool WasStableSession(DateTimeOffset now) =>
        Verified && SessionStartedUtc is { } started && now - started >= StableSession;

    /// <summary>Счётчики повторов обнуляются: подключение работало или так решил пользователь.</summary>
    public void ResetRetries()
    {
        DialAttempt = 0;
        VerifyFailures = 0;
    }

    public void ResetConnection(DateTimeOffset now)
    {
        var stable = WasStableSession(now);
        Connection = null;
        Session = null;
        Adapter = null;
        ResetVerification();
        SessionStartedUtc = null;
        Statistics = null;
        NextDialAt = now;
        if (stable)
        {
            ResetRetries();
        }
    }

    /// <summary>Пробы прежнего сеанса больше не влияют на состояние и не мешают проверке нового.</summary>
    public void ResetVerification()
    {
        VerifyGeneration = 0;
        Verifying = false;
        Verified = false;
        VerifyProbeFailures = 0;
        NextVerifyAt = default;
    }
}

/// <summary>Живой процесс-помощник AnyConnect. Поколение отсекает события прежних процессов.</summary>
internal sealed class AnyConnectLink(IAnyConnectSession session, int generation)
{
    public IAnyConnectSession Session { get; } = session;

    public int Generation { get; } = generation;

    public bool Established { get; set; }

    public ulong Luid { get; set; }

    public string? ClientVersion { get; set; }

    /// <summary>Служба сама остановила сеанс: итог Cancelled не считается отменой входа.</summary>
    public bool StopRequested { get; set; }

    /// <summary>Адреса шлюза, разрешённые по запросу помощника (перенаправление на другой узел кластера).</summary>
    public List<uint> ResolvedAddresses { get; } = [];
}

/// <summary>Адрес, закреплённый за целью правилом для домена, и срок его действия.</summary>
/// <summary>
/// Закрепление адреса за целью. Суффикс — правило, которое его создало: по нему закрепление отзывается,
/// когда правило исчезло или сменило цель.
/// </summary>
internal readonly record struct PinnedRoute(Core.Policy.RouteTarget Target, DateTimeOffset ExpiresUtc, string Suffix);
