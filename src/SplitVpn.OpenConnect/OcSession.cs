using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.RegularExpressions;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.OpenConnect;

namespace SplitVpn.OpenConnect;

/// <summary>Куда помощник отправляет события для службы.</summary>
internal interface IHelperOutput
{
    /// <summary>
    /// Отправляет событие; false — не доставлено (канал закрыт или событие больше кадра канала). Кому важна
    /// доставка (параметры сеанса), тот проверяет результат: служба без них считала бы сеанс прежним.
    /// </summary>
    bool Send(HelperEvent helperEvent);
}

/// <summary>Системные действия помощника, которые в тестах подменяются.</summary>
internal interface IHelperSystem
{
    /// <summary>Назначает адаптеру адрес /32 и MTU; возвращает LUID адаптера.</summary>
    ulong ConfigureInterface(string interfaceName, SessionInfo session);

    /// <summary>Удаляет оставшуюся от прошлого сеанса запись адаптера с этим именем; возвращает число удалённых.</summary>
    int RemoveStaleInterface(string interfaceName);

    /// <summary>
    /// Адреса GnuTLS (system:win:…) для сертификата компьютера с отпечатком и предупреждение для журнала
    /// (null - предупреждать не о чем).
    /// </summary>
    (string Certificate, string Key, string? Warning) PrepareClientCertificate(string thumbprint);

    /// <summary>Принимает ли адрес TCP-соединение на порт за отведённое время: выбор живого узла шлюза из нескольких.</summary>
    bool CanConnect(string address, int port, TimeSpan timeout, CancellationToken cancellationToken);
}

/// <summary>
/// Сеанс шлюза AnyConnect в процессе помощника: вход (SSO, формы), CSTP, DTLS, адаптер, mainloop.
/// Работает в своём потоке; команды службы приходят через <see cref="Post"/> из потока канала.
/// Один экземпляр — один сеанс: после завершения процесс помощника выходит.
/// </summary>
internal sealed partial class OcSession : IOcCallbacks, IDisposable
{
    internal static readonly TimeSpan SignInTimeout = TimeSpan.FromMinutes(5);
    internal static readonly TimeSpan ResolveTimeout = TimeSpan.FromSeconds(30);
    internal static readonly TimeSpan StatsInterval = TimeSpan.FromSeconds(2);

    /// <summary>Сколько ждать TCP-соединения с одним адресом узла, когда адресов несколько.</summary>
    internal static readonly TimeSpan AddressProbeTimeout = TimeSpan.FromSeconds(3);

    private readonly IOcLib _lib;
    private readonly IHelperOutput _output;
    private readonly IHelperSystem _system;
    private readonly BlockingCollection<HelperCommand> _commands = new();
    private readonly CancellationTokenSource _stop = new();
    private readonly Lock _commandLifetime = new();
    private bool _disposed;
    private StartCommand? _start;
    private bool _groupSwitched;

    /// <summary>Группа, выбранная пользователем в форме: в форме этой группы она выбирается сама.</summary>
    private string? _userGroup;

    /// <summary>Значения, введённые вместе со сменой группы: переносятся в форму новой группы.</summary>
    private Dictionary<string, string>? _carried;
    private bool _passwordOffered;
    private bool _formSeen;
    private bool _browserLoginStarted;
    private bool _certificateRejected;

    /// <summary>Адаптер не перенастроен после переподключения: сеанс завершается как обрыв связи.</summary>
    private string? _interfaceFailure;
    private bool _hostScanRequested;

    /// <summary>Последняя ошибка библиотеки: код возврата сам по себе причину не объясняет (-5 — любой сбой TLS или HTTP).</summary>
    /// <summary>
    /// Значения, которые пользователь ввёл или браузер передал при входе (пароль, код, cookie SSO): в подробном
    /// журнале библиотека может повторить их в заголовках и телах запросов — они заменяются дословно.
    /// </summary>
    private readonly object _redactionLock = new();
    private volatile string[] _secretValues = [];

    private string? _lastLibraryError;

    /// <summary>
    /// Предупреждение о чужих сертификатах с тем же ключом: если туннель не поднялся, оно добавляется к причине
    /// завершения - иначе пользователь видел бы только код отказа, а объяснение было бы лишь в журнале службы.
    /// </summary>
    private string? _certificateWarning;

    /// <summary>openconnect_disable_ipv6 завершился ошибкой: признак уходит службе в параметрах сеанса.</summary>
    private bool _ipv6NotDisabled;

    /// <summary>Туннель поднят (службе отправлено Established): дальнейшие сбои с сертификатом клиента не связаны.</summary>
    private bool _established;
    private bool _signInCancelled;

    /// <summary>Шлюз прислал адрес SSO длиннее <see cref="HelperLimits.MaxSsoUri"/>: причина завершения входа.</summary>
    private string? _ssoRejected;
    private volatile bool _commandPipeReady;

    public OcSession(IOcLib lib, IHelperOutput output, IHelperSystem system)
    {
        _lib = lib;
        _output = output;
        _system = system;
    }

    public bool Verbose { get; init; }

    /// <summary>Команда службы. Stop обрабатывается сразу: отменяет ожидания и останавливает mainloop.</summary>
    public void Post(HelperCommand command)
    {
        if (command is StopCommand)
        {
            RequestStop();
            return;
        }

        try
        {
            _commands.Add(command);
        }
        catch (Exception ex) when (ex is InvalidOperationException or ObjectDisposedException)
        {
            // Сеанс уже завершён: команда запоздала.
        }
    }

    public void Dispose()
    {
        lock (_commandLifetime)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _commands.Dispose();
            _stop.Dispose();
            _lib.Dispose();
        }
    }

    public void RequestStop()
    {
        var cancelLost = false;

        // Run уже мог завершиться, пока поток канала ещё отправляет Cancel в нативный сеанс.
        lock (_commandLifetime)
        {
            if (_disposed || _stop.IsCancellationRequested)
            {
                return;
            }

            _stop.Cancel();
            if (_commandPipeReady)
            {
                try
                {
                    _lib.SendCommand(Native.OcNative.CmdCancel);
                }
                catch (IOException ex)
                {
                    // Отмена не дошла до цикла библиотеки: он продолжает работать, и Terminated о конце сеанса был бы
                    // неправдой - служба уже отпустила помощника, а адаптер жил бы до её срока принудительного завершения.
                    Log(OcCodes.PrgErr, "Отмена не передана в libopenconnect: " + ex.Message);
                    cancelLost = true;
                }
            }
        }

        // Ожидания колбэков (вход, разрешение имён) отменяет _stop, и сеанс завершается сам; цикл библиотеки без
        // команды отмены не остановить - процесс завершается, адаптер Wintun уходит вместе с ним.
        if (cancelLost && !_runFinished.Task.Wait(CancelLostGrace))
        {
            ExitProcess(1);
        }
    }

    /// <summary>Сколько ждать конца сеанса, когда команда отмены не дошла до библиотеки.</summary>
    internal static readonly TimeSpan CancelLostGrace = TimeSpan.FromSeconds(2);

    /// <summary>Завершение процесса помощника, когда сеанс иначе не остановить (подменяется в тестах).</summary>
    internal Action<int> ExitProcess { get; init; } = Environment.Exit;

    private readonly TaskCompletionSource _runFinished = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Итог сеанса уже отправлен службе: второй Terminated после него не нужен.</summary>
    private volatile bool _terminationSent;

    /// <summary>Весь сеанс от входа до завершения. Возвращает итог, уже отправленный службе.</summary>
    public TerminationKind Run(StartCommand start)
    {
        _start = start;
        try
        {
            return Terminate(Connect(start));
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return Terminate((TerminationKind.Internal, ex.Message));
        }
        finally
        {
            _commands.CompleteAdding();
            _runFinished.TrySetResult();
        }
    }

    private (TerminationKind Kind, string Text) Connect(StartCommand start)
    {
        _lib.Create(this, start.UserAgent, Verbose);
        _output.Send(new HelloEvent(HelperContract.Version, _lib.Version));
        if (_lib.ParseUrl(start.GatewayUrl) != 0)
        {
            return (TerminationKind.Internal, "Неверный адрес шлюза: " + start.GatewayUrl);
        }

        // Маршрутизация и фильтры службы — только IPv4: адрес IPv6 от шлюза на адаптере был бы вне её модели.
        // Сбой - не отказ от сеанса: защита пропускает через туннель AnyConnect только IPv4, а служба получает признак
        // в параметрах сеанса и показывает предупреждение.
        if (_lib.DisableIpv6() != 0)
        {
            _ipv6NotDisabled = true;
            Log(OcCodes.PrgErr,"Не удалось отключить IPv6 в туннеле: IPv6 через туннель будет заблокирован защитой.");
        }

        // Канал команд — до входа: отмена прерывает и сетевые ожидания библиотеки, а не только колбэки.
        _lib.SetupCommandPipe();
        _commandPipeReady = true;
        if (_stop.IsCancellationRequested)
        {
            return (TerminationKind.Cancelled, "Вход отменён.");
        }

        if (!string.IsNullOrEmpty(start.CertificateThumbprint))
        {
            string certificate, key;
            string? warning;
            try
            {
                (certificate, key, warning) = _system.PrepareClientCertificate(start.CertificateThumbprint);
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception
                or System.Security.Cryptography.CryptographicException or UnauthorizedAccessException)
            {
                // Сертификат не найден, без ключа или ключ недоступен библиотеке: повтор без действия пользователя не поможет.
                return (TerminationKind.CertificateRejected, ex.Message);
            }

            if (warning is not null)
            {
                _certificateWarning = warning;
                Log(OcCodes.PrgInfo, warning);
            }

            if (_lib.SetClientCertificate(certificate, key) != 0)
            {
                return (TerminationKind.CertificateRejected, "Клиентский сертификат не загружен библиотекой.");
            }
        }

        var obtained = _lib.ObtainCookie();
        if (_stop.IsCancellationRequested)
        {
            return (TerminationKind.Cancelled, "Вход отменён.");
        }

        if (obtained != 0)
        {
            return ClassifyAuthFailure(obtained);
        }

        var cstp = _lib.MakeCstpConnection();
        if (cstp != 0)
        {
            return cstp == -OcCodes.Eperm
                ? (TerminationKind.AuthRejected, "Шлюз отклонил сеанс (401).")
                : (TerminationKind.NetworkError, $"Не удалось установить туннель CSTP (код {cstp}).");
        }

        if (start.UseDtls ? _lib.SetupDtls() != 0 : _lib.DisableDtls() != 0)
        {
            Log(OcCodes.PrgInfo, "DTLS недоступен, туннель работает по TLS.");
        }

        if (_system.RemoveStaleInterface(start.InterfaceName) > 0)
        {
            Log(OcCodes.PrgInfo, "Удалена запись адаптера «" + start.InterfaceName + "», оставшаяся от прошлого сеанса.");
        }

        // С этого места сеанс CSTP на шлюзе открыт: выход без mainloop после создания адаптера закрывает его через
        // CloseGatewaySession, иначе шлюз держал бы место лицензии и одновременный вход до своего тайм-аута.
        if (_lib.SetupTunDevice(start.InterfaceName) != 0)
        {
            // Без адаптера BYE не отправляется: mainloop без адаптера сначала ещё раз целиком создаёт его и только потом
            // читает отмену - медленный сбой Wintun повторился бы до сообщения службе (её срок подъёма мог бы истечь
            // раньше), а удачный повтор ненадолго поднял бы ненастроенный адаптер. Сеанс на шлюзе истечёт сам.
            return (TerminationKind.Internal, "Не удалось создать адаптер Wintun «" + start.InterfaceName + "».");
        }

        SessionInfo session;
        ulong luid;
        try
        {
            session = ReadSession();
            if (session.TunnelAddressProblem() is { } problem)
            {
                // Адрес из служебного диапазона не назначается адаптеру вовсе: /32 с Preferred перехватил бы его у всей машины.
                CloseGatewaySession();
                return (TerminationKind.Internal, char.ToUpperInvariant(problem[0]) + problem[1..] + ".");
            }

            luid = _system.ConfigureInterface(start.InterfaceName, session);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            CloseGatewaySession();
            throw;
        }

        _established = true;
        if (!_output.Send(new EstablishedEvent(luid, start.InterfaceName, session)))
        {
            // Служба не узнала о сеансе (канал закрыт или событие не влезло в кадр): держать его на шлюзе незачем.
            CloseGatewaySession();
            return (TerminationKind.Internal, "Параметры сеанса не переданы службе.");
        }

        return RunMainloop();
    }

    /// <summary>Параметры сеанса в пределах <see cref="HelperLimits"/>; что урезано — в журнал.</summary>
    private SessionInfo ReadSession()
    {
        var session = _lib.ReadSession().Capped() with { Ipv6NotDisabled = _ipv6NotDisabled };
        foreach (var item in session.Truncated)
        {
            Log(OcCodes.PrgInfo, "Шлюз прислал слишком много данных сеанса, лишнее отброшено: " + item + ".");
        }

        return session;
    }

    /// <summary>
    /// Прощается со шлюзом, когда сеанс CSTP уже открыт, а mainloop не начинался: отмена кладётся в канал команд,
    /// и цикл библиотеки сразу отправляет BYE и возвращает -EINTR (openconnect_vpninfo_free BYE не отправляет).
    /// Вызывается только при созданном адаптере: без него цикл перед этим ещё раз целиком создавал бы его сам.
    /// Ошибки прощания не заменяют причину завершения: последняя ошибка библиотеки восстанавливается.
    /// </summary>
    private void CloseGatewaySession()
    {
        if (!_commandPipeReady)
        {
            return;
        }

        var reason = _lastLibraryError;
        try
        {
            _lib.SendCommand(Native.OcNative.CmdCancel);
            _ = _lib.Mainloop();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Log(OcCodes.PrgInfo, "Не удалось попрощаться со шлюзом: " + ex.Message);
        }
        finally
        {
            _lastLibraryError = reason;
        }
    }

    private (TerminationKind, string) RunMainloop()
    {
        var stats = new Timer(_ =>
        {
            try { _lib.SendCommand(Native.OcNative.CmdStats); }
            catch (IOException ex) { Log(OcCodes.PrgErr, ex.Message); }
        }, null, StatsInterval, StatsInterval);
        try
        {
            if (_stop.IsCancellationRequested)
            {
                // Остановили, пока поднимался туннель: сеанс CSTP на шлюзе уже есть, и цикл библиотеки
                // должен попрощаться со шлюзом (BYE), иначе шлюз держал бы сеанс до своего тайм-аута.
                CloseGatewaySession();
                return (TerminationKind.Cancelled, "Сеанс завершён службой.");
            }

            var result = _lib.Mainloop();
            return result switch
            {
                _ when _stop.IsCancellationRequested => (TerminationKind.Cancelled, "Сеанс завершён службой."),
                _ when _interfaceFailure is { } failure => (TerminationKind.NetworkError, failure),
                // Переподключение снова проверяет сертификат шлюза: отказ — та же блокирующая ошибка, что и при входе.
                _ when _certificateRejected => (TerminationKind.CertificateRejected, "Сертификат шлюза не прошёл проверку при переподключении."),
                -OcCodes.Eperm => (TerminationKind.AuthRejected, "Шлюз отклонил сеанс (401): требуется новый вход."),
                -OcCodes.Epipe => (TerminationKind.SessionExpired, "Шлюз завершил сеанс."),
                -OcCodes.Eintr => (TerminationKind.Cancelled, "Сеанс завершён."),
                _ => (TerminationKind.NetworkError, $"Связь со шлюзом потеряна (код {result})."),
            };
        }
        finally
        {
            // Обычный Dispose не ждёт уже начавшийся callback. Нативный сеанс освобождается
            // после Run: к этому моменту таймер больше не должен обращаться к его сокету.
            stats.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
    }

    private (TerminationKind, string) ClassifyAuthFailure(int code)
    {
        if (_ssoRejected is { } rejected)
        {
            return (TerminationKind.Internal, rejected);
        }

        if (_signInCancelled)
        {
            return (TerminationKind.Cancelled, "Вход отменён пользователем или истекло время входа.");
        }

        if (_certificateRejected)
        {
            return (TerminationKind.CertificateRejected, "Сертификат шлюза не прошёл проверку.");
        }

        if (_hostScanRequested)
        {
            return (TerminationKind.HostScanRequired, "Шлюз требует проверку состояния компьютера (HostScan), она не поддерживается.");
        }

        return _formSeen && code is -OcCodes.Eperm or -13
            ? (TerminationKind.AuthRejected, $"Вход не выполнен (код {code}).")
            : (TerminationKind.NetworkError, $"Шлюз недоступен (код {code}).");
    }

    private TerminationKind Terminate((TerminationKind Kind, string Text) result)
    {
        if (result.Kind is TerminationKind.NetworkError or TerminationKind.Internal or TerminationKind.AuthRejected && _lastLibraryError is { } reason)
        {
            result.Text = result.Text.TrimEnd('.') + ": " + reason;
        }

        // Отказ входа или сбой до подъёма туннеля мог вызвать чужой сертификат с тем же ключом: пользователю нужна
        // подсказка рядом с кодом отказа. К остановке, отмене и сбоям поднятого туннеля она не относится.
        if (!_established && _certificateWarning is { } warning && result.Kind is TerminationKind.AuthRejected
                or TerminationKind.CertificateRejected or TerminationKind.NetworkError or TerminationKind.Internal)
        {
            var text = result.Text.TrimEnd();
            result.Text = text + (text.EndsWith('.') ? " " : ". ") + warning;
        }

        if (!_terminationSent)
        {
            _terminationSent = true;
            _output.Send(new TerminatedEvent(result.Kind, result.Text));
        }

        return result.Kind;
    }

    // ---- колбэки библиотеки ----

    public int ValidatePeerCertificate(string reason)
    {
        _certificateRejected = true;
        Log(OcCodes.PrgErr, "Сертификат шлюза отклонён: " + reason);
        return -1;
    }

    public void Log(int level, string message)
    {
        // Просьбу шлюза о HostScan библиотека сообщает ошибкой; отладочные дампы HTTP и XML подробного журнала могут
        // упоминать csd и тогда, когда шлюз проверку не требует - обычный отказ входа выглядел бы блокирующим.
        if (level <= OcCodes.PrgInfo && HostScanPattern().IsMatch(message))
        {
            _hostScanRequested = true;
        }

        if (level > OcCodes.PrgInfo && !Verbose)
        {
            return;
        }

        var name = level switch { OcCodes.PrgErr => "error", OcCodes.PrgInfo => "info", _ => "debug" };
        var text = RedactValues(Redact(message));
        if (level == OcCodes.PrgErr && !string.IsNullOrWhiteSpace(text))
        {
            _lastLibraryError = text.Trim().TrimEnd('.');
        }

        _output.Send(new LogEvent(name, text));
    }

    public int OpenWebview(string uri)
    {
        _browserLoginStarted = true;
        if (uri.Length > HelperLimits.MaxSsoUri)
        {
            // Обрезанный адрес вход не откроет, а целиком он раздул бы каждый ответ службы о состоянии.
            _ssoRejected = string.Create(System.Globalization.CultureInfo.InvariantCulture,
                $"Шлюз прислал слишком длинный адрес страницы входа ({uri.Length} символов при пределе {HelperLimits.MaxSsoUri}).");
            return -OcCodes.Einval;
        }

        var requestId = Guid.NewGuid();
        // После перенаправления на другой узел кластера cookie SSO принадлежат новому узлу, а не узлу из профиля.
        _output.Send(new SsoOpenEvent(requestId, uri, CurrentGatewayHost()));
        var deadline = Stopwatch.GetTimestamp() + (long)(SignInTimeout.TotalSeconds * Stopwatch.Frequency);
        while (true)
        {
            var command = Wait(deadline);
            switch (command)
            {
                case null:
                    _signInCancelled = true;
                    _output.Send(new SsoResultEvent(requestId, false, _stop.IsCancellationRequested ? "Вход отменён." : "Время входа истекло."));
                    return -OcCodes.Ecanceled;
                case WebviewClosedCommand closed when closed.RequestId == requestId:
                    _signInCancelled = true;
                    _output.Send(new SsoResultEvent(requestId, false, "Окно входа закрыто."));
                    return -OcCodes.Ecanceled;
                case WebviewLoadCommand load when load.RequestId == requestId:
                    foreach (var cookie in load.Cookies)
                    {
                        RememberSecret(cookie.Value);
                    }

                    var code = _lib.WebviewLoadChanged(load.Uri, load.Cookies);
                    if (code == -OcCodes.Eagain)
                    {
                        continue;
                    }

                    _output.Send(new SsoResultEvent(requestId, code == 0, code == 0 ? null : $"Шлюз не принял вход (код {code})."));
                    return code;
                default:
                    // Ответ на устаревший запрос входа — пропускается.
                    continue;
            }
        }
    }

    public int ProcessForm(OcForm form)
    {
        _formSeen = true;
        if (form.AuthId == "success")
        {
            return OcCodes.FormOk;
        }

        if (form.Group is { } group && TryAutoSelectGroup(form, group) is { } groupResult)
        {
            return groupResult;
        }

        var missing = FillKnownFields(form);
        if (missing.Count == 0)
        {
            return OcCodes.FormOk;
        }

        return AskUser(form, missing);
    }

    public string? Resolve(string host)
    {
        // Порт текущего узла: перенаправление меняет и его, а служба открывает фильтры по порту.
        var port = _lib.CurrentPort;
        _output.Send(new ResolveHostEvent(host, port));
        var deadline = Stopwatch.GetTimestamp() + (long)(ResolveTimeout.TotalSeconds * Stopwatch.Frequency);
        while (Wait(deadline) is { } command)
        {
            if (command is ResolveReplyCommand reply && string.Equals(reply.Host, host, StringComparison.OrdinalIgnoreCase))
            {
                return ChooseAddress(reply, port, deadline);
            }
        }

        return null;
    }

    /// <summary>
    /// Адрес для подключения к узлу. Библиотека получает от нас один адрес, а у имени их может быть несколько: служба
    /// присылает все (маршруты и фильтры открыты ко всем), и если первый не принимает соединение, берётся следующий —
    /// иначе один недоступный адрес из нескольких оставлял бы без входа.
    /// </summary>
    private string? ChooseAddress(ResolveReplyCommand reply, int port, long deadline)
    {
        var candidates = (reply.Addresses ?? []).Where(a => !string.IsNullOrWhiteSpace(a)).Distinct(StringComparer.Ordinal).ToList();
        if (candidates.Count <= 1 || port is <= 0 or > ushort.MaxValue)
        {
            return reply.Address ?? candidates.FirstOrDefault();
        }

        foreach (var address in candidates)
        {
            var remaining = Stopwatch.GetElapsedTime(Stopwatch.GetTimestamp(), deadline);
            if (_stop.IsCancellationRequested || remaining <= TimeSpan.Zero) { break; }
            if (_system.CanConnect(address, port, remaining < AddressProbeTimeout ? remaining : AddressProbeTimeout, _stop.Token))
            {
                if (!string.Equals(address, candidates[0], StringComparison.Ordinal))
                {
                    Log(OcCodes.PrgInfo, $"Узел {reply.Host}: адрес {candidates[0]} не отвечает, подключение к {address}.");
                }

                return address;
            }
        }

        // Не ответил никто: библиотека попробует первый и сама сообщит причину.
        return candidates[0];
    }

    public void Reconnected()
    {
        _output.Send(new ReconnectingEvent("Туннель переподключён."));
        SessionInfo session;

        // Шлюз мог выдать другой адрес или MTU: адаптер настраивается заново, иначе он остался бы с прежними.
        try
        {
            session = ReadSession();
            if (session.TunnelAddressProblem() is { } problem)
            {
                throw new InvalidOperationException(problem);
            }

            _system.ConfigureInterface(_start!.InterfaceName, session);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // Адаптер остался с прежним адресом: сообщить службе «сеанс жив, адрес новый» нельзя - она сочла бы
            // туннель рабочим. Сеанс завершается как обрыв связи, и служба поднимает его заново.
            FailInterface("Не удалось перенастроить адаптер после переподключения: " + ex.Message);
            return;
        }

        if (!_output.Send(new IpInfoChangedEvent(session)))
        {
            // Служба осталась бы с прежними параметрами (сети, DNS, адрес), а адаптер уже с новыми.
            FailInterface("Новые параметры сеанса после переподключения не переданы службе.");
        }
    }

    /// <summary>Адаптер и служба разошлись с сеансом: mainloop отменяется (с BYE), итог - обрыв связи.</summary>
    private void FailInterface(string reason)
    {
        Log(OcCodes.PrgErr, reason);
        _interfaceFailure = reason;
        try
        {
            _lib.SendCommand(Native.OcNative.CmdCancel);
        }
        catch (IOException ex)
        {
            // Цикл библиотеки не узнает об отмене и продолжит на прежнем адресе: служба узнаёт об обрыве сразу и
            // отпускает помощника, а конец канала завершает процесс (RequestStop).
            Log(OcCodes.PrgErr, "Отмена не передана в libopenconnect: " + ex.Message);
            _terminationSent = true;
            _output.Send(new TerminatedEvent(TerminationKind.NetworkError, reason));
        }
    }

    public void Stats(ulong bytesSent, ulong bytesReceived) => _output.Send(new StatsEvent(bytesSent, bytesReceived, _lib.DtlsActive));

    // ---- формы ----

    /// <summary>
    /// Группа из профиля (или выбранная пользователем в форме) выбирается сама; смена группы перезапрашивает форму один раз.
    /// </summary>
    private int? TryAutoSelectGroup(OcForm form, OcField group)
    {
        var index = WantedGroupIndex(group);
        if (index < 0)
        {
            return null;
        }

        group.Set(group.Choices[index].Name);
        if (index != form.GroupSelection && !_groupSwitched)
        {
            _groupSwitched = true;
            return OcCodes.FormNewGroup;
        }

        return null;
    }

    /// <summary>
    /// Номер группы, которую нужно выбрать: из профиля, а если её нет среди предложенных — выбранной пользователем
    /// в прошлой форме; -1 — выбирать нечего, группу спрашивают у пользователя.
    /// </summary>
    private int WantedGroupIndex(OcField group)
    {
        foreach (var wanted in new[] { _start!.Group, _userGroup })
        {
            if (string.IsNullOrWhiteSpace(wanted))
            {
                continue;
            }

            var index = group.Choices.ToList().FindIndex(c => string.Equals(c.Name, wanted, StringComparison.OrdinalIgnoreCase)
                || string.Equals(c.Label, wanted, StringComparison.OrdinalIgnoreCase));
            if (index >= 0)
            {
                return index;
            }
        }

        return -1;
    }

    /// <summary>Заполняет то, что известно из профиля; возвращает поля, которые должен ввести пользователь.</summary>
    private List<OcField> FillKnownFields(OcForm form)
    {
        var missing = new List<OcField>();

        // Значения, введённые пользователем вместе со сменой группы, переносятся в форму новой группы один раз:
        // иначе после выбора группы те же логин и пароль пришлось бы вводить заново.
        var carried = _carried;
        _carried = null;
        foreach (var field in form.Fields.Where(f => !f.Ignored))
        {
            if (carried is not null && form.Error is null && field.Kind is (OcFieldKind.Text or OcFieldKind.Password or OcFieldKind.Select)
                && !ReferenceEquals(field, form.Group) && carried.TryGetValue(field.Name, out var typed)
                && (field.Kind != OcFieldKind.Select || field.Choices.Any(choice => choice.Name == typed)))
            {
                field.Set(typed);
                continue;
            }

            switch (field.Kind)
            {
                case OcFieldKind.Select when ReferenceEquals(field, form.Group) && WantedGroupIndex(field) >= 0:
                    break;
                case OcFieldKind.Select when field.Choices.Count == 1:
                    field.Set(field.Choices[0].Name);
                    break;
                case OcFieldKind.Text when form.Error is null && IsUserField(field) && !string.IsNullOrEmpty(_start!.UserName):
                    field.Set(_start.UserName);
                    break;
                // Сохранённый пароль предлагается один раз и только без ошибки: неверный пароль не повторяется по кругу.
                case OcFieldKind.Password when IsPrimaryPassword(form, field) && !_passwordOffered && form.Error is null && _start!.Password is { Length: > 0 }:
                {
                    // Библиотеке и списку скрываемых в журнале значений нужна строка: помощник живёт один сеанс.
                    var savedPassword = new string(_start.Password);
                    RememberSecret(savedPassword);
                    field.Set(savedPassword);
                    _passwordOffered = true;
                    break;
                }
                case OcFieldKind.Text or OcFieldKind.Password or OcFieldKind.Select:
                    missing.Add(field);
                    break;
            }
        }

        return missing;
    }

    private int AskUser(OcForm form, List<OcField> missing)
    {
        var requestId = Guid.NewGuid();
        var fields = missing.Select(f => new AuthFieldDto(f.Name, f.Label, f.Kind switch
        {
            OcFieldKind.Password => AuthFieldKind.Password,
            OcFieldKind.Select => AuthFieldKind.Select,
            _ => AuthFieldKind.Text,
        }, f.Choices, DefaultValue(form, f))).ToList();
        // Тексты и поля шлюза - в пределах HelperLimits: служба показывает форму в каждом ответе о состоянии.
        _output.Send(new AuthFormEvent(requestId, form.Banner, form.Message, form.Error, fields).Capped());

        var deadline = Stopwatch.GetTimestamp() + (long)(SignInTimeout.TotalSeconds * Stopwatch.Frequency);
        while (Wait(deadline) is { } command)
        {
            if (command is not FormReplyCommand reply || reply.RequestId != requestId)
            {
                continue;
            }

            if (reply.Cancel)
            {
                _signInCancelled = true;
                return OcCodes.FormCancelled;
            }

            foreach (var field in missing)
            {
                if (reply.Values.TryGetValue(field.Name, out var value))
                {
                    if (field.Kind is not (OcFieldKind.Text or OcFieldKind.Select))
                    {
                        RememberSecret(value);
                    }

                    field.Set(value);
                }
            }

            return GroupChangedByUser(form, missing, reply) ? OcCodes.FormNewGroup : OcCodes.FormOk;
        }

        _signInCancelled = true;
        return OcCodes.FormCancelled;
    }

    /// <summary>
    /// Пользователь выбрал в форме другую группу. Шлюз должен прислать форму этой группы (у неё свои поля и способ
    /// входа): с FormOk библиотека отправила бы введённое под прежней группой. Выбор и остальные введённые значения
    /// запоминаются для формы новой группы.
    /// </summary>
    private bool GroupChangedByUser(OcForm form, List<OcField> missing, FormReplyCommand reply)
    {
        if (form.Group is not { } group || !missing.Contains(group) || !reply.Values.TryGetValue(group.Name, out var chosen))
        {
            return false;
        }

        var index = group.Choices.ToList().FindIndex(c => string.Equals(c.Name, chosen, StringComparison.Ordinal));
        if (index < 0 || index == form.GroupSelection)
        {
            return false;
        }

        _userGroup = group.Choices[index].Name;
        _carried = reply.Values.Where(v => v.Key != group.Name).ToDictionary(v => v.Key, v => v.Value, StringComparer.Ordinal);
        Log(OcCodes.PrgInfo, "Выбрана группа «" + group.Choices[index].Label + "»: шлюз пришлёт её форму входа.");
        return true;
    }

    /// <summary>
    /// Что подставить в поле формы: имя пользователя из профиля, а в списке групп — группу, выбранную шлюзом.
    /// Без этого окно выбрало бы первую группу и отправка формы молча сменила бы выбор шлюза.
    /// </summary>
    private string? DefaultValue(OcForm form, OcField field)
    {
        if (IsUserField(field))
        {
            return _start!.UserName;
        }

        return ReferenceEquals(field, form.Group) && form.GroupSelection >= 0 && form.GroupSelection < field.Choices.Count
            ? field.Choices[form.GroupSelection].Name
            : null;
    }

    private static bool IsUserField(OcField field) =>
        field.Name.ToLowerInvariant() is "user" or "username" or "user_name" or "uname" or "login";

    private bool IsPrimaryPassword(OcForm form, OcField field)
    {
        if (_browserLoginStarted || field.Name.ToLowerInvariant() is not ("password" or "passwd" or "primary_password"))
        {
            return false;
        }

        var label = field.Label.Trim().TrimEnd(':').TrimEnd().ToLowerInvariant();
        if (label is not ("password" or "passwd" or "primary password" or "primary_password" or "пароль"))
        {
            return false;
        }

        var prompt = string.Join(' ', form.AuthId, form.Banner, form.Message);
        return !ChallengeWords.Any(word => prompt.Contains(word, StringComparison.OrdinalIgnoreCase))
            && (form.Fields.Any(f => !f.Ignored && f.Kind == OcFieldKind.Text && IsUserField(f))
                || form.Group is not null || field.Name.Equals("primary_password", StringComparison.OrdinalIgnoreCase));
    }

    private static readonly string[] ChallengeWords = ["otp", "one-time", "one time", "passcode", "verification code", "token", "challenge", "2fa", "mfa", "одноразов", "код подтверждения"];

    private HelperCommand? Wait(long deadline)
    {
        var remaining = Stopwatch.GetElapsedTime(Stopwatch.GetTimestamp(), deadline);
        if (remaining <= TimeSpan.Zero || _stop.IsCancellationRequested)
        {
            return null;
        }

        try
        {
            return _commands.TryTake(out var command, (int)Math.Ceiling(remaining.TotalMilliseconds), _stop.Token) ? command : null;
        }
        catch (Exception ex) when (ex is OperationCanceledException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>Узел, с которым библиотека работает сейчас; без него — узел из адреса профиля.</summary>
    private string CurrentGatewayHost() =>
        _lib.CurrentHost is { Length: > 0 } host ? host
        : Uri.TryCreate(_start?.GatewayUrl, UriKind.Absolute, out var uri) ? uri.Host : "";

    /// <summary>Значения короче этого не заменяются: «1» или «yes» испортили бы весь журнал.</summary>
    private const int MinSecretLength = 4;

    private void RememberSecret(string? value)
    {
        if (value is { Length: >= MinSecretLength })
        {
            lock (_redactionLock)
            {
                if (!_secretValues.Contains(value, StringComparer.Ordinal))
                {
                    _secretValues = _secretValues.Append(value).OrderByDescending(s => s.Length).ToArray();
                }
            }
        }
    }

    /// <summary>Введённые при входе значения — дословно, самые длинные первыми.</summary>
    private string RedactValues(string text)
    {
        var secrets = _secretValues;
        if (secrets.Length == 0)
        {
            return text;
        }

        foreach (var secret in secrets)
        {
            text = text.Replace(secret, "<скрыто>", StringComparison.Ordinal);
        }

        return text;
    }

    /// <summary>Cookie сеанса, токены SSO, заголовки авторизации и секреты DTLS не уходят в журнал службы.</summary>
    internal static string Redact(string text)
    {
        text = CookieValue().Replace(text, "$1=<скрыто>");
        text = HeaderSecret().Replace(text, "$1<скрыто>");
        return TokenXml().Replace(text, "<$1><скрыто></$1>");
    }

    [GeneratedRegex(@"(webvpn[a-z_]*|acSamlv2Token|acSamlv2Error|SAMLResponse|openconnect_strapkey)=[^;\s""&]+", RegexOptions.IgnoreCase)]
    private static partial Regex CookieValue();

    [GeneratedRegex(@"((?:X-DTLS-Session-ID|X-DTLS-Master-Secret|X-DTLS12-Master-Secret|Set-Cookie|Cookie|Authorization|Proxy-Authorization|X-CSTP-Post-Auth-XML|X-AnyConnect-STRAP-[A-Za-z-]+):\s*)\S.*", RegexOptions.IgnoreCase)]
    private static partial Regex HeaderSecret();

    [GeneratedRegex(@"<(sso-token|session-token|session-id|opaque[^>]*)>[^<]*</[^>]+>", RegexOptions.IgnoreCase)]
    private static partial Regex TokenXml();

    [GeneratedRegex(@"\b(CSD|HostScan|host-scan|trojan)\b", RegexOptions.IgnoreCase)]
    private static partial Regex HostScanPattern();
}
