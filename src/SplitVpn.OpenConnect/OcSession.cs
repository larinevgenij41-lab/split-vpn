using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.OpenConnect;

namespace SplitVpn.OpenConnect;

/// <summary>Куда помощник отправляет события для службы.</summary>
internal interface IHelperOutput
{
    void Send(HelperEvent helperEvent);
}

/// <summary>Системные действия помощника, которые в тестах подменяются.</summary>
internal interface IHelperSystem
{
    /// <summary>Назначает адаптеру адрес /32 и MTU; возвращает LUID адаптера.</summary>
    ulong ConfigureInterface(string interfaceName, SessionInfo session);

    /// <summary>Удаляет оставшуюся от прошлого сеанса запись адаптера с этим именем; возвращает число удалённых.</summary>
    int RemoveStaleInterface(string interfaceName);

    /// <summary>Адреса GnuTLS (system:win:…) для сертификата компьютера с отпечатком.</summary>
    (string Certificate, string Key) PrepareClientCertificate(string thumbprint);
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

    private readonly IOcLib _lib;
    private readonly IHelperOutput _output;
    private readonly IHelperSystem _system;
    private readonly BlockingCollection<HelperCommand> _commands = new();
    private readonly CancellationTokenSource _stop = new();
    private StartCommand? _start;
    private bool _groupSwitched;
    private bool _passwordOffered;
    private bool _formSeen;
    private bool _certificateRejected;
    private bool _hostScanRequested;

    /// <summary>Последняя ошибка библиотеки: код возврата сам по себе причину не объясняет (-5 — любой сбой TLS или HTTP).</summary>
    private string? _lastLibraryError;
    private bool _signInCancelled;
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
        _commands.Dispose();
        _stop.Dispose();
        _lib.Dispose();
    }

    public void RequestStop()
    {
        try
        {
            if (_stop.IsCancellationRequested)
            {
                return;
            }

            _stop.Cancel();
            if (_commandPipeReady)
            {
                _lib.SendCommand(Native.OcNative.CmdCancel);
            }
        }
        catch (ObjectDisposedException)
        {
            // Сеанс уже завершён.
        }
    }

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

        // Канал команд — до входа: отмена прерывает и сетевые ожидания библиотеки, а не только колбэки.
        _lib.SetupCommandPipe();
        _commandPipeReady = true;
        if (_stop.IsCancellationRequested)
        {
            return (TerminationKind.Cancelled, "Вход отменён.");
        }

        if (!string.IsNullOrEmpty(start.CertificateThumbprint))
        {
            var (certificate, key) = _system.PrepareClientCertificate(start.CertificateThumbprint);
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

        if (_lib.SetupTunDevice(start.InterfaceName) != 0)
        {
            return (TerminationKind.Internal, "Не удалось создать адаптер Wintun «" + start.InterfaceName + "».");
        }

        var session = _lib.ReadSession();
        var luid = _system.ConfigureInterface(start.InterfaceName, session);
        _output.Send(new EstablishedEvent(luid, start.InterfaceName, session));
        return RunMainloop();
    }

    private (TerminationKind, string) RunMainloop()
    {
        using var stats = new Timer(_ => _lib.SendCommand(Native.OcNative.CmdStats), null, StatsInterval, StatsInterval);
        if (_stop.IsCancellationRequested)
        {
            return (TerminationKind.Cancelled, "Сеанс завершён службой.");
        }

        var result = _lib.Mainloop();
        return result switch
        {
            _ when _stop.IsCancellationRequested => (TerminationKind.Cancelled, "Сеанс завершён службой."),
            -OcCodes.Eperm => (TerminationKind.AuthRejected, "Шлюз отклонил сеанс (401): требуется новый вход."),
            -OcCodes.Epipe => (TerminationKind.SessionExpired, "Шлюз завершил сеанс."),
            -OcCodes.Eintr => (TerminationKind.Cancelled, "Сеанс завершён."),
            _ => (TerminationKind.NetworkError, $"Связь со шлюзом потеряна (код {result})."),
        };
    }

    private (TerminationKind, string) ClassifyAuthFailure(int code)
    {
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

        return _formSeen
            ? (TerminationKind.AuthRejected, $"Вход не выполнен (код {code}).")
            : (TerminationKind.NetworkError, $"Шлюз недоступен (код {code}).");
    }

    private TerminationKind Terminate((TerminationKind Kind, string Text) result)
    {
        if (result.Kind is TerminationKind.NetworkError or TerminationKind.Internal && _lastLibraryError is { } reason)
        {
            result.Text = result.Text.TrimEnd('.') + ": " + reason;
        }

        _output.Send(new TerminatedEvent(result.Kind, result.Text));
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
        if (level > OcCodes.PrgInfo && !Verbose)
        {
            return;
        }

        if (HostScanPattern().IsMatch(message))
        {
            _hostScanRequested = true;
        }

        var name = level switch { OcCodes.PrgErr => "error", OcCodes.PrgInfo => "info", _ => "debug" };
        var text = Redact(message);
        if (level == OcCodes.PrgErr && !string.IsNullOrWhiteSpace(text))
        {
            _lastLibraryError = text.Trim().TrimEnd('.');
        }

        _output.Send(new LogEvent(name, text));
    }

    public int OpenWebview(string uri)
    {
        var requestId = Guid.NewGuid();
        _output.Send(new SsoOpenEvent(requestId, uri, GatewayHost()));
        var deadline = DateTime.UtcNow + SignInTimeout;
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
        _output.Send(new ResolveHostEvent(host));
        var deadline = DateTime.UtcNow + ResolveTimeout;
        while (Wait(deadline) is { } command)
        {
            if (command is ResolveReplyCommand reply && string.Equals(reply.Host, host, StringComparison.OrdinalIgnoreCase))
            {
                return reply.Address;
            }
        }

        return null;
    }

    public void Reconnected()
    {
        _output.Send(new ReconnectingEvent("Туннель переподключён."));
        _output.Send(new IpInfoChangedEvent(_lib.ReadSession()));
    }

    public void Stats(ulong bytesSent, ulong bytesReceived) => _output.Send(new StatsEvent(bytesSent, bytesReceived, _lib.DtlsActive));

    // ---- формы ----

    /// <summary>Группа из профиля выбирается сама; смена группы перезапрашивает форму один раз.</summary>
    private int? TryAutoSelectGroup(OcForm form, OcField group)
    {
        var wanted = _start!.Group;
        if (string.IsNullOrWhiteSpace(wanted))
        {
            return null;
        }

        var index = group.Choices.ToList().FindIndex(c => string.Equals(c.Name, wanted, StringComparison.OrdinalIgnoreCase)
            || string.Equals(c.Label, wanted, StringComparison.OrdinalIgnoreCase));
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

    /// <summary>Заполняет то, что известно из профиля; возвращает поля, которые должен ввести пользователь.</summary>
    private List<OcField> FillKnownFields(OcForm form)
    {
        var missing = new List<OcField>();
        foreach (var field in form.Fields.Where(f => !f.Ignored))
        {
            switch (field.Kind)
            {
                case OcFieldKind.Select when ReferenceEquals(field, form.Group) && !string.IsNullOrWhiteSpace(_start!.Group)
                    && field.Choices.Any(c => string.Equals(c.Name, _start.Group, StringComparison.OrdinalIgnoreCase) || string.Equals(c.Label, _start.Group, StringComparison.OrdinalIgnoreCase)):
                    break;
                case OcFieldKind.Select when field.Choices.Count == 1:
                    field.Set(field.Choices[0].Name);
                    break;
                case OcFieldKind.Text when IsUserField(field) && !string.IsNullOrEmpty(_start!.UserName):
                    field.Set(_start.UserName);
                    break;
                // Сохранённый пароль предлагается один раз и только без ошибки: неверный пароль не повторяется по кругу.
                case OcFieldKind.Password when !_passwordOffered && form.Error is null && !string.IsNullOrEmpty(_start!.Password):
                    field.Set(_start.Password);
                    _passwordOffered = true;
                    break;
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
        }, f.Choices, IsUserField(f) ? _start!.UserName : null)).ToList();
        _output.Send(new AuthFormEvent(requestId, form.Banner, form.Message, form.Error, fields));

        var deadline = DateTime.UtcNow + SignInTimeout;
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
                    field.Set(value);
                }
            }

            return OcCodes.FormOk;
        }

        _signInCancelled = true;
        return OcCodes.FormCancelled;
    }

    private static bool IsUserField(OcField field) =>
        field.Name.StartsWith("user", StringComparison.OrdinalIgnoreCase) || field.Name.StartsWith("uname", StringComparison.OrdinalIgnoreCase);

    private HelperCommand? Wait(DateTime deadline)
    {
        var remaining = deadline - DateTime.UtcNow;
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

    private string GatewayHost() =>
        Uri.TryCreate(_start?.GatewayUrl, UriKind.Absolute, out var uri) ? uri.Host : "";

    /// <summary>Cookie сеанса, токены SSO и секреты DTLS не уходят в журнал службы.</summary>
    internal static string Redact(string text)
    {
        text = CookieValue().Replace(text, "$1=<скрыто>");
        text = HeaderSecret().Replace(text, "$1<скрыто>");
        return TokenXml().Replace(text, "<$1><скрыто></$1>");
    }

    [GeneratedRegex(@"(webvpn[a-z_]*|acSamlv2Token|acSamlv2Error|SAMLResponse|openconnect_strapkey)=[^;\s""&]+", RegexOptions.IgnoreCase)]
    private static partial Regex CookieValue();

    [GeneratedRegex(@"((?:X-DTLS-Session-ID|X-DTLS-Master-Secret|X-DTLS12-Master-Secret|Set-Cookie|Cookie|X-CSTP-Post-Auth-XML|X-AnyConnect-STRAP-[A-Za-z-]+):\s*)\S.*", RegexOptions.IgnoreCase)]
    private static partial Regex HeaderSecret();

    [GeneratedRegex(@"<(sso-token|session-token|session-id|opaque[^>]*)>[^<]*</[^>]+>", RegexOptions.IgnoreCase)]
    private static partial Regex TokenXml();

    [GeneratedRegex(@"\b(CSD|HostScan|host-scan|trojan)\b", RegexOptions.IgnoreCase)]
    private static partial Regex HostScanPattern();
}
