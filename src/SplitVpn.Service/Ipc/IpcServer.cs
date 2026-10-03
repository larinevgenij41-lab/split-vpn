using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Claims;
using System.Security.Principal;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SplitVpn.Core.Diagnostics;
using SplitVpn.Core.Ipc;
using SplitVpn.Service.Coordination;

namespace SplitVpn.Service.Ipc;

/// <summary>
/// Канал управления. ACL: SYSTEM и Administrators — полный доступ, интерактивные пользователи — чтение и
/// запись без создания экземпляров канала, сетевой доступ запрещён. Команды принимаются только от
/// администратора интерактивного сеанса (в том числе с фильтрованным UAC-токеном).
///
/// Имя канала — случайное на каждый запуск и публикуется в HKLM (<see cref="IpcNames"/>): постоянное имя
/// обычный пользователь занял бы до запуска службы. Клиент без прав отсекается сразу после подключения
/// по токену своего процесса, не дожидаясь первого кадра: иначе он держал бы экземпляр канала.
/// </summary>
public sealed class IpcServer(Coordinator coordinator, ILogger<IpcServer> logger) : BackgroundService
{
    internal const int MaxInstances = 16;
    private const int BufferBytes = 64 * 1024;
    /// <summary>
    /// Клиент пишет первый запрос сразу после подключения и проверки сервера через SCM — это миллисекунды,
    /// но при входе в систему (запуск программ, проверка антивирусом, холодный JIT интерфейса) бывает и
    /// больше секунды; три секунды — запас на это. Длиннее не нужно: удержание экземпляров посторонним
    /// процессом таймаут не предотвращает (он переподключается), а опоздавший клиент получает разрыв и
    /// переподключается, как при перезапуске службы.
    /// </summary>
    internal static readonly TimeSpan FirstFrameTimeout = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan CreateRetryDelay = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan WarningInterval = TimeSpan.FromMinutes(10);

    private readonly Dictionary<string, DateTimeOffset> _deniedWarnings = new(StringComparer.OrdinalIgnoreCase);
    private DateTimeOffset _lastCreateWarning = DateTimeOffset.MinValue;

    /// <summary>Имя канала; в тестах — своё, чтобы не пересекаться с установленной службой. Не задано — случайное.</summary>
    internal string? PipeName { get; init; }

    /// <summary>Новое случайное имя канала; в тестах — своё.</summary>
    internal Func<string> NewPipeName { get; init; } = IpcNames.NewPipeName;

    /// <summary>Публикация имени канала для клиентов (HKLM); в тестах — своя.</summary>
    internal Action<string> PublishPipeName { get; init; } = IpcNames.PublishPipeName;

    /// <summary>Сколько новых имён подряд пробуется без паузы, если первый экземпляр канала не создаётся.</summary>
    internal const int MaxBusyNames = 5;

    /// <summary>Проверка клиента до первого кадра: false — отказ, null — не определить. В тестах — своя.</summary>
    internal Func<NamedPipeServerStream, bool?>? Precheck { get; init; }

    /// <summary>ACL канала; в тестах — null (права создателя), иначе процесс без SYSTEM не создаст второй экземпляр.</summary>
    internal Func<PipeSecurity?> Security { get; init; } = CreatePipeSecurity;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Загрузить сборки проверки клиента до первого олицетворения.
        using (var self = WindowsIdentity.GetCurrent())
        {
            _ = IsAllowedCaller(self);
        }

        var clients = new List<Task>();

        // Имя, под которым создан первый экземпляр канала; null — первого экземпляра ещё нет.
        string? name = null;

        // Постоянное имя, которое не меняется и не публикуется: заданное тестом или основное, если реестр недоступен.
        var fixedName = PipeName;
        var busyNames = 0;
        while (!stoppingToken.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            var candidate = name ?? fixedName ?? NewPipeName();
            try
            {
                // Первый экземпляр — только свой: если имя уже занял посторонний процесс, клиентов к нему не делим.
                var options = PipeOptions.Asynchronous | (name is null ? PipeOptions.FirstPipeInstance : PipeOptions.None);
                pipe = NamedPipeServerStreamAcl.Create(candidate, PipeDirection.InOut, MaxInstances, PipeTransmissionMode.Byte,
                    options, BufferBytes, BufferBytes, Security());
                if (name is null && fixedName is null && !Publish(candidate))
                {
                    // Имя не записано в реестр — клиенты его не найдут: основное имя, по которому они идут без записи.
                    fixedName = IpcNames.PipeName;
                    continue;
                }

                // Имя публикуется только после создания первого экземпляра: прочитав его в HKLM, посторонний
                // процесс может подключиться как клиент, но занять имя раньше службы уже не успеет.
                name = candidate;
                busyNames = 0;
                await pipe.WaitForConnectionAsync(stoppingToken);
                clients.RemoveAll(t => t.IsCompleted);
                clients.Add(ServeAsync(pipe, stoppingToken));
                pipe = null;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                if (name is null && fixedName is null && ++busyNames <= MaxBusyNames)
                {
                    // Случайное имя занято — совпадение или подбор. Нигде не опубликованное новое имя подобрать
                    // заранее нельзя, поэтому пробуется сразу, без паузы; серия ограничена, чтобы ошибка, не
                    // зависящая от имени (права, ресурсы), не крутила цикл вхолостую.
                    if (busyNames == 1)
                    {
                        logger.LogWarning(ex, "Канал управления {Pipe} не создан: пробуется новое имя", candidate);
                    }

                    continue;
                }

                // Ошибка одного экземпляра канала — занятое имя, все экземпляры заняты чужими подключениями,
                // клиент, отвалившийся до ConnectNamedPipe, — не должна останавливать приём: иначе вместе с
                // хостом остановился бы и координатор, а защита осталась бы без DNS-посредника.
                busyNames = 0;
                WarnAcceptFailure(ex, name is null, candidate);
                try
                {
                    await Task.Delay(CreateRetryDelay, stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
            finally
            {
                if (pipe is not null)
                {
                    await pipe.DisposeAsync();
                }
            }
        }

        await Task.WhenAll(clients);
    }

    /// <summary>Имя канала для клиентов в реестре; false — не записалось, служба переходит на основное имя.</summary>
    private bool Publish(string name)
    {
        try
        {
            PublishPipeName(name);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            logger.LogError(ex, "Имя канала управления не записано в реестр: используется постоянное {Pipe}", IpcNames.PipeName);
            return false;
        }
    }

    private void WarnAcceptFailure(Exception exception, bool firstInstance, string name)
    {
        var now = DateTimeOffset.UtcNow;
        if (now - _lastCreateWarning < TimeSpan.FromMinutes(1))
        {
            return;
        }

        _lastCreateWarning = now;
        if (firstInstance)
        {
            logger.LogError(exception, "Канал управления не создан (последнее имя {Pipe}): команды не принимаются, повтор каждую секунду", name);
        }
        else
        {
            logger.LogWarning(exception, "Экземпляр канала управления не принял подключение: приём продолжается через секунду");
        }
    }

    internal static PipeSecurity CreatePipeSecurity()
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
            PipeAccessRights.ReadData | PipeAccessRights.WriteData | PipeAccessRights.ReadAttributes | PipeAccessRights.Synchronize,
            AccessControlType.Allow));
        return security;
    }

    /// <summary>Администратор: SID группы Administrators в токене, в том числе как deny-only в фильтрованном UAC-токене.</summary>
    internal static bool IsAllowedCaller(WindowsIdentity identity) =>
        identity.User?.IsWellKnown(WellKnownSidType.LocalSystemSid) == true
        || (IsAdministrator(identity) && identity.Groups?.Contains(InteractiveSid) == true);

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        await using (pipe)
        {
            var trace = new IpcConnectionTrace(DescribeProcess(pipe));
            try
            {
                // Клиент без прав отсекается сразу, по токену процесса: ответ «отказано» уходит до его запроса,
                // клиент прочтёт его и после разрыва (IpcClient), а экземпляр канала освобождается немедленно.
                if ((Precheck ?? (p => PrecheckClientProcess(p, trace)))(pipe) == false)
                {
                    TraceDenied(trace, "по токену процесса до первого кадра");
                    await WriteAsync(pipe, DeniedResponse, cancellationToken);
                    return;
                }

                // Олицетворение клиента канала возможно только после чтения данных: сначала первый кадр, затем
                // окончательная проверка — номер процесса клиента подтверждением прав не служит.
                using var firstFrameTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                firstFrameTimeout.CancelAfter(FirstFrameTimeout);
                var first = await FrameCodec.ReadAsync(pipe, firstFrameTimeout.Token);
                if (first is null)
                {
                    return;
                }

                if (!Authorize(pipe, trace))
                {
                    TraceDenied(trace, "по олицетворению");
                    await WriteAsync(pipe, DeniedResponse, cancellationToken);
                    return;
                }

                if (logger.IsEnabled(LogLevel.Debug))
                {
                    logger.LogDebug("IPC подключение: {Caller}; процесс {Process}", trace.Caller, trace.Process);
                }

                await HandleFrameAsync(pipe, first, trace, cancellationToken);
                await LoopAsync(pipe, trace, cancellationToken);
            }
            catch (Exception ex) when (ex is IOException or IpcProtocolException or OperationCanceledException or ObjectDisposedException)
            {
                logger.LogDebug(ex, "Клиент IPC отключился: {Caller}; процесс {Process}", trace.Caller, trace.Process);
            }
            catch (Exception ex)
            {
                // Неожиданная ошибка одного клиента остаётся его ошибкой: приём продолжается, а задача
                // клиента не уходит в ожидание остановки службы незавершённой.
                logger.LogError(ex, "Ошибка обслуживания клиента IPC");
            }
            finally
            {
                if (trace.HasRequests && logger.IsEnabled(LogLevel.Debug))
                {
                    logger.LogDebug("IPC соединение закрыто: {Caller}; процесс {Process}; {Summary}", trace.Caller, trace.Process, trace.Summary());
                }
            }
        }
    }

    /// <summary>Номер процесса, сеанс Windows и имя образа клиента — для журнала; имя образа только в подробном режиме.</summary>
    private static string DescribeProcess(NamedPipeServerStream pipe)
    {
        uint processId, sessionId;
        try
        {
            (processId, sessionId) = PipeClientIdentity.ProcessAndSession(pipe.SafePipeHandle);
        }
        catch (Exception ex) when (ex is InvalidOperationException or ObjectDisposedException or IOException)
        {
            return "не определён";
        }

        var image = "";
        if (Verbose.IsOn && processId != 0)
        {
            try
            {
                using var process = System.Diagnostics.Process.GetProcessById((int)processId);
                image = " " + process.ProcessName;
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                image = " (процесс завершился)";
            }
        }

        return string.Create(System.Globalization.CultureInfo.InvariantCulture, $"PID {processId}, сеанс {sessionId}{image}");
    }

    /// <summary>
    /// Отказ — в подробный журнал, но не чаще раза в 10 секунд на учётную запись: интерфейс без прав
    /// переподключается постоянно и иначе вытеснил бы из ротации ту историю, ради которой режим включали.
    /// </summary>
    private void TraceDenied(IpcConnectionTrace trace, string stage)
    {
        if (!logger.IsEnabled(LogLevel.Debug))
        {
            return;
        }

        int suppressed;
        lock (_deniedTraces)
        {
            var now = DateTimeOffset.UtcNow;
            _deniedTraces.TryGetValue(trace.Caller, out var entry);
            if (now - entry.Last < DeniedTraceInterval)
            {
                _deniedTraces[trace.Caller] = (entry.Last, entry.Suppressed + 1);
                return;
            }

            suppressed = entry.Suppressed;
            _deniedTraces[trace.Caller] = (now, 0);
        }

        logger.LogDebug("IPC отказ {Stage}: {Caller}; процесс {Process}; причина: {Reason}; с прошлой записи ещё отказов {Suppressed}",
            stage, trace.Caller, trace.Process, trace.DenialReason, suppressed);
    }

    private static readonly TimeSpan DeniedTraceInterval = TimeSpan.FromSeconds(10);

    private readonly Dictionary<string, (DateTimeOffset Last, int Suppressed)> _deniedTraces = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Кто на том конце канала: учётная запись, SID и то, что решает допуск (Administrators и INTERACTIVE).</summary>
    internal static string DescribeAccess(WindowsIdentity identity)
    {
        var admin = !IsAdministrator(identity) ? "нет"
            : identity.Groups?.Any(g => g.Value == AdministratorsSid) == true ? "да"
            : "только запрет (UAC без повышения)";
        var interactive = identity.Groups?.Contains(InteractiveSid) == true ? "да" : "нет";
        return $"{identity.Name} ({identity.User?.Value}), Administrators: {admin}, INTERACTIVE: {interactive}";
    }

    /// <summary>Почему клиенту отказано — словами, для журнала.</summary>
    internal static string DenialReason(WindowsIdentity identity) =>
        !IsAdministrator(identity) ? "учётная запись не входит в группу Administrators"
        : identity.Groups?.Contains(InteractiveSid) != true ? "вход не интерактивный (служба, сеть или пакетное задание)"
        : "не определена";

    private static readonly string AdministratorsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value;

    private static readonly SecurityIdentifier InteractiveSid = new(WellKnownSidType.InteractiveSid, null);

    private static bool IsAdministrator(WindowsIdentity identity) =>
        identity.Groups?.Any(g => g.Value == AdministratorsSid) == true
        || identity.Claims.Any(c => c.Type == ClaimTypes.DenyOnlySid && c.Value == AdministratorsSid);

    private static IpcResponse DeniedResponse => IpcResponse.Failure(IpcErrorCodes.Denied, "Управление службой доступно только администратору компьютера.");

    /// <summary>Токен процесса клиента: только отказ — подтверждение прав остаётся за олицетворением.</summary>
    private bool? PrecheckClientProcess(NamedPipeServerStream pipe, IpcConnectionTrace trace)
    {
        try
        {
            using var client = PipeClientIdentity.TryOpen(pipe.SafePipeHandle);
            if (client is not null)
            {
                trace.Caller = DescribeAccess(client);
            }

            if (client is null || IsAllowedCaller(client))
            {
                return client is null ? null : true;
            }

            trace.DenialReason = DenialReason(client);

            if (ShouldWarnDenied(client.Name))
            {
                logger.LogWarning("Отклонён клиент IPC {User}: не администратор интерактивного сеанса", client.Name);
            }

            return false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or System.Security.SecurityException)
        {
            logger.LogDebug(ex, "Процесс клиента IPC не проверен до первого кадра: {Process}", trace.Process);
            return null;
        }
    }

    private bool Authorize(NamedPipeServerStream pipe, IpcConnectionTrace trace)
    {
        try
        {
            // Под олицетворением токеном уровня Identification поток не может открывать файлы, в том числе
            // загружать сборки. Внутри только снимается токен; разбор групп — после возврата к токену службы.
            WindowsIdentity? client = null;
            pipe.RunAsClient(() => client = WindowsIdentity.GetCurrent(TokenAccessLevels.Query));
            using (client)
            {
                var allowed = client is not null && IsAllowedCaller(client);
                if (client is not null)
                {
                    trace.Caller = DescribeAccess(client);
                    trace.DenialReason = allowed ? "" : DenialReason(client);
                }
                else
                {
                    trace.DenialReason = "токен клиента не получен";
                }

                if (!allowed && ShouldWarnDenied(client?.Name ?? ""))
                {
                    // Пульт без прав опрашивает службу постоянно: одно предупреждение на пользователя за интервал.
                    logger.LogWarning("Отклонён клиент IPC {User}: не администратор интерактивного сеанса", client?.Name);
                }

                return allowed;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            logger.LogWarning(ex, "Не удалось проверить клиента IPC");
            trace.DenialReason = "проверка не удалась: " + ex.Message;
            return false;
        }
    }

    private bool ShouldWarnDenied(string user)
    {
        lock (_deniedWarnings)
        {
            var now = DateTimeOffset.UtcNow;
            if (_deniedWarnings.TryGetValue(user, out var last) && now - last < WarningInterval)
            {
                return false;
            }

            _deniedWarnings[user] = now;
            return true;
        }
    }

    private async Task LoopAsync(NamedPipeServerStream pipe, IpcConnectionTrace trace, CancellationToken cancellationToken)
    {
        while (pipe.IsConnected)
        {
            var payload = await FrameCodec.ReadAsync(pipe, cancellationToken);
            if (payload is null)
            {
                return;
            }

            await HandleFrameAsync(pipe, payload, trace, cancellationToken);
        }
    }

    private async Task HandleFrameAsync(NamedPipeServerStream pipe, byte[] payload, IpcConnectionTrace trace, CancellationToken cancellationToken)
    {
        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        var request = IpcSerializer.TryDeserializeRequest(payload);
        var response = request is null
            ? IpcResponse.Failure(IpcErrorCodes.BadRequest, "Неверный или неизвестный запрос.")
            : await coordinator.SubmitAsync(request, cancellationToken);
        await WriteAsync(pipe, response, cancellationToken);
        if (logger.IsEnabled(LogLevel.Debug) && trace.Record(request, response, System.Diagnostics.Stopwatch.GetElapsedTime(started)) is { } line)
        {
            // Только тип запроса и итог: тело (пароли, cookie SSO, настройки) в журнал не попадает никогда.
            logger.LogDebug("IPC {Line} ← {Caller}", line, trace.Caller);
        }
    }

    private static Task WriteAsync(Stream pipe, IpcResponse response, CancellationToken cancellationToken) =>
        FrameCodec.WriteAsync(pipe, IpcSerializer.SerializeResponse(response), cancellationToken);
}
