using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Claims;
using System.Security.Principal;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SplitVpn.Core.Ipc;
using SplitVpn.Service.Coordination;

namespace SplitVpn.Service.Ipc;

/// <summary>
/// Канал управления. ACL: SYSTEM и Administrators — полный доступ, интерактивные пользователи — чтение и
/// запись без создания экземпляров канала, сетевой доступ запрещён. Команды принимаются только от
/// администратора интерактивного сеанса (в том числе с фильтрованным UAC-токеном).
/// </summary>
public sealed class IpcServer(Coordinator coordinator, ILogger<IpcServer> logger) : BackgroundService
{
    internal const int MaxInstances = 16;
    private const int BufferBytes = 64 * 1024;
    internal static readonly TimeSpan FirstFrameTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan CreateRetryDelay = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan WarningInterval = TimeSpan.FromMinutes(10);

    private readonly Dictionary<string, DateTimeOffset> _deniedWarnings = new(StringComparer.OrdinalIgnoreCase);
    private DateTimeOffset _lastCreateWarning = DateTimeOffset.MinValue;

    /// <summary>Имя канала; в тестах — своё, чтобы не пересекаться с установленной службой.</summary>
    internal string PipeName { get; init; } = IpcNames.PipeName;

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
        var firstInstance = true;
        while (!stoppingToken.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                // Первый экземпляр — только свой: если имя уже занял посторонний процесс, клиентов к нему не делим.
                var options = PipeOptions.Asynchronous | (firstInstance ? PipeOptions.FirstPipeInstance : PipeOptions.None);
                pipe = NamedPipeServerStreamAcl.Create(PipeName, PipeDirection.InOut, MaxInstances, PipeTransmissionMode.Byte,
                    options, BufferBytes, BufferBytes, Security());
                firstInstance = false;
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
                // Ошибка одного экземпляра канала — занятое имя, все экземпляры заняты чужими подключениями,
                // клиент, отвалившийся до ConnectNamedPipe, — не должна останавливать приём: иначе вместе с
                // хостом остановился бы и координатор, а защита осталась бы без DNS-посредника.
                WarnAcceptFailure(ex, firstInstance);
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

    private void WarnAcceptFailure(Exception exception, bool firstInstance)
    {
        var now = DateTimeOffset.UtcNow;
        if (now - _lastCreateWarning < TimeSpan.FromMinutes(1))
        {
            return;
        }

        _lastCreateWarning = now;
        if (firstInstance)
        {
            logger.LogError(exception, "Канал управления {Pipe} уже занят другим процессом: команды не принимаются, повтор каждую секунду", PipeName);
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
    internal static bool IsAllowedCaller(WindowsIdentity identity)
    {
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value;
        var interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);
        if (identity.User?.IsWellKnown(WellKnownSidType.LocalSystemSid) == true)
        {
            return true;
        }

        var isAdministrator = identity.Groups?.Any(g => g.Value == administrators) == true
            || identity.Claims.Any(c => c.Type == ClaimTypes.DenyOnlySid && c.Value == administrators);
        return isAdministrator && identity.Groups?.Contains(interactive) == true;
    }

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        await using (pipe)
        {
            try
            {
                // Олицетворение клиента канала возможно только после чтения данных: сначала первый кадр, затем проверка.
                using var firstFrameTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                firstFrameTimeout.CancelAfter(FirstFrameTimeout);
                var first = await FrameCodec.ReadAsync(pipe, firstFrameTimeout.Token);
                if (first is null)
                {
                    return;
                }

                if (!Authorize(pipe))
                {
                    await WriteAsync(pipe, IpcResponse.Failure(IpcErrorCodes.Denied, "Управление службой доступно только администратору компьютера."), cancellationToken);
                    return;
                }

                await HandleFrameAsync(pipe, first, cancellationToken);
                await LoopAsync(pipe, cancellationToken);
            }
            catch (Exception ex) when (ex is IOException or IpcProtocolException or OperationCanceledException or ObjectDisposedException)
            {
                logger.LogDebug(ex, "Клиент IPC отключился");
            }
            catch (Exception ex)
            {
                // Неожиданная ошибка одного клиента остаётся его ошибкой: приём продолжается, а задача
                // клиента не уходит в ожидание остановки службы незавершённой.
                logger.LogError(ex, "Ошибка обслуживания клиента IPC");
            }
        }
    }

    private bool Authorize(NamedPipeServerStream pipe)
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

    private async Task LoopAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        while (pipe.IsConnected)
        {
            var payload = await FrameCodec.ReadAsync(pipe, cancellationToken);
            if (payload is null)
            {
                return;
            }

            await HandleFrameAsync(pipe, payload, cancellationToken);
        }
    }

    private async Task HandleFrameAsync(NamedPipeServerStream pipe, byte[] payload, CancellationToken cancellationToken)
    {
        var request = IpcSerializer.TryDeserializeRequest(payload);
        var response = request is null
            ? IpcResponse.Failure(IpcErrorCodes.BadRequest, "Неверный или неизвестный запрос.")
            : await coordinator.SubmitAsync(request, cancellationToken);
        await WriteAsync(pipe, response, cancellationToken);
    }

    private static Task WriteAsync(Stream pipe, IpcResponse response, CancellationToken cancellationToken) =>
        FrameCodec.WriteAsync(pipe, IpcSerializer.SerializeResponse(response), cancellationToken);
}
