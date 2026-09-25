using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace SplitVpn.Core.Ipc;

/// <summary>Почему служба недоступна: от причины зависят текст для пользователя, совет и частота повторных попыток.</summary>
public enum ServiceUnavailableReason
{
    /// <summary>Канал не открывается или закрылся: служба не запущена или перезапускается.</summary>
    NotRunning,

    /// <summary>Канал открыт, но ответа нет дольше отведённого времени.</summary>
    Timeout,

    /// <summary>Служба отвечает, но отказывает: пользователь не администратор.</summary>
    Denied,

    /// <summary>Версии контракта приложения и службы не совпадают.</summary>
    VersionMismatch,

    /// <summary>Имя канала занято не службой: команды отправлять нельзя.</summary>
    Untrusted,
}

public sealed class ServiceUnavailableException(string message, Exception? inner = null, ServiceUnavailableReason reason = ServiceUnavailableReason.NotRunning)
    : Exception(message, inner)
{
    public ServiceUnavailableReason Reason { get; } = reason;
}

/// <summary>Предел ожидания ответа по типу запроса: зависшая служба не должна замораживать интерфейс.</summary>
public static class RequestTimeouts
{
    public static readonly TimeSpan Query = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan Lookup = TimeSpan.FromSeconds(15);

    /// <summary>Аварийное восстановление идёт по своему соединению, но в очереди актора может ждать долгую сверку.</summary>
    public static readonly TimeSpan Recover = TimeSpan.FromSeconds(20);
    public static readonly TimeSpan Command = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan Test = TimeSpan.FromSeconds(120);

    public static TimeSpan For(IpcRequest request) => request switch
    {
        GetStatusRequest or GetEventsRequest or GetAdaptersRequest or GetSettingsRequest or ExportReportRequest => Query,
        CheckAddressRequest or SsoNavigationRequest or SubmitAuthFormRequest or CancelSignInRequest or BeginSignInRequest => Lookup,
        RecoverNetworkRequest => Recover,
        TestProfileRequest => Test,
        _ => Command,
    };
}

/// <summary>
/// Клиент канала управления службой. Перед отправкой команд проверяет сервер канала через SCM: процесс
/// сервера — это процесс службы, запущенной от LocalSystem из Program Files. Обычный процесс пользователя
/// не может ни зарегистрировать службу, ни писать в Program Files, поэтому занять имя канала до запуска
/// службы и перехватить пароль он не сможет. Открывать сам процесс службы не нужно: из неповышенного
/// токена это запрещено.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class IpcClient : IAsyncDisposable
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryConfig = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const int ScStatusProcessInfo = 0;
    private const int ErrorInsufficientBuffer = 122;

    private readonly NamedPipeClientStream _pipe;
    private readonly SemaphoreSlim _lock = new(1, 1);

    internal IpcClient(NamedPipeClientStream pipe)
    {
        _pipe = pipe;
    }

    public static Task<IpcClient> ConnectAsync(string serviceName, TimeSpan timeout, CancellationToken cancellationToken) =>
        ConnectAsync(serviceName, timeout, timeout, cancellationToken);

    /// <summary>
    /// Подключение с раздельными пределами: открытие канала короткое (остановленная служба видна быстро),
    /// проверка совместимости версий — как обычный запрос состояния (занятая служба успевает ответить).
    /// </summary>
    public static async Task<IpcClient> ConnectAsync(string serviceName, TimeSpan connectTimeout, TimeSpan verifyTimeout, CancellationToken cancellationToken)
    {
        var pipe = OpenPipe();
        try
        {
            await pipe.ConnectAsync(connectTimeout, cancellationToken);
            VerifyServer(pipe, serviceName);
            var client = new IpcClient(pipe);
            var response = await client.SendAsync(new GetStatusRequest(), verifyTimeout, cancellationToken);
            if (!response.Ok && response.ErrorCode == IpcErrorCodes.Denied)
            {
                throw new ServiceUnavailableException("Управлять службой может только администратор компьютера.", null, ServiceUnavailableReason.Denied);
            }

            if (!response.Ok || !ContractMatches(response))
            {
                throw new ServiceUnavailableException("Версия приложения несовместима со службой. Обновите приложение и службу вместе.", null, ServiceUnavailableReason.VersionMismatch);
            }

            return client;
        }
        catch (ServiceUnavailableException)
        {
            await pipe.DisposeAsync();
            throw;
        }
        catch (UnauthorizedAccessException ex)
        {
            await pipe.DisposeAsync();
            throw new ServiceUnavailableException("Канал управления открыт не службой «Раздельный VPN»: " + ex.Message, ex, ServiceUnavailableReason.Untrusted);
        }
        catch (Exception ex) when (ex is TimeoutException or IOException)
        {
            await pipe.DisposeAsync();
            throw new ServiceUnavailableException("Служба «Раздельный VPN» недоступна.", ex);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            await pipe.DisposeAsync();
            throw new ServiceUnavailableException("Служба не ответила на проверку совместимости версий.", ex, ServiceUnavailableReason.Timeout);
        }
        catch
        {
            await pipe.DisposeAsync();
            throw;
        }
    }

    /// <summary>Ответ чужой версии может и не разбираться в StatusDto — это тоже несовпадение версий.</summary>
    private static bool ContractMatches(IpcResponse response)
    {
        try
        {
            return response.ResultAs<StatusDto>()?.ContractVersion == IpcNames.ContractVersion;
        }
        catch (System.Text.Json.JsonException)
        {
            return false;
        }
    }

    /// <summary>
    /// Канал с минимальными правами. PipeDirection.InOut запрашивает GENERIC_WRITE, куда входят создание
    /// экземпляра канала и запись атрибутов, — их ACL службы интерактивным пользователям не даёт.
    /// </summary>
    public static NamedPipeClientStream OpenPipe() => new(".", IpcNames.PipeName,
        PipeAccessRights.ReadData | PipeAccessRights.WriteData | PipeAccessRights.ReadAttributes | PipeAccessRights.Synchronize,
        PipeOptions.Asynchronous, TokenImpersonationLevel.Identification, HandleInheritability.None);

    public Task<IpcResponse> SendAsync(IpcRequest request, CancellationToken cancellationToken) =>
        SendAsync(request, Timeout.InfiniteTimeSpan, cancellationToken);

    /// <summary>
    /// Запрос с пределом ожидания. При прерывании обмена канал закрывается: поздний ответ на
    /// брошенный запрос не должен достаться следующему. Вызывающий создаёт новое соединение.
    /// </summary>
    public async Task<IpcResponse> SendAsync(IpcRequest request, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        using var timed = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (timeout != Timeout.InfiniteTimeSpan)
        {
            timed.CancelAfter(timeout);
        }

        try
        {
            await _lock.WaitAsync(timed.Token);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw new ServiceUnavailableException($"Служба не ответила за {timeout.TotalSeconds:0} с.", ex, ServiceUnavailableReason.Timeout);
        }

        try
        {
            await FrameCodec.WriteAsync(_pipe, IpcSerializer.SerializeRequest(request), timed.Token);
            var payload = await FrameCodec.ReadAsync(_pipe, timed.Token)
                ?? throw new ServiceUnavailableException("Служба закрыла канал.");
            return IpcSerializer.DeserializeResponse(payload);
        }
        catch (IOException ex)
        {
            throw new ServiceUnavailableException("Связь со службой прервана.", ex);
        }
        catch (OperationCanceledException ex)
        {
            await _pipe.DisposeAsync();
            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }

            throw new ServiceUnavailableException($"Служба не ответила за {timeout.TotalSeconds:0} с.", ex, ServiceUnavailableReason.Timeout);
        }
        finally
        {
            _lock.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _pipe.DisposeAsync();
        _lock.Dispose();
    }

    private static void VerifyServer(NamedPipeClientStream pipe, string serviceName)
    {
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var serverProcessId))
        {
            throw new UnauthorizedAccessException("Не удалось определить процесс сервера канала: " + LastError());
        }

        var service = QueryService(serviceName);
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var trustedLocation = service.ImagePath.StartsWith(programFiles + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        var localSystem = string.Equals(service.StartName, "LocalSystem", StringComparison.OrdinalIgnoreCase);
        if (service.ProcessId == 0 || service.ProcessId != serverProcessId || !trustedLocation || !localSystem)
        {
            throw new UnauthorizedAccessException(
                $"Канал управления открыт не службой «{serviceName}»: процесс канала {serverProcessId}, процесс службы {service.ProcessId}, образ {service.ImagePath}, учётная запись {service.StartName}.");
        }
    }

    private static unsafe (uint ProcessId, string ImagePath, string StartName) QueryService(string serviceName)
    {
        var manager = OpenSCManager(null, null, ScManagerConnect);
        if (manager == 0)
        {
            throw new ServiceUnavailableException("Диспетчер служб недоступен: " + LastError());
        }

        try
        {
            var service = OpenService(manager, serviceName, ServiceQueryConfig | ServiceQueryStatus);
            if (service == 0)
            {
                throw new ServiceUnavailableException($"Служба «{serviceName}» не установлена или недоступна: " + LastError());
            }

            try
            {
                var status = default(ServiceStatusProcess);
                if (!QueryServiceStatusEx(service, ScStatusProcessInfo, (byte*)&status, (uint)sizeof(ServiceStatusProcess), out _))
                {
                    throw new ServiceUnavailableException("Не удалось получить состояние службы: " + LastError());
                }

                var (image, startName) = QueryConfig(service);
                return (status.ProcessId, image, startName);
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    private static unsafe (string ImagePath, string StartName) QueryConfig(nint service)
    {
        QueryServiceConfig(service, null, 0, out var needed);
        if (Marshal.GetLastPInvokeError() != ErrorInsufficientBuffer)
        {
            throw new ServiceUnavailableException("Не удалось прочитать конфигурацию службы: " + LastError());
        }

        var buffer = new byte[needed];
        fixed (byte* pointer = buffer)
        {
            if (!QueryServiceConfig(service, pointer, needed, out _))
            {
                throw new ServiceUnavailableException("Не удалось прочитать конфигурацию службы: " + LastError());
            }

            var config = (QueryServiceConfigW*)pointer;
            return (ExecutablePath(new string(config->BinaryPathName)), new string(config->ServiceStartName));
        }
    }

    /// <summary>Путь исполняемого файла из командной строки службы: в кавычках или до «.exe».</summary>
    internal static string ExecutablePath(string commandLine)
    {
        var trimmed = commandLine.Trim();
        if (trimmed.StartsWith('"'))
        {
            var end = trimmed.IndexOf('"', 1);
            return end > 0 ? trimmed[1..end] : trimmed.Trim('"');
        }

        var exe = trimmed.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        return exe >= 0 ? trimmed[..(exe + 4)] : trimmed;
    }

    private static string LastError() => new Win32Exception(Marshal.GetLastPInvokeError()).Message;

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct QueryServiceConfigW
    {
        public uint ServiceType;
        public uint StartType;
        public uint ErrorControl;
        public char* BinaryPathName;
        public char* LoadOrderGroup;
        public uint TagId;
        public char* Dependencies;
        public char* ServiceStartName;
        public char* DisplayName;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeServerProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe, out uint serverProcessId);

    [LibraryImport("advapi32.dll", EntryPoint = "OpenSCManagerW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint OpenSCManager(string? machineName, string? databaseName, uint desiredAccess);

    [LibraryImport("advapi32.dll", EntryPoint = "OpenServiceW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint OpenService(nint manager, string serviceName, uint desiredAccess);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool QueryServiceStatusEx(nint service, int infoLevel, byte* buffer, uint bufferSize, out uint bytesNeeded);

    [LibraryImport("advapi32.dll", EntryPoint = "QueryServiceConfigW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool QueryServiceConfig(nint service, byte* buffer, uint bufferSize, out uint bytesNeeded);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseServiceHandle(nint handle);
}
