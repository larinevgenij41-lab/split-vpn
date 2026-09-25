using System.Text.Json;
using SplitVpn.Core.Ipc;

namespace SplitVpn.App.Services;

/// <summary>
/// Соединение со службой. Запросы идут по отдельным каналам, чтобы долгие команды не задерживали опрос:
/// <list type="bullet">
/// <item>опрос — состояние и журнал событий: частые и дешёвые, никогда не ждут команду;</item>
/// <item>чтение — настройки, адаптеры, отчёт: не ждут команду и не задерживают опрос;</item>
/// <item>проверка адреса и вход AnyConnect — короткие запросы пользователя, не ждут долгих команд;</item>
/// <item>команды — всё, что меняет состояние службы, по одной за раз;</item>
/// <item>пробный дозвон и «Восстановить сеть» — своё соединение на каждый запрос.</item>
/// </list>
/// Каждый канал переподключается при следующем запросе после разрыва. У каждого запроса предел ожидания
/// по его типу (<see cref="RequestTimeouts"/>): зависшая служба не замораживает интерфейс. Все ошибки связи
/// превращаются в <see cref="ServiceUnavailableException"/> с причиной, по которой интерфейс подбирает текст
/// и частоту повторных попыток.
/// </summary>
public sealed class ServiceConnection : IDisposable
{
    public const string ServiceName = "SplitVpn";

    /// <summary>Открытие канала: остановленная служба должна обнаруживаться быстро.</summary>
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(2);

    /// <summary>Проверка версии при подключении — обычный запрос состояния, занятая служба успевает ответить.</summary>
    private static readonly TimeSpan VerifyTimeout = RequestTimeouts.Query;

    private readonly Lane _poll = new();
    private readonly Lane _reads = new();
    private readonly Lane _signIn = new();
    private readonly Lane _commands = new();

    public bool IsAvailable { get; private set; }

    public string? LastError { get; private set; }

    public ServiceUnavailableReason? LastReason { get; private set; }

    public async Task<IpcResponse> SendAsync(IpcRequest request, CancellationToken cancellationToken = default)
    {
        var timeout = RequestTimeouts.For(request);
        if (request is TestProfileRequest or RecoverNetworkRequest)
        {
            // Пробный дозвон длится до минуты, а «Восстановить сеть» — аварийная команда: у каждого запроса
            // своё соединение, чтобы они не стояли в очереди за «Подключить» и не задерживали её сами.
            return await GuardAsync(async () =>
            {
                await using var separate = await IpcClient.ConnectAsync(ServiceName, ConnectTimeout, VerifyTimeout, cancellationToken);
                return await separate.SendAsync(request, timeout, cancellationToken);
            }, drop: null);
        }

        var lane = request switch
        {
            GetStatusRequest or GetEventsRequest => _poll,
            GetSettingsRequest or GetAdaptersRequest or ExportReportRequest => _reads,
            CheckAddressRequest or BeginSignInRequest or SsoNavigationRequest or SubmitAuthFormRequest or CancelSignInRequest => _signIn,
            _ => _commands,
        };

        // Ожидание своей очереди входит в предел запроса: очередь не копится бесконечно за зависшим запросом.
        using var waiting = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        waiting.CancelAfter(timeout);
        try
        {
            await lane.Gate.WaitAsync(waiting.Token);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            return await GuardAsync(() => Task.FromException<IpcResponse>(new ServiceUnavailableException(
                $"Служба не ответила за {timeout.TotalSeconds:0} с: предыдущий запрос ещё выполняется.", ex, ServiceUnavailableReason.Timeout)), drop: null);
        }

        try
        {
            return await GuardAsync(async () =>
            {
                lane.Client ??= await IpcClient.ConnectAsync(ServiceName, ConnectTimeout, VerifyTimeout, cancellationToken);
                return await lane.Client.SendAsync(request, timeout, cancellationToken);
            }, drop: lane);
        }
        finally
        {
            lane.Gate.Release();
        }
    }

    /// <summary>Запрос с результатом; отказ службы — исключение с её текстом.</summary>
    public async Task<T> RequestAsync<T>(IpcRequest request, CancellationToken cancellationToken = default)
    {
        var response = await SendAsync(request, cancellationToken);
        return response.Ok
            ? response.ResultAs<T>()!
            : throw new ServiceCommandException(response.ErrorMessage ?? response.ErrorCode ?? "Служба отклонила запрос.");
    }

    /// <summary>Команда без результата; отказ службы — исключение с её текстом.</summary>
    public async Task<IpcResponse> CommandAsync(IpcRequest request, CancellationToken cancellationToken = default)
    {
        var response = await SendAsync(request, cancellationToken);
        return response.Ok ? response : throw new ServiceCommandException(response.ErrorMessage ?? response.ErrorCode ?? "Служба отклонила запрос.");
    }

    public void Dispose()
    {
        _poll.Dispose();
        _reads.Dispose();
        _signIn.Dispose();
        _commands.Dispose();
    }

    private async Task<IpcResponse> GuardAsync(Func<Task<IpcResponse>> send, Lane? drop)
    {
        try
        {
            var response = await send();
            IsAvailable = true;
            LastError = null;
            LastReason = null;
            return response;
        }
        catch (Exception ex) when (ex is ServiceUnavailableException or UnauthorizedAccessException or IpcProtocolException or JsonException)
        {
            var unavailable = ex as ServiceUnavailableException ?? Wrap(ex);
            if (drop is not null)
            {
                // После таймаута или ошибки протокола кадры в канале рассинхронизированы — соединение закрывается.
                await drop.DropAsync();
            }

            IsAvailable = false;
            LastError = unavailable.Message;
            LastReason = unavailable.Reason;
            throw unavailable;
        }
        catch (OperationCanceledException)
        {
            // Отмена пользователем тоже прерывает кадр. Следующий запрос открывает новый канал.
            if (drop is not null)
            {
                await drop.DropAsync();
            }

            throw;
        }
    }

    private static ServiceUnavailableException Wrap(Exception ex) => ex switch
    {
        JsonException => new ServiceUnavailableException("Ответ службы не распознан: версии приложения и службы не совпадают.", ex, ServiceUnavailableReason.VersionMismatch),
        UnauthorizedAccessException => new ServiceUnavailableException("Канал управления открыт не службой «Раздельный VPN».", ex, ServiceUnavailableReason.Untrusted),
        _ => new ServiceUnavailableException(ex.Message, ex),
    };

    /// <summary>Канал запросов: своё соединение и своя очередь, по одному запросу за раз.</summary>
    private sealed class Lane : IDisposable
    {
        public SemaphoreSlim Gate { get; } = new(1, 1);

        public IpcClient? Client { get; set; }

        public async Task DropAsync()
        {
            if (Client is { } client)
            {
                Client = null;
                await client.DisposeAsync();
            }
        }

        public void Dispose()
        {
            Client?.DisposeAsync().AsTask().GetAwaiter().GetResult();
            Gate.Dispose();
        }
    }
}

public sealed class ServiceCommandException(string message) : Exception(message);
