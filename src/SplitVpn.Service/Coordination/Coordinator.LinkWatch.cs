using System.Globalization;
using SplitVpn.Core.State;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Coordination;

/// <summary>
/// Контроль работающего сеанса RAS (SSTP, IKEv2, L2TP). Соединение с сервером может зависнуть, не закрываясь:
/// провайдер перестаёт пропускать пакеты, а Windows узнаёт об этом только по исчерпанию повторов TCP - через
/// 60-75 секунд (код 829). Всё это время трафик через туннель стоит. Служба замечает тишину сама: если от сервера
/// не пришло ни байта, через туннель уходит проба к контрольной цели; несколько проб подряд без ответа - сеанс
/// разрывается и сразу поднимается заново.
/// </summary>
public sealed partial class Coordinator
{
    /// <summary>Как часто проверяется, пришли ли от сервера новые данные.</summary>
    internal static readonly TimeSpan LinkWatchInterval = TimeSpan.FromSeconds(5);

    /// <summary>Пауза перед повторной пробой после неудачной.</summary>
    internal static readonly TimeSpan LinkWatchRetry = TimeSpan.FromSeconds(1);

    /// <summary>Сколько ждать ответа пробы. Короче обычной проверки готовности: сеанс уже работал, задержка известна.</summary>
    internal static readonly TimeSpan LinkWatchProbeTimeout = TimeSpan.FromSeconds(3);

    /// <summary>Сколько проб подряд должно не пройти, чтобы сеанс был разорван. Одна потерянная проба его не рвёт.</summary>
    internal const int LinkWatchFailureLimit = 2;

    /// <summary>
    /// Проверка идёт только у проверенного сеанса RAS, которому политика отдала контрольную иностранную цель.
    /// Пока от сервера приходят данные, проба не нужна и лишний трафик не создаётся.
    /// </summary>
    private bool StartLinkWatch()
    {
        if (_state.Intent != Intent.Connected || Facts.ProfileTestRunning || Facts.Primary is null)
        {
            return false;
        }

        var now = _deps.Time.GetUtcNow();
        foreach (var tunnel in Facts.Tunnels.Values.Where(t => t is { Connection: not null, Verified: true, LinkWatchRunning: false, HangUpPending: false }).ToList())
        {
            if (now < tunnel.NextLinkWatchAt || tunnel.Adapter is not { IsUp: true, Addresses.Count: > 0 } adapter)
            {
                continue;
            }

            var received = tunnel.Statistics?.BytesReceived;
            // Первая проверка сеанса только запоминает счётчик: сравнивать его ещё не с чем.
            var silent = received == tunnel.LinkWatchReceived;
            tunnel.LinkWatchReceived = received;
            if (!silent)
            {
                // Данные от сервера идут: связь есть.
                tunnel.LinkWatchFailures = 0;
                tunnel.NextLinkWatchAt = now + LinkWatchInterval;
                continue;
            }

            var targets = ForeignTargetsOf(tunnel);
            if (targets.Count == 0)
            {
                tunnel.NextLinkWatchAt = now + LinkWatchInterval;
                continue;
            }

            tunnel.LinkWatchRunning = true;
            var profileId = tunnel.ProfileId;
            var handle = tunnel.Connection!.Value;
            var name = tunnel.Name;
            var addresses = adapter.Addresses;
            var sessionToken = (tunnel.LinkWatchCancellation ??= new CancellationTokenSource()).Token;
            _ = Task.Run(async () =>
            {
                var alive = false;
                try
                {
                    using var limit = CancellationTokenSource.CreateLinkedTokenSource(sessionToken);
                    limit.CancelAfter(LinkWatchProbeTimeout);
                    alive = await ProbeAsync(targets, addresses, limit.Token);
                }
                catch (OperationCanceledException) when (sessionToken.IsCancellationRequested) { return; }
                catch (OperationCanceledException) { }
                catch (Exception ex)
                {
                    _deps.Logger.LogWarning(ex, "Контроль связи «{Name}» прерван", name);
                }

                if (sessionToken.IsCancellationRequested)
                {
                    return;
                }

                await EnqueueAsync("LinkWatch", () => OnLinkWatchAsync(profileId, handle, alive, CancellationToken.None));
            });
        }

        // Сверка не нужна: результат придёт в очередь отдельным событием.
        return false;
    }

    internal async Task OnLinkWatchAsync(Guid profileId, RasConnectionHandle handle, bool alive, CancellationToken cancellationToken)
    {
        if (Facts.Tunnels.GetValueOrDefault(profileId) is not { } tunnel || tunnel.Connection != handle)
        {
            return;
        }

        var now = _deps.Time.GetUtcNow();
        tunnel.LinkWatchRunning = false;
        if (tunnel.HangUpPending)
        {
            // Сеанс уже решено разорвать: разрыв повторяет сверка, проба ничего не добавляет.
            return;
        }

        if (alive || !tunnel.Verified || _state.Intent != Intent.Connected)
        {
            tunnel.LinkWatchFailures = 0;
            tunnel.NextLinkWatchAt = now + LinkWatchInterval;
            return;
        }

        if (++tunnel.LinkWatchFailures < LinkWatchFailureLimit)
        {
            tunnel.NextLinkWatchAt = now + LinkWatchRetry;
            _deps.Logger.LogInformation("«{Name}»: данных от сервера нет, проба через туннель не прошла ({Attempt} из {Total})",
                tunnel.Name, tunnel.LinkWatchFailures, LinkWatchFailureLimit);
            return;
        }

        // Устойчивый сеанс переподключается сразу и с первой попытки; короткий идёт по растущей паузе,
        // иначе неработающее подключение дозванивалось бы по кругу каждые несколько секунд.
        var stable = tunnel.WasStableSession(now);
        Journal("Ошибка", $"«{tunnel.Name}»: соединение зависло - данных от сервера нет, пробы через туннель без ответа. Переподключение.");
        // Отметка обрыва и срок дозвона - до разрыва: исключение из него не должно их пропустить, иначе новый
        // сеанс не ждал бы ServerHoldWindow, а дозвон шёл бы без паузы. До сервера разрыв по зависшему соединению
        // мог не дойти: он ещё держит прежний сеанс.
        tunnel.UncleanDropUtc = now;
        TimeSpan? delay = null;
        if (stable)
        {
            tunnel.ResetRetries();
            tunnel.NextDialAt = now;
        }
        else
        {
            delay = ScheduleRetry(tunnel, now);
        }

        // Отказ RasHangUp не повторяет счёт: туннель ждёт повтора разрыва, контроль связи его больше не пробует.
        await HangUpOrDeferAsync(tunnel, "соединение зависло", cancellationToken);
        if (delay is { } wait)
        {
            Journal("Сведения", string.Create(CultureInfo.InvariantCulture, $"«{tunnel.Name}»: следующая попытка через {wait.TotalSeconds:F0} с."));
        }

        await ReconcileAsync(cancellationToken);
    }
}
