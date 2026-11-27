using Microsoft.Extensions.Logging;
using SplitVpn.Core.Settings;
using SplitVpn.Windows.Native;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Coordination;

/// <summary>
/// Разрыв RAS-соединения без долгой остановки очереди актора. RasHangUp возвращается сразу, а RAS отпускает соединение
/// когда успеет (RasClient ждёт этого до 15 с). Очередь ждёт не дольше <see cref="ActorHangUpWait"/>; остаток ожидания
/// идёт в фоне, а его итог приходит в очередь событием <see cref="OnHangUpFinishedAsync"/>. Пока RAS не отпустил
/// соединение, запись считается занятой: её туннель не дозванивается и не подхватывает этот сеанс заново.
/// Снятие защиты (<see cref="TeardownAsync"/>) по-прежнему ждёт разрыва целиком: маршруты, DNS и фильтры снимаются
/// только после того, как сеансов нет.
/// </summary>
public sealed partial class Coordinator
{
    /// <summary>
    /// Сколько очередь ждёт, пока RAS отпустит соединение. Обычно это доли секунды; дольше — ожидание уходит в фон.
    /// Заметно короче срока закрепления DNS (<see cref="PinApplyTimeout"/>): закрепление, вставшее в очередь за
    /// разрывом, успевает примениться.
    /// </summary>
    internal static readonly TimeSpan ActorHangUpWait = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Разрыв, который RAS ещё не завершил. <paramref name="Tracked"/> — это был сеанс туннеля (<see cref="TunnelFacts.Connection"/>):
    /// если RAS его так и не отпустит, туннель снова получает это соединение с отметкой <see cref="TunnelFacts.HangUpPending"/>,
    /// как при отказе синхронного разрыва. Остатки (мёртвое соединение, сеанс положенного туннеля, чужие параметры
    /// входа) при отказе ничего не возвращают: их, как и раньше, уберёт следующая сверка или дозвон записи, - кроме
    /// остатков туннеля, чей профиль выключен или удалён: такой туннель ждёт итога разрыва и получает сеанс обратно.
    /// </summary>
    internal sealed record PendingRelease(Guid? ProfileId, string EntryName, string Name, bool Tracked);

    /// <summary>Разрывы, ожидание которых идёт в фоне. Только из очереди актора.</summary>
    private readonly Dictionary<RasConnectionHandle, PendingRelease> _releasing = [];

    /// <summary>
    /// Соединения, которые RAS уже однажды не отпустил за свой срок (handle → имя записи). Повторный разрыв такого
    /// соединения ждётся целиком, как до выноса ожидания из очереди: отказ возвращается вызывающему (сверке — с растущей
    /// паузой неполного применения), а не уходит снова в фон по кругу раз в ~16 с без паузы и с ложной записью «разорвано».
    /// Только из очереди актора.
    /// </summary>
    private readonly Dictionary<RasConnectionHandle, string> _releaseRefused = [];

    /// <summary>Для тестов и диагностики: сколько разрывов RAS ещё не завершил.</summary>
    internal int ReleasingCount => _releasing.Count;

    /// <summary>Сеанс записи этого туннеля ещё разрывается: новый дозвон дал бы второй сеанс той же записи (756).</summary>
    private bool IsReleasing(Guid profileId) => _releasing.Values.Any(r => r.ProfileId == profileId);

    /// <summary>Это соединение — то, которое служба сама разрывает: подхватывать или разрывать его заново не нужно.</summary>
    private bool IsReleasing(RasActiveConnection connection) =>
        _releasing.TryGetValue(connection.Handle, out var release)
        && string.Equals(release.EntryName, connection.EntryName, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// RasHangUp и короткое ожидание освобождения. Отказ самого RasHangUp и сбой, пришедший за это ожидание, выходят
    /// наружу, как раньше. Не успел RAS — разрыв считается начатым: вызывающий продолжает так, будто сеанса нет, а
    /// повторный дозвон записи ждёт события завершения.
    /// </summary>
    private async Task HangUpConnectionAsync(RasConnectionHandle handle, PendingRelease release, CancellationToken cancellationToken)
    {
        // Сверяется и запись: значение handle система может отдать новому соединению другой записи, пока итог
        // прежнего разрыва ещё в очереди, - разрыв нового соединения пропускать нельзя.
        if (_releasing.TryGetValue(handle, out var pending)
            && string.Equals(pending.EntryName, release.EntryName, StringComparison.OrdinalIgnoreCase))
        {
            // RasHangUp этого соединения уже вызван, его итог придёт событием.
            return;
        }

        if (_releaseRefused.TryGetValue(handle, out var refused)
            && string.Equals(refused, release.EntryName, StringComparison.OrdinalIgnoreCase))
        {
            // RAS это соединение уже не отпустил: повтор ждётся целиком, отказ выходит наружу (редкий путь).
            await _deps.Ras.HangUpAsync(handle, cancellationToken);
            _releaseRefused.Remove(handle);
            return;
        }

        // Ожидание в RasClient не привязано к сроку работы очереди: оно доходит до конца и в фоне.
        var hangUp = _deps.Ras.HangUpAsync(handle, CancellationToken.None);
        if (!hangUp.IsCompleted)
        {
            using var wait = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var limit = Task.Delay(ActorHangUpWait, _deps.Time, wait.Token);
            await Task.WhenAny(hangUp, limit);
            await wait.CancelAsync();
            if (!hangUp.IsCompleted)
            {
                DeferRelease(handle, release, hangUp);
                // Остановка службы проходит насквозь, как прежде из ожидания RasClient: RasHangUp уже вызван.
                cancellationToken.ThrowIfCancellationRequested();
                return;
            }
        }

        await hangUp;
    }

    private void DeferRelease(RasConnectionHandle handle, PendingRelease release, Task hangUp)
    {
        _releasing[handle] = release;
        _deps.Logger.LogInformation("RAS не отпустил соединение {Name} (handle {Handle}) за {Wait} мс: ожидание разрыва продолжается вне очереди",
            release.Name, handle, (int)ActorHangUpWait.TotalMilliseconds);
        _ = hangUp.ContinueWith(
            done => TryEnqueue("HangUpFinished", () => OnHangUpFinishedAsync(handle, release, done.Exception?.GetBaseException(), CancellationToken.None)),
            CancellationToken.None, TaskContinuationOptions.None, TaskScheduler.Default);
    }

    /// <summary>
    /// Итог фонового ожидания разрыва. Успех освобождает запись для дозвона. Отказ (RAS не отпустил соединение за свой
    /// срок) для сеанса туннеля возвращает прежнее поведение синхронного разрыва: соединение снова за туннелем, разрыв
    /// повторит сверка (<see cref="RetryPendingHangUpAsync"/>), новый дозвон поверх него не начинается.
    /// </summary>
    internal async Task OnHangUpFinishedAsync(RasConnectionHandle handle, PendingRelease release, Exception? failure, CancellationToken cancellationToken)
    {
        if (!_releasing.TryGetValue(handle, out var current) || current != release)
        {
            return;
        }

        _releasing.Remove(handle);
        // Отметки отказа исчезнувших соединений не копятся.
        foreach (var gone in _releaseRefused.Keys.Where(ConnectionGone).ToList())
        {
            _releaseRefused.Remove(gone);
        }

        if (failure is null)
        {
            _releaseRefused.Remove(handle);
            _deps.Logger.LogInformation("Соединение {Name} (handle {Handle}) разорвано: RAS его отпустил", release.Name, handle);
        }
        else if (ConnectionGone(handle))
        {
            _deps.Logger.LogInformation(failure, "Соединение {Name} (handle {Handle}): ожидание разрыва не удалось, но соединения уже нет", release.Name, handle);
        }
        else
        {
            _deps.Logger.LogWarning(failure, "Соединение {Name} (handle {Handle}) не отпущено RAS", release.Name, handle);
            // Следующий разрыв этого соединения ждётся целиком (HangUpConnectionAsync, RetryPendingHangUpAsync).
            _releaseRefused[handle] = release.EntryName;
            // Сеанс выключенного или удалённого профиля возвращается туннелю, даже если разрыв не был его сеансом:
            // туннель ещё ждёт итога (SyncTunnelsAsync), и без владельца живой сеанс остался бы висеть.
            if (release.ProfileId is { } id && Facts.Tunnels.GetValueOrDefault(id) is { } tunnel
                && (release.Tracked || ActiveProfiles.All(p => p.Id != id))
                && tunnel is { Connection: null, Dialing: false } && VpnProtocols.UsesRas(tunnel.Protocol)
                && string.Equals(tunnel.EntryName, release.EntryName, StringComparison.OrdinalIgnoreCase))
            {
                // Интерфейса и маршрутов у сеанса уже нет: трафик через него не идёт, а сверка повторит разрыв.
                tunnel.Connection = handle;
                tunnel.HangUpPending = true;
                Journal("Ошибка", $"Не удалось разорвать соединение «{tunnel.Name}»: {failure.Message}. Повтор на следующей сверке.");
            }
        }

        await ReconcileAsync(cancellationToken);
    }

    /// <summary>Соединение исчезло. Состояние не читается — считаем, что оно ещё есть: повтор разрыва безвреден.</summary>
    private bool ConnectionGone(RasConnectionHandle handle)
    {
        try
        {
            return _deps.Ras.GetStatus(handle) == RasConnectionStatus.Gone;
        }
        catch (NativeCallException)
        {
            return false;
        }
    }
}
