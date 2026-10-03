using SplitVpn.Core.Ipc;
using SplitVpn.Core.State;

namespace SplitVpn.Service.Coordination;

public sealed partial class Coordinator
{
    // Неизменяемая запись публикуется отдельно от снимка статуса: IPC видит новый этап,
    // даже когда очередь актора заблокирована синхронным вызовом WFP или маршрутов.
    private volatile ServiceProgressDto? _workProgress;

    internal void SetProgress(string stage, int percent) => _workProgress = new ServiceProgressDto
    {
        Stage = stage,
        Percent = percent,
        StartedUtc = _deps.Time.GetUtcNow(),
    };

    internal void ClearProgress() => _workProgress = null;

    internal void ReportItems(string stage, int completed, int total)
    {
        var previous = _workProgress;
        _workProgress = new ServiceProgressDto
        {
            Stage = stage,
            Completed = completed,
            Total = total,
            Percent = total > 0 ? (int)(100L * completed / total) : 100,
            StartedUtc = previous?.Stage == stage ? previous.StartedUtc : _deps.Time.GetUtcNow(),
        };
    }

    private void ReportFilterItems(string stage, int completed, int total)
    {
        if (completed == total && total > 0)
        {
            // Все вызовы добавления/удаления выполнены, но фиксация транзакции BFE
            // сама может занять секунды. Этот этап нельзя выдавать за завершённую защиту.
            _workProgress = new ServiceProgressDto
            {
                Stage = "Сохранение правил защиты",
                StartedUtc = _deps.Time.GetUtcNow(),
            };
            return;
        }

        ReportItems(stage, completed, total);
    }

    private ServiceProgressDto? CurrentProgress(ServiceProgressDto? fallback)
    {
        var progress = _workProgress ?? fallback;
        return progress is null ? null : progress with
        {
            ElapsedSeconds = progress.StartedUtc is { } started
                ? (int)Math.Clamp((_deps.Time.GetUtcNow() - started).TotalSeconds, 0, int.MaxValue) : 0,
        };
    }

    private ServiceProgressDto? ConnectionProgress()
    {
        if (_state.Intent != Intent.Connected || _state.ProtectionSuspended) { return null; }
        var active = Facts.Tunnels.Values.Where(t => !t.Paused).ToList();
        var dialing = active.Where(t => t.Dialing || t.AnyConnect is not null && !t.IsUp && t.SignIn is null).ToList();
        if (dialing.Count > 0)
        {
            return new ServiceProgressDto
            {
                Stage = "Ожидание VPN-сервера: " + string.Join(", ", dialing.Select(t => t.Name)),
                StartedUtc = dialing.Select(t => t.AnyConnect is not null
                    ? t.AnyConnectStartedUtc ?? _deps.Time.GetUtcNow()
                    : t.DialStartedUtc ?? _deps.Time.GetUtcNow()).Min(),
            };
        }

        var verifying = active.Where(t => t.IsUp && !t.Verified).ToList();
        if (verifying.Count > 0)
        {
            return new ServiceProgressDto
            {
                Stage = "Проверка подключения: " + string.Join(", ", verifying.Select(t => t.Name)),
                StartedUtc = verifying.Select(t => t.SessionStartedUtc ?? _deps.Time.GetUtcNow()).Min(),
            };
        }

        var signIn = active.Where(t => t.SignIn is not null).ToList();
        return signIn.Count == 0 ? null : new ServiceProgressDto
        {
            Stage = "Ожидание входа: " + string.Join(", ", signIn.Select(t => t.Name)),
        };
    }
}
