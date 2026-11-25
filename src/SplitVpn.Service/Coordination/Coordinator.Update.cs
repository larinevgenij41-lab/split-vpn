using SplitVpn.Core.Ipc;
using SplitVpn.Core.Policy;
using SplitVpn.Core.State;
using SplitVpn.Core.Update;

namespace SplitVpn.Service.Coordination;

/// <summary>Обновление самой программы: общее правило выхода в сеть и предупреждения для шапки.</summary>
public sealed partial class Coordinator
{
    /// <summary>
    /// Можно ли сейчас идти в сеть за обновлением списка адресов или программы: защита выключена либо
    /// приостановлена, или «остальной интернет» идёт через проверенный туннель. Иначе фильтры WFP оборвут
    /// запрос, и попытка только потратит срок следующей проверки. Прочие туннели (положенный вручную,
    /// AnyConnect без входа, остановленный ошибкой) запросу не нужны и обновления не держат.
    /// </summary>
    internal bool NetworkPathAllowed =>
        _state.Intent == Intent.Off || _state.ProtectionSuspended
        || EssentialTunnels().Exists(t => t.Verified)
        || DirectPathOpen;

    /// <summary>
    /// «Остальной интернет» идёт напрямую: у него нет носителей, и защита прямой публичный трафик через основной
    /// адаптер не блокирует ни при каком состоянии туннелей. Обрыв (FilterPlanBuilder.IsOutage) определён только
    /// для носителей «остального интернета», поэтому и «блокировать весь публичный» здесь не включается, а при
    /// «отключить VPN, сохранить защиту» прямые назначения по-прежнему разрешены. Опорный туннель, лежащий или
    /// ждущий пароля, запросу не нужен. Нужны основной адаптер и доведённая до фильтров политика - иначе запрос
    /// оборвали бы фильтры, оставшиеся от прежнего состояния. Когда «остальной интернет» назначен туннелю или
    /// группе, путь по-прежнему только через проверенный туннель: запрос мимо VPN был бы утечкой.
    /// </summary>
    private bool DirectPathOpen =>
        _settings.DefaultTarget.Kind == TargetKind.Direct && Facts.Primary is not null && Facts.PolicyApplied;

    /// <summary>Фоновая проверка или загрузка обновления; для тестов.</summary>
    internal Task UpdateWork => _update.Pending ?? Task.CompletedTask;

    private IEnumerable<StatusWarning> UpdateWarnings()
    {
        var state = _update.State;
        switch (state.Phase)
        {
            case UpdatePhase.Ready when state.AvailableVersion is { } ready:
                yield return new StatusWarning("update-ready",
                    $"Готово обновление до версии {ready}: установка займёт около минуты.", "update-install");
                break;

            // Источник раз за разом отдаёт не тот файл: автозагрузка остановлена, и молчать об этом нельзя.
            case UpdatePhase.Available when state.AvailableVersion is { } broken && UpdateManager.AutoDownloadSuspended(state):
                yield return new StatusWarning("update-download-failed",
                    $"Обновление до версии {broken} не скачивается: контрольная сумма установщика не совпала с подписанным " +
                    "списком выпусков несколько раз подряд. Автозагрузка остановлена; повторить загрузку можно вручную.", "update-open");
                break;

            // Пока установщик качается сам, сообщать не о чем: предупреждение появится, когда он будет готов.
            case UpdatePhase.Available when state.AvailableVersion is { } found && !_settings.AppUpdate.AutoDownload:
                yield return new StatusWarning("update-available", $"Доступно обновление до версии {found}.", "update-open");
                break;

            case UpdatePhase.Failed:
                yield return new StatusWarning("update-failed",
                    "Обновление программы не установилось: " + state.LastInstallResult, "update-open");
                break;

            default:
                break;
        }
    }
}
