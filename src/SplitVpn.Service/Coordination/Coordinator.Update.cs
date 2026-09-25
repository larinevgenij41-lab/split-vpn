using SplitVpn.Core.Ipc;
using SplitVpn.Core.State;
using SplitVpn.Core.Update;

namespace SplitVpn.Service.Coordination;

/// <summary>Обновление самой программы: общее правило выхода в сеть и предупреждения для шапки.</summary>
public sealed partial class Coordinator
{
    /// <summary>
    /// Можно ли сейчас идти в сеть за обновлением списка адресов или программы: защита выключена либо
    /// приостановлена, или все туннели подняты и проверены. Иначе фильтры WFP оборвут запрос, и
    /// попытка только потратит срок следующей проверки.
    /// </summary>
    internal bool NetworkPathAllowed =>
        _state.Intent == Intent.Off || _state.ProtectionSuspended
        || (Facts.Tunnels.Count > 0 && Facts.Tunnels.Values.All(t => t.Verified));

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
