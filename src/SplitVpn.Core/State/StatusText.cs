using SplitVpn.Core.Ipc;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.State;

/// <summary>Текстовые статусы для главного экрана и трея (PLAN §6): состояние не передаётся только цветом.</summary>
public static class StatusText
{
    public static string StateName(ConnectionState state) => state switch
    {
        ConnectionState.Disconnected => "Отключено",
        ConnectionState.PreparingProtection => "Подготовка защиты",
        ConnectionState.Connecting => "Подключение",
        ConnectionState.ApplyingRoutes => "Применение маршрутов",
        ConnectionState.Connected => "Подключено",
        ConnectionState.Reconnecting => "Переподключение",
        ConnectionState.TrafficBlocked => "Трафик заблокирован",
        ConnectionState.Error => "Ошибка",
        ConnectionState.DisconnectedExternally => "VPN отключён извне",
        ConnectionState.PasswordRequired => "Требуется пароль",
        ConnectionState.PartiallyApplied => "Неполное применение",
        _ => state.ToString(),
    };

    /// <summary>Строка вида «Россия → напрямую · Остальные адреса → через «Основной» · Защита включена».</summary>
    public static string Format(StatusDto status)
    {
        ArgumentNullException.ThrowIfNull(status);
        var adapter = string.IsNullOrWhiteSpace(status.PrimaryAdapterName) ? "основной адаптер" : status.PrimaryAdapterName;
        var parts = new List<string>
        {
            "Россия → " + Where(status, status.GeoTargetName, adapter),
            "Остальные адреса → " + Where(status, status.DefaultTargetName, adapter),
        };

        // Список обхода блокировок упоминается, только когда он загружен и ведёт не туда же, куда всё остальное:
        // иначе строка состояния росла бы без всякой пользы.
        if (status.Bypass is { FollowsDefault: false, Revision: not null } bypass)
        {
            parts.Insert(1, "Обход блокировок → " + Where(status, bypass.TargetName, adapter));
        }

        parts.Add(status.ProtectionSuspended ? "Защита снята восстановлением сети"
            : status.ProtectionActive ? "Защита включена" : "Защита выключена");
        return string.Join(" · ", parts);
    }

    /// <summary>Цель словами; если она ведёт в VPN, а её туннель недоступен — причина вместо названия.</summary>
    private static string Where(StatusDto status, string target, string adapter)
    {
        if (target.StartsWith("напрямую", StringComparison.Ordinal))
        {
            return adapter;
        }

        if (target.StartsWith("блокировать", StringComparison.Ordinal))
        {
            return "заблокированы";
        }

        if (TargetUp(status, target))
        {
            return target;
        }

        return VpnUnavailableText(status);
    }

    /// <summary>
    /// Поднят ли туннель цели. «Остальной интернет» несут туннели с признаком IsAnchor (для группы достаточно
    /// одного); цель-туннель узнаётся по названию. Без сведений о туннелях — по общему состоянию.
    /// </summary>
    private static bool TargetUp(StatusDto status, string target)
    {
        if (target == status.DefaultTargetName && status.Tunnels.Any(t => t.IsAnchor))
        {
            return status.Tunnels.Any(t => t.IsAnchor && t.State == ConnectionState.Connected);
        }

        var tunnel = status.Tunnels.FirstOrDefault(t => target == "через «" + t.Name + "»");
        return tunnel?.State == ConnectionState.Connected || (tunnel is null && status.State == ConnectionState.Connected);
    }

    private static string VpnUnavailableText(StatusDto status)
    {
        if (!status.ProtectionActive)
        {
            return "напрямую (VPN отключён)";
        }

        return status.OutageMode == OutageMode.AllowAll ? "напрямую (разрешено при обрыве)" : "заблокированы";
    }
}
