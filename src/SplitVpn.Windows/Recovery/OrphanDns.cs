using SplitVpn.Windows.Dns;

namespace SplitVpn.Windows.Recovery;

/// <summary>Что сбросить на «автоматически» (DHCP) у адаптера без записи в копии DNS.</summary>
/// <param name="V4">IPv4-список DNS.</param>
/// <param name="V6">IPv6-список DNS.</param>
/// <param name="KeptStatic">
/// Сбросить было бы нужно, но IPv4-адрес адаптера статический (DHCP выключен): «автоматически» оставило бы адаптер совсем
/// без DNS, поэтому адаптер не трогается, а человеку говорится указать DNS вручную.
/// </param>
public readonly record struct OrphanDnsReset(bool V4, bool V6, bool KeptStatic = false)
{
    public bool Any => V4 || V6;

    /// <summary>Пояснение для отчёта и журнала об адаптере, оставленном из-за статического адреса.</summary>
    public static string StaticNote(string adapterName, string nameServers) =>
        $"адаптер «{adapterName}» {Core.Recovery.EmergencyNotes.StaticAddress}: DNS «{nameServers}» программы не сброшен (без DHCP адаптер остался бы без DNS) — DNS укажите вручную";
}

/// <summary>Кто слушает UDP-порт 53 так, что ему доходят запросы к loopback.</summary>
/// <param name="V4">Запросы к 127.0.0.1 кто-то принимает: слушатель на 127.0.0.1, 0.0.0.0 или [::] (двойной стек).</param>
/// <param name="V6">Запросы к [::1] кто-то принимает: слушатель на [::1] или [::].</param>
/// <param name="V4Exact">Слушатель именно на 127.0.0.1:53 — так слушает локальный резолвер пользователя (AdGuard Home, dnscrypt-proxy).</param>
/// <param name="V6Exact">Слушатель именно на [::1]:53.</param>
public readonly record struct LoopbackListeners(bool V4, bool V6, bool V4Exact = false, bool V6Exact = false);

/// <summary>
/// Правила для адаптеров, чей DNS выглядит нашим, а записи в копии DNS у них нет (копия потеряна, повреждена, снята
/// раньше времени или каталог данных недоверенный). Без посредника такой DNS не разрешает ни одного имени.
/// </summary>
public static class OrphanDns
{
    /// <summary>
    /// Решение по адаптеру. IPv4 наш — <see cref="InterfaceDnsOps.IsProxySet"/>: только loopback либо «IPv4-адрес, 127.0.0.1»
    /// (адрес не сверяется с текущим: после его смены на адаптере остаётся прежний).
    /// <para><paramref name="serviceStopped"/> — служба остановлена или «пустая» после экстренного отключения: наш посредник
    /// точно не слушает. Тогда список сбрасывается, если никто не слушает именно 127.0.0.1:53 (<see cref="LoopbackListeners.V4Exact"/>):
    /// слушатель только на 0.0.0.0:53 или [::]:53 — чаще чужая программа, а не резолвер, ради которого пользователь вписал
    /// 127.0.0.1, а вот слушатель на 127.0.0.1:53 — его локальный резолвер, и копии у такого адаптера и не должно быть.
    /// IPv6 «только ::1» — так же по [::1]:53; адаптер, оставленный ради резолвера на 127.0.0.1, не трогается целиком.</para>
    /// <para>Служба работает (команда «Восстановить сеть»): только если запросы к 127.0.0.1 никто не принимает
    /// (<see cref="LoopbackListeners.V4"/>); IPv6 «только ::1» — вместе с нашим IPv4 или если запросы к [::1] никто не
    /// принимает: посредник ставит ::1 только вместе с IPv4-loopback.</para>
    /// <para><paramref name="staticIpv4"/> — IPv4-адрес адаптера статический: тогда адаптер не сбрасывается вовсе
    /// (<see cref="OrphanDnsReset.KeptStatic"/>).</para>
    /// </summary>
    public static OrphanDnsReset Decide(string nameServerV4, string? nameServerV6, bool serviceStopped, LoopbackListeners listeners, bool staticIpv4 = false)
    {
        ArgumentNullException.ThrowIfNull(nameServerV4);
        var oursV4 = InterfaceDnsOps.IsProxySet(nameServerV4);
        var onlyV6Loopback = nameServerV6 is not null && IsOnlyV6Loopback(nameServerV6);
        bool v4, v6;
        if (serviceStopped)
        {
            v4 = oursV4 && !listeners.V4Exact;
            v6 = onlyV6Loopback && !listeners.V6Exact && !(oursV4 && listeners.V4Exact);
        }
        else
        {
            v4 = oursV4 && !listeners.V4;
            v6 = onlyV6Loopback && (v4 || !listeners.V6);
        }

        return staticIpv4 && (v4 || v6) ? new OrphanDnsReset(false, false, KeptStatic: true) : new OrphanDnsReset(v4, v6);
    }

    private static bool IsOnlyV6Loopback(string nameServers)
    {
        var parts = nameServers.Split([' ', ','], StringSplitOptions.RemoveEmptyEntries);
        return parts.Length > 0 && parts.All(p => p == InterfaceDnsOps.LoopbackV6);
    }

    /// <summary>
    /// Суффиксы, которые дописывала программа: в каждой копии — то, что есть в применённом списке (AppliedSearchList), но
    /// не в исходном (SearchList). Сами суффиксы шлюзов нигде больше не хранятся.
    /// </summary>
    public static HashSet<string> OurSuffixes(IEnumerable<InterfaceDnsBackup> backups)
    {
        ArgumentNullException.ThrowIfNull(backups);
        var ours = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var backup in backups)
        {
            if (backup.AppliedSearchList is not { } applied)
            {
                continue;
            }

            var original = Suffixes(backup.SearchList).ToHashSet(StringComparer.OrdinalIgnoreCase);
            ours.UnionWith(Suffixes(applied).Where(s => !original.Contains(s)));
        }

        return ours;
    }

    /// <summary>Список поиска адаптера без копии состоит только из наших суффиксов: его можно очистить.</summary>
    public static bool ShouldClearSearchList(string current, IReadOnlySet<string> ours)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(ours);
        var actual = Suffixes(current);
        return actual.Length > 0 && ours.Count > 0 && actual.All(ours.Contains);
    }

    private static string[] Suffixes(string list) => list.Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries);
}
