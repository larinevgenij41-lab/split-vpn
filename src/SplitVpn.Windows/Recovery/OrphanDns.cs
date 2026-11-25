using SplitVpn.Windows.Dns;

namespace SplitVpn.Windows.Recovery;

/// <summary>Что сбросить на «автоматически» (DHCP) у адаптера без записи в копии DNS.</summary>
/// <param name="V4">IPv4-список DNS.</param>
/// <param name="V6">IPv6-список DNS.</param>
public readonly record struct OrphanDnsReset(bool V4, bool V6)
{
    public bool Any => V4 || V6;
}

/// <summary>
/// Правила для адаптеров, чей DNS выглядит нашим, а записи в копии DNS у них нет (копия потеряна, повреждена, снята
/// раньше времени или каталог данных недоверенный). Без посредника такой DNS не разрешает ни одного имени.
/// </summary>
public static class OrphanDns
{
    /// <summary>
    /// Решение по адаптеру. IPv4 наш — <see cref="InterfaceDnsOps.IsProxySet"/>: только loopback либо «IPv4-адрес, 127.0.0.1»
    /// (адрес не сверяется с текущим: после его смены на адаптере остаётся прежний). <paramref name="serviceStopped"/> —
    /// служба остановлена или «пустая» после экстренного отключения: тогда наш посредник точно не слушает, и такой
    /// список сбрасывается, даже если порт 53 кто-то слушает (чаще всего это 0.0.0.0:53 чужой программы, а не резолвер,
    /// ради которого пользователь вписал 127.0.0.1). Иначе — только если на 127.0.0.1:53 никто не слушает
    /// (<paramref name="v4Listening"/>). IPv6 «только ::1» сбрасывается вместе с нашим IPv4 или если на [::1]:53 никто не
    /// слушает (<paramref name="v6Listening"/>): посредник ставит ::1 только вместе с IPv4-loopback.
    /// </summary>
    public static OrphanDnsReset Decide(string nameServerV4, string? nameServerV6, bool serviceStopped, bool v4Listening, bool v6Listening)
    {
        ArgumentNullException.ThrowIfNull(nameServerV4);
        var v4 = InterfaceDnsOps.IsProxySet(nameServerV4) && (serviceStopped || !v4Listening);
        var v6 = nameServerV6 is not null && IsOnlyV6Loopback(nameServerV6)
            && (v4 || (InterfaceDnsOps.IsProxySet(nameServerV4) && serviceStopped) || !v6Listening);
        return new OrphanDnsReset(v4, v6);
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
