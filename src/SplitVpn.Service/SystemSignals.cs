using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using Windows.Networking.Connectivity;

namespace SplitVpn.Service;

/// <summary>Сигналы Windows, которые нельзя получить через RAS/IP Helper напрямую.</summary>
public static class SystemSignals
{
    private const int RasTerminatedEventId = 20226;

    /// <summary>
    /// Код завершения последнего соединения из журнала RasClient (событие 20226) после момента <paramref name="since"/>.
    /// Имя записи в событии не используется: у Windows оно бывает искажено кодировкой.
    /// </summary>
    public static uint? RasTerminationReason(DateTimeOffset since)
    {
        var query = new EventLogQuery("Application", PathType.LogName,
            $"*[System[Provider[@Name='RasClient'] and EventID={RasTerminatedEventId} and TimeCreated[@SystemTime>='{since.UtcDateTime.AddSeconds(-2):yyyy-MM-ddTHH:mm:ss.fffZ}']]]")
        {
            ReverseDirection = true,
        };
        try
        {
            using var reader = new EventLogReader(query);
            using var record = reader.ReadEvent();
            return record?.Properties.Select(p => Convert.ToString(p.Value, CultureInfo.InvariantCulture))
                .Select(v => uint.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out var code) ? (uint?)code : null)
                .LastOrDefault(v => v is not null);
        }
        catch (EventLogException)
        {
            return null;
        }
    }

    /// <summary>Лимитная сеть по данным Windows (стоимость подключения к интернету).</summary>
    public static bool IsMeteredNetwork()
    {
        try
        {
            var cost = NetworkInformation.GetInternetConnectionProfile()?.GetConnectionCost();
            return cost is not null && (cost.NetworkCostType is NetworkCostType.Fixed or NetworkCostType.Variable || cost.Roaming || cost.OverDataLimit);
        }
        catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or UnauthorizedAccessException or InvalidOperationException)
        {
            return false;
        }
    }
}
