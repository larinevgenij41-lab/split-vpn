using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using Windows.Networking.Connectivity;

namespace SplitVpn.Service;

/// <summary>Завершение соединения RAS по журналу: код (631 — отключил пользователь) и время события.</summary>
public readonly record struct RasTermination(uint? Code, DateTimeOffset TimeUtc);

/// <summary>Сигналы Windows, которые нельзя получить через RAS/IP Helper напрямую.</summary>
public static class SystemSignals
{
    private const int RasTerminatedEventId = 20226;

    /// <summary>Сколько последних событий 20226 просматривается в поисках своей записи.</summary>
    private const int RasEventsScanned = 50;

    /// <summary>
    /// Код завершения последнего соединения записи <paramref name="entryName"/> из журнала RasClient (событие
    /// 20226: CoId, пользователь, имя записи, код) после момента <paramref name="since"/>. Событие чужого
    /// соединения не подходит: его 631 не значит, что пользователь отключил наш туннель. Кириллица имени
    /// в журнале бывает искажена кодировкой («Р Р°Р·РґРµР»...»), поэтому сверяется хвост имени — ASCII-метка
    /// профиля после последнего пробела. Вместе с кодом отдаётся время события: по нему свой RasHangUp
    /// отличают от решения пользователя. null — события своей записи нет.
    /// </summary>
    public static RasTermination? RasTerminationReason(DateTimeOffset since, string entryName)
    {
        var tag = entryName[(entryName.LastIndexOf(' ') + 1)..];
        var query = new EventLogQuery("Application", PathType.LogName,
            $"*[System[Provider[@Name='RasClient'] and EventID={RasTerminatedEventId} and TimeCreated[@SystemTime>='{since.UtcDateTime.AddSeconds(-2):yyyy-MM-ddTHH:mm:ss.fffZ}']]]")
        {
            ReverseDirection = true,
        };
        try
        {
            using var reader = new EventLogReader(query);
            for (var i = 0; i < RasEventsScanned; i++)
            {
                using var record = reader.ReadEvent();
                if (record is null)
                {
                    return null;
                }

                var values = record.Properties.Select(p => Convert.ToString(p.Value, CultureInfo.InvariantCulture) ?? "").ToList();
                if (values.Exists(v => IsEntry(v, entryName, tag)))
                {
                    var code = values
                        .Select(v => uint.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) ? (uint?)parsed : null)
                        .LastOrDefault(v => v is not null);
                    var created = record.TimeCreated is { } time ? new DateTimeOffset(time.ToUniversalTime(), TimeSpan.Zero) : DateTimeOffset.UtcNow;
                    return new RasTermination(code, created);
                }
            }

            return null;
        }
        catch (EventLogException)
        {
            return null;
        }
    }

    private static bool IsEntry(string value, string entryName, string tag) =>
        string.Equals(value, entryName, StringComparison.OrdinalIgnoreCase)
        || (tag.Length > 0 && tag.Length < entryName.Length && value.EndsWith(" " + tag, StringComparison.OrdinalIgnoreCase));

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

    /// <summary>
    /// Ждёт завершения процесса по номеру и возвращает его код. Нужен, чтобы узнать итог msiexec,
    /// который запустил интерфейс: сам он к этому моменту уже закрыт. null — процесса нет (он успел
    /// завершиться, номер переиспользован) или код недоступен.
    /// </summary>
    public static async Task<int?> WaitForProcessAsync(int processId, CancellationToken cancellationToken)
    {
        try
        {
            using var process = System.Diagnostics.Process.GetProcessById(processId);
            await process.WaitForExitAsync(cancellationToken);
            return process.ExitCode;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return null;
        }
    }
}
