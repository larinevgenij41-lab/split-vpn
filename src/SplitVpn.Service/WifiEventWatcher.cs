using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;
using SplitVpn.Service.Coordination;

namespace SplitVpn.Service;

/// <summary>
/// Подписка на события службы автонастройки WLAN: подключение и отключение Wi-Fi, повторная проверка безопасности
/// и восстановление адаптера (System 4003). Уведомления IP Helper этого не сообщают: повторная проверка безопасности
/// не меняет ни адрес, ни маршруты, а именно она предвещает перезапуск адаптера через 16 секунд.
/// Обработчик вызывается из потока журнала событий и не должен блокировать.
/// </summary>
internal sealed class WifiEventWatcher : IDisposable
{
    private const string WlanLog = "Microsoft-Windows-WLAN-AutoConfig/Operational";

    private readonly Action<WifiEvent> _raise;
    private readonly List<EventLogWatcher> _watchers = [];

    private WifiEventWatcher(Action<WifiEvent> raise) => _raise = raise;

    /// <summary>Недоступный журнал (служба WLAN не установлена, журнал выключен) — исключение; частичная подписка снимается.</summary>
    public static WifiEventWatcher Start(Action<WifiEvent> raise)
    {
        ArgumentNullException.ThrowIfNull(raise);
        var watcher = new WifiEventWatcher(raise);
        try
        {
            watcher.Watch(WlanLog, "*[System[(EventID=8001 or EventID=8003 or EventID=11004 or EventID=11005)]]");
            watcher.Watch("System", "*[System[Provider[@Name='Microsoft-Windows-WLAN-AutoConfig'] and (EventID=4003)]]");
            return watcher;
        }
        catch
        {
            watcher.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        foreach (var watcher in _watchers)
        {
            try
            {
                watcher.Enabled = false;
                watcher.Dispose();
            }
            catch (Exception ex) when (ex is EventLogException or InvalidOperationException)
            {
                // Журнал уже недоступен: подписки больше нет.
            }
        }

        _watchers.Clear();
    }

    private void Watch(string log, string query)
    {
        var watcher = new EventLogWatcher(new EventLogQuery(log, PathType.LogName, query));
        _watchers.Add(watcher);
        watcher.EventRecordWritten += OnRecord;
        watcher.Enabled = true;
    }

    private void OnRecord(object? sender, EventRecordWrittenEventArgs e)
    {
        try
        {
            using var record = e.EventRecord;
            if (record is not null && Parse(record.Id, record.TimeCreated, record.ToXml()) is { } parsed)
            {
                _raise(parsed);
            }
        }
        catch (Exception)
        {
            // Исключение не должно уйти в поток журнала событий: самописец пропустит одну строку.
        }
    }

    /// <summary>Событие журнала в событие Wi-Fi; незнакомый номер — null.</summary>
    internal static WifiEvent? Parse(int id, DateTime? created, string xml)
    {
        WifiEventKind? kind = id switch
        {
            8001 => WifiEventKind.Connected,
            8003 => WifiEventKind.Disconnected,
            11004 => WifiEventKind.SecurityStopped,
            11005 => WifiEventKind.SecuritySucceeded,
            4003 => WifiEventKind.Recovery,
            _ => null,
        };
        if (kind is null)
        {
            return null;
        }

        var data = XDocument.Parse(xml).Descendants().Where(x => x.Name.LocalName == "Data")
            .Select(x => (Name: (string?)x.Attribute("Name") ?? "", Value: x.Value.Trim())).ToList();
        // У событий подключения поле называется InterfaceGuid, у событий проверки безопасности - DeviceGuid.
        var guid = data.Where(d => d.Name is "InterfaceGuid" or "DeviceGuid").Select(d => Guid.TryParse(d.Value, out var g) ? g : (Guid?)null).FirstOrDefault();
        // Имя сети, MAC-адреса и описание адаптера в запись не идут: хватает номеров причин и состояний.
        var detail = string.Join(", ", data.Where(d => d.Name is "Reason" or "ReasonCode" or "Event" or "ErrorCode" or "ChangeReason" or "IpFamily" or "ConnectionId")
            .Select(d => d.Name + "=" + (d.Value.Length > 80 ? d.Value[..80] : d.Value)));
        var time = created is { } local ? new DateTimeOffset(local.ToUniversalTime(), TimeSpan.Zero) : DateTimeOffset.UtcNow;
        return new WifiEvent(kind.Value, guid, time, detail);
    }
}
