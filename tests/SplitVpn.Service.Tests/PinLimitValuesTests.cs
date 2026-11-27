using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Пределы закреплений - в абсолютных значениях, обещанных в docs/notes-0.20.0.md. Остальные тесты считают сроки
/// от самих констант и пропускали бы, например, продление на 30 суток вместо 24 часов.
/// </summary>
public sealed class PinLimitValuesTests
{
    [Fact]
    public void PinLingerLimits_MatchReleaseNotes()
    {
        // «маршрут держится, пока к адресу есть соединение: до 24 часов»
        Assert.Equal(TimeSpan.FromHours(24), Coordinator.MaxPinLinger);
        // «если правило выводит адрес из VPN или из-под блокировки — не дольше часа»
        Assert.Equal(TimeSpan.FromHours(1), Coordinator.MaxUnprotectedPinLinger);
        // «Потоки UDP/QUIC (HTTP/3) держатся 5 минут после срока записи»
        Assert.Equal(TimeSpan.FromMinutes(5), Coordinator.PinLingerGrace);
    }

    [Fact]
    public void PinCountLimits_MatchReleaseNotes()
    {
        // «из одного ответа DNS закрепляется не больше 16 адресов, на одно правило — не больше 2000»
        Assert.Equal(16, DnsProxyServer.MaxPinnedAddressesPerAnswer);
        Assert.Equal(2000, Coordinator.MaxPinsPerRule);
    }
}
