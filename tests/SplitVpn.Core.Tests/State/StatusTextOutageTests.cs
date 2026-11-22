using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;

namespace SplitVpn.Core.Tests.State;

/// <summary>
/// Строка состояния в режиме «Разрешить всё» (круг 3 код-ревью, S5): напрямую идёт только «остальной интернет»
/// и только при настоящем обрыве. Положенный пользователем носитель, назначения другого туннеля и отключение
/// с сохранённой защитой остаются заблокированными - строка не должна говорить обратное.
/// </summary>
public class StatusTextOutageTests
{
    private static StatusDto Status(bool anchorPaused, Intent intent = Intent.Connected) => new()
    {
        State = anchorPaused ? ConnectionState.TrafficBlocked : ConnectionState.Reconnecting,
        Intent = intent,
        ProtectionActive = true,
        OutageMode = OutageMode.AllowAll,
        GeoTargetName = "через «Германия»",
        DefaultTargetName = "через «Нидерланды»",
        PrimaryAdapterName = "Ethernet",
        Tunnels =
        [
            new TunnelStatusDto { Name = "Нидерланды", State = anchorPaused ? ConnectionState.Disconnected : ConnectionState.Reconnecting, IsAnchor = true, Paused = anchorPaused },
            new TunnelStatusDto { Name = "Германия", State = ConnectionState.Reconnecting },
        ],
    };

    [Fact]
    public void RealOutage_DefaultGoesDirect_OtherTunnelStaysBlocked()
    {
        Assert.Equal(
            "Россия → заблокированы · Остальные адреса → напрямую (разрешено при обрыве) · Защита включена",
            StatusText.Format(Status(anchorPaused: false)));
    }

    [Fact]
    public void PausedAnchor_IsNotOutage()
    {
        Assert.Equal(
            "Россия → заблокированы · Остальные адреса → заблокированы · Защита включена",
            StatusText.Format(Status(anchorPaused: true)));
    }

    [Fact]
    public void ProtectedWithoutVpn_IsNotOutage()
    {
        Assert.Contains("Остальные адреса → заблокированы", StatusText.Format(Status(anchorPaused: false, Intent.Protected)), StringComparison.Ordinal);
    }
}
