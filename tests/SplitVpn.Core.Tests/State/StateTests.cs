using SplitVpn.Core.Diagnostics;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;

namespace SplitVpn.Core.Tests.State;

public class StateTests
{
    [Theory]
    [InlineData(691, ErrorCategory.Authentication, false)]
    [InlineData(-2146762487, ErrorCategory.Certificate, false)]
    [InlineData(868, ErrorCategory.NameResolution, true)]
    [InlineData(809, ErrorCategory.ServerUnreachable, true)]
    [InlineData(12345, ErrorCategory.Other, true)]
    public void RasErrors_AreClassified(int code, ErrorCategory category, bool retryable)
    {
        var info = RasErrorClassifier.Classify(code);

        Assert.Equal(category, info.Category);
        Assert.Equal(retryable, info.Retryable);
    }

    [Fact]
    public void Backoff_GrowsAndIsCapped()
    {
        var random = new Random(1);
        var max = TimeSpan.FromSeconds(60);

        for (var attempt = 0; attempt < 40; attempt++)
        {
            var delay = Backoff.Delay(attempt, max, random);
            var expected = Math.Min(Math.Pow(2, Math.Min(attempt, 30)), 60);
            Assert.InRange(delay.TotalSeconds, Math.Max(0.5, expected * 0.8) - 0.001, (expected * 1.2) + 0.001);
        }
    }

    [Fact]
    public void StatusText_DescribesSplitAndProtection()
    {
        var status = new StatusDto
        {
            State = ConnectionState.Connected,
            ProtectionActive = true,
            GeoTargetName = "напрямую",
            DefaultTargetName = "через «Германия»",
            PrimaryAdapterName = "Беспроводная сеть",
        };

        Assert.Equal("Россия → Беспроводная сеть · Остальные адреса → через «Германия» · Защита включена", StatusText.Format(status));
        Assert.Equal(
            "Россия → Беспроводная сеть · Остальные адреса → заблокированы · Защита включена",
            StatusText.Format(status with { State = ConnectionState.Reconnecting }));
        Assert.Equal(
            "Россия → напрямую (VPN отключён) · Остальные адреса → напрямую (VPN отключён) · Защита выключена",
            StatusText.Format(status with { State = ConnectionState.Disconnected, ProtectionActive = false, GeoTargetName = "через «Германия»" }));
        Assert.Contains("разрешено при обрыве", StatusText.Format(status with { State = ConnectionState.Reconnecting, OutageMode = OutageMode.AllowAll }), StringComparison.Ordinal);
    }

    [Fact]
    public void StatusText_UsesTargetTunnels_NotOverallState()
    {
        var status = new StatusDto
        {
            State = ConnectionState.Connected,
            ProtectionActive = true,
            GeoTargetName = "через «Дополнительное»",
            DefaultTargetName = "через «Основное»",
            PrimaryAdapterName = "Ethernet",
            Tunnels =
            [
                new TunnelStatusDto { Name = "Основное", State = ConnectionState.Connected, IsAnchor = true },
                new TunnelStatusDto { Name = "Дополнительное", State = ConnectionState.Error },
            ],
        };

        Assert.Equal("Россия → заблокированы · Остальные адреса → через «Основное» · Защита включена", StatusText.Format(status));
    }

    [Fact]
    public void StatusText_TellsThatProtectionWasSuspendedByRecovery()
    {
        var status = new StatusDto { State = ConnectionState.Disconnected, ProtectionSuspended = true, GeoTargetName = "напрямую", DefaultTargetName = "напрямую" };

        Assert.EndsWith("Защита снята восстановлением сети", StatusText.Format(status), StringComparison.Ordinal);
        Assert.StartsWith("Россия → заблокированы", StatusText.Format(status with { GeoTargetName = "блокировать" }), StringComparison.Ordinal);
    }

    [Fact]
    public void Redactor_MasksPersonalData_ButKeepsTimes()
    {
        var text = "12:30:45 user=ivanov server 330399.fornex.cloud ip 203.0.113.20/32 gw 192.168.1.1 v6 2001:db8::1 fe80::1%12 "
            + "mac 00-1A-2B-3C-4D-5E if {6B29FC40-CA47-1067-B31D-00DD010662DA} full 2001:0db8:0000:0000:0000:ff00:0042:8329";

        var redacted = Redactor.Redact(text, ["ivanov", "330399.fornex.cloud"]);

        Assert.StartsWith("12:30:45", redacted, StringComparison.Ordinal);
        foreach (var secret in new[] { "ivanov", "fornex", "89.127", "192.168", "2001:db8", "fe80", "00-1A", "6B29FC40", "ff00" })
        {
            Assert.DoesNotContain(secret, redacted, StringComparison.OrdinalIgnoreCase);
        }
    }
}
