using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Native;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Аудит 0.19.0: в копии DNS адаптера свои IPv6-серверы, а IPv6 у адаптера потом отвязали. Чтение IPv6 с кодом
/// «IPv6 нет» - IPv6-часть восстановлена (::1 на адаптере без IPv6 стоять не может), копию можно удалить; иначе
/// «Восстановить сеть» вечно сообщала бы о невосстановленных IPv6 DNS. Иной сбой чтения мог быть временным -
/// по-прежнему Incomplete: ложный успех удалил бы единственную запись исходных серверов. Без чтения сохранённого
/// IPv6-списка (readStoredV6 не передан) раздел IPv6-настроек считается отсутствующим.
/// </summary>
public sealed class InterfaceDnsRestoreIpv6AbsentTests
{
    private static readonly Guid Adapter = new("eeeeeeee-0000-0000-0000-000000000016");

    private static Func<Guid, bool, InterfaceDnsState> FailingIpv6(uint code, string v4) => (_, ipv6) => ipv6
        ? throw new NativeCallException("GetInterfaceDnsSettings", code)
        : new InterfaceDnsState(v4, "", 0, "");

    [Theory]
    [InlineData(2u, "127.0.0.1", DnsRestoreOutcome.Restored)]
    [InlineData(1168u, "127.0.0.1", DnsRestoreOutcome.Restored)]
    [InlineData(50u, "127.0.0.1", DnsRestoreOutcome.Restored)]
    [InlineData(2u, "", DnsRestoreOutcome.NothingToRestore)]
    [InlineData(1168u, "192.0.2.99", DnsRestoreOutcome.ChangedByUser)]
    [InlineData(87u, "127.0.0.1", DnsRestoreOutcome.Incomplete)]
    [InlineData(1722u, "127.0.0.1", DnsRestoreOutcome.Incomplete)]
    [InlineData(87u, "", DnsRestoreOutcome.Incomplete)]
    public void Restore_Ipv6ReadFailure_AbsentIsRestoredTransientIsIncomplete(uint code, string currentV4, DnsRestoreOutcome expected)
    {
        var backup = new InterfaceDnsBackup(Adapter, "192.0.2.1", "2001:db8::53", "", 0, default);
        var writes = new List<(string Value, bool Ipv6)>();

        var outcome = InterfaceDnsOps.Restore(Adapter, backup, FailingIpv6(code, currentV4), (_, value, ipv6) => writes.Add((value, ipv6)), (_, _) => { });

        Assert.Equal(expected, outcome);
        Assert.DoesNotContain(writes, w => w.Ipv6);
        Assert.Equal(currentV4 == "127.0.0.1", writes.Contains(("192.0.2.1", false)));
    }

    /// <summary>
    /// Ревью: код «IPv6 нет» бывает и у интерфейса, временно выпавшего из стека, а в настройках адаптера остаётся
    /// наш ::1. Тогда исходные серверы пытаются записаться; запись не прошла — Incomplete, копия сохраняется (IPv4 при
    /// этом возвращён). Раздела IPv6-настроек нет (null) или в нём не наш ::1 — возвращать нечего, копию можно удалить.
    /// </summary>
    [Theory]
    [InlineData(1168u, "::1", false, DnsRestoreOutcome.Incomplete)]
    [InlineData(2u, "::1", false, DnsRestoreOutcome.Incomplete)]
    [InlineData(1168u, "::1", true, DnsRestoreOutcome.Restored)]
    [InlineData(1168u, null, false, DnsRestoreOutcome.Restored)]
    [InlineData(1168u, "2001:db8::53", false, DnsRestoreOutcome.Restored)]
    [InlineData(1168u, "2001:db8::77", false, DnsRestoreOutcome.Restored)]
    public void Restore_Ipv6Absent_StoredLoopbackKeepsBackupUntilWritten(uint code, string? stored, bool writeSucceeds, DnsRestoreOutcome expected)
    {
        var backup = new InterfaceDnsBackup(Adapter, "192.0.2.1", "2001:db8::53", "", 0, default);
        var writes = new List<(string Value, bool Ipv6)>();

        var outcome = InterfaceDnsOps.Restore(Adapter, backup, FailingIpv6(code, "127.0.0.1"), (_, value, ipv6) =>
        {
            writes.Add((value, ipv6));
            if (ipv6 && !writeSucceeds)
            {
                throw new NativeCallException("SetInterfaceDnsSettings", code);
            }
        }, (_, _) => { }, _ => stored);

        Assert.Equal(expected, outcome);
        Assert.Contains(("192.0.2.1", false), writes);
        Assert.Equal(stored == "::1", writes.Contains(("2001:db8::53", true)));
    }

    /// <summary>IPv4 уже не наш, но в сохранённом IPv6-списке наш ::1 — он тоже возвращается, как при прочитанном IPv6.</summary>
    [Fact]
    public void Restore_Ipv6Absent_StoredLoopbackWithForeignIpv4_IsIncompleteWhenWriteFails()
    {
        var backup = new InterfaceDnsBackup(Adapter, "192.0.2.1", "2001:db8::53", "", 0, default);

        var outcome = InterfaceDnsOps.Restore(Adapter, backup, FailingIpv6(1168, "192.0.2.99"), (_, _, ipv6) =>
        {
            if (ipv6) throw new NativeCallException("SetInterfaceDnsSettings", 1168);
        }, (_, _) => { }, _ => "::1");

        Assert.Equal(DnsRestoreOutcome.Incomplete, outcome);
    }

    /// <summary>Сохранённый список не прочитался (нет доступа) — он неизвестен: копия с исходными серверами сохраняется.</summary>
    [Fact]
    public void Restore_Ipv6Absent_StoredListUnreadable_IsIncomplete()
    {
        var backup = new InterfaceDnsBackup(Adapter, "192.0.2.1", "2001:db8::53", "", 0, default);

        var outcome = InterfaceDnsOps.Restore(Adapter, backup, FailingIpv6(1168, "127.0.0.1"), (_, _, _) => { }, (_, _) => { },
            _ => throw new UnauthorizedAccessException());

        Assert.Equal(DnsRestoreOutcome.Incomplete, outcome);
    }
}
