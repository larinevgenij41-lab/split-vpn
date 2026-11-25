using SplitVpn.Windows.Dns;
using SplitVpn.Windows.Native;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Снимок DNS адаптера, у которого IPv6-настройки не читаются: какой бы код ни вернула система, снимок создаётся,
/// а IPv6-часть берётся из прежней копии; без копии она пуста при «IPv6 нет» и неизвестна при временном сбое.
/// Иначе адаптер не переводился бы на посредник.
/// </summary>
public sealed class InterfaceDnsCaptureIpv6Tests
{
    private static readonly Guid Adapter = new("eeeeeeee-0000-0000-0000-000000000006");

    private static Func<Guid, bool, InterfaceDnsState> FailingIpv6(uint code) => (_, ipv6) => ipv6
        ? throw new NativeCallException("GetInterfaceDnsSettings", code)
        : new InterfaceDnsState("192.0.2.53", "", 0, "home.test");

    [Theory]
    [InlineData(87u)]
    [InlineData(2u)]
    [InlineData(1168u)]
    [InlineData(5u)]
    public void Capture_Ipv6ReadFailure_KeepsPreviousIpv6(uint code)
    {
        var previous = new InterfaceDnsBackup(Adapter, "192.0.2.1", "2001:db8::53", "", 0, default, "home.test");

        var backup = InterfaceDnsOps.Capture(Adapter, previous, DateTimeOffset.UnixEpoch, ownsIpv6Loopback: false, FailingIpv6(code));

        Assert.Equal("2001:db8::53", backup.NameServerV6);
        Assert.Equal("192.0.2.53", backup.NameServerV4);
    }

    /// <summary>
    /// Без прежней копии временный сбой чтения IPv6 (87, RPC 1722, ERROR_NOT_READY) не даёт «пусто»: IPv6-часть
    /// неизвестна, иначе восстановление затёрло бы статический IPv6 DNS пользователя. Прежде здесь было пусто.
    /// </summary>
    [Theory]
    [InlineData(87u)]
    [InlineData(1722u)]
    [InlineData(21u)]
    public void Capture_TransientIpv6ReadFailure_WithoutPreviousBackup_MarksIpv6Unknown(uint code)
    {
        var backup = InterfaceDnsOps.Capture(Adapter, null, DateTimeOffset.UnixEpoch, ownsIpv6Loopback: true, FailingIpv6(code));

        Assert.True(backup.Ipv6Unknown);
        Assert.Null(InterfaceDnsOps.KnownOriginalV6(backup));
        Assert.Equal("192.0.2.53", backup.NameServerV4);
        Assert.Equal("home.test", backup.AppliedSearchList);
    }

    /// <summary>Коды «IPv6 нет» (2, 1168, 50): IPv6-часть пуста и известна, как раньше.</summary>
    [Theory]
    [InlineData(2u)]
    [InlineData(1168u)]
    [InlineData(50u)]
    public void Capture_Ipv6Absent_WithoutPreviousBackup_LeavesIpv6Empty(uint code)
    {
        var backup = InterfaceDnsOps.Capture(Adapter, null, DateTimeOffset.UnixEpoch, ownsIpv6Loopback: true, FailingIpv6(code));

        Assert.False(backup.Ipv6Unknown);
        Assert.Equal("", InterfaceDnsOps.KnownOriginalV6(backup));
    }

    /// <summary>Копия с неизвестной IPv6-частью дополняется, когда чтение удалось; неизвестная копия прежним значением не считается.</summary>
    [Fact]
    public void Capture_AfterUnknown_ReadsIpv6Again()
    {
        var unknown = InterfaceDnsOps.Capture(Adapter, null, DateTimeOffset.UnixEpoch, ownsIpv6Loopback: false, FailingIpv6(1722));
        Func<Guid, bool, InterfaceDnsState> read = (_, ipv6) => new InterfaceDnsState(ipv6 ? "2001:db8::53" : "127.0.0.1", "", 0, "home.test");

        var again = InterfaceDnsOps.Capture(Adapter, unknown, DateTimeOffset.UnixEpoch, ownsIpv6Loopback: false, read);
        var stillFailing = InterfaceDnsOps.Capture(Adapter, unknown, DateTimeOffset.UnixEpoch, ownsIpv6Loopback: false, FailingIpv6(1722));

        Assert.False(again.Ipv6Unknown);
        Assert.Equal("2001:db8::53", again.NameServerV6);
        Assert.True(stillFailing.Ipv6Unknown);
    }

    /// <summary>Восстановление при неизвестной IPv6-части: IPv4 возвращается, IPv6 (статический ::1 или свой DNS пользователя) не трогается.</summary>
    [Theory]
    [InlineData("::1")]
    [InlineData("")]
    public void Restore_Ipv6Unknown_DoesNotTouchIpv6(string userV6)
    {
        var backup = new InterfaceDnsBackup(Adapter, "192.0.2.1", "", "", 0, default, Ipv6Unknown: true);
        var writes = new List<(string Value, bool Ipv6)>();
        Func<Guid, bool, InterfaceDnsState> read = (_, ipv6) => new InterfaceDnsState(ipv6 ? userV6 : "127.0.0.1", "", 0, "");

        var outcome = InterfaceDnsOps.Restore(Adapter, backup, read, (_, value, ipv6) => writes.Add((value, ipv6)), (_, _) => { });

        Assert.Equal(DnsRestoreOutcome.Restored, outcome);
        var write = Assert.Single(writes);
        Assert.Equal(("192.0.2.1", false), write);
    }

    /// <summary>Для сравнения: при известной пустой IPv6-части наш ::1 снимается, как раньше.</summary>
    [Fact]
    public void Restore_Ipv6KnownEmpty_RemovesLoopback()
    {
        var backup = new InterfaceDnsBackup(Adapter, "192.0.2.1", "", "", 0, default);
        var writes = new List<(string Value, bool Ipv6)>();
        Func<Guid, bool, InterfaceDnsState> read = (_, ipv6) => new InterfaceDnsState(ipv6 ? "::1" : "127.0.0.1", "", 0, "");

        var outcome = InterfaceDnsOps.Restore(Adapter, backup, read, (_, value, ipv6) => writes.Add((value, ipv6)), (_, _) => { });

        Assert.Equal(DnsRestoreOutcome.Restored, outcome);
        Assert.Contains(("", true), writes);
    }

    /// <summary>Файл копий прежней версии (без поля ipv6Unknown) читается: IPv6-часть известна.</summary>
    [Fact]
    public void BackupStore_ReadsOldFileWithoutUnknownFlag()
    {
        var path = Path.Combine(Path.GetTempPath(), "splitvpn-dns-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            File.WriteAllText(path, $$"""
                [ { "interfaceGuid": "{{Adapter}}", "nameServerV4": "192.0.2.1", "nameServerV6": "2001:db8::53",
                    "profileNameServerV4": "", "dohServerPropertiesV4": 0, "savedUtc": "2026-01-01T00:00:00+00:00", "searchList": "" } ]
                """);

            var backup = new DnsBackupStore(path).Load()[Adapter];

            Assert.False(backup.Ipv6Unknown);
            Assert.Equal("2001:db8::53", InterfaceDnsOps.KnownOriginalV6(backup));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Capture_Ipv4ReadFailure_StillThrows()
    {
        Func<Guid, bool, InterfaceDnsState> read = (_, _) => throw new NativeCallException("GetInterfaceDnsSettings", 87);

        Assert.Throws<NativeCallException>(() => InterfaceDnsOps.Capture(Adapter, null, DateTimeOffset.UnixEpoch, ownsIpv6Loopback: false, read));
    }

    [Fact]
    public void Capture_ReadsIpv6WhenAvailable()
    {
        Func<Guid, bool, InterfaceDnsState> read = (_, ipv6) => new InterfaceDnsState(ipv6 ? "2001:db8::1" : "192.0.2.53", "", 0, "");

        var backup = InterfaceDnsOps.Capture(Adapter, null, DateTimeOffset.UnixEpoch, ownsIpv6Loopback: false, read);

        Assert.Equal("2001:db8::1", backup.NameServerV6);
    }
}
