using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Dns;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Закрепления по правилам для доменов переживают перезапуск службы: первая сверка нового процесса уже содержит их маршруты
/// и разрешения. Восстановленные проходят те же проверки, что и живые, а сроки из файла не длиннее наибольшего TTL. После
/// перезагрузки Windows закрепления не восстанавливаются, а простой считается по времени работы Windows, а не по часам.
/// </summary>
public sealed partial class CoordinatorTests
{
    private static readonly uint SavedPinAddress = Ipv4.Parse("93.184.216.50");

    /// <summary>Новый процесс службы; фоновая запись файла прежним дожидается, иначе она легла бы поверх файла теста.</summary>
    private async Task<Coordinator> RestartAsync(Coordinator previous)
    {
        await previous.PinFileWritesAsync();
        var restarted = new Coordinator(_world.Dependencies());
        await restarted.StartupAsync(CancellationToken.None);
        await CompleteDialAsync(restarted);
        await restarted.PinFileWritesAsync();
        return restarted;
    }

    /// <summary>Правила для закреплений и включённая защита; фоновая запись после снятия защиты при запуске закончена.</summary>
    private async Task<Coordinator> QuietLingerRulesAsync(RouteTarget? first = null, RouteTarget? defaultTarget = null)
    {
        var coordinator = await WithLingerRulesAsync(first: first, defaultTarget: defaultTarget);
        await coordinator.PinFileWritesAsync();
        return coordinator;
    }

    private static async Task SaveNowAsync(Coordinator coordinator)
    {
        coordinator.SavePinFile(force: true);
        await coordinator.PinFileWritesAsync();
    }

    /// <summary>Служба простаивала: идут и настенные часы, и время работы Windows.</summary>
    private void Downtime(TimeSpan duration)
    {
        _world.Time.Advance(duration);
        _world.Uptime += duration;
    }

    private void WritePinFile(DateTimeOffset savedUtc, params PinFileEntry?[] pins) => WritePinFile(savedUtc, _world.Uptime, null, pins);

    private void WritePinFile(DateTimeOffset savedUtc, TimeSpan? uptime, string? bootId, params PinFileEntry?[] pins) =>
        new ServiceStores(_world.Paths).SavePins(new PinFileContent(ServiceStores.PinFileVersion, savedUtc, uptime, bootId, pins));

    private PinFileEntry TunnelPinEntry(uint address, DateTimeOffset expires, string suffix = "first.example") =>
        new(Ipv4.Format(address), TargetKind.Tunnel, _profile.Id, suffix, suffix, null, expires, default);

    private static bool HasHostRoute(FakeWorld world, uint address) => world.Routes.Current.Any(r => r.Destination == new Ipv4Cidr(address, 32));

    [Fact]
    public async Task PinFile_RoundTrip_FirstPolicyAfterRestartAlreadyHasThePin()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var first = await QuietLingerRulesAsync();
        Assert.True(await PinAsync(first, "first.example", vpn, TimeSpan.FromMinutes(30), SavedPinAddress));
        await SaveNowAsync(first);
        Assert.True(File.Exists(_world.Paths.Pins));

        var restarted = await RestartAsync(first);

        Assert.True(HasHostRoute(_world, SavedPinAddress));
        Assert.Equal(vpn, restarted.Facts.Pinned[SavedPinAddress].Target);
        Assert.Equal(_profile.Id, restarted.Facts.Policy!.Classify(SavedPinAddress).Tunnel);
        // Срок - прежний, а не новый TTL от момента запуска.
        Assert.Equal(_world.Time.GetUtcNow() + TimeSpan.FromMinutes(30), restarted.Facts.Pinned[SavedPinAddress].ExpiresUtc);
    }

    [Fact]
    public async Task PinFile_ExpiredDuringDowntime_WithoutConnections_IsNotRestored()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var first = await QuietLingerRulesAsync();
        Assert.True(await PinAsync(first, "first.example", vpn, TimeSpan.FromSeconds(60), SavedPinAddress));
        await SaveNowAsync(first);

        // Без простоя тот же файл восстанавливается.
        var control = await RestartAsync(first);
        Assert.Contains(SavedPinAddress, control.Facts.Pinned.Keys);

        Downtime(TimeSpan.FromHours(2));
        var restarted = await RestartAsync(control);

        Assert.DoesNotContain(SavedPinAddress, restarted.Facts.Pinned.Keys);
        Assert.False(HasHostRoute(_world, SavedPinAddress));
    }

    [Fact]
    public async Task PinFile_LingerWithLiveConnection_SurvivesRestart()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var first = await QuietLingerRulesAsync();
        Assert.True(await PinAsync(first, "first.example", vpn, TimeSpan.FromSeconds(60), SavedPinAddress));
        _world.TcpConnections = [SavedPinAddress];
        await AdvanceAndTickAsync(first, TimeSpan.FromSeconds(61) + Coordinator.PinLingerGrace);
        Assert.Contains(SavedPinAddress, first.Facts.Pinned.Keys);
        await SaveNowAsync(first);

        Downtime(TimeSpan.FromMinutes(10));
        var restarted = await RestartAsync(first);

        Assert.Equal(_profile.Id, restarted.Facts.Policy!.Classify(SavedPinAddress).Tunnel);

        // Соединение закрылось: продление снимается, как у живого закрепления.
        _world.TcpConnections = [];
        await AdvanceAndTickAsync(restarted, Coordinator.PinLingerGrace + TimeSpan.FromSeconds(1));
        Assert.DoesNotContain(SavedPinAddress, restarted.Facts.Pinned.Keys);
    }

    [Fact]
    public async Task PinFile_RuleRemovedBetweenRestarts_PinIsDropped()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var first = await QuietLingerRulesAsync();
        Assert.True(await PinAsync(first, "first.example", vpn, TimeSpan.FromMinutes(30), SavedPinAddress));
        await SaveNowAsync(first);

        // С прежним правилом тот же файл восстанавливается.
        var control = await RestartAsync(first);
        Assert.Contains(SavedPinAddress, control.Facts.Pinned.Keys);

        SaveSettings(Settings() with
        {
            DefaultTarget = RouteTarget.Direct,
            DomainRules = [new DomainRuleSetting { Suffix = "second.example", Target = RouteTarget.Direct }],
        });
        var restarted = await RestartAsync(control);

        Assert.DoesNotContain(SavedPinAddress, restarted.Facts.Pinned.Keys);
        Assert.Equal(Decision.Direct, restarted.Facts.Policy!.Classify(SavedPinAddress).Decision);
    }

    [Fact]
    public async Task PinFile_RuleChangedTarget_PinIsDropped()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var first = await QuietLingerRulesAsync();
        Assert.True(await PinAsync(first, "first.example", vpn, TimeSpan.FromMinutes(30), SavedPinAddress));
        await SaveNowAsync(first);

        var control = await RestartAsync(first);
        Assert.Equal(vpn, control.Facts.Pinned[SavedPinAddress].Target);

        SaveSettings(Settings() with
        {
            DefaultTarget = vpn,
            DomainRules = [new DomainRuleSetting { Suffix = "first.example", Target = RouteTarget.Direct }],
        });
        var restarted = await RestartAsync(control);

        Assert.DoesNotContain(SavedPinAddress, restarted.Facts.Pinned.Keys);
    }

    [Fact]
    public async Task PinFile_TamperedLifetimes_AreClampedToTheLongestTtl()
    {
        var first = await QuietLingerRulesAsync();
        var now = _world.Time.GetUtcNow();
        WritePinFile(now, TunnelPinEntry(SavedPinAddress, now + TimeSpan.FromDays(30)) with { LingerUntilUtc = now + TimeSpan.FromDays(10) });

        var restarted = await RestartAsync(first);

        var pin = restarted.Facts.Pinned[SavedPinAddress];
        Assert.True(pin.ExpiresUtc <= _world.Time.GetUtcNow() + DnsProxyServer.MaxRouteTtl);
        Assert.True(pin.LingerUntilUtc <= _world.Time.GetUtcNow() + Coordinator.PinLingerGrace);
    }

    [Fact]
    public async Task PinFile_ClockMovedBackAfterSave_DowntimeCountsByUptime()
    {
        var first = await QuietLingerRulesAsync();
        var now = _world.Time.GetUtcNow();
        // Файл записан «в будущем»: часы с тех пор переведены назад на сутки, а служба простаивала 3 минуты. Номер
        // загрузки тот же: без него такое расхождение часов считалось бы перезагрузкой (см. ниже).
        _world.BootId = "8";
        var saved = now + TimeSpan.FromDays(1);
        WritePinFile(saved, _world.Uptime, "8", TunnelPinEntry(SavedPinAddress, saved + TimeSpan.FromMinutes(10)));
        _world.Uptime += TimeSpan.FromMinutes(3);

        var restarted = await RestartAsync(first);

        Assert.Equal(now + TimeSpan.FromMinutes(7), restarted.Facts.Pinned[SavedPinAddress].ExpiresUtc);
    }

    [Fact]
    public async Task PinFile_ClockMovedForwardAfterSave_DowntimeCountsByUptime()
    {
        var first = await QuietLingerRulesAsync();
        var now = _world.Time.GetUtcNow();
        // Часы с записи ушли вперёд на сутки (отставали, синхронизировались), а служба простаивала 3 минуты: по настенным
        // часам срок давно истёк бы. Номер загрузки тот же.
        _world.BootId = "8";
        var saved = now - TimeSpan.FromDays(1);
        WritePinFile(saved, _world.Uptime, "8", TunnelPinEntry(SavedPinAddress, saved + TimeSpan.FromMinutes(10)));
        _world.Uptime += TimeSpan.FromMinutes(3);

        var restarted = await RestartAsync(first);

        Assert.Equal(now + TimeSpan.FromMinutes(7), restarted.Facts.Pinned[SavedPinAddress].ExpiresUtc);
    }

    [Fact]
    public async Task PinFile_AfterWindowsReboot_IsNotRestoredAndIsDeleted()
    {
        var first = await QuietLingerRulesAsync();
        var now = _world.Time.GetUtcNow();
        var entry = TunnelPinEntry(SavedPinAddress, now + TimeSpan.FromMinutes(30));

        // Время работы Windows меньше записанного: перезагрузка, даже если часы показывают, что прошла минута.
        WritePinFile(now - TimeSpan.FromMinutes(1), _world.Uptime + TimeSpan.FromHours(1), null, entry);
        var rebooted = await RestartAsync(first);
        Assert.Empty(rebooted.Facts.Pinned);
        Assert.False(HasHostRoute(_world, SavedPinAddress));
        Assert.False(File.Exists(_world.Paths.Pins));

        // Время работы больше, но номер загрузки другой (перезагрузка вскоре после записи).
        _world.BootId = "8";
        WritePinFile(now, _world.Uptime - TimeSpan.FromMinutes(1), "7", entry);
        var rebootedAgain = await RestartAsync(rebooted);
        Assert.Empty(rebootedAgain.Facts.Pinned);
        Assert.False(File.Exists(_world.Paths.Pins));

        // Файл без времени работы - не восстанавливается.
        WritePinFile(now, null, "8", entry);
        var withoutUptime = await RestartAsync(rebootedAgain);
        Assert.Empty(withoutUptime.Facts.Pinned);

        // Контроль: та же загрузка - восстанавливается.
        WritePinFile(now, _world.Uptime, "8", entry);
        var sameBoot = await RestartAsync(withoutUptime);
        Assert.Contains(SavedPinAddress, sameBoot.Facts.Pinned.Keys);
    }

    /// <summary>
    /// Номер загрузки не прочитан ни при записи, ни при запуске, а служба запустилась после перезагрузки позже записанного
    /// времени работы: по одному времени работы перезагрузку не видно. Простой по настенным часам тогда расходится с
    /// простоем по времени работы - файл не восстанавливается и удаляется. В пределах допуска - восстанавливается.
    /// </summary>
    [Fact]
    public async Task PinFile_WithoutBootId_WallClockDisagreeing_IsTreatedAsReboot()
    {
        var first = await QuietLingerRulesAsync();
        var now = _world.Time.GetUtcNow();
        var entry = TunnelPinEntry(SavedPinAddress, now + TimeSpan.FromMinutes(30));
        Assert.Null(_world.BootId);

        // Записан 2 часа назад при времени работы 2 ч 57 мин; сейчас время работы 3 ч: «простой» 3 минуты не сходится.
        WritePinFile(now - TimeSpan.FromHours(2), _world.Uptime - TimeSpan.FromMinutes(3), null, entry);
        var rebooted = await RestartAsync(first);
        Assert.Empty(rebooted.Facts.Pinned);
        Assert.False(HasHostRoute(_world, SavedPinAddress));
        Assert.False(File.Exists(_world.Paths.Pins));

        // Номер загрузки записан, но сейчас не прочитан - сверка с часами тоже действует.
        WritePinFile(now - TimeSpan.FromHours(2), _world.Uptime - TimeSpan.FromMinutes(3), "8", entry);
        var withoutCurrentBoot = await RestartAsync(rebooted);
        Assert.Empty(withoutCurrentBoot.Facts.Pinned);
        Assert.False(File.Exists(_world.Paths.Pins));

        // Расхождение в пределах допуска - восстанавливается.
        var drift = Coordinator.PinFileClockTolerance - TimeSpan.FromMinutes(1);
        WritePinFile(now - TimeSpan.FromMinutes(3) - drift, _world.Uptime - TimeSpan.FromMinutes(3), null, entry);
        var sameBoot = await RestartAsync(withoutCurrentBoot);
        Assert.Contains(SavedPinAddress, sameBoot.Facts.Pinned.Keys);
    }

    /// <summary>
    /// Экстренное отключение останавливает работающую службу через диспетчер служб, без «Отключить»: при остановке
    /// служба читает отметку заново и удаляет файл закреплений, а не пишет его. Отметка не прочиталась - тоже удаляет.
    /// </summary>
    [Fact]
    public async Task PinFile_StopAfterEmergencyOffMark_DeletesTheFileInsteadOfWriting()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var first = await QuietLingerRulesAsync();
        Assert.True(await PinAsync(first, "first.example", vpn, TimeSpan.FromMinutes(30), SavedPinAddress));

        // Контроль: без отметки остановка пишет файл.
        first.SavePinFileOnStop();
        await first.PinFileWritesAsync();
        Assert.Single(new ServiceStores(_world.Paths).LoadPins()!.Pins!);

        Assert.True(await PinAsync(first, "first.example", vpn, TimeSpan.FromMinutes(30), SavedPinAddress + 1));
        _world.EmergencyMark = () => new SplitVpn.Core.Recovery.EmergencyFlag(EmergencySince);
        first.SavePinFileOnStop();
        await first.PinFileWritesAsync();
        Assert.False(File.Exists(_world.Paths.Pins));

        // Отметка не читается: служба на всякий случай тоже удаляет файл.
        _world.EmergencyMark = () => null;
        await SaveNowAsync(first);
        Assert.Equal(2, new ServiceStores(_world.Paths).LoadPins()!.Pins!.Count);
        _world.EmergencyMark = () => throw new UnauthorizedAccessException("нет доступа");
        first.SavePinFileOnStop();
        await first.PinFileWritesAsync();
        Assert.False(File.Exists(_world.Paths.Pins));
    }

    /// <summary>
    /// Недописанные временные файлы атомарной записи (процесс завершён посреди записи) удаляются при запуске - только с
    /// именем точно «pins.json.&lt;число&gt;-&lt;число&gt;.tmp» и только в каталоге данных.
    /// </summary>
    [Fact]
    public async Task PinFile_StaleTemporaryFiles_AreDeletedOnStart()
    {
        var first = await QuietLingerRulesAsync();
        var root = Path.GetDirectoryName(_world.Paths.Pins)!;
        string[] stale = ["pins.json.4242-7.tmp", "pins.json.1-1.tmp", "PINS.JSON.77-123.TMP"];
        string[] kept = ["pins.json.bak", "pins.json.x-1.tmp", "pins.json.42-.tmp", "pins.json.-1.tmp", "pins.json.4-2-1.tmp",
            "pins.json.42-1.tmp.keep", "other.json.42-1.tmp", "pins.json..tmp", "pins.json.tmp"];
        foreach (var name in stale.Concat(kept))
        {
            File.WriteAllText(Path.Combine(root, name), "{}");
        }

        var nested = Directory.CreateDirectory(Path.Combine(root, "nested"));
        File.WriteAllText(Path.Combine(nested.FullName, "pins.json.5-5.tmp"), "{}");

        await RestartAsync(first);

        Assert.All(stale, name => Assert.False(File.Exists(Path.Combine(root, name)), name));
        Assert.All(kept, name => Assert.True(File.Exists(Path.Combine(root, name)), name));
        Assert.True(File.Exists(Path.Combine(nested.FullName, "pins.json.5-5.tmp")));
    }

    [Theory]
    [InlineData("pins.json.1-1.tmp", true)]
    [InlineData("pins.json.123456-789.tmp", true)]
    [InlineData("pins.json.1-1.tmp.x", false)]
    [InlineData("pins.json.a-1.tmp", false)]
    [InlineData("pins.json.1-.tmp", false)]
    [InlineData("pins.json.-1.tmp", false)]
    [InlineData("pins.json.1.tmp", false)]
    [InlineData("pins.json.tmp", false)]
    [InlineData("pins.json", false)]
    [InlineData("pins.jsonx.1-1.tmp", false)]
    public void PinFile_TemporaryName_IsRecognisedExactly(string name, bool expected) =>
        Assert.Equal(expected, ServiceStores.IsPinTempName("pins.json", name));

    [Fact]
    public void PinFile_EmergencyStepDeletesPinFilesOnlyInTheDataDirectory()
    {
        var root = Path.GetDirectoryName(_world.Paths.Pins)!;
        File.WriteAllText(_world.Paths.Pins, "{}");
        File.WriteAllText(Path.Combine(root, "pins.json.9-9.tmp"), "{}");
        File.WriteAllText(Path.Combine(root, "pinsXjson"), "{}");
        File.WriteAllText(Path.Combine(root, "settings.json.pins.json"), "{}");
        var nested = Directory.CreateDirectory(Path.Combine(root, "nested"));
        File.WriteAllText(Path.Combine(nested.FullName, "pins.json"), "{}");

        Assert.Equal(2, ServiceRecovery.DeletePinFiles(root));

        Assert.False(File.Exists(_world.Paths.Pins));
        Assert.False(File.Exists(Path.Combine(root, "pins.json.9-9.tmp")));
        Assert.True(File.Exists(Path.Combine(root, "pinsXjson")));
        Assert.True(File.Exists(Path.Combine(root, "settings.json.pins.json")));
        Assert.True(File.Exists(Path.Combine(nested.FullName, "pins.json")));
        Assert.Equal(0, ServiceRecovery.DeletePinFiles(Path.Combine(root, "нет")));
    }

    [Fact]
    public async Task PinFile_CorruptForeignOrOversized_IsIgnored()
    {
        var previous = await QuietLingerRulesAsync();
        foreach (var content in new[]
        {
            "{ это не json",
            """{"version":99,"savedUtc":"2026-09-13T10:00:00+00:00","savedUptime":"03:00:00","pins":[]}""",
            """{"version":1,"savedUtc":"2026-09-13T10:00:00+00:00","pins":[]}""",
            """{"version":2,"savedUtc":"2026-09-13T10:00:00+00:00","savedUptime":"03:00:00","pins":[null,{"address":"не адрес","kind":"Tunnel","suffix":"first.example"}]}""",
        })
        {
            File.WriteAllText(_world.Paths.Pins, content);
            previous = await RestartAsync(previous);
            Assert.Null(previous.Facts.PartialError);
            Assert.Empty(previous.Facts.Pinned);
        }

        using (var stream = File.Create(_world.Paths.Pins))
        {
            stream.SetLength(ServiceStores.MaxPinFileBytes + 1);
        }

        Assert.Throws<InvalidDataException>(() => new ServiceStores(_world.Paths).LoadPins());
        var afterOversized = await RestartAsync(previous);
        Assert.Empty(afterOversized.Facts.Pinned);

        // Контроль: исправный файл на том же месте восстанавливается.
        var now = _world.Time.GetUtcNow();
        WritePinFile(now, TunnelPinEntry(SavedPinAddress, now + TimeSpan.FromMinutes(10)));
        var valid = await RestartAsync(afterOversized);
        Assert.Contains(SavedPinAddress, valid.Facts.Pinned.Keys);
    }

    [Fact]
    public async Task PinFile_RecordWithoutKind_IsRejected()
    {
        var coordinator = await QuietLingerRulesAsync(first: RouteTarget.Direct, defaultTarget: RouteTarget.Tunnel(_profile.Id));
        var now = _world.Time.GetUtcNow();
        var direct = new PinFileEntry(Ipv4.Format(SavedPinAddress), TargetKind.Direct, null, "first.example", "first.example", null,
            now + TimeSpan.FromMinutes(10), default);

        Assert.Equal(0, coordinator.RestorePins(new PinFileContent(ServiceStores.PinFileVersion, now, _world.Uptime, null, [direct with { Kind = null }]), TimeSpan.Zero));
        Assert.Equal(1, coordinator.RestorePins(new PinFileContent(ServiceStores.PinFileVersion, now, _world.Uptime, null, [direct]), TimeSpan.Zero));
    }

    [Fact]
    public async Task PinFile_TemporaryOwnersAreNotSaved()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var first = await QuietLingerRulesAsync();
        // Ответ ещё не выдан клиенту (временный владелец): в файл не попадает.
        var notice = new PinnedRouteNotice("first.example", "first.example", vpn, [SavedPinAddress], TimeSpan.FromMinutes(30)) { LeaseId = Guid.NewGuid() };
        var pending = first.ObservePinnedAsync(notice, CancellationToken.None);
        await first.DrainAsync();
        Assert.True(await pending);

        await SaveNowAsync(first);
        Assert.False(File.Exists(_world.Paths.Pins));

        // Выдан - сохраняется.
        Assert.True(await first.CompletePinnedAsync(notice, accepted: true));
        await SaveNowAsync(first);
        Assert.Single(new ServiceStores(_world.Paths).LoadPins()!.Pins!);
    }

    [Fact]
    public async Task PinFile_RestoreRespectsThePerRuleLimit()
    {
        var coordinator = await QuietLingerRulesAsync();
        var now = _world.Time.GetUtcNow();
        var entries = Enumerable.Range(0, Coordinator.MaxPinsPerRule + 5)
            .Select(i => (PinFileEntry?)TunnelPinEntry(Ipv4.Parse("100.64.0.0") + (uint)i, now + TimeSpan.FromMinutes(10)))
            .ToArray();

        var restored = coordinator.RestorePins(new PinFileContent(ServiceStores.PinFileVersion, now, _world.Uptime, null, entries), TimeSpan.Zero);

        Assert.Equal(Coordinator.MaxPinsPerRule, restored);
    }

    /// <summary>
    /// «Отключить» удаляет файл сразу, без тика. Запись, начатая перед этим (фоновая), его не воскрешает: удаление встаёт
    /// за ней в ту же очередь.
    /// </summary>
    [Fact]
    public async Task PinFile_DeletedImmediatelyWhenProtectionIsOff_EvenWithWriteInFlight()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var first = await QuietLingerRulesAsync();
        Assert.True(await PinAsync(first, "first.example", vpn, TimeSpan.FromMinutes(30), SavedPinAddress));
        await SaveNowAsync(first);
        Assert.True(File.Exists(_world.Paths.Pins));

        Assert.True(await PinAsync(first, "first.example", vpn, TimeSpan.FromMinutes(30), SavedPinAddress + 1));
        first.SavePinFile(force: true);
        await first.HandleRequestAsync(new Core.Ipc.DisconnectRequest(KeepProtection: false), CancellationToken.None);
        await first.PinFileWritesAsync();

        Assert.False(File.Exists(_world.Paths.Pins));
        // И следующий тик его не пишет заново.
        await AdvanceAndTickAsync(first, Coordinator.PinSaveInterval + TimeSpan.FromSeconds(1));
        await first.PinFileWritesAsync();
        Assert.False(File.Exists(_world.Paths.Pins));
    }

    [Fact]
    public async Task PinFile_DeletedOnStart_WhenProtectionIsOffOrSuspended()
    {
        var first = await QuietLingerRulesAsync();
        var now = _world.Time.GetUtcNow();
        var stores = new ServiceStores(_world.Paths);
        var state = stores.LoadState();

        WritePinFile(now, TunnelPinEntry(SavedPinAddress, now + TimeSpan.FromMinutes(30)));
        stores.SaveState(state with { Intent = Intent.Off });
        var off = await RestartAsync(first);
        Assert.Empty(off.Facts.Pinned);
        Assert.False(File.Exists(_world.Paths.Pins));

        WritePinFile(now, TunnelPinEntry(SavedPinAddress, now + TimeSpan.FromMinutes(30)));
        stores.SaveState(state with { Intent = Intent.Connected, ProtectionSuspended = true });
        var suspended = await RestartAsync(off);
        Assert.Empty(suspended.Facts.Pinned);
        Assert.False(File.Exists(_world.Paths.Pins));
    }

    /// <summary>
    /// Восстановленное продлённое закрепление «напрямую» на адресе, который адресная политика ведёт в туннель, держится не
    /// дольше <see cref="Coordinator.MaxUnprotectedPinLinger"/> от истечения TTL даже при живом соединении - как и до
    /// перезапуска. Закрепление в туннель (контроль) живёт дальше.
    /// </summary>
    [Fact]
    public async Task PinFile_RestoredDirectPinLeavingProtection_IsBoundedByUnprotectedLinger()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var first = await QuietLingerRulesAsync(first: RouteTarget.Direct, defaultTarget: vpn);
        var tunnelAddress = SavedPinAddress + 1;
        var now = _world.Time.GetUtcNow();
        WritePinFile(now,
            new PinFileEntry(Ipv4.Format(SavedPinAddress), TargetKind.Direct, null, "first.example", "first.example", null,
                now - TimeSpan.FromMinutes(50), now + TimeSpan.FromMinutes(1)),
            new PinFileEntry(Ipv4.Format(tunnelAddress), TargetKind.Tunnel, _profile.Id, "second.example", "second.example", null,
                now - TimeSpan.FromMinutes(50), now + TimeSpan.FromMinutes(1)));
        SaveSettings(Settings() with
        {
            DefaultTarget = vpn,
            DomainRules =
            [
                new DomainRuleSetting { Suffix = "first.example", Target = RouteTarget.Direct },
                new DomainRuleSetting { Suffix = "second.example", Target = vpn },
            ],
        });
        _world.TcpConnections = [SavedPinAddress, tunnelAddress];

        var restarted = await RestartAsync(first);
        Assert.Contains(SavedPinAddress, restarted.Facts.Pinned.Keys);
        Assert.Contains(tunnelAddress, restarted.Facts.Pinned.Keys);

        for (var i = 0; i < 12; i++)
        {
            await AdvanceAndTickAsync(restarted, TimeSpan.FromMinutes(1));
        }

        // Час от истечения TTL вышел: «напрямую» снято, хотя соединение живо; в туннель - держится.
        Assert.DoesNotContain(SavedPinAddress, restarted.Facts.Pinned.Keys);
        Assert.Contains(tunnelAddress, restarted.Facts.Pinned.Keys);
    }

    /// <summary>
    /// Восстановленное закрепление DNS-сервера туннеля снимается, а адрес сервера VPN в туннель не уводится, - как у живых
    /// ответов DNS.
    /// </summary>
    [Fact]
    public async Task PinFile_RestoredServiceAddresses_NeverGetPinRoutes()
    {
        var first = await QuietLingerRulesAsync();
        var now = _world.Time.GetUtcNow();
        var tunnelDns = Ipv4.Parse("198.51.100.50");
        WritePinFile(now,
            TunnelPinEntry(FakeWorld.Server, now + TimeSpan.FromMinutes(30)),
            new PinFileEntry(Ipv4.Format(tunnelDns), TargetKind.Direct, null, "second.example", "second.example", null, now + TimeSpan.FromMinutes(30), default),
            TunnelPinEntry(SavedPinAddress, now + TimeSpan.FromMinutes(30)));
        _world.Routes.Ever.Clear();

        var restarted = await RestartAsync(first);

        Assert.Contains(SavedPinAddress, restarted.Facts.Pinned.Keys);
        // Ни одно применение после запуска, в том числе первое, не вело их мимо назначенного пути.
        Assert.DoesNotContain(_world.Routes.Ever, r => r.Destination == new Ipv4Cidr(FakeWorld.Server, 32) && r.InterfaceLuid != FakeWorld.WiFiLuid);
        Assert.DoesNotContain(_world.Routes.Ever, r => r.Destination == new Ipv4Cidr(tunnelDns, 32) && r.InterfaceLuid == FakeWorld.WiFiLuid);
        // Адрес сервера политика молча не закрепляет (как и живой ответ с ним): маршрута в туннель нет.
        Assert.NotEqual(Decision.Vpn, restarted.Facts.Policy!.Classify(FakeWorld.Server).Decision);
        Assert.DoesNotContain(tunnelDns, restarted.Facts.Pinned.Keys);
        Assert.DoesNotContain(_world.Routes.Current, r => r.Destination == new Ipv4Cidr(FakeWorld.Server, 32) && r.InterfaceLuid == FakeWorld.TunnelLuid);
    }

    /// <summary>
    /// Настройки при запуске не читаются: закрепления не восстанавливаются (проверить их не по чему), а файл не трогается.
    /// Настройки прочитались - закрепления восстанавливаются с первой сверкой.
    /// </summary>
    [Fact]
    public async Task PinFile_UnreadableSettingsAtStart_RestoresOnceSettingsAreRead()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var first = await QuietLingerRulesAsync();
        Assert.True(await PinAsync(first, "first.example", vpn, TimeSpan.FromMinutes(30), SavedPinAddress));
        await SaveNowAsync(first);

        Coordinator restarted;
        using (new FileStream(_world.Paths.Settings, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            restarted = new Coordinator(_world.Dependencies());
            await restarted.StartupAsync(CancellationToken.None);
            await CompleteDialAsync(restarted);
            await TickAsync(restarted);
            restarted.SavePinFile(force: true);
            await restarted.PinFileWritesAsync();

            Assert.Empty(restarted.Facts.Pinned);
            Assert.True(File.Exists(_world.Paths.Pins));
        }

        await TickAsync(restarted);
        await restarted.PinFileWritesAsync();

        Assert.Equal(vpn, restarted.Facts.Pinned[SavedPinAddress].Target);
        Assert.True(HasHostRoute(_world, SavedPinAddress));
    }

    /// <summary>
    /// Файл переписывается только при существенном изменении набора: продление срока продления или сдвиг основного срока
    /// в пределах шага его не трогают, новый адрес - переписывает.
    /// </summary>
    [Fact]
    public async Task PinFile_IsRewrittenOnlyOnMaterialChange()
    {
        var vpn = RouteTarget.Tunnel(_profile.Id);
        var first = await QuietLingerRulesAsync();
        // Сроки - внутри одного шага отпечатка: начало шага через 30-35 минут плюс 1 и 3 минуты.
        var step = Coordinator.PinFileExpiryGranularity.Ticks;
        var bucket = new DateTimeOffset((_world.Time.GetUtcNow() + TimeSpan.FromMinutes(30)).UtcTicks / step * step + step, TimeSpan.Zero);
        TimeSpan TtlUntil(DateTimeOffset expires) => expires - _world.Time.GetUtcNow();
        Assert.True(await PinAsync(first, "first.example", vpn, TtlUntil(bucket + TimeSpan.FromMinutes(1)), SavedPinAddress));
        await SaveNowAsync(first);
        Assert.True(File.Exists(_world.Paths.Pins));

        // Файл убран в сторону: если служба его перепишет, он появится снова.
        File.Delete(_world.Paths.Pins);
        _world.Time.Advance(TimeSpan.FromSeconds(30));
        Assert.True(await PinAsync(first, "first.example", vpn, TtlUntil(bucket + TimeSpan.FromMinutes(3)), SavedPinAddress));
        await SaveNowAsync(first);
        Assert.False(File.Exists(_world.Paths.Pins));

        // Срок ушёл на следующий шаг - файл переписывается.
        Assert.True(await PinAsync(first, "first.example", vpn, TtlUntil(bucket + Coordinator.PinFileExpiryGranularity + TimeSpan.FromMinutes(1)), SavedPinAddress));
        await SaveNowAsync(first);
        Assert.Single(new ServiceStores(_world.Paths).LoadPins()!.Pins!);

        Assert.True(await PinAsync(first, "first.example", vpn, TimeSpan.FromMinutes(30), SavedPinAddress + 1));
        await SaveNowAsync(first);
        Assert.Equal(2, new ServiceStores(_world.Paths).LoadPins()!.Pins!.Count);
    }

    /// <summary>Файл, который не уложился бы в предел чтения, урезается при записи до самых свежих записей и читается.</summary>
    [Fact]
    public void PinFile_OversizedSet_IsTrimmedToFitTheReadLimit()
    {
        var now = _world.Time.GetUtcNow();
        var name = new string('a', 240) + ".example";
        var entries = Enumerable.Range(0, 3 * Coordinator.MaxSavedPinRecords)
            .Select(i => (PinFileEntry?)new PinFileEntry(Ipv4.Format(Ipv4.Parse("100.64.0.0") + (uint)i), TargetKind.Tunnel, _profile.Id, name, name, name,
                now + TimeSpan.FromMinutes(10), now + TimeSpan.FromMinutes(15)))
            .ToArray();
        var stores = new ServiceStores(_world.Paths);

        var saved = stores.SavePins(new PinFileContent(ServiceStores.PinFileVersion, now, _world.Uptime, null, entries));

        Assert.InRange(saved, 1, entries.Length - 1);
        Assert.True(new FileInfo(_world.Paths.Pins).Length <= ServiceStores.MaxPinFileBytes / 2);
        var loaded = stores.LoadPins()!;
        Assert.Equal(saved, loaded.Pins!.Count);
        Assert.Equal(entries[0], loaded.Pins[0]);
    }
}
