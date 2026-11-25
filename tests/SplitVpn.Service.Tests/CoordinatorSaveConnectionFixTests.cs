using Microsoft.Extensions.Time.Testing;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Native;
using SplitVpn.Windows.Operations;

namespace SplitVpn.Service.Tests;

/// <summary>Сохранение подключения: сбой разрыва, недоступный секрет, повторное использование данных входа.</summary>
public sealed partial class CoordinatorTests
{
    /// <summary>Разрыв после записи нового пароля не удался: адреса прежнего сервера всё равно забываются.</summary>
    [Fact]
    public async Task SaveConnection_SecretHangUpFailure_StillForgetsOldServer()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        Assert.NotEmpty(tunnel.ServerAddresses);
        _world.Ras.HangUpFailure = new NativeCallException("RasHangUp", 5);
        var moved = _profile with { Server = "203.0.113.11:4443" };

        // Повторный разрыв при смене сервера тоже падает: исход запроса здесь не важен, важны последствия.
        _ = await Record.ExceptionAsync(() => coordinator.HandleRequestAsync(
            new SaveConnectionRequest(coordinator.Settings with { Profiles = [moved] }, moved.Id, "new-password", null), CancellationToken.None));

        Assert.Equal("203.0.113.11:4443", coordinator.Settings.Profile(_profile.Id)!.Server);
        Assert.Equal("new-password", _world.Secrets.Saved[_profile.Id]);
        Assert.Empty(tunnel.ServerAddresses);
        Assert.DoesNotContain(coordinator.State.Servers, s => s.ProfileId == _profile.Id);
        Assert.True(tunnel.ReconnectRequired);
        _world.Ras.HangUpFailure = null;
    }

    private static Dictionary<string, System.Text.Json.JsonElement> ForgedSection() => new()
    {
        [UnknownSettingValues.PreservedKey] = System.Text.Json.JsonDocument.Parse("""{"role":"Primary","authMethod":"Pap"}""").RootElement.Clone(),
    };

    /// <summary>
    /// Клиент подложил раздел исходных значений: служба его снимает, подключение проходит полную проверку,
    /// а в файл не попадают ни опорная роль, ни PAP.
    /// </summary>
    [Fact]
    public async Task SaveSettings_ForgedPreservedSection_IsDroppedAndNotWritten()
    {
        var coordinator = await StartAsync();
        var forged = new ConnectionProfile { Name = "Чужое", Server = "203.0.113.30:4443", UserName = "u", Extra = ForgedSection() };
        var changed = coordinator.Settings with { Profiles = [.. coordinator.Settings.Profiles, forged] };

        var response = await coordinator.HandleRequestAsync(new SaveSettingsRequest(changed), CancellationToken.None);

        Assert.True(response.Ok, response.ErrorMessage);
        Assert.False(UnknownSettingValues.HasPreservedValues(coordinator.Settings.Profile(forged.Id)));
        var stored = new ServiceStores(_world.Paths).LoadSettings(out _).Profile(forged.Id)!;
        Assert.Equal(ProfileRole.Off, stored.Role);
        Assert.Equal(AuthMethod.MsChapV2, stored.AuthMethod);
        Assert.Equal(ProfileRole.Primary, coordinator.Settings.Profile(_profile.Id)!.Role);
    }

    /// <summary>Подложенный раздел не даёт пропустить проверку: подключение без адреса сервера отклоняется.</summary>
    [Fact]
    public async Task SaveSettings_ForgedPreservedSection_DoesNotSkipValidation()
    {
        var coordinator = await StartAsync();
        var forged = new ConnectionProfile { Name = "Чужое", Server = "", UserName = "u", Extra = ForgedSection() };

        var response = await coordinator.HandleRequestAsync(
            new SaveSettingsRequest(coordinator.Settings with { Profiles = [.. coordinator.Settings.Profiles, forged] }), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Null(coordinator.Settings.Profile(forged.Id));
    }

    /// <summary>Пароль записан, но сейчас не расшифровывается: без копии он не удаляется, настройки не меняются.</summary>
    [Fact]
    public async Task SaveSettings_UnreadableStoredPassword_IsNotDeletedWithoutBackup()
    {
        var coordinator = await StartAsync();
        _world.Secrets.Unreadable.Add(_profile.Id);
        var changed = coordinator.Settings with { Profiles = [_profile with { UserName = "new-user" }] };

        var response = await coordinator.HandleRequestAsync(new SaveSettingsRequest(changed), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal("user", coordinator.Settings.Profile(_profile.Id)!.UserName);
        Assert.Equal("secret", _world.Secrets.Saved[_profile.Id]);
        _world.Secrets.Unreadable.Clear();
    }

    /// <summary>Подтверждённое использование прежнего ключа IPsec, которого нет, отклоняется: без ключа L2TP/PSK не дозвонится.</summary>
    [Fact]
    public async Task SaveConnection_ReuseWithoutStoredKey_IsRejected()
    {
        var original = _profile with { Protocol = VpnProtocol.L2tpIpsec, Server = "203.0.113.10" };
        SaveSettings(Multi(original));
        var coordinator = await StartAsync();
        var changed = original with { Server = "203.0.113.20" };

        var response = await coordinator.HandleRequestAsync(new SaveConnectionRequest(Multi(changed), changed.Id, null, null, original), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.InvalidSettings, response.ErrorCode);
        Assert.Equal("203.0.113.10", coordinator.Settings.Profile(original.Id)!.Server);
    }

    /// <summary>
    /// L2TP/PSK с сохранением пароля, но пароль ещё не сохранён (его вводят при подключении): смена сервера
    /// с подтверждённым использованием прежних данных оставляет ключ IPsec, а пароль спросят при дозвоне.
    /// </summary>
    [Fact]
    public async Task SaveConnection_ReuseWithoutStoredPassword_KeepsKey()
    {
        var original = _profile with { Protocol = VpnProtocol.L2tpIpsec, Server = "203.0.113.10", SavePassword = true };
        SaveSettings(Multi(original));
        _world.Secrets.Delete(original.Id);
        _world.Secrets.Save(original.Id, "shared-key", SecretKind.PreSharedKey);
        var coordinator = await StartAsync();
        var changed = original with { Server = "203.0.113.20" };

        var response = await coordinator.HandleRequestAsync(new SaveConnectionRequest(Multi(changed), changed.Id, null, null, original), CancellationToken.None);

        Assert.True(response.Ok);
        Assert.Equal("203.0.113.20", coordinator.Settings.Profile(original.Id)!.Server);
        Assert.Equal("shared-key", _world.Secrets.Keys[original.Id]);
        Assert.False(_world.Secrets.Saved.ContainsKey(original.Id));
    }

    /// <summary>
    /// CryptProtectData отказал при записи нового пароля (NativeCallException, не CryptographicException): ошибка
    /// возвращается ответом, а соединение со старым сервером всё равно разрывается.
    /// </summary>
    [Fact]
    public async Task SaveConnection_DpapiSaveFailure_StillDropsOldServer()
    {
        var secrets = new DpapiFailingSecrets(_world.Secrets);
        var coordinator = new Coordinator(_world.Dependencies() with { Secrets = secrets });
        await coordinator.StartupAsync(CancellationToken.None);
        await CompleteDialAsync(coordinator);
        await ConnectAsync(coordinator);
        var hangUps = _world.Ras.HangUps;
        secrets.FailProtect = true;
        var moved = _profile with { Server = "203.0.113.11:4443", SavePassword = true };

        var response = await coordinator.HandleRequestAsync(
            new SaveConnectionRequest(coordinator.Settings with { Profiles = [moved] }, moved.Id, "new-password", null), CancellationToken.None);

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.Failed, response.ErrorCode);
        Assert.Equal("203.0.113.11:4443", coordinator.Settings.Profile(_profile.Id)!.Server);
        Assert.True(_world.Ras.HangUps > hangUps);
        Assert.False(_world.Ras.Connected);
    }

    /// <summary>
    /// Пароль не читается дольше нескольких минут (постоянный сбой DPAPI, копию отложить не удалось): сохранение
    /// больше не блокируется навсегда, пароль удаляется с предупреждением в журнале.
    /// </summary>
    [Fact]
    public async Task SaveSettings_PersistentlyUnreadablePassword_IsDeletedAfterGrace()
    {
        var coordinator = await StartAsync();
        _world.Secrets.Unreadable.Add(_profile.Id);
        var changed = coordinator.Settings with { Profiles = [_profile with { UserName = "new-user" }] };

        var first = await coordinator.HandleRequestAsync(new SaveSettingsRequest(changed), CancellationToken.None);
        _world.Time.Advance(TimeSpan.FromMinutes(1));
        var early = await coordinator.HandleRequestAsync(new SaveSettingsRequest(changed), CancellationToken.None);
        Assert.False(first.Ok);
        Assert.False(early.Ok);
        Assert.Equal("secret", _world.Secrets.Saved[_profile.Id]);

        _world.Time.Advance(Coordinator.UnreadableSecretGrace);
        var late = await coordinator.HandleRequestAsync(new SaveSettingsRequest(changed), CancellationToken.None);

        Assert.True(late.Ok);
        Assert.Equal("new-user", coordinator.Settings.Profile(_profile.Id)!.UserName);
        Assert.False(_world.Secrets.Saved.ContainsKey(_profile.Id));
        Assert.Contains(_world.Journal.Since(0), e => e.Level == "Предупреждение" && e.Text.Contains("не может расшифровать", StringComparison.Ordinal));
        _world.Secrets.Unreadable.Clear();
    }

    /// <summary>
    /// Windows поправила системные часы на несколько часов вперёд (две системы, снимок виртуальной машины): срок
    /// отсчитывается по монотонным часам, и секрет, нечитаемый всего полминуты, не удаляется.
    /// </summary>
    [Fact]
    public async Task SaveSettings_UnreadablePassword_WallClockJump_DoesNotEndGrace()
    {
        var clock = new JumpingClock(_world.Time);
        var coordinator = new Coordinator(_world.Dependencies() with { Time = clock });
        await coordinator.StartupAsync(CancellationToken.None);
        await CompleteDialAsync(coordinator);
        _world.Secrets.Unreadable.Add(_profile.Id);
        var changed = coordinator.Settings with { Profiles = [_profile with { UserName = "new-user" }] };

        var first = await coordinator.HandleRequestAsync(new SaveSettingsRequest(changed), CancellationToken.None);
        clock.Offset = TimeSpan.FromHours(3);
        _world.Time.Advance(TimeSpan.FromSeconds(30));
        var retry = await coordinator.HandleRequestAsync(new SaveSettingsRequest(changed), CancellationToken.None);

        Assert.False(first.Ok);
        Assert.False(retry.Ok);
        Assert.Equal("user", coordinator.Settings.Profile(_profile.Id)!.UserName);
        Assert.Equal("secret", _world.Secrets.Saved[_profile.Id]);
        _world.Secrets.Unreadable.Clear();
    }

    /// <summary>
    /// Давняя отметка о нечитаемом секрете не действует: после неудачного сохранения при загрузке секрет читался
    /// и работал часами, и разовый сбой DPAPI при следующем сохранении снова только останавливает сохранение.
    /// </summary>
    [Fact]
    public async Task SaveSettings_StaleUnreadableMark_RestartsGrace()
    {
        var coordinator = await StartAsync();
        _world.Secrets.Unreadable.Add(_profile.Id);
        var changed = coordinator.Settings with { Profiles = [_profile with { UserName = "new-user" }] };
        var atBoot = await coordinator.HandleRequestAsync(new SaveSettingsRequest(changed), CancellationToken.None);
        Assert.False(atBoot.Ok);

        _world.Secrets.Unreadable.Clear();
        _world.Time.Advance(TimeSpan.FromHours(3));
        _world.Secrets.Unreadable.Add(_profile.Id);
        var glitch = await coordinator.HandleRequestAsync(new SaveSettingsRequest(changed), CancellationToken.None);

        Assert.False(glitch.Ok);
        Assert.Equal("secret", _world.Secrets.Saved[_profile.Id]);
        Assert.Equal("user", coordinator.Settings.Profile(_profile.Id)!.UserName);
        _world.Secrets.Unreadable.Clear();
    }

    /// <summary>
    /// Срок вышел: потерянный пароль удаляется до записи файла настроек, без копии. Запись не удалась - прежние
    /// настройки остаются, а пароль уже не вернуть (в журнале об этом сказано). Удаление после записи могло бы
    /// не состояться, и ожившая расшифровка отдала бы прежний пароль новому серверу.
    /// </summary>
    [Fact]
    public async Task SaveSettings_LostPassword_IsDeletedBeforeSettingsWrite()
    {
        var coordinator = await StartAsync();
        _world.Secrets.Unreadable.Add(_profile.Id);
        var changed = coordinator.Settings with { Profiles = [_profile with { UserName = "new-user" }] };
        Assert.False((await coordinator.HandleRequestAsync(new SaveSettingsRequest(changed), CancellationToken.None)).Ok);
        _world.Time.Advance(Coordinator.UnreadableSecretGrace + TimeSpan.FromMinutes(1));

        IpcResponse failed;
        using (new FileStream(_world.Paths.Settings, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            failed = await coordinator.HandleRequestAsync(new SaveSettingsRequest(changed), CancellationToken.None);
        }

        Assert.False(failed.Ok);
        Assert.Equal(IpcErrorCodes.Failed, failed.ErrorCode);
        Assert.Equal("user", coordinator.Settings.Profile(_profile.Id)!.UserName);
        Assert.False(_world.Secrets.Saved.ContainsKey(_profile.Id));
        Assert.Contains(_world.Journal.Since(0), e => e.Level == "Предупреждение" && e.Text.Contains("не вернётся", StringComparison.Ordinal));

        var saved = await coordinator.HandleRequestAsync(new SaveSettingsRequest(changed), CancellationToken.None);

        Assert.True(saved.Ok);
        Assert.Equal("new-user", coordinator.Settings.Profile(_profile.Id)!.UserName);
        _world.Secrets.Unreadable.Clear();
    }

    /// <summary>
    /// Срок вышел, но удалить потерянный пароль не удалось: сохранение прерывается, настройки и пароль остаются
    /// прежними. Следующее сохранение удаляет его сразу, без нового ожидания.
    /// </summary>
    [Fact]
    public async Task SaveSettings_LostPasswordDeleteFails_AbortsSave()
    {
        var secrets = new DeleteFailingSecrets(_world.Secrets);
        var coordinator = new Coordinator(_world.Dependencies() with { Secrets = secrets });
        await coordinator.StartupAsync(CancellationToken.None);
        await CompleteDialAsync(coordinator);
        _world.Secrets.Unreadable.Add(_profile.Id);
        var changed = coordinator.Settings with { Profiles = [_profile with { UserName = "new-user" }] };
        Assert.False((await coordinator.HandleRequestAsync(new SaveSettingsRequest(changed), CancellationToken.None)).Ok);
        _world.Time.Advance(Coordinator.UnreadableSecretGrace + TimeSpan.FromMinutes(1));
        secrets.FailPasswordDelete = true;

        var failed = await coordinator.HandleRequestAsync(new SaveSettingsRequest(changed), CancellationToken.None);

        Assert.False(failed.Ok);
        Assert.Equal(IpcErrorCodes.Failed, failed.ErrorCode);
        Assert.Equal("user", coordinator.Settings.Profile(_profile.Id)!.UserName);
        Assert.Equal("secret", _world.Secrets.Saved[_profile.Id]);
        Assert.Contains(_world.Journal.Since(0), e => e.Level == "Ошибка" && e.Text.Contains("не удалось удалить", StringComparison.Ordinal));

        secrets.FailPasswordDelete = false;
        var saved = await coordinator.HandleRequestAsync(new SaveSettingsRequest(changed), CancellationToken.None);

        Assert.True(saved.Ok);
        Assert.Equal("new-user", coordinator.Settings.Profile(_profile.Id)!.UserName);
        Assert.False(_world.Secrets.Saved.ContainsKey(_profile.Id));
        _world.Secrets.Unreadable.Clear();
    }

    /// <summary>
    /// «Сохранять пароль» выключено, когда записанный пароль временно не читается: он не остаётся в файле молча
    /// (иначе после включения ожил бы), а сохранение ждёт срок, как при смене сервера, и затем удаляет пароль.
    /// </summary>
    [Fact]
    public async Task SaveSettings_SavePasswordOffWhileUnreadable_BlocksThenDeletes()
    {
        var coordinator = await StartAsync();
        Assert.True(coordinator.Settings.Profile(_profile.Id)!.SavePassword);
        _world.Secrets.Unreadable.Add(_profile.Id);
        var changed = coordinator.Settings with { Profiles = [_profile with { SavePassword = false }] };

        var blocked = await coordinator.HandleRequestAsync(new SaveSettingsRequest(changed), CancellationToken.None);

        Assert.False(blocked.Ok);
        Assert.True(coordinator.Settings.Profile(_profile.Id)!.SavePassword);
        Assert.Equal("secret", _world.Secrets.Saved[_profile.Id]);

        _world.Time.Advance(Coordinator.UnreadableSecretGrace);
        var saved = await coordinator.HandleRequestAsync(new SaveSettingsRequest(changed), CancellationToken.None);

        Assert.True(saved.Ok);
        Assert.False(coordinator.Settings.Profile(_profile.Id)!.SavePassword);
        Assert.False(_world.Secrets.Saved.ContainsKey(_profile.Id));
        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("пароль больше не сохраняется", StringComparison.Ordinal));
        _world.Secrets.Unreadable.Clear();
    }

    /// <summary>Системные часы, которые можно сдвинуть отдельно от монотонных (поправка часов Windows).</summary>
    private sealed class JumpingClock(FakeTimeProvider inner) : TimeProvider
    {
        public TimeSpan Offset { get; set; }

        public override DateTimeOffset GetUtcNow() => inner.GetUtcNow() + Offset;

        public override long GetTimestamp() => inner.GetTimestamp();

        public override long TimestampFrequency => inner.TimestampFrequency;

        public override TimeZoneInfo LocalTimeZone => inner.LocalTimeZone;

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) =>
            inner.CreateTimer(callback, state, dueTime, period);
    }

    /// <summary>Хранилище, в котором удаление пароля падает (файл занят, нет доступа).</summary>
    private sealed class DeleteFailingSecrets(FakeSecrets inner) : ISecretOps
    {
        public bool FailPasswordDelete { get; set; }

        public char[]? TryLoad(Guid profileId, SecretKind kind = SecretKind.Password) => inner.TryLoad(profileId, kind);

        public void Save(Guid profileId, ReadOnlySpan<char> password, SecretKind kind = SecretKind.Password) => inner.Save(profileId, password, kind);

        public void Delete(Guid profileId, SecretKind kind = SecretKind.Password)
        {
            if (FailPasswordDelete && kind == SecretKind.Password)
            {
                throw new IOException("файл пароля занят");
            }

            inner.Delete(profileId, kind);
        }

        public bool Contains(Guid profileId, SecretKind kind = SecretKind.Password) => inner.Contains(profileId, kind);

        public bool IsStored(Guid profileId, SecretKind kind = SecretKind.Password) => inner.IsStored(profileId, kind);
    }

    /// <summary>Хранилище, у которого CryptProtectData отказывает так же, как настоящий SecretStore.</summary>
    private sealed class DpapiFailingSecrets(FakeSecrets inner) : ISecretOps
    {
        public bool FailProtect { get; set; }

        public char[]? TryLoad(Guid profileId, SecretKind kind = SecretKind.Password) => inner.TryLoad(profileId, kind);

        public void Save(Guid profileId, ReadOnlySpan<char> password, SecretKind kind = SecretKind.Password)
        {
            if (FailProtect)
            {
                throw new NativeCallException("CryptProtectData", 0x80090345);
            }

            inner.Save(profileId, password, kind);
        }

        public void Delete(Guid profileId, SecretKind kind = SecretKind.Password) => inner.Delete(profileId, kind);

        public bool Contains(Guid profileId, SecretKind kind = SecretKind.Password) => inner.Contains(profileId, kind);

        public bool IsStored(Guid profileId, SecretKind kind = SecretKind.Password) => inner.IsStored(profileId, kind);
    }

    /// <summary>Новый ключ в том же запросе заменяет отсутствующий сохранённый: сохранение проходит.</summary>
    [Fact]
    public async Task SaveConnection_ReuseWithNewKeyInRequest_IsAccepted()
    {
        var original = _profile with { Protocol = VpnProtocol.L2tpIpsec, Server = "203.0.113.10" };
        SaveSettings(Multi(original));
        var coordinator = await StartAsync();
        var changed = original with { Server = "203.0.113.20" };

        var response = await coordinator.HandleRequestAsync(new SaveConnectionRequest(Multi(changed), changed.Id, null, "new-key", original), CancellationToken.None);

        Assert.True(response.Ok);
        Assert.Equal("secret", _world.Secrets.Saved[original.Id]);
        Assert.Equal("new-key", _world.Secrets.Keys[original.Id]);
    }
}
