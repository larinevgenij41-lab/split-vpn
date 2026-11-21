using SplitVpn.Core.Ipc;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Native;
using SplitVpn.Windows.Operations;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Ревью исправлений 0.15.20: положенный туннель не подхватывает сеанс своей записи, а разрывает его; нечитаемый
/// пароль после срока просит ввода, а прерванная серия сбоев не съедает срок следующей; автоподключение не идёт
/// с паролем, который не расшифруется никогда.
/// </summary>
public sealed partial class CoordinatorTests
{
    /// <summary>
    /// Сеанс записи положенного туннеля появился снова (rasdial, неудачный разрыв): сверка его не подхватывает, а
    /// разрывает. Сбой разрыва только пишется в журнал службы, и следующая сверка повторяет разрыв.
    /// </summary>
    [Fact]
    public async Task PausedTunnel_LiveSessionOfItsEntry_IsHungUpNotAdopted()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        await coordinator.HandleRequestAsync(new SetTunnelPausedRequest(_profile.Id, true), CancellationToken.None);
        await CompleteDialAsync(coordinator);
        Assert.True(tunnel.Paused);
        Assert.False(_world.Ras.Connected);
        var hangUps = _world.Ras.HangUps;

        await _world.Ras.DialAsync(Coordinator.EntryNameFor(_profile), "user", "secret".AsMemory(), null, CancellationToken.None);
        _world.Ras.HangUpFailure = new NativeCallException("RasHangUp", 668);
        await coordinator.ReconcileAsync(CancellationToken.None);

        Assert.Null(tunnel.Connection);
        Assert.True(_world.Ras.Connected);
        Assert.True(_world.Ras.HangUps > hangUps);

        _world.Ras.HangUpFailure = null;
        await coordinator.ReconcileAsync(CancellationToken.None);

        Assert.True(tunnel.Paused);
        Assert.Null(tunnel.Connection);
        Assert.False(_world.Ras.Connected, Dump(coordinator));
        Assert.DoesNotContain(_world.Journal.Since(0), e => e.Text.Contains("Подхвачено существующее соединение", StringComparison.Ordinal));
    }

    /// <summary>
    /// Сохранённый пароль не читается и дольше срока ожидания (сбой не временный): туннель перестаёт повторять и просит
    /// пароль, как до хранения нечитаемого значения. Повторы идут по своей паузе, срок считается от первого сбоя.
    /// </summary>
    [Fact]
    public async Task UnreadablePassword_PastGrace_FallsBackToPasswordRequired()
    {
        _world.Secrets.Unreadable.Add(_profile.Id);
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        var started = _world.Time.GetUtcNow();
        Assert.False(tunnel.PasswordRequired);
        Assert.True(tunnel.NextDialAt > started);

        for (var i = 0; i < 20 && !tunnel.PasswordRequired; i++)
        {
            _world.Time.Advance(tunnel.NextDialAt - _world.Time.GetUtcNow() + TimeSpan.FromSeconds(1));
            await TickAsync(coordinator);
        }

        Assert.True(tunnel.PasswordRequired, Dump(coordinator));
        Assert.True(_world.Time.GetUtcNow() - started >= Coordinator.UnreadablePasswordGrace);
        Assert.Equal(ConnectionState.PasswordRequired, coordinator.DeriveState());
        Assert.Equal(0, _world.Ras.Dials);
        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("введите его заново", StringComparison.Ordinal));
    }

    /// <summary>
    /// Серия сбоев чтения пароля прервана (туннель отключили вручную), а через несколько часов DPAPI разово снова не
    /// расшифровал пароль: это новая серия со своим сроком, а не «введите пароль заново» по старой отметке.
    /// </summary>
    [Fact]
    public async Task UnreadablePassword_StaleMarkFromInterruptedSeries_StartsNewGrace()
    {
        _world.Secrets.Unreadable.Add(_profile.Id);
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        Assert.False(tunnel.PasswordRequired);

        await coordinator.HandleRequestAsync(new SetTunnelPausedRequest(_profile.Id, true), CancellationToken.None);
        await CompleteDialAsync(coordinator);
        _world.Time.Advance(TimeSpan.FromHours(3));
        await TickAsync(coordinator);

        await coordinator.HandleRequestAsync(new SetTunnelPausedRequest(_profile.Id, false), CancellationToken.None);
        await CompleteDialAsync(coordinator);

        Assert.False(tunnel.PasswordRequired, Dump(coordinator));
        Assert.True(tunnel.NextDialAt > _world.Time.GetUtcNow());
        Assert.DoesNotContain(_world.Journal.Since(0), e => e.Text.Contains("введите его заново", StringComparison.Ordinal));

        // Пароль снова читается: туннель подключается по своей паузе.
        _world.Secrets.Unreadable.Clear();
        _world.Time.Advance(tunnel.NextDialAt - _world.Time.GetUtcNow() + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);

        Assert.Equal(1, _world.Ras.Dials);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    /// <summary>
    /// Пароль записан, но не расшифруется никогда (зашифрован на другом компьютере): хранилище откладывает его при чтении,
    /// и автоподключение при загрузке не включается - иначе туннель ждал бы пароля за kill switch.
    /// </summary>
    [Fact]
    public async Task AutoConnect_PasswordPermanentlyUndecryptable_IsSkipped()
    {
        var stores = new ServiceStores(_world.Paths);
        stores.SaveSettings(stores.LoadSettings(out _) with { AutoConnect = true });
        _world.Uptime = TimeSpan.FromMinutes(1);
        var secrets = new SetAsideSecrets(_world.Secrets);
        secrets.Permanent.Add(_profile.Id);

        var coordinator = await StartWithAsync(d => d with { Secrets = secrets });

        Assert.Equal(Intent.Off, coordinator.State.Intent);
        Assert.Equal(0, _world.Ras.Dials);
        Assert.False(_world.Secrets.IsStored(_profile.Id));
    }
}

/// <summary>Хранилище, которое при чтении откладывает значение, не расшифровываемое никогда, как SecretStore.</summary>
internal sealed class SetAsideSecrets(FakeSecrets inner) : ISecretOps
{
    /// <summary>Профили, чьи пароли зашифрованы ключом другого компьютера.</summary>
    public HashSet<Guid> Permanent { get; } = [];

    public char[]? TryLoad(Guid profileId, SecretKind kind = SecretKind.Password)
    {
        if (Permanent.Contains(profileId))
        {
            inner.Delete(profileId, kind);
            return null;
        }

        return inner.TryLoad(profileId, kind);
    }

    public void Save(Guid profileId, ReadOnlySpan<char> password, SecretKind kind = SecretKind.Password) => inner.Save(profileId, password, kind);

    public void Delete(Guid profileId, SecretKind kind = SecretKind.Password) => inner.Delete(profileId, kind);

    public bool Contains(Guid profileId, SecretKind kind = SecretKind.Password)
    {
        var value = TryLoad(profileId, kind);
        if (value is null)
        {
            return false;
        }

        Array.Clear(value);
        return true;
    }

    public bool IsStored(Guid profileId, SecretKind kind = SecretKind.Password) => inner.IsStored(profileId, kind);
}
