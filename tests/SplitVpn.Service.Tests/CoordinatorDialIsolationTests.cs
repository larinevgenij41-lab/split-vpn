using System.Runtime.InteropServices;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Operations;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Подъём туннелей: неожиданный сбой одного туннеля не останавливает остальные; туннель, ждущий перечисления RAS,
/// не держит очередь вечно; проба SSH не снимает предупреждение о российской цели; нечитаемый ключ после срока
/// называет действие пользователя.
/// </summary>
public sealed partial class CoordinatorTests
{
    /// <summary>
    /// Подготовка записи первого туннеля бросает COMException (не из числа ожидаемых): второй туннель всё равно
    /// дозванивается, первый получает текст ошибки и повтор по паузе, а сверка не уходит в «неполное применение».
    /// </summary>
    [Fact]
    public async Task DialStart_UnexpectedException_IsIsolatedToItsTunnel()
    {
        var second = SecondProfile();
        SaveSettings(Settings() with { Profiles = [_profile, second] });
        var firstEntry = Coordinator.EntryNameFor(_profile);
        _world.Ras.BeforeSaveEntry = name =>
        {
            if (string.Equals(name, firstEntry, StringComparison.OrdinalIgnoreCase))
            {
                throw new COMException("Не удалось преобразовать EAP XML", unchecked((int)0x80004005));
            }
        };
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var first = coordinator.Facts.Tunnels[_profile.Id];
        Assert.Contains(Coordinator.EntryNameFor(second), _world.Ras.ConnectedEntries);
        Assert.DoesNotContain(firstEntry, _world.Ras.DialOrder);
        Assert.True(first.DialSettled);
        Assert.False(first.Dialing);
        Assert.Equal(ErrorCategory.None, first.BlockingError);
        Assert.Equal(ErrorCategory.Other, first.LastErrorCategory);
        Assert.Contains("COMException", first.LastErrorText, StringComparison.Ordinal);
        Assert.True(first.NextDialAt > _world.Time.GetUtcNow());
        Assert.Null(coordinator.Facts.PartialError);
        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("подключение не началось", StringComparison.Ordinal));

        // Сбой прошёл: повтор по паузе поднимает и первый туннель.
        _world.Ras.BeforeSaveEntry = null;
        _world.Time.Advance(first.NextDialAt - _world.Time.GetUtcNow() + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);
        Assert.Contains(firstEntry, _world.Ras.ConnectedEntries);
    }

    /// <summary>
    /// Подъём по очереди, свои соединения RAS не перечисляются (RasMan сбоит): первый туннель RAS ждёт следующей сверки,
    /// а стоящий за ним SSH, которому RAS не нужен, запускается не позже чем через SequentialDialWait.
    /// </summary>
    [Fact]
    public async Task SequentialDial_RasEnumerationFailure_DoesNotHoldSshForever()
    {
        var ssh = _ssh with { Role = ProfileRole.Secondary };
        SaveSettings(Settings() with { Profiles = [_profile, ssh], SequentialDial = true });
        _world.Secrets.Save(ssh.Id, SshKeyText, SecretKind.SshPrivateKey);
        _world.Ras.FailFind = true;
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        Assert.Equal(0, _world.Ras.Dials);

        for (var i = 0; i < 10 && _world.SshTunnel.Last is null; i++)
        {
            _world.Time.Advance(TimeSpan.FromSeconds(5));
            await TickAsync(coordinator);
        }

        Assert.NotNull(_world.SshTunnel.Last);
        Assert.Equal(0, _world.Ras.Dials);
    }

    /// <summary>
    /// Предупреждение «российская цель недоступна», выставленное пробой туннеля RAS, проверка туннеля SSH не снимает:
    /// российскую цель она не проверяет.
    /// </summary>
    [Fact]
    public async Task SshVerify_KeepsRussianTargetWarning()
    {
        // Предупреждение выставляет проба живого туннеля RAS (оно держится, пока жив его проверенный сеанс).
        _world.Probes.RussianWorks = false;
        var coordinator = await StartWithSshAsync(Settings() with { Profiles = [_profile, _ssh with { Role = ProfileRole.Secondary }] });

        await RaiseSshAsync(coordinator);

        Assert.True(coordinator.Facts.Tunnels[_profile.Id].Verified, Dump(coordinator));
        Assert.True(coordinator.Facts.Tunnels[_ssh.Id].Verified, Dump(coordinator));
        Assert.True(coordinator.Facts.RussianTargetUnreachable);
    }

    /// <summary>
    /// Сохранённый ключ IPsec не читается дольше срока: текст ошибки называет действие пользователя, запись в журнале
    /// одна, повторы продолжаются не реже раза в минуту и поднимают туннель, когда ключ снова читается.
    /// </summary>
    [Fact]
    public async Task UnreadablePresharedKey_PastGrace_TellsToSaveItAgainAndKeepsRetrying()
    {
        var l2tp = _profile with { Protocol = VpnProtocol.L2tpIpsec, Server = "203.0.113.10", AuthMethod = AuthMethod.EapMsChapV2 };
        SaveSettings(Settings() with { Profiles = [l2tp], DefaultTarget = RouteTarget.Tunnel(l2tp.Id) });
        _world.Secrets.Keys[l2tp.Id] = "psk";
        var secrets = new KindUnreadableSecrets(_world.Secrets);
        secrets.Unreadable.Add((l2tp.Id, SecretKind.PreSharedKey));
        var coordinator = await StartWithAsync(d => d with { Secrets = secrets });
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[l2tp.Id];
        var started = _world.Time.GetUtcNow();
        Assert.Contains("сейчас не читается", tunnel.LastErrorText, StringComparison.Ordinal);

        for (var i = 0; i < 20 && tunnel.LastErrorText?.Contains("сохраните его заново", StringComparison.Ordinal) != true; i++)
        {
            Assert.True(tunnel.NextDialAt - _world.Time.GetUtcNow() <= Coordinator.UnreadablePasswordGrace / 2);
            _world.Time.Advance(tunnel.NextDialAt - _world.Time.GetUtcNow() + TimeSpan.FromSeconds(1));
            await TickAsync(coordinator);
        }

        Assert.Contains("сохраните его заново", tunnel.LastErrorText, StringComparison.Ordinal);
        Assert.True(_world.Time.GetUtcNow() - started >= Coordinator.UnreadablePasswordGrace);
        Assert.Equal(ErrorCategory.None, tunnel.BlockingError);
        Assert.Equal(0, _world.Ras.Dials);

        // Ещё одна попытка с тем же сбоем: запись в журнале не повторяется.
        _world.Time.Advance(tunnel.NextDialAt - _world.Time.GetUtcNow() + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);
        Assert.Single(_world.Journal.Since(0), e => e.Text.Contains("сохраните его заново", StringComparison.Ordinal));

        secrets.Unreadable.Clear();
        _world.Time.Advance(tunnel.NextDialAt - _world.Time.GetUtcNow() + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);
        Assert.Equal(1, _world.Ras.Dials);
        Assert.Equal(ConnectionState.Connected, coordinator.DeriveState());
    }

    /// <summary>Ключ SSH не читается дольше срока: то же - понятный текст и продолжающиеся повторы.</summary>
    [Fact]
    public async Task UnreadableSshKey_PastGrace_TellsToLoadItAgainAndKeepsRetrying()
    {
        new ServiceStores(_world.Paths).SaveSettings(SshSettings());
        _world.Secrets.Save(_ssh.Id, SshKeyText, SecretKind.SshPrivateKey);
        var secrets = new KindUnreadableSecrets(_world.Secrets);
        secrets.Unreadable.Add((_ssh.Id, SecretKind.SshPrivateKey));
        var coordinator = await StartWithAsync(d => d with { Secrets = secrets });
        await ConnectAsync(coordinator);
        var tunnel = coordinator.Facts.Tunnels[_ssh.Id];
        Assert.Contains("сейчас не читается", tunnel.LastErrorText, StringComparison.Ordinal);

        for (var i = 0; i < 20 && tunnel.LastErrorText?.Contains("загрузите файл ключа заново", StringComparison.Ordinal) != true; i++)
        {
            _world.Time.Advance(tunnel.NextDialAt - _world.Time.GetUtcNow() + TimeSpan.FromSeconds(1));
            await TickAsync(coordinator);
        }

        Assert.Contains("загрузите файл ключа заново", tunnel.LastErrorText, StringComparison.Ordinal);
        Assert.Equal(ErrorCategory.None, tunnel.BlockingError);
        Assert.Null(_world.SshTunnel.Last);
        Assert.True(tunnel.NextDialAt > _world.Time.GetUtcNow());

        secrets.Unreadable.Clear();
        _world.Time.Advance(tunnel.NextDialAt - _world.Time.GetUtcNow() + TimeSpan.FromSeconds(1));
        await TickAsync(coordinator);
        Assert.NotNull(_world.SshTunnel.Last);
    }
}

/// <summary>Хранилище, в котором отдельные секреты (профиль и вид) записаны, но сейчас не читаются.</summary>
internal sealed class KindUnreadableSecrets(FakeSecrets inner) : ISecretOps
{
    public HashSet<(Guid ProfileId, SecretKind Kind)> Unreadable { get; } = [];

    public char[]? TryLoad(Guid profileId, SecretKind kind = SecretKind.Password) =>
        Unreadable.Contains((profileId, kind)) ? null : inner.TryLoad(profileId, kind);

    public void Save(Guid profileId, ReadOnlySpan<char> password, SecretKind kind = SecretKind.Password) => inner.Save(profileId, password, kind);

    public void Delete(Guid profileId, SecretKind kind = SecretKind.Password) => inner.Delete(profileId, kind);

    public bool Contains(Guid profileId, SecretKind kind = SecretKind.Password) =>
        !Unreadable.Contains((profileId, kind)) && inner.Contains(profileId, kind);

    public bool IsStored(Guid profileId, SecretKind kind = SecretKind.Password) => inner.IsStored(profileId, kind);
}
