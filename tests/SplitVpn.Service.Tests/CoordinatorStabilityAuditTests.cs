using System.Net;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;
using SplitVpn.Core.SshTunnel;
using SplitVpn.Service.Coordination;
using SplitVpn.Windows.Operations;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Аудит стабильности 27.11: проверка ключа SSH только после всех прочих проверок, одна за раз и с отменой уходом
/// клиента; проверка адреса с пустым и слишком длинным запросом; контрольные цели при применении; cookie SSO.
/// </summary>
public sealed partial class CoordinatorTests
{
    private static readonly TimeSpan PromptAnswer = TimeSpan.FromSeconds(5);

    /// <summary>Проверка ключа, которая ждёт, пока её не отпустят или не отменят, и считает одновременные вызовы.</summary>
    private sealed class GatedKeyCheck(FakeSshTunnel inner) : ISshTunnelOps
    {
        private int _running;

        public TaskCompletionSource<bool> Gate { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int Calls;

        public int MaxConcurrent;

        public string? EnginePath => inner.EnginePath;

        public Task PrepareInterfaceAsync(string name) => inner.PrepareInterfaceAsync(name);

        public ISshTunnelSession Start(SingBoxParameters parameters, ReadOnlySpan<char> privateKey, Action<SshTunnelEvent> onEvent) =>
            inner.Start(parameters, privateKey, onEvent);

        public async Task<bool> CanReadKeyAsync(SingBoxParameters parameters, string privateKey, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref Calls);
            var running = Interlocked.Increment(ref _running);
            InterlockedMax(ref MaxConcurrent, running);
            try
            {
                return await Gate.Task.WaitAsync(cancellationToken);
            }
            finally
            {
                Interlocked.Decrement(ref _running);
            }
        }

        public Task<bool> ProbeAsync(IReadOnlyList<IPEndPoint> dnsServers, uint? interfaceIndex, CancellationToken cancellationToken) =>
            inner.ProbeAsync(dnsServers, interfaceIndex, cancellationToken);

        private static void InterlockedMax(ref int target, int value)
        {
            int current;
            while ((current = Volatile.Read(ref target)) < value && Interlocked.CompareExchange(ref target, value, current) != current)
            {
            }
        }
    }

    private async Task<(Coordinator Coordinator, GatedKeyCheck Check)> StartWithGatedKeyCheckAsync(AppSettings? settings = null)
    {
        new ServiceStores(_world.Paths).SaveSettings(settings ?? SshSettings());
        _world.Secrets.Save(_ssh.Id, SshKeyText, SecretKind.SshPrivateKey);
        var check = new GatedKeyCheck(_world.SshTunnel);
        var coordinator = new Coordinator(_world.Dependencies() with { SshTunnel = check });
        await coordinator.StartupAsync(CancellationToken.None);
        await CompleteDialAsync(coordinator);
        return (coordinator, check);
    }

    /// <summary>
    /// Отклонённое и без проверки ключа сохранение не запускает движок: устаревшая ревизия, протокол без ключа SSH,
    /// поле, которое отклонит проверка настроек (имя пользователя длиннее 64 знаков не помещалось в настройки движка).
    /// </summary>
    [Fact]
    public async Task SshKey_IsNotCheckedForRequestRejectedAnyway()
    {
        var (coordinator, check) = await StartWithGatedKeyCheckAsync();
        var current = coordinator.Settings;
        var sstp = _ssh with { Protocol = VpnProtocol.Sstp, AuthMethod = AuthMethod.MsChapV2, Server = "vpn.example.org" };
        var requests = new (SaveConnectionRequest Request, string Code)[]
        {
            (new SaveConnectionRequest(current, _ssh.Id, null, null, SshPrivateKey: SshKeyFile(),
                ExpectedRevision: SettingsSerializer.Revision(current with { Profiles = [] })), IpcErrorCodes.Busy),
            (new SaveConnectionRequest(current with { Profiles = [sstp] }, _ssh.Id, null, null, SshPrivateKey: SshKeyFile()), IpcErrorCodes.InvalidSettings),
            (new SaveConnectionRequest(current with { Profiles = [_ssh with { UserName = new string('u', 5000) }] }, _ssh.Id, null, null,
                SshPrivateKey: SshKeyFile()), IpcErrorCodes.InvalidSettings),
            (new SaveConnectionRequest(current, Guid.NewGuid(), null, null, SshPrivateKey: SshKeyFile()), IpcErrorCodes.InvalidSettings),
        };

        foreach (var (request, code) in requests)
        {
            var response = await coordinator.SubmitAsync(request, TestContext.Current.CancellationToken).WaitAsync(PromptAnswer, TestContext.Current.CancellationToken);
            Assert.Equal(code, response.ErrorCode);
        }

        Assert.Equal(0, check.Calls);
    }

    /// <summary>Клиент ушёл — проверка ключа отменяется, а не держит процесс движка до своего срока.</summary>
    [Fact]
    public async Task SshKey_CheckIsCancelledWhenClientLeaves()
    {
        var (coordinator, check) = await StartWithGatedKeyCheckAsync();
        using var client = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var pending = coordinator.SubmitAsync(new SaveConnectionRequest(coordinator.Settings, _ssh.Id, null, null, SshPrivateKey: SshKeyFile()),
            client.Token, CancellationToken.None);
        await WaitAsync(coordinator, () => Volatile.Read(ref check.Calls) == 1);

        await client.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending.WaitAsync(PromptAnswer, TestContext.Current.CancellationToken));
        Assert.Equal(SshKeyText, _world.Secrets.SshKeys[_ssh.Id]);
    }

    /// <summary>Одновременно — одна проверка ключа: вторая получает «занято», а не второй процесс движка.</summary>
    [Fact]
    public async Task SshKey_OnlyOneCheckAtATime()
    {
        var (coordinator, check) = await StartWithGatedKeyCheckAsync();
        var request = new SaveConnectionRequest(coordinator.Settings, _ssh.Id, null, null, SshPrivateKey: SshKeyFile());
        var first = coordinator.SubmitAsync(request, TestContext.Current.CancellationToken);
        await WaitAsync(coordinator, () => Volatile.Read(ref check.Calls) == 1);

        var second = await coordinator.SubmitAsync(request, TestContext.Current.CancellationToken).WaitAsync(PromptAnswer, TestContext.Current.CancellationToken);

        Assert.Equal(IpcErrorCodes.Busy, second.ErrorCode);
        Assert.Equal(1, check.MaxConcurrent);
        check.Gate.SetResult(true);
        await WaitAsync(coordinator, () => first.IsCompleted);
        Assert.True((await first).Ok, (await first).ErrorMessage);
    }

    /// <summary>Элемент-null в списке подключений запроса не роняет обработку мимо понятного ответа.</summary>
    [Fact]
    public async Task SshKey_NullProfileInRequestIsNotException()
    {
        var coordinator = await StartWithSshAsync();
        var settings = coordinator.Settings with { Profiles = [null!, _ssh] };

        var pending = coordinator.SubmitAsync(new SaveConnectionRequest(settings, _ssh.Id, null, null, SshPrivateKey: SshKeyFile()),
            TestContext.Current.CancellationToken);
        await WaitAsync(coordinator, () => pending.IsCompleted);

        var response = await pending;
        Assert.True(response.Ok, response.ErrorMessage);
    }

    /// <summary>Пустой запрос проверки адреса не возвращает адреса самой машины, длинный — не роняет проверку исключением.</summary>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(300)]
    public async Task CheckAddress_EmptyOrTooLongQueryIsClearRefusal(object query)
    {
        var coordinator = await StartAsync();
        var text = query is int length ? new string('a', length) : (string)query;

        var pending = coordinator.SubmitAsync(new CheckAddressRequest(text), TestContext.Current.CancellationToken);
        await WaitAsync(coordinator, () => pending.IsCompleted);
        var viaQueue = await pending;
        var direct = await coordinator.HandleRequestAsync(new CheckAddressRequest(text), TestContext.Current.CancellationToken);

        foreach (var response in new[] { viaQueue, direct })
        {
            Assert.False(response.Ok);
            Assert.Equal(IpcErrorCodes.BadRequest, response.ErrorCode);
            Assert.DoesNotContain("прервана", response.ErrorMessage, StringComparison.Ordinal);
        }
    }

    /// <summary>Неразобранная контрольная цель при применении — запись в журнале событий, а не тихий пропуск.</summary>
    [Fact]
    public void CheckTargets_SkippedItemsAreReported()
    {
        var reported = new List<(string Targets, IReadOnlyList<string> Skipped, int Used)>();
        var targets = Coordinator.ParseTargets("1.1.1.1:443, 1.1.1.01:80", (t, s, u) => reported.Add((t, s, u)));

        Assert.Single(targets);
        var report = Assert.Single(reported);
        Assert.Equal(["1.1.1.01:80"], report.Skipped);
        Assert.Equal(1, report.Used);

        var many = string.Join(", ", Enumerable.Range(1, 12).Select(i => $"10.0.0.{i}:443"));
        Assert.Equal(SettingsValidator.MaxCheckTargets, Coordinator.ParseTargets(many).Count);
    }

    [Fact]
    public async Task CheckTargets_TypoIsJournaledWhenTunnelIsVerified()
    {
        new ServiceStores(_world.Paths).SaveSettings(Settings() with { CheckTargets = new CheckTargets { Foreign = "1.1.1.l:443" } });
        var coordinator = await StartAsync();

        await ConnectAsync(coordinator);

        Assert.Contains(_world.Journal.Since(0), e => e.Text.Contains("Контрольные цели «1.1.1.l:443» не разобраны", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("webvpn", "a+b/c==", true)]
    [InlineData("acSamlv2Token", "\"quoted value, with spaces\"", true)]
    [InlineData("", "value", true)]
    [InlineData("name", "line\r\nSet-Cookie: x=y", false)]
    [InlineData("name", "a;b", false)]
    [InlineData("na=me", "value", false)]
    [InlineData("na\nme", "value", false)]
    public void SsoCookie_HeaderBreakingValuesAreRejected(string name, string value, bool accepted)
    {
        Assert.Equal(accepted, Coordinator.IsAcceptableCookie(new SsoCookie(name, value)));
    }

    [Fact]
    public void SsoCookie_LengthAndNullAreLimited()
    {
        Assert.True(Coordinator.IsAcceptableCookie(new SsoCookie("n", new string('v', Coordinator.MaxCookieLength - 1))));
        Assert.False(Coordinator.IsAcceptableCookie(new SsoCookie("n", new string('v', Coordinator.MaxCookieLength))));
        Assert.False(Coordinator.IsAcceptableCookie(null));
        Assert.False(Coordinator.IsAcceptableCookie(new SsoCookie(null!, "v")));
    }
}
