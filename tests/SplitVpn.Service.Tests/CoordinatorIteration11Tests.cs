using System.Globalization;
using System.Text.Json;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;
using SplitVpn.Core.State;
using SplitVpn.Service.Coordination;
using SplitVpn.Service.Ipc;
using SplitVpn.Windows.Native;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Итерация 11: размер состояния и отчёта при тысячах сетей шлюза, временные коды RAS при подготовке записи, отказ
/// записи настроек и состояния без ложного «неполного применения».
/// </summary>
public sealed partial class CoordinatorTests
{
    private static List<string> ManyIncludes(int count) => Enumerable.Range(0, count)
        .Select(i => string.Create(CultureInfo.InvariantCulture, $"10.{i / 256}.{i % 256}.0/255.255.255.0")).ToList();

    [Fact]
    public async Task ManyGatewayNetworks_StatusCarriesCountAndFirstPage_RestIsPaged()
    {
        var coordinator = await StartWithAnyConnectAsync();
        await EstablishWithIncludesAsync(coordinator, ManyIncludes(3000));

        var gateway = coordinator.BuildStatus().Tunnels.Single(t => t.ProfileId == _anyConnect.Id).ServerNetworks!;
        Assert.Equal(3000, gateway.NetworkCount);
        Assert.Equal(3000, gateway.TotalNetworks);
        Assert.True(gateway.NetworksTruncated);
        Assert.Equal(ServerNetworksDto.MaxStatusNetworks, gateway.Networks.Count);
        Assert.Equal("10.0.0.0/24", gateway.Networks[0]);

        var all = new List<string>();
        while (true)
        {
            var response = await coordinator.HandleRequestAsync(new GetServerNetworksRequest(_anyConnect.Id, all.Count), CancellationToken.None);
            var page = response.ResultAs<ServerNetworksPageDto>()!;
            Assert.True(page.Networks.Count <= ServerNetworksPageDto.MaxPage);
            Assert.Equal(3000, page.Total);
            all.AddRange(page.Networks);
            if (page.Networks.Count == 0 || all.Count >= page.Total) break;
        }

        Assert.Equal(3000, all.Distinct().Count());
        Assert.Equal("10.11.183.0/24", all[^1]);
        Assert.Equal(IpcErrorCodes.BadRequest, (await coordinator.HandleRequestAsync(new GetServerNetworksRequest(_anyConnect.Id, -1), CancellationToken.None)).ErrorCode);
        Assert.Equal(IpcErrorCodes.NotFound, (await coordinator.HandleRequestAsync(new GetServerNetworksRequest(_profile.Id, 0), CancellationToken.None)).ErrorCode);
    }

    [Fact]
    public async Task GatewayNetworks_FormattedOncePerSession()
    {
        var coordinator = await StartWithAnyConnectAsync();
        await EstablishWithIncludesAsync(coordinator, ManyIncludes(10));

        var first = coordinator.BuildStatus().Tunnels.Single(t => t.ProfileId == _anyConnect.Id).ServerNetworks!;
        var second = coordinator.BuildStatus().Tunnels.Single(t => t.ProfileId == _anyConnect.Id).ServerNetworks!;
        Assert.False(first.NetworksTruncated);
        Assert.Equal(10, first.NetworkCount);
        Assert.Same(first.Networks, second.Networks);
    }

    /// <summary>Десять шлюзов по 16384 сети: состояние остаётся в кадре канала, а не превращается в отказ.</summary>
    [Fact]
    public void OversizedStatus_LosesNetworkListsInsteadOfFailing()
    {
        var networks = Enumerable.Range(0, 16384).Select(i => string.Create(CultureInfo.InvariantCulture, $"10.{i / 256}.{i % 256}.0/24")).ToArray();
        var status = new StatusDto
        {
            ContractVersion = IpcNames.ContractVersion,
            Tunnels = [.. Enumerable.Range(0, 10).Select(i => new TunnelStatusDto
            {
                ProfileId = Guid.NewGuid(),
                Name = "Шлюз " + i,
                ServerNetworks = new ServerNetworksDto { Networks = networks, Dns = ["10.0.0.1"] },
            })],
        };
        var response = IpcResponse.Success(status);
        Assert.True(IpcSerializer.SerializeResponse(response).Length > FrameCodec.MaxFrameBytes);

        var payload = IpcServer.FramePayload(response);

        Assert.True(payload.Length <= FrameCodec.MaxFrameBytes);
        var delivered = IpcSerializer.DeserializeResponse(payload);
        Assert.True(delivered.Ok);
        var tunnels = delivered.ResultAs<StatusDto>()!.Tunnels;
        Assert.Equal(10, tunnels.Count);
        Assert.All(tunnels, t =>
        {
            Assert.Empty(t.ServerNetworks!.Networks);
            Assert.True(t.ServerNetworks.NetworksTruncated);
            Assert.Equal(16384, t.ServerNetworks.TotalNetworks);
            Assert.Equal(["10.0.0.1"], t.ServerNetworks.Dns);
        });
    }

    [Fact]
    public void OversizedNonStatusResponse_StillFailsClearly()
    {
        var payload = IpcServer.FramePayload(IpcResponse.Success(new string('x', FrameCodec.MaxFrameBytes)));
        var delivered = IpcSerializer.DeserializeResponse(payload);
        Assert.False(delivered.Ok);
        Assert.Equal(IpcErrorCodes.Failed, delivered.ErrorCode);
    }

    [Fact]
    public async Task ExportReport_IsCompactAndFallsBackToRecentEvents()
    {
        var coordinator = await StartAsync();
        var report = (await coordinator.HandleRequestAsync(new ExportReportRequest(MaskPersonalData: false), CancellationToken.None)).ResultAs<string>()!;
        Assert.DoesNotContain("\n", report, StringComparison.Ordinal);
        using (var document = JsonDocument.Parse(report))
        {
            Assert.Equal(JsonValueKind.Null, document.RootElement.GetProperty("note").ValueKind);
        }

        // Кавычки занимают от 4 байт после двойного экранирования: полный журнал в кадр не помещается. (Управляющие
        // символы журнал теперь сам записывает как «\uXXXX» и обрезает: они раздувают текст меньше.)
        for (var i = 0; i < 500; i++)
        {
            coordinator.Journal("Сведения", new string('"', EventJournal.MaxTextLength));
        }

        var response = await coordinator.HandleRequestAsync(new ExportReportRequest(MaskPersonalData: true), CancellationToken.None);
        Assert.True(response.Ok, response.ErrorMessage);
        Assert.True(IpcSerializer.SerializeResponse(response).Length <= FrameCodec.MaxFrameBytes);
        using var reduced = JsonDocument.Parse(response.ResultAs<string>()!);
        Assert.Equal(Coordinator.ReportFallbackEvents, reduced.RootElement.GetProperty("events").GetArrayLength());
        Assert.Contains("сокращён", reduced.RootElement.GetProperty("note").GetString()!, StringComparison.Ordinal);
    }

    [Fact]
    public void Journal_LongTextIsBounded()
    {
        var journal = new EventJournal(TimeProvider.System);
        journal.Add("Сведения", new string('я', EventJournal.MaxTextLength * 3));
        Assert.Equal(EventJournal.MaxTextLength + 1, journal.Since(0)[0].Text.Length);
    }

    [Theory]
    [InlineData(711u)]
    [InlineData(1058u)]
    [InlineData(1062u)]
    [InlineData(1068u)]
    [InlineData(1722u)]
    [InlineData(1726u)]
    [InlineData(1727u)]
    public async Task RasUnavailableDuringPrepare_RetriesInsteadOfBlocking(uint code)
    {
        _world.Ras.SaveEntryFailure = new NativeCallException("RasSetEntryProperties", code);
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);

        var tunnel = coordinator.Facts.Tunnels[_profile.Id];
        Assert.Equal(ErrorCategory.None, tunnel.BlockingError);
        Assert.Equal(ErrorCategory.Other, tunnel.LastErrorCategory);
        Assert.True(tunnel.NextDialAt > _world.Time.GetUtcNow());
        Assert.True(Coordinator.IsTransientPrepareError(new NativeCallException("RasSetEntryProperties", code)));
    }

    [Fact]
    public async Task SetProfileOrder_SettingsWriteFails_ReportsFailureAndKeepsOrder()
    {
        var coordinator = await StartWithAnyConnectAsync();
        var before = coordinator.Settings.Profiles.Select(p => p.Id).ToList();
        IpcResponse response;
        using (new FileStream(_world.Paths.Settings, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            response = await coordinator.HandleRequestAsync(new SetProfileOrderRequest([.. Enumerable.Reverse(before)]), CancellationToken.None);
        }

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.Failed, response.ErrorCode);
        Assert.Contains("файл настроек", response.ErrorMessage!, StringComparison.Ordinal);
        Assert.Equal(before, coordinator.Settings.Profiles.Select(p => p.Id).ToList());
    }

    [Fact]
    public async Task SetProfileRole_SettingsWriteFails_ReportsFailureAndKeepsRole()
    {
        var coordinator = await StartWithAnyConnectAsync();
        IpcResponse response;
        using (new FileStream(_world.Paths.Settings, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            response = await coordinator.HandleRequestAsync(new SetProfileRoleRequest(_anyConnect.Id, ProfileRole.Off), CancellationToken.None);
        }

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.Failed, response.ErrorCode);
        Assert.Equal(ProfileRole.Secondary, coordinator.Settings.Profile(_anyConnect.Id)!.Role);
    }

    [Fact]
    public async Task ChangeIntent_StateWriteFails_ReportsFailureAndKeepsIntent()
    {
        var coordinator = await StartAsync();
        await ConnectAsync(coordinator);
        IpcResponse response;
        using (new FileStream(_world.Paths.State, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            response = await coordinator.HandleRequestAsync(new DisconnectRequest(KeepProtection: true), CancellationToken.None);
        }

        Assert.False(response.Ok);
        Assert.Equal(IpcErrorCodes.Failed, response.ErrorCode);
        Assert.Contains("файл состояния", response.ErrorMessage!, StringComparison.Ordinal);
        Assert.Equal(Intent.Connected, coordinator.BuildStatus().Intent);
    }
}
