using System.Text.Json;
using System.Text.Json.Nodes;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Ipc;

/// <summary>
/// Урезание ответа с состоянием: пропадают только списки сетей шлюзов, их число остаётся, отметка «список не
/// полон» ставится, остальное состояние не меняется ни в одном байте значения. Ответ без списков - null.
/// </summary>
public sealed class ResponseTrimmingTests
{
    private static TunnelStatusDto Tunnel(string name, int networks, int networkCount = 0, bool truncated = false) => new()
    {
        ProfileId = Guid.NewGuid(),
        Name = name,
        Protocol = VpnProtocol.AnyConnect,
        BytesSent = ulong.MaxValue,
        ServerNetworks = new ServerNetworksDto
        {
            Networks = [.. Enumerable.Range(0, networks).Select(i => $"10.{i / 256 % 256}.{i % 256}.0/24")],
            NetworkCount = networkCount,
            NetworksTruncated = truncated,
            Dns = ["10.0.0.53"],
            DnsSuffixes = ["corp.example.org"],
            ProxyPac = "http://wpad/" + new string('я', 10),
        },
    };

    private static StatusDto Status(params TunnelStatusDto[] tunnels) => new()
    {
        ContractVersion = IpcNames.ContractVersion,
        DefaultTargetName = "Нидерланды «тест» \\ \"кавычки\" \u2028",
        Tunnels = tunnels,
        BytesReceived = ulong.MaxValue,
        SessionStartedUtc = new DateTimeOffset(2026, 11, 27, 1, 2, 3, 456, TimeSpan.FromHours(3)),
        ErrorText = "😀",
    };

    private static StatusDto Trimmed(IpcResponse response)
    {
        var trimmed = ResponseTrimming.WithoutNetworkLists(response);
        Assert.NotNull(trimmed);
        return trimmed.ResultAs<StatusDto>()!;
    }

    [Fact]
    public void ListsAreRemoved_CountIsKept_AndMarkedTruncated()
    {
        var response = IpcResponse.Success(Status(Tunnel("A", 300), Tunnel("B", 0), Tunnel("C", 5, networkCount: 9000, truncated: true)));

        var status = Trimmed(response);

        Assert.All(status.Tunnels, t => Assert.Empty(t.ServerNetworks!.Networks));
        Assert.Equal([300, 0, 9000], status.Tunnels.Select(t => t.ServerNetworks!.TotalNetworks));
        Assert.Equal([true, false, true], status.Tunnels.Select(t => t.ServerNetworks!.NetworksTruncated));
    }

    [Fact]
    public void EverythingElse_IsPreservedExactly()
    {
        var original = Status(Tunnel("Офис", 10));
        var response = IpcResponse.Success(original);

        var status = Trimmed(response);

        var expected = original with
        {
            Tunnels = [original.Tunnels[0] with { ServerNetworks = original.Tunnels[0].ServerNetworks! with { Networks = [], NetworkCount = 10, NetworksTruncated = true } }],
        };
        Assert.Equal(JsonSerializer.Serialize(expected, JsonDefaults.Compact), JsonSerializer.Serialize(status, JsonDefaults.Compact));
        Assert.Equal(ulong.MaxValue, status.BytesReceived);
        Assert.Equal(original.SessionStartedUtc, status.SessionStartedUtc);
    }

    [Fact]
    public void OkFlagAndErrorFields_AreKept()
    {
        var response = new IpcResponse(true, "code", "message", IpcResponse.Success(Status(Tunnel("A", 1))).Result);

        var trimmed = ResponseTrimming.WithoutNetworkLists(response)!;

        Assert.True(trimmed.Ok);
        Assert.Equal("code", trimmed.ErrorCode);
        Assert.Equal("message", trimmed.ErrorMessage);
    }

    /// <summary>Урезанный ответ всегда короче исходного, в том числе когда строки состояния целиком не ASCII.</summary>
    [Theory]
    [InlineData(1)]
    [InlineData(ServerNetworksDto.MaxStatusNetworks)]
    [InlineData(5000)]
    public void TrimmedPayload_IsSmaller_AndValidJson(int networks)
    {
        var response = IpcResponse.Success(Status(Tunnel(new string('ж', 200), networks)));

        var before = IpcSerializer.SerializeResponse(response);
        var after = IpcSerializer.SerializeResponse(ResponseTrimming.WithoutNetworkLists(response)!);

        Assert.True(after.Length < before.Length);
        using var _ = JsonDocument.Parse(after);
    }

    /// <summary>Сценарий канала: состояние больше кадра из-за сетей шлюзов после урезания в кадр помещается.</summary>
    [Fact]
    public void OversizedStatus_FitsFrameAfterTrimming()
    {
        var tunnels = Enumerable.Range(0, 8).Select(i => Tunnel("T" + i, 20000)).ToArray();
        var response = IpcResponse.Success(Status(tunnels));
        Assert.True(IpcSerializer.SerializeResponse(response).Length > FrameCodec.MaxFrameBytes);

        var trimmed = IpcSerializer.SerializeResponse(ResponseTrimming.WithoutNetworkLists(response)!);

        Assert.True(trimmed.Length <= FrameCodec.MaxFrameBytes);
    }

    [Fact]
    public void NothingToTrim_ReturnsNull()
    {
        Assert.Null(ResponseTrimming.WithoutNetworkLists(IpcResponse.Success(Status())));
        Assert.Null(ResponseTrimming.WithoutNetworkLists(IpcResponse.Success(Status(Tunnel("A", 0)))));
        Assert.Null(ResponseTrimming.WithoutNetworkLists(IpcResponse.Success(Status(new TunnelStatusDto { Name = "без сетей" }))));
    }

    /// <summary>Урезание идемпотентно: повторный вызов уже нечего менять.</summary>
    [Fact]
    public void SecondTrim_ReturnsNull()
    {
        var once = ResponseTrimming.WithoutNetworkLists(IpcResponse.Success(Status(Tunnel("A", 3))))!;

        Assert.Null(ResponseTrimming.WithoutNetworkLists(once));
    }

    [Theory]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("\"tunnels\"")]
    [InlineData("42")]
    [InlineData("{}")]
    [InlineData("{\"tunnels\":null}")]
    [InlineData("{\"tunnels\":{}}")]
    [InlineData("{\"tunnels\":[1,\"x\",null,[]]}")]
    [InlineData("{\"tunnels\":[{\"serverNetworks\":null}]}")]
    [InlineData("{\"tunnels\":[{\"serverNetworks\":{\"networks\":\"10.0.0.0/8\"}}]}")]
    [InlineData("{\"Tunnels\":[{\"ServerNetworks\":{\"Networks\":[\"10.0.0.0/8\"]}}]}")]
    public void NonStatusOrUnexpectedShapes_ReturnNull_WithoutThrowing(string result)
    {
        var response = new IpcResponse(true, null, null, JsonDocument.Parse(result).RootElement.Clone());

        Assert.Null(ResponseTrimming.WithoutNetworkLists(response));
    }

    [Fact]
    public void FailureWithoutResult_ReturnsNull() =>
        Assert.Null(ResponseTrimming.WithoutNetworkLists(IpcResponse.Failure("Failed", "x")));

    [Fact]
    public void NullResponse_Throws() => Assert.Throws<ArgumentNullException>(() => ResponseTrimming.WithoutNetworkLists(null!));

    /// <summary>Число сетей не уменьшается: берётся большее из счётчика и длины списка; счётчик не числом - длина списка.</summary>
    [Theory]
    [InlineData("3", 2, 3)]
    [InlineData("1", 2, 2)]
    [InlineData("0", 2, 2)]
    [InlineData("-5", 2, 2)]
    [InlineData("\"7\"", 2, 2)]
    [InlineData("null", 2, 2)]
    [InlineData("1.5", 2, 2)]
    [InlineData("2147483647", 2, int.MaxValue)]
    public void NetworkCount_IsMaxOfCounterAndList(string counter, int listLength, int expected)
    {
        var list = string.Join(',', Enumerable.Range(0, listLength).Select(i => $"\"10.0.{i}.0/24\""));
        var result = $"{{\"tunnels\":[{{\"name\":\"A\",\"serverNetworks\":{{\"networks\":[{list}],\"networkCount\":{counter}}}}}]}}";
        var response = new IpcResponse(true, null, null, JsonDocument.Parse(result).RootElement.Clone());

        var trimmed = ResponseTrimming.WithoutNetworkLists(response)!;

        var networks = JsonNode.Parse(trimmed.Result!.Value.GetRawText())!["tunnels"]![0]!["serverNetworks"]!;
        Assert.Equal(expected, networks["networkCount"]!.GetValue<int>());
        Assert.True(networks["networksTruncated"]!.GetValue<bool>());
        Assert.Empty(networks["networks"]!.AsArray());
        Assert.Equal("A", JsonNode.Parse(trimmed.Result!.Value.GetRawText())!["tunnels"]![0]!["name"]!.GetValue<string>());
    }

    /// <summary>Незнакомые этой версии поля (ответ новой службы) не теряются при урезании.</summary>
    [Fact]
    public void UnknownFields_AreKept()
    {
        const string result = "{\"future\":{\"x\":[1,2,3]},\"tunnels\":[{\"futureField\":\"да\",\"serverNetworks\":{\"networks\":[\"10.0.0.0/8\"],\"futureInner\":true}}]}";
        var response = new IpcResponse(true, null, null, JsonDocument.Parse(result).RootElement.Clone());

        var text = ResponseTrimming.WithoutNetworkLists(response)!.Result!.Value.GetRawText();

        Assert.Contains("\"future\":{\"x\":[1,2,3]}", text, StringComparison.Ordinal);
        Assert.Contains("\"futureField\":\"да\"", text, StringComparison.Ordinal);
        Assert.Contains("\"futureInner\":true", text, StringComparison.Ordinal);
    }
}
