using System.Text;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Ipc;

public class IpcTests
{
    private const string PasswordMarker = "Pa$$-marker-7f3c9";

    [Fact]
    public async Task Frame_RoundTrips()
    {
        using var stream = new MemoryStream();
        var request = new DisconnectRequest(KeepProtection: true);

        await FrameCodec.WriteAsync(stream, IpcSerializer.SerializeRequest(request), CancellationToken.None);
        stream.Position = 0;
        var payload = await FrameCodec.ReadAsync(stream, CancellationToken.None);

        Assert.Equal(request, IpcSerializer.TryDeserializeRequest(payload!));
        Assert.Null(await FrameCodec.ReadAsync(stream, CancellationToken.None));
    }

    [Fact]
    public async Task Frame_RejectsOversizeAndTruncation()
    {
        await Assert.ThrowsAsync<IpcProtocolException>(() =>
            FrameCodec.WriteAsync(new MemoryStream(), new byte[FrameCodec.MaxFrameBytes + 1], CancellationToken.None));

        using var oversized = new MemoryStream(BitConverter.GetBytes(FrameCodec.MaxFrameBytes + 1));
        await Assert.ThrowsAsync<IpcProtocolException>(() => FrameCodec.ReadAsync(oversized, CancellationToken.None));

        using var truncated = new MemoryStream([10, 0, 0, 0, 1, 2]);
        await Assert.ThrowsAsync<IpcProtocolException>(() => FrameCodec.ReadAsync(truncated, CancellationToken.None));
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("{\"type\":\"runShell\",\"command\":\"format c:\"}")]
    [InlineData("{\"keepProtection\":true}")]
    [InlineData("[]")]
    public void UnknownOrInvalidRequests_AreRejected(string json)
    {
        Assert.Null(IpcSerializer.TryDeserializeRequest(Encoding.UTF8.GetBytes(json)));
    }

    [Fact]
    public void Response_CarriesTypedResult()
    {
        var response = IpcResponse.Success(new StatusDto { ProfileName = "Германия", ProtectionActive = true });

        var roundTripped = IpcSerializer.DeserializeResponse(IpcSerializer.SerializeResponse(response));

        Assert.True(roundTripped.Ok);
        Assert.Equal("Германия", roundTripped.ResultAs<StatusDto>()?.ProfileName);
    }

    [Fact]
    public void SecretRequests_DoNotExposePasswordInToString()
    {
        var set = new SetPasswordRequest(Guid.NewGuid(), PasswordMarker);
        var connect = new ConnectRequest(null, PasswordMarker);

        Assert.True(set.ContainsSecret);
        Assert.True(connect.ContainsSecret);
        Assert.DoesNotContain(PasswordMarker, set.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(PasswordMarker, connect.ToString(), StringComparison.Ordinal);
        Assert.False(new ConnectRequest(null, null).ContainsSecret);
    }

    [Fact]
    public void SettingsExport_NeverContainsPassword()
    {
        var settings = new AppSettings
        {
            Profiles = [new ConnectionProfile { Name = "Германия", Server = "vpn.example.com", UserName = "user" }],
        };

        // Пароль хранится отдельно от настроек: в модели для него нет поля.
        var json = SettingsSerializer.Serialize(settings);

        Assert.DoesNotContain("\"password\"", json, StringComparison.OrdinalIgnoreCase);
    }
}
