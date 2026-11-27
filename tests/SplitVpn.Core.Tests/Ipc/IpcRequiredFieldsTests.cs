using System.Text;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Ipc;

/// <summary>
/// Запрос без обязательного поля или с null в нём не разбирается (служба отвечает BadRequest): иначе
/// saveSettings без settings сохранил бы настройки по умолчанию и стёр все подключения.
/// </summary>
public sealed class IpcRequiredFieldsTests
{
    private const string Id = "6f1c2a52-0b4e-4c8c-9a3e-0d1f2e3a4b5c";

    [Theory]
    [InlineData("""{"type":"saveSettings","contractVersion":10}""")]
    [InlineData("""{"type":"saveSettings","contractVersion":10,"settings":null}""")]
    [InlineData("""{"type":"saveConnection","contractVersion":10,"profileId":"6f1c2a52-0b4e-4c8c-9a3e-0d1f2e3a4b5c","password":null,"preSharedKey":null}""")]
    [InlineData("""{"type":"setProfileOrder","contractVersion":10}""")]
    [InlineData("""{"type":"setProfileOrder","contractVersion":10,"order":null}""")]
    [InlineData("""{"type":"geoImport","contractVersion":10}""")]
    [InlineData("""{"type":"geoImport","contractVersion":10,"content":null}""")]
    [InlineData("""{"type":"submitAuthForm","contractVersion":10,"profileId":"6f1c2a52-0b4e-4c8c-9a3e-0d1f2e3a4b5c","requestId":"6f1c2a52-0b4e-4c8c-9a3e-0d1f2e3a4b5c","cancel":false}""")]
    [InlineData("""{"type":"submitAuthForm","contractVersion":10,"profileId":"6f1c2a52-0b4e-4c8c-9a3e-0d1f2e3a4b5c","requestId":"6f1c2a52-0b4e-4c8c-9a3e-0d1f2e3a4b5c","values":null,"cancel":false}""")]
    [InlineData("""{"type":"setPassword","contractVersion":10,"profileId":"6f1c2a52-0b4e-4c8c-9a3e-0d1f2e3a4b5c","password":null}""")]
    [InlineData("""{"type":"checkAddress","contractVersion":10,"query":null}""")]
    [InlineData("""{"type":"ssoNavigation","contractVersion":10,"profileId":"6f1c2a52-0b4e-4c8c-9a3e-0d1f2e3a4b5c","requestId":"6f1c2a52-0b4e-4c8c-9a3e-0d1f2e3a4b5c","uri":"https://gw/","cookies":null}""")]
    public void RequestWithoutRequiredField_IsRejected(string json)
    {
        Assert.Null(IpcSerializer.TryDeserializeRequest(Encoding.UTF8.GetBytes(json)));
    }

    [Fact]
    public void CompleteRequests_StillParse()
    {
        IpcRequest[] requests =
        [
            new SaveSettingsRequest(new AppSettings()),
            new SaveConnectionRequest(new AppSettings(), Guid.Parse(Id), null, null),
            new SetProfileOrderRequest([Guid.Parse(Id)]),
            new GeoImportRequest("1.2.3.0/24"),
            new SubmitAuthFormRequest(Guid.Parse(Id), Guid.Parse(Id), new Dictionary<string, string> { ["username"] = "u" }, false),
            new ConnectRequest(null, null),
            new CheckAddressRequest("8.8.8.8"),
        ];

        foreach (var request in requests)
        {
            Assert.NotNull(IpcSerializer.TryDeserializeRequest(IpcSerializer.SerializeRequest(request)));
        }

        // Необязательные (nullable) поля по-прежнему принимают null.
        Assert.IsType<ConnectRequest>(IpcSerializer.TryDeserializeRequest(
            Encoding.UTF8.GetBytes("""{"type":"connect","contractVersion":10,"profileId":null,"password":null}""")));
    }

    /// <summary>Файлы настроек на диске читаются как раньше: null вместо списка заменяет нормализация.</summary>
    [Fact]
    public void SettingsFile_WithNullLists_StillLoads()
    {
        var result = SettingsSerializer.Deserialize("""{"schemaVersion":1,"profiles":null,"rules":null,"upstreamDns":null}""");

        Assert.Null(result.Error);
        Assert.NotNull(result.Settings);
        Assert.Empty(result.Settings!.Profiles);
        Assert.Empty(result.Settings.Rules);
    }
}
