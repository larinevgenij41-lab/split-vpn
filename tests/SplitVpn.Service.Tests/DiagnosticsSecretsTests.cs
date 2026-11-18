using System.IO.Compression;
using System.Text;
using SplitVpn.Core.Diagnostics;
using SplitVpn.Core.Ipc;
using SplitVpn.Service.Coordination;
using SplitVpn.Service.Diagnostics;

namespace SplitVpn.Service.Tests;

public sealed class DiagnosticsSecretsTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "splitvpn-secrets-tests", Guid.NewGuid().ToString("N"));

    public DiagnosticsSecretsTests() => Directory.CreateDirectory(_root);

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact]
    public void StatusForArchiveHasNoSsoQueryOrFieldValues()
    {
        var status = new StatusDto
        {
            Tunnels =
            [
                new TunnelStatusDto
                {
                    SignIn = new SignInPromptDto
                    {
                        Uri = "https://gw.example.org/saml?SAMLRequest=secret&RelayState=token",
                        Fields = [new AuthFieldDto("password", "Пароль", AuthFieldKind.Password, [], "hunter2")],
                    },
                    ServerNetworks = new ServerNetworksDto { ProxyPac = "https://u:p@gw.example.org/pac?key=abc" },
                },
            ],
        };

        var text = System.Text.Json.JsonSerializer.Serialize(Coordinator.WithoutUrlSecrets(status));

        foreach (var secret in new[] { "secret", "token", "hunter2", "abc", "u:p@" })
        {
            Assert.DoesNotContain(secret, text, StringComparison.Ordinal);
        }

        Assert.Contains("gw.example.org/saml", text, StringComparison.Ordinal);
    }

    [Fact]
    public void CancelledCollectionStopsBetweenParts()
    {
        var collector = new DiagnosticsCollector(new ServicePaths(Path.Combine(_root, "data")), TimeProvider.System, () => [], () => []);
        using var cancel = new CancellationTokenSource();
        var second = false;
        using var stream = new MemoryStream();

        Assert.Throws<OperationCanceledException>(() => collector.Write(stream,
        [
            new DiagnosticsPart("a.txt", () =>
            {
                cancel.Cancel();
                return "a";
            }),
            new DiagnosticsPart("b.txt", () =>
            {
                second = true;
                return "b";
            }),
        ], cancel.Token));

        Assert.False(second);
    }

    [Fact]
    public void PbkInArchiveHasNoSecretLines()
    {
        var paths = new ServicePaths(Path.Combine(_root, "data"));
        Directory.CreateDirectory(Path.GetDirectoryName(paths.Phonebook)!);
        File.WriteAllText(paths.Phonebook, "[SplitVpn]\r\nPhoneNumber=vpn.example.org\r\nPreSharedKey=topsecret\r\n");
        var collector = new DiagnosticsCollector(paths, TimeProvider.System, () => [], () => []);
        using var stream = new MemoryStream();

        collector.Write(stream, [], TestContext.Current.CancellationToken);

        stream.Position = 0;
        using var zip = new ZipArchive(stream);
        using var reader = new StreamReader(zip.GetEntry("files/splitvpn.pbk")!.Open(), Encoding.UTF8);
        var text = reader.ReadToEnd();
        Assert.DoesNotContain("topsecret", text, StringComparison.Ordinal);
        Assert.Contains("vpn.example.org", text, StringComparison.Ordinal);
    }
}
