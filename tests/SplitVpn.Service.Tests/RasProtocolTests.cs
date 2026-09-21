using SplitVpn.Core.Settings;
using SplitVpn.Windows.Ras;

namespace SplitVpn.Service.Tests;

/// <summary>Настоящие Windows API, только отдельная временная телефонная книга; дозвон не выполняется.</summary>
public sealed class RasProtocolTests
{
    public static IEnumerable<object[]> Profiles() => Enum.GetValues<VpnProtocol>()
        .SelectMany(p => Enum.GetValues<AuthMethod>().Where(a => VpnProtocols.Supports(p, a)).Select(a => new object[] { p, a }));

    [Theory]
    [MemberData(nameof(Profiles))]
    public void NativeEntryAndEapIdentityAcceptSupportedCombinations(VpnProtocol protocol, AuthMethod method)
    {
        var directory = Path.Combine(Path.GetTempPath(), "SplitVpn-native-" + Guid.NewGuid());
        var book = Path.Combine(directory, "probe.pbk");
        const string entry = "SplitVpn-Test";
        var profile = new ConnectionProfile { Name = entry, Server = "vpn.example.org", UserName = "test-user", Protocol = protocol, AuthMethod = method,
            Eap = new() { ServerNames = "radius.example.org", TrustedRootThumbprints = [new string('A', 40)], ClientCertificateThumbprint = new string('B', 40) } };
        try
        {
            RasPhonebook.Save(book, new RasEntrySpec(entry, profile.Server) { Protocol = protocol, AuthMethod = method });
            var description = RasPhonebook.Describe(book, entry);
            Assert.Equal(protocol switch { VpnProtocol.Sstp => "0x00000005", VpnProtocol.L2tpIpsec => "0x00000003", VpnProtocol.Ikev2 => "0x00000007", _ => "0x00000001" }, description["dwVpnStrategy"]);
            Assert.Equal(profile.Server, description["szLocalPhoneNumber"]);
            if (VpnProtocols.IsEap(method))
            {
                var config = EapNative.Configuration(profile);
                Assert.NotEmpty(config);
                RasPhonebook.SetEapConfiguration(book, entry, config);
                var credentials = EapNative.Identity(profile, config, "test-password");
                try { Assert.NotEmpty(credentials); }
                finally { Array.Clear(credentials); }
            }
        }
        finally
        {
            if (RasPhonebook.Exists(book, entry)) { RasPhonebook.Delete(book, entry); }
            if (Directory.Exists(directory)) { Directory.Delete(directory, recursive: true); }
        }
    }
}
