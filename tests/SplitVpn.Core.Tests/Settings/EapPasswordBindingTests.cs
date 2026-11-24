using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Settings;

/// <summary>
/// Пароль EAP с проверкой сервера привязан и к самой проверке: смена имён сервера или доверенных корневых CA
/// снимает привязку, иначе прежний пароль ушёл бы подставному серверу.
/// </summary>
public sealed class EapPasswordBindingTests
{
    private const string RootA = "0123456789ABCDEF0123456789ABCDEF01234567";
    private const string RootB = "89ABCDEF0123456789ABCDEF0123456789ABCDEF";

    private static readonly ConnectionProfile Peap = new()
    {
        Name = "Офис",
        Server = "vpn.example.org",
        UserName = "u",
        Protocol = VpnProtocol.Ikev2,
        AuthMethod = AuthMethod.PeapMsChapV2,
        Eap = new EapSettings { ServerNames = "nps.example.org;nps2.example.org", TrustedRootThumbprints = [RootA, RootB] },
    };

    [Fact]
    public void SameValidation_InOtherOrderAndCase_KeepsBinding()
    {
        var reordered = Peap with
        {
            Eap = new EapSettings
            {
                ServerNames = " NPS2.example.org ; nps.EXAMPLE.org",
                TrustedRootThumbprints = [RootB.ToLowerInvariant(), "01 23 45 67 89 AB CD EF 01 23 45 67 89 AB CD EF 01 23 45 67"],
            },
        };

        Assert.False(ConnectionEdits.PasswordBindingChanged(Peap, reordered));
    }

    [Fact]
    public void ChangedServerNames_BreaksBinding()
    {
        var changed = Peap with { Eap = Peap.Eap with { ServerNames = "nps.example.org;evil.example.org" } };

        Assert.True(ConnectionEdits.PasswordBindingChanged(Peap, changed));
    }

    [Fact]
    public void ChangedTrustedRoots_BreaksBinding()
    {
        Assert.True(ConnectionEdits.PasswordBindingChanged(Peap, Peap with { Eap = Peap.Eap with { TrustedRootThumbprints = [RootA] } }));
        Assert.True(ConnectionEdits.PasswordBindingChanged(Peap, Peap with
        {
            Eap = Peap.Eap with { TrustedRootThumbprints = [RootA, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"] },
        }));
    }

    [Fact]
    public void MethodWithoutServerValidation_IgnoresEapSection()
    {
        var chap = Peap with { AuthMethod = AuthMethod.MsChapV2, Protocol = VpnProtocol.Sstp };

        Assert.False(ConnectionEdits.PasswordBindingChanged(chap, chap with { Eap = new EapSettings { ServerNames = "other.example.org" } }));
    }
}
