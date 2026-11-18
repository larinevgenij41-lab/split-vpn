using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Settings;

/// <summary>
/// «profile set» без флага сохранения пароля не должен молча включать запись пароля на диск у профиля,
/// для которого она выключена.
/// </summary>
public sealed class SavePasswordChoiceTests
{
    private static readonly ConnectionProfile NoSave = new() { Name = "Основное", Server = "vpn.example.org", UserName = "u", SavePassword = false };

    [Fact]
    public void ExistingProfile_WithoutFlag_KeepsItsChoice()
    {
        Assert.False(ConnectionEdits.SavePasswordFor(NoSave, requested: null));
        Assert.True(ConnectionEdits.SavePasswordFor(NoSave with { SavePassword = true }, requested: null));
    }

    [Fact]
    public void NewProfile_WithoutFlag_SavesPassword() =>
        Assert.True(ConnectionEdits.SavePasswordFor(existing: null, requested: null));

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ExplicitFlag_Wins(bool requested)
    {
        Assert.Equal(requested, ConnectionEdits.SavePasswordFor(NoSave, requested));
        Assert.Equal(requested, ConnectionEdits.SavePasswordFor(existing: null, requested));
    }
}
