using SplitVpn.Core.Ipc;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Settings;

/// <summary>
/// Порядок подключений — это порядок списка <see cref="AppSettings.Profiles"/>, и другого источника
/// правды нет: он же виден на экране, он же задаёт очерёдность подъёма.
/// </summary>
public class ProfileOrderTests
{
    private static ConnectionProfile Profile(string name, ProfileRole role) =>
        new() { Name = name, Server = "203.0.113.10:4443", UserName = "user", Role = role };

    [Fact]
    public void ActiveProfiles_KeepsListOrder_EvenWhenPrimaryIsNotFirst()
    {
        var second = Profile("Резерв", ProfileRole.Secondary);
        var primary = Profile("Опорное", ProfileRole.Primary);
        var off = Profile("Выключено", ProfileRole.Off);
        var settings = new AppSettings { Profiles = [second, primary, off] };

        Assert.Equal([second.Id, primary.Id], settings.ActiveProfiles.Select(p => p.Id));
        Assert.Equal(primary.Id, settings.PrimaryProfile!.Id);
    }

    [Fact]
    public void Reorder_KeepsEveryProfile_AndAppliesNewOrder()
    {
        var first = Profile("Первое", ProfileRole.Primary);
        var second = Profile("Второе", ProfileRole.Secondary);
        var third = Profile("Третье", ProfileRole.Secondary);
        var settings = new AppSettings { Profiles = [first, second, third] };

        var reordered = ConnectionEdits.Reorder(settings, [third.Id, first.Id, second.Id]);

        Assert.Equal([third.Id, first.Id, second.Id], reordered.Profiles.Select(p => p.Id));
        Assert.Equal(3, reordered.Profiles.Count);
        Assert.Equal("Третье", reordered.Profiles[0].Name);
    }

    [Fact]
    public void Reorder_RejectsSetThatDoesNotMatch()
    {
        var first = Profile("Первое", ProfileRole.Primary);
        var second = Profile("Второе", ProfileRole.Secondary);
        var settings = new AppSettings { Profiles = [first, second] };

        Assert.False(ConnectionEdits.IsSameSet(settings.Profiles, [first.Id]));
        Assert.False(ConnectionEdits.IsSameSet(settings.Profiles, [first.Id, first.Id]));
        Assert.False(ConnectionEdits.IsSameSet(settings.Profiles, [first.Id, Guid.NewGuid()]));
        Assert.True(ConnectionEdits.IsSameSet(settings.Profiles, [second.Id, first.Id]));
        Assert.Throws<ArgumentException>(() => ConnectionEdits.Reorder(settings, [first.Id]));
    }

    [Fact]
    public void Reorder_DoesNotTouchTargets()
    {
        var first = Profile("Первое", ProfileRole.Primary);
        var second = Profile("Второе", ProfileRole.Secondary);
        var settings = new AppSettings
        {
            Profiles = [first, second],
            DefaultTarget = RouteTarget.Tunnel(first.Id),
            Rules = [new UserRuleSetting { Cidr = "13.107.0.0/16", Target = RouteTarget.Tunnel(second.Id) }],
        };

        var reordered = ConnectionEdits.Reorder(settings, [second.Id, first.Id]);

        Assert.Equal(settings.DefaultTarget, reordered.DefaultTarget);
        Assert.Equal(settings.Rules[0].Target, reordered.Rules[0].Target);
        Assert.True(SettingsValidator.Validate(reordered).IsValid);
    }

    [Fact]
    public void Order_SurvivesSerialization()
    {
        var first = Profile("Первое", ProfileRole.Primary);
        var second = Profile("Второе", ProfileRole.Secondary);
        var third = Profile("Третье", ProfileRole.Secondary);
        var settings = new AppSettings { Profiles = [third, first, second], SequentialDial = true };

        var restored = SettingsSerializer.Deserialize(SettingsSerializer.Serialize(settings)).Settings;

        Assert.NotNull(restored);
        Assert.Equal([third.Id, first.Id, second.Id], restored.Profiles.Select(p => p.Id));
        Assert.True(restored.SequentialDial);
    }

    /// <summary>Настройка появилась в 0.8.x: старый файл без неё читается как «поднимать все сразу».</summary>
    [Fact]
    public void SequentialDial_DefaultsToOff()
    {
        Assert.False(new AppSettings().SequentialDial);
    }

    [Fact]
    public void NewRequests_AreInTheWhiteList()
    {
        var paused = new SetTunnelPausedRequest(Guid.NewGuid(), Paused: true);
        var order = new SetProfileOrderRequest([Guid.NewGuid(), Guid.NewGuid()]);

        Assert.Equal(paused, IpcSerializer.TryDeserializeRequest(IpcSerializer.SerializeRequest(paused)));
        var restored = Assert.IsType<SetProfileOrderRequest>(IpcSerializer.TryDeserializeRequest(IpcSerializer.SerializeRequest(order)));
        Assert.Equal(order.Order, restored.Order);
    }
}
