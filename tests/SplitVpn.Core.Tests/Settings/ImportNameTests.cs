using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Settings;

/// <summary>Названия импортированных подключений сравниваются и ограничиваются так же, как в проверке настроек.</summary>
public sealed class ImportNameTests
{
    private static AppSettings With(IEnumerable<ConnectionProfile> existing, IEnumerable<ConnectionProfile> imported) =>
        new() { Profiles = [.. existing, .. imported] };

    [Fact]
    public void ExistingNameWithSpaces_IsTaken_ImportGetsSuffix()
    {
        var existing = new ConnectionProfile { Name = "Office ", Server = "vpn.example.org", UserName = "u" };
        var input = new ConnectionProfile { Name = "office", Server = "vpn2.example.org", UserName = "u" };

        var imported = Assert.Single(ConnectionEdits.PrepareImport([existing.Name], [input]));

        Assert.Equal("office 2", imported.Name);
        Assert.True(SettingsValidator.Validate(With([existing], [imported])).IsValid,
            string.Join(" ", SettingsValidator.Validate(With([existing], [imported])).Errors));
    }

    [Fact]
    public void UniqueButTooLongName_IsCutToLimit()
    {
        var input = new ConnectionProfile { Name = new string('я', SettingsValidator.MaxNameLength + 50), Server = "vpn.example.org", UserName = "u" };

        var imported = Assert.Single(ConnectionEdits.PrepareImport([], [input]));

        Assert.Equal(SettingsValidator.MaxNameLength, imported.Name.Length);
        Assert.True(SettingsValidator.Validate(With([], [imported])).IsValid);
    }

    [Fact]
    public void Cut_DoesNotSplitSurrogatePair()
    {
        // 199 букв и смайлик из двух знаков: обрезка до 200 разрезала бы пару.
        var name = new string('a', SettingsValidator.MaxNameLength - 1) + "😀" + "хвост";

        var unique = ConnectionEdits.UniqueName(new HashSet<string>(), name);

        Assert.Equal(SettingsValidator.MaxNameLength - 1, unique.Length);
        Assert.False(char.IsHighSurrogate(unique[^1]));

        var second = ConnectionEdits.UniqueName(new HashSet<string> { unique }, name);
        Assert.True(second.Length <= SettingsValidator.MaxNameLength);
        Assert.EndsWith(" 2", second, StringComparison.Ordinal);
    }

    [Fact]
    public void UniqueName_ComparesLikeValidator_EvenWithPlainSet()
    {
        var taken = new HashSet<string>(StringComparer.Ordinal) { "  Дом  " };

        Assert.Equal("дом 2", ConnectionEdits.UniqueName(taken, " дом "));
    }
}
