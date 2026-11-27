using System.Globalization;
using System.Text.Json;
using SplitVpn.Core.Diagnostics;

namespace SplitVpn.Core.Tests.Diagnostics;

/// <summary>
/// Сведения о клиенте для environment.json. Значения зависят от машины, поэтому проверяется только форма:
/// корректный JSON, полный набор ключей, дополнительные поля заменяют и добавляют, числа - цифрами ASCII при любой культуре.
/// </summary>
public sealed class ClientEnvironmentTests
{
    private static readonly string[] Keys =
    [
        "user", "sid", "session", "processId", "process", "administrators", "interactive", "authentication",
        "pipe", "verboseUntilUtc", "autostart", "os", "machine", "timeZone",
    ];

    private static Dictionary<string, string?> Parse(string json) =>
        JsonSerializer.Deserialize<Dictionary<string, string?>>(json)!;

    [Fact]
    public void Json_HasAllKeys_AndIsValid()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Только Windows.");
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var values = Parse(ClientEnvironment.Json());

        Assert.All(Keys, k => Assert.True(values.ContainsKey(k), k));
        Assert.Contains(values["administrators"], new[] { "да, с повышением", "да, без повышения (UAC)", "нет" });
        Assert.Contains(values["interactive"], new[] { "да", "нет" });
        Assert.False(string.IsNullOrEmpty(values["autostart"]));
    }

    [Fact]
    public void Json_ExtraValues_OverrideAndExtend_IncludingNullAndSpecialCharacters()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Только Windows.");
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var extra = new Dictionary<string, string?>
        {
            ["machine"] = "подмена",
            ["sid"] = null,
            ["ui \"key\""] = "значение\n\"кавычки\" \\ \u0001 😀",
        };

        var values = Parse(ClientEnvironment.Json(extra));

        Assert.Equal("подмена", values["machine"]);
        Assert.Null(values["sid"]);
        Assert.Equal(extra["ui \"key\""], values["ui \"key\""]);
        Assert.Equal(Keys.Length + 1, values.Count);
    }

    [Fact]
    public void NumbersAreAsciiDigits_UnderAnyCulture()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Только Windows.");
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        foreach (var culture in TestCulture.Sensitive)
        {
            var values = TestCulture.Run(CultureInfo.GetCultureInfo(culture), ClientEnvironment.Describe);
            Assert.Matches("^[0-9]+$", values["session"]);
            Assert.Equal(Environment.ProcessId.ToString(CultureInfo.InvariantCulture), values["processId"]);
        }
    }
}
