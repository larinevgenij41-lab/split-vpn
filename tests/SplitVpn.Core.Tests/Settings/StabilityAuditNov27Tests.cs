using System.Text;
using SplitVpn.Core.Dns;
using SplitVpn.Core.Ipc;
using SplitVpn.Core.Policy;
using SplitVpn.Core.Settings;

namespace SplitVpn.Core.Tests.Settings;

/// <summary>
/// Аудит стабильности 27.11: null в коллекциях запросов, контрольные цели, правила на публичных зонах, пределы количества.
/// Новые проверки запрещают только новые значения: уже сохранённые — предупреждение.
/// </summary>
public sealed class StabilityAuditNov27Tests
{
    private const string Id = "6f1c2a52-0b4e-4c8c-9a3e-0d1f2e3a4b5c";

    private static AppSettings Valid()
    {
        var profile = new ConnectionProfile { Name = "Германия", Server = "vpn.example.org", UserName = "user", Role = ProfileRole.Primary };
        return new AppSettings { Profiles = [profile], DefaultTarget = RouteTarget.Tunnel(profile.Id) };
    }

    // ---- null в коллекциях запросов ----

    [Theory]
    [InlineData("""{"type":"submitAuthForm","contractVersion":10,"profileId":"6f1c2a52-0b4e-4c8c-9a3e-0d1f2e3a4b5c","requestId":"6f1c2a52-0b4e-4c8c-9a3e-0d1f2e3a4b5c","values":{"x":null},"cancel":false}""")]
    [InlineData("""{"type":"ssoNavigation","contractVersion":10,"profileId":"6f1c2a52-0b4e-4c8c-9a3e-0d1f2e3a4b5c","requestId":"6f1c2a52-0b4e-4c8c-9a3e-0d1f2e3a4b5c","uri":"https://gw/","cookies":[null]}""")]
    [InlineData("""{"type":"saveSettings","contractVersion":10,"settings":{"schemaVersion":3,"profiles":[null]}}""")]
    [InlineData("""{"type":"saveConnection","contractVersion":10,"settings":{"schemaVersion":3,"profiles":[null]},"profileId":"6f1c2a52-0b4e-4c8c-9a3e-0d1f2e3a4b5c","password":null,"preSharedKey":null}""")]
    [InlineData("""{"type":"saveSettings","contractVersion":10,"settings":{"schemaVersion":3,"groups":[{"name":"g","members":[]}],"localDnsSuffixes":["lan",null]}}""")]
    public void NullElement_IsRejectedWithReason(string json)
    {
        Assert.Null(IpcSerializer.TryDeserializeRequest(Encoding.UTF8.GetBytes(json), out var problem));
        Assert.Contains("null", problem, StringComparison.Ordinal);
    }

    /// <summary>Обычные запросы, в том числе с null в полях, где он допустим, разбираются как прежде.</summary>
    [Fact]
    public void UsualRequests_StillParse()
    {
        var folder = new RoutingFolderSetting { Name = "Работа" };
        var settings = Valid() with
        {
            RoutingFolders = [folder],
            Rules = [new UserRuleSetting { Cidr = "10.0.0.0/8", Comment = null, FolderId = folder.Id }],
            DomainRules = [new DomainRuleSetting { Suffix = "example.org" }],
            LocalDnsSuffixes = ["lan"],
            LocalDnsServer = null,
        };
        IpcRequest[] requests =
        [
            new SaveSettingsRequest(settings),
            new SaveConnectionRequest(settings, settings.Profiles[0].Id, "пароль", null),
            new SubmitAuthFormRequest(Guid.Parse(Id), Guid.Parse(Id), new Dictionary<string, string> { ["username"] = "user", ["password"] = "" }, false),
            new SsoNavigationRequest(Guid.Parse(Id), Guid.Parse(Id), "https://gw/", [new SsoCookie("webvpn", "a+b/c==")]),
            new SetProfileOrderRequest([Guid.Parse(Id)]),
        ];

        foreach (var request in requests)
        {
            Assert.NotNull(IpcSerializer.TryDeserializeRequest(IpcSerializer.SerializeRequest(request), out var problem));
            Assert.Null(problem);
        }
    }

    // ---- контрольные цели ----

    [Theory]
    [InlineData("1.1.1.1:443, 1.1.1.1:0")]
    [InlineData("1.1.1.1")]
    [InlineData("1.1.1.l:443")]
    [InlineData("1.1.1.1:70000")]
    [InlineData("example.org:443")]
    public void CheckTargets_UnparsedItemIsErrorWhenNew(string foreign)
    {
        var settings = Valid() with { CheckTargets = new CheckTargets { Foreign = foreign } };

        Assert.Contains(SettingsValidator.Validate(settings).Errors, e => e.Contains("Иностранная контрольная цель", StringComparison.Ordinal));
        // Уже сохранённая цель не мешает сохранять остальное: предупреждение, а не ошибка.
        var kept = SettingsValidator.Validate(settings, previous: settings);
        Assert.DoesNotContain(kept.Errors, e => e.Contains("контрольная цель", StringComparison.Ordinal));
        Assert.Contains(kept.Warnings, w => w.Contains("Иностранная контрольная цель", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("")]
    [InlineData("1.1.1.1:443, 1.1.1.1:80")]
    [InlineData("1.1.1.1:443;8.8.8.8:53 9.9.9.9:53")]
    public void CheckTargets_UsualValuesPass(string foreign)
    {
        var result = SettingsValidator.Validate(Valid() with { CheckTargets = new CheckTargets { Foreign = foreign } });
        Assert.DoesNotContain(result.Errors.Concat(result.Warnings), e => e.Contains("контрольная цель", StringComparison.Ordinal));
    }

    [Fact]
    public void CheckTargets_CountIsLimited()
    {
        var many = string.Join(", ", Enumerable.Range(1, SettingsValidator.MaxCheckTargets + 1).Select(i => $"10.0.0.{i}:443"));
        var settings = Valid() with { CheckTargets = new CheckTargets { Russian = many } };

        Assert.Contains(SettingsValidator.Validate(settings).Errors, e => e.Contains("Российская контрольная цель", StringComparison.Ordinal));
        Assert.DoesNotContain(SettingsValidator.Validate(settings, settings).Errors, e => e.Contains("контрольная цель", StringComparison.Ordinal));
    }

    /// <summary>Предел - по различным целям: при применении повторы убираются, и список из 8 целей с повтором годится.</summary>
    [Fact]
    public void CheckTargets_CountIsOfDistinctTargets()
    {
        var targets = Enumerable.Range(1, SettingsValidator.MaxCheckTargets).Select(i => $"10.0.0.{i}:443").ToList();
        var withRepeats = string.Join(", ", targets.Append("10.0.0.1:443").Append("10.0.0.2:443"));

        var result = SettingsValidator.Validate(Valid() with { CheckTargets = new CheckTargets { Foreign = withRepeats } });

        Assert.DoesNotContain(result.Errors.Concat(result.Warnings), e => e.Contains("контрольная цель", StringComparison.Ordinal));
    }

    /// <summary>Каждая цель списка приводится к каноническому виду, а не только первая.</summary>
    [Fact]
    public void LegacyIpv4_CanonicalizesEveryCheckTarget()
    {
        var settings = Valid() with { CheckTargets = new CheckTargets { Foreign = "001.1.1.1:443, 1.1.1.01:80", Russian = "77.88.55.242:443" } };

        var fixedSettings = LegacyIpv4.Canonicalize(settings, out var warning);

        Assert.Null(warning);
        Assert.Equal("1.1.1.1:443, 1.1.1.1:80", fixedSettings.CheckTargets.Foreign);
        Assert.Equal("77.88.55.242:443", fixedSettings.CheckTargets.Russian);
    }

    // ---- публичные зоны ----

    [Theory]
    [InlineData("co.uk")]
    [InlineData("com.ru")]
    [InlineData("COM.RU.")]
    public void DomainRule_OnPublicZoneIsErrorWhenNew(string suffix)
    {
        var settings = Valid() with { DomainRules = [new DomainRuleSetting { Suffix = suffix }] };

        Assert.Contains(SettingsValidator.Validate(settings).Errors, e => e.Contains("общедоступная зона", StringComparison.Ordinal));
        var kept = SettingsValidator.Validate(settings, settings);
        Assert.DoesNotContain(kept.Errors, e => e.Contains("общедоступная зона", StringComparison.Ordinal));
        Assert.Contains(kept.Warnings, w => w.Contains("общедоступная зона", StringComparison.Ordinal));
    }

    /// <summary>
    /// Ведомственная зона («gov.ru», «ac.uk»): сторонние домены в ней не регистрируют, правило «gov.ru → напрямую»
    /// осмысленно — не ошибка, а предупреждение о широте у нового правила. Для списка поиска DNS она по-прежнему публичная.
    /// </summary>
    [Theory]
    [InlineData("gov.ru")]
    [InlineData("mil.ru")]
    [InlineData("edu.ru")]
    [InlineData("ac.ru")]
    [InlineData("gov.uk")]
    [InlineData("ac.uk")]
    [InlineData("sch.uk")]
    [InlineData("gov.cn")]
    [InlineData("GOV.KZ.")]
    public void DomainRule_OnInstitutionalZoneIsAllowed(string suffix)
    {
        var settings = Valid() with { DomainRules = [new DomainRuleSetting { Suffix = suffix, Target = RouteTarget.Direct }] };

        var result = SettingsValidator.Validate(settings);
        Assert.True(result.IsValid, string.Join(Environment.NewLine, result.Errors));
        Assert.Contains(result.Warnings, w => w.Contains("ведомственную зону", StringComparison.Ordinal));
        Assert.DoesNotContain(SettingsValidator.Validate(settings, settings).Warnings, w => w.Contains("ведомственную зону", StringComparison.Ordinal));

        var normalized = SettingsSerializer.NormalizeSuffix(suffix);
        Assert.True(PublicSuffixes.IsPublicZone(normalized));
        Assert.False(PublicSuffixes.IsSearchListSuffix(suffix));
    }

    [Fact]
    public void DomainRule_InsidePublicZonePasses()
    {
        var result = SettingsValidator.Validate(Valid() with { DomainRules = [new DomainRuleSetting { Suffix = "example.co.uk" }] });
        Assert.True(result.IsValid, string.Join(Environment.NewLine, result.Errors));
    }

    [Theory]
    [InlineData("com", true)]
    [InlineData("ru", true)]
    [InlineData("рф", true)]
    [InlineData("com.ru", true)]
    [InlineData("lan", false)]
    [InlineData("home.arpa", false)]
    [InlineData("office.example.org", false)]
    public void LocalSuffix_PublicZoneIsWarning(string suffix, bool warned)
    {
        var result = SettingsValidator.Validate(Valid() with { LocalDnsSuffixes = [suffix] });

        Assert.True(result.IsValid, string.Join(Environment.NewLine, result.Errors));
        Assert.Equal(warned, result.Warnings.Any(w => w.Contains("Локальный DNS-суффикс", StringComparison.Ordinal)));
    }

    [Fact]
    public void PublicSuffixes_KnowTopLevelAndTwoLabelZones()
    {
        Assert.True(PublicSuffixes.IsTopLevelDomain("com"));
        Assert.True(PublicSuffixes.IsTopLevelDomain("de"));
        Assert.False(PublicSuffixes.IsTopLevelDomain("lan"));
        Assert.False(PublicSuffixes.IsTopLevelDomain("example.com"));
        Assert.True(PublicSuffixes.IsPublicZone("co.uk"));
        Assert.False(PublicSuffixes.IsPublicZone("example.co.uk"));
    }

    // ---- пределы количества ----

    private static AppSettings WithProfiles(int count)
    {
        var profiles = Enumerable.Range(0, count)
            .Select(i => new ConnectionProfile { Name = $"VPN {i}", Server = "vpn.example.org", UserName = "user", Role = ProfileRole.Off })
            .ToList();
        return new AppSettings { Profiles = profiles };
    }

    [Fact]
    public void Profiles_CountIsLimitedForNewOnly()
    {
        var over = WithProfiles(SettingsValidator.MaxProfiles + 1);

        Assert.Contains(SettingsValidator.Validate(over).Errors, e => e.StartsWith("Подключений:", StringComparison.Ordinal));
        Assert.True(SettingsValidator.Validate(WithProfiles(SettingsValidator.MaxProfiles)).IsValid);

        // Уже сохранённое превышение: предупреждение, пока число не растёт; удаление лишнего сохраняется.
        var kept = SettingsValidator.Validate(over, over);
        Assert.True(kept.IsValid, string.Join(Environment.NewLine, kept.Errors));
        Assert.Contains(kept.Warnings, w => w.StartsWith("Подключений:", StringComparison.Ordinal));
        var grown = over with { Profiles = [.. over.Profiles, new ConnectionProfile { Name = "Ещё", Server = "vpn.example.org", UserName = "user", Role = ProfileRole.Off }] };
        Assert.Contains(SettingsValidator.Validate(grown, over).Errors, e => e.StartsWith("Подключений:", StringComparison.Ordinal));
    }

    [Fact]
    public void DomainRules_CountIsLimited()
    {
        var rules = Enumerable.Range(0, SettingsValidator.MaxDomainRules + 1).Select(i => new DomainRuleSetting { Suffix = $"d{i}.example.org" }).ToList();
        var settings = Valid() with { DomainRules = rules };

        Assert.Contains(SettingsValidator.Validate(settings).Errors, e => e.StartsWith("Правил доменов:", StringComparison.Ordinal));
        Assert.DoesNotContain(SettingsValidator.Validate(settings, settings).Errors, e => e.StartsWith("Правил доменов:", StringComparison.Ordinal));
    }
}
