using SplitVpn.Core.Ipc;
using SplitVpn.Core.Net;
using SplitVpn.Core.OpenConnect;
using SplitVpn.Core.Policy;

namespace SplitVpn.Core.Tests.OpenConnect;

/// <summary>Данные недоверенного шлюза AnyConnect: адрес туннеля, DNS, пределы сеанса и формы входа.</summary>
public sealed class GatewayDataLimitsTests
{
    [Theory]
    [InlineData("0.0.0.0", true)]
    [InlineData("0.1.2.3", true)]
    [InlineData("127.0.0.1", true)]
    [InlineData("169.254.0.5", true)]
    [InlineData("224.0.0.1", true)]
    [InlineData("239.255.255.250", true)]
    [InlineData("240.0.0.1", true)]
    [InlineData("255.255.255.255", true)]
    [InlineData("", true)]
    [InlineData("10.0.7.190", false)]
    [InlineData("192.168.1.50", false)]
    [InlineData("1.1.1.1", false)]
    public void TunnelAddressProblem_RejectsServiceRanges(string address, bool rejected)
    {
        var problem = new SessionInfo { Address = address }.TunnelAddressProblem();

        Assert.Equal(rejected, problem is not null);
    }

    /// <summary>Link-local «DNS шлюза» не годится: его нельзя спросить через туннель, а политика увела бы его туда.</summary>
    [Fact]
    public void DnsAddresses_DropsLinkScope()
    {
        var session = new SessionInfo { Dns = ["169.254.1.1", "127.0.0.53", "224.0.0.251", "10.0.16.21", "0.0.0.0"] };

        Assert.Equal([Ipv4.Parse("10.0.16.21")], session.DnsAddresses());
    }

    [Fact]
    public void Capped_LimitsListsAndMarksTruncation_AndIsIdempotent()
    {
        var session = new SessionInfo
        {
            Address = "10.0.7.190",
            SplitIncludes = Enumerable.Range(0, 70_000).Select(i => $"10.{i / 65536}.{i / 256 % 256}.{i % 256}/32").ToList(),
            SplitExcludes = ["192.168.0.0/16", new string('9', 500)],
            SplitDns = Enumerable.Range(0, 70).Select(i => $"d{i}.example.org").ToList(),
            Domain = new string('d', 10_000),
            ProxyPac = "http://pac.example.org/" + new string('p', 10_000),
        };

        var capped = session.Capped();

        Assert.Equal(HelperLimits.MaxSplitRoutes, capped.SplitIncludes.Count);
        Assert.Equal(["192.168.0.0/16"], capped.SplitExcludes);
        Assert.Equal(HelperLimits.MaxSplitDns, capped.SplitDns.Count);
        Assert.Equal(HelperLimits.MaxSessionText, capped.Domain!.Length);
        Assert.Null(capped.ProxyPac);
        Assert.Equal(5, capped.Truncated.Count);
        Assert.Contains(capped.Truncated, t => t.Contains("взято 16384 из 70000", StringComparison.Ordinal));
        Assert.True(JsonSize(capped) < FrameCodec.MaxFrameBytes);

        var again = capped.Capped();
        Assert.Same(capped, again);
    }

    /// <summary>
    /// Худший случай после урезания: полные таблицы split-include и split-exclude записями наибольшей длины, все
    /// остальные поля на пределе и в символах, которые JSON экранирует, — событие всё равно меньше кадра канала.
    /// </summary>
    [Fact]
    public void Capped_WorstCaseSession_FitsFrame()
    {
        const string longest = "255.255.255.255/255.255.255.255";
        Assert.Equal(HelperLimits.MaxRouteLength, longest.Length);
        Assert.Equal(GatewayNetworkLimits.MaxRoutes, HelperLimits.MaxSplitRoutes);
        var escaped = new string('я', HelperLimits.MaxSessionText);
        var session = new SessionInfo
        {
            Address = "255.255.255.255",
            Netmask = "255.255.255.255",
            Dns = Enumerable.Repeat("255.255.255.255", 100).ToList(),
            SplitIncludes = Enumerable.Repeat(longest, HelperLimits.MaxSplitRoutes + 10).ToList(),
            SplitExcludes = Enumerable.Repeat(longest, HelperLimits.MaxSplitRoutes + 10).ToList(),
            SplitDns = Enumerable.Repeat(new string('я', HelperLimits.MaxDnsNameLength), 100).ToList(),
            Domain = escaped + "x",
            ProxyPac = escaped,
            Truncated = Enumerable.Repeat(escaped[..200], 8).ToList(),
        };

        var capped = session.Capped();
        var size = JsonSize(capped);

        Assert.Equal(HelperLimits.MaxSplitRoutes, capped.SplitIncludes.Count);
        Assert.Equal(HelperLimits.MaxSplitRoutes, capped.SplitExcludes.Count);
        Assert.True(size < FrameCodec.MaxFrameBytes, $"{size} байт");
    }

    /// <summary>Шлюз, присылавший 16384 сетей (предел службы после свёртки), не урезается.</summary>
    [Fact]
    public void Capped_FullRouteTableOfWorkingGateway_IsKept()
    {
        var includes = Enumerable.Range(0, GatewayNetworkLimits.MaxRoutes).Select(i => $"10.{i / 256 % 256}.{i % 256}.0/255.255.255.0").ToList();
        var session = new SessionInfo { Address = "10.0.7.190", SplitIncludes = includes, SplitExcludes = includes };

        Assert.Same(session, session.Capped());
    }

    /// <summary>
    /// Запись не из цифр, точек и косой черты (её JSON экранировал бы) отбрасывается с отметкой; сеть IPv6 — молча:
    /// туннель только IPv4.
    /// </summary>
    [Fact]
    public void Capped_DropsNonRouteEntries_AndIpv6Silently()
    {
        var ipv6Only = new SessionInfo { SplitIncludes = ["10.0.0.0/255.0.0.0", "fd00::/64"] }.Capped();
        Assert.Equal(["10.0.0.0/255.0.0.0"], ipv6Only.SplitIncludes);
        Assert.Empty(ipv6Only.Truncated);

        var garbage = new SessionInfo { SplitIncludes = ["10.0.0.0/8", "яяя", "10.0.0.0/8 x"] }.Capped();
        Assert.Equal(["10.0.0.0/8"], garbage.SplitIncludes);
        Assert.Contains(garbage.Truncated, t => t.Contains("неверного вида или длины 2", StringComparison.Ordinal));
    }

    [Fact]
    public void Capped_LeavesOrdinarySessionUntouched()
    {
        var session = new SessionInfo { Address = "10.0.7.190", Dns = ["10.0.16.21"], SplitIncludes = ["10.0.0.0/255.0.0.0"] };

        Assert.Same(session, session.Capped());
        Assert.Empty(session.Truncated);
    }

    [Fact]
    public void AuthForm_Capped_LimitsTextsFieldsAndChoices()
    {
        var choices = Enumerable.Range(0, 1000).Select(i => new AuthChoiceDto("g" + i, new string('c', 1000))).Append(new AuthChoiceDto(new string('n', 2000), "long")).ToList();
        var fields = Enumerable.Range(0, 100).Select(i => new AuthFieldDto("f" + i, new string('l', 1000), AuthFieldKind.Select, choices, new string('v', 5000)))
            .Prepend(new AuthFieldDto(new string('x', 300), "too long name", AuthFieldKind.Text, [], null))
            .ToList();
        var form = new AuthFormEvent(Guid.NewGuid(), new string('t', 2_000_000), new string('m', 5000), "short", fields).Capped();

        Assert.Equal(HelperLimits.MaxFormText, form.Title!.Length);
        Assert.EndsWith("…", form.Title, StringComparison.Ordinal);
        Assert.Equal(HelperLimits.MaxFormText, form.Message!.Length);
        Assert.Equal("short", form.Error);
        Assert.InRange(form.Fields.Count, 1, HelperLimits.MaxFormFields);
        Assert.Equal("f0", form.Fields[0].Name);
        Assert.All(form.Fields, f =>
        {
            Assert.Equal(HelperLimits.MaxLabel, f.Label.Length);
            Assert.Null(f.Value);
            Assert.InRange(f.Choices.Count, 0, HelperLimits.MaxChoices);
            Assert.All(f.Choices, c => Assert.Equal(HelperLimits.MaxLabel, c.Label.Length));
            Assert.DoesNotContain(f.Choices, c => c.Name.Length > HelperLimits.MaxLabel);
        });
        var chars = form.Fields.Sum(f => f.Name.Length + f.Label.Length + (f.Value?.Length ?? 0) + f.Choices.Sum(c => c.Name.Length + c.Label.Length));
        Assert.True(chars <= HelperLimits.MaxFormFieldChars);
        // Даже при экранировании каждого символа (\uXXXX) форма много меньше кадра канала.
        Assert.True(HelperContract.Serialize(form).Length < FrameCodec.MaxFrameBytes / 4);
    }

    [Fact]
    public void AuthForm_Capped_KeepsOrdinaryFormWhole()
    {
        var group = new AuthFieldDto("group_list", "Группа", AuthFieldKind.Select, [new("staff", "Сотрудники"), new("guest", "Гости")], "staff");
        var fields = new List<AuthFieldDto> { group, new("username", "Имя", AuthFieldKind.Text, [], "ivan"), new("password", "Пароль", AuthFieldKind.Password, [], null) };
        var form = new AuthFormEvent(Guid.NewGuid(), "Вход", "Введите данные", null, fields);

        var capped = form.Capped();

        Assert.Equal(form.Title, capped.Title);
        Assert.Equal(fields, capped.Fields, (a, b) => a.Name == b.Name && a.Label == b.Label && a.Value == b.Value && a.Choices.SequenceEqual(b.Choices));
    }

    /// <summary>Обрезка не рвёт суррогатную пару: половина пары - недопустимый UTF-16 для сериализатора.</summary>
    [Fact]
    public void Truncate_DoesNotSplitSurrogatePair()
    {
        var text = new string('a', 2) + "\U0001F600" + new string('b', 10);

        var cut = HelperLimits.Truncate(text, 4)!;

        Assert.Equal("aa…", cut);
        Assert.Null(HelperLimits.Truncate(null, 4));
        Assert.Equal("abc", HelperLimits.Truncate("abc", 4));
    }

    /// <summary>DNS шлюза из сети своего адаптера остаётся в локальной сети: LAN важнее DNS туннеля.</summary>
    [Fact]
    public void TunnelHost_OnLinkAddress_StaysLocal()
    {
        var tunnel = Guid.NewGuid();
        var lanHost = Ipv4.Parse("192.168.1.10");
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            DefaultTarget = RouteTarget.Direct,
            OnLinePrefixes = [Ipv4Cidr.Parse("192.168.1.0/24")],
            ServerNetworks = [new ServerNetworks(RouteTarget.Tunnel(tunnel), [Ipv4Cidr.Parse("10.0.0.0/8")])],
            TunnelHosts = [new TunnelHost(tunnel, lanHost), new TunnelHost(tunnel, Ipv4.Parse("10.0.16.21"))],
        });

        Assert.Equal(DecisionSource.OnLink, policy.Classify(lanHost).Source);
        Assert.Equal(Decision.Local, policy.Classify(lanHost).Decision);
        Assert.Equal(DecisionSource.TunnelInfrastructure, policy.Classify(Ipv4.Parse("10.0.16.21")).Source);
    }

    private static int JsonSize(SessionInfo session) =>
        HelperContract.Serialize(new EstablishedEvent(1, "SplitVpn AC", session)).Length;
}
