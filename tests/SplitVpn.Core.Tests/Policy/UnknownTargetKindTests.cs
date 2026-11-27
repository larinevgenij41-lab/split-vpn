using SplitVpn.Core.Net;
using SplitVpn.Core.Policy;

namespace SplitVpn.Core.Tests.Policy;

/// <summary>Неизвестный вид цели (число вместо имени в файле или запросе) блокируется, а не уходит мимо VPN.</summary>
public sealed class UnknownTargetKindTests
{
    [Fact]
    public void UnknownDefaultTarget_IsBlocked()
    {
        var policy = PolicyCompiler.Compile(new PolicyInput { DefaultTarget = new RouteTarget((TargetKind)7) });

        Assert.Equal(Decision.Block, policy.Classify(Ipv4.Parse("8.8.8.8")).Decision);
    }

    [Fact]
    public void UnknownRuleTarget_IsBlocked_DirectStaysDirect()
    {
        var policy = PolicyCompiler.Compile(new PolicyInput
        {
            DefaultTarget = RouteTarget.Direct,
            Rules = [new UserRule(Ipv4Cidr.Parse("8.8.8.0/24"), new RouteTarget((TargetKind)7))],
        });

        Assert.Equal(Decision.Block, policy.Classify(Ipv4.Parse("8.8.8.8")).Decision);
        Assert.Equal(Decision.Direct, policy.Classify(Ipv4.Parse("9.9.9.9")).Decision);
    }

    [Fact]
    public void Label_UnknownKind_IsBlock()
    {
        Assert.Equal(Decision.Block, PolicyCompiler.Label(new RouteTarget((TargetKind)7), DecisionSource.Default).Decision);
        Assert.Equal(Decision.Direct, PolicyCompiler.Label(RouteTarget.Direct, DecisionSource.Default).Decision);
    }
}
