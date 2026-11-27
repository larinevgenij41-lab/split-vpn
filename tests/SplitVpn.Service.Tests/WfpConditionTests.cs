using System.Net;
using SplitVpn.Core.Net;
using SplitVpn.Core.Protection;
using SplitVpn.Windows.Native;
using SplitVpn.Windows.Wfp;
using Windows.Win32;
using Windows.Win32.NetworkManagement.WindowsFilteringPlatform;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Перевод условий плана в условия WFP без движка (раньше это проверяли только тесты с правами администратора):
/// развёртка «любой из диапазонов» в подряд идущие условия одного поля, поле, тип сравнения и значение каждого условия.
/// </summary>
public sealed unsafe class WfpConditionTests
{
    private static readonly uint A = Ipv4.Parse("10.0.0.0");
    private static readonly uint B = Ipv4.Parse("10.0.0.255");
    private static readonly uint C = Ipv4.Parse("192.0.2.7");

    [Fact]
    public void RemoteRanges_ExpandInOrder_OtherConditionsStayInPlace()
    {
        var protocol = new ProtocolCondition(FilterPlanBuilder.ProtocolTcp);
        var port = new RemotePortCondition(443);
        var ranges = new RemoteRangesV4([new Ipv4Range(A, B), Ipv4Range.Host(C)]);

        var expanded = WfpOps.ExpandConditions([protocol, ranges, port]);

        Assert.Equal<FilterCondition>([protocol, new RemoteRangeV4(A, B), new RemoteRangeV4(C, C), port], expanded);
        Assert.Equal<FilterCondition>([protocol, port], WfpOps.ExpandConditions([protocol, port]));
        Assert.Empty(WfpOps.ExpandConditions([]));
    }

    [Fact]
    public void ExpandedRanges_AreOrConditionsOnTheRemoteAddressField()
    {
        using var arena = new NativeArena();
        using var cache = new WfpOps.ConditionCache();
        var ranges = new RemoteRangesV4([new Ipv4Range(A, B), Ipv4Range.Host(C)]);

        var built = WfpOps.ExpandConditions([ranges]).Select(c => WfpOps.BuildCondition(c, arena, cache)).ToArray();

        Assert.Equal(2, built.Length);
        Assert.All(built, c => Assert.Equal(PInvoke.FWPM_CONDITION_IP_REMOTE_ADDRESS, c.fieldKey));
        AssertRange32(built[0], A, B);
        // Один адрес - не диапазон, а сравнение на равенство.
        Assert.Equal(FWP_MATCH_TYPE.FWP_MATCH_EQUAL, built[1].matchType);
        Assert.Equal(FWP_DATA_TYPE.FWP_UINT32, built[1].conditionValue.type);
        Assert.Equal(C, built[1].conditionValue.uint32);
    }

    [Fact]
    public void Conditions_MapToFieldMatchAndValue()
    {
        using var arena = new NativeArena();
        using var cache = new WfpOps.ConditionCache();
        FWPM_FILTER_CONDITION0 Build(FilterCondition condition) => WfpOps.BuildCondition(condition, arena, cache);

        var loopback = Build(new LoopbackCondition());
        Assert.Equal(PInvoke.FWPM_CONDITION_FLAGS, loopback.fieldKey);
        Assert.Equal(FWP_MATCH_TYPE.FWP_MATCH_FLAGS_ALL_SET, loopback.matchType);
        Assert.Equal(1u, loopback.conditionValue.uint32);

        var notAddress = Build(new RemoteAddressNotV4(C));
        Assert.Equal(PInvoke.FWPM_CONDITION_IP_REMOTE_ADDRESS, notAddress.fieldKey);
        Assert.Equal(FWP_MATCH_TYPE.FWP_MATCH_NOT_EQUAL, notAddress.matchType);
        Assert.Equal(C, notAddress.conditionValue.uint32);

        var prefix = Build(new RemotePrefixV6(IPNetwork.Parse("2001:db8::/32")));
        Assert.Equal(PInvoke.FWPM_CONDITION_IP_REMOTE_ADDRESS, prefix.fieldKey);
        Assert.Equal(FWP_MATCH_TYPE.FWP_MATCH_EQUAL, prefix.matchType);
        Assert.Equal(FWP_DATA_TYPE.FWP_V6_ADDR_MASK, prefix.conditionValue.type);
        Assert.Equal(32, prefix.conditionValue.v6AddrMask->prefixLength);
        Assert.Equal(IPAddress.Parse("2001:db8::").GetAddressBytes(), prefix.conditionValue.v6AddrMask->addr.AsSpan().ToArray());
        Assert.Throws<ArgumentException>(() => Build(new RemotePrefixV6(IPNetwork.Parse("10.0.0.0/8"))));

        var port = Build(new RemotePortCondition(53));
        Assert.Equal(PInvoke.FWPM_CONDITION_IP_REMOTE_PORT, port.fieldKey);
        Assert.Equal(FWP_MATCH_TYPE.FWP_MATCH_EQUAL, port.matchType);
        Assert.Equal(FWP_DATA_TYPE.FWP_UINT16, port.conditionValue.type);
        Assert.Equal(53, port.conditionValue.uint16);
        Assert.Equal(FWP_MATCH_TYPE.FWP_MATCH_NOT_EQUAL, Build(new RemotePortCondition(53, NotEqual: true)).matchType);

        var localPort = Build(new LocalPortRange(68, 68));
        Assert.Equal(PInvoke.FWPM_CONDITION_IP_LOCAL_PORT, localPort.fieldKey);
        Assert.Equal(FWP_MATCH_TYPE.FWP_MATCH_EQUAL, localPort.matchType);
        Assert.Equal(68, localPort.conditionValue.uint16);
        var localRange = Build(new LocalPortRange(50000, 50100));
        Assert.Equal(PInvoke.FWPM_CONDITION_IP_LOCAL_PORT, localRange.fieldKey);
        Assert.Equal(FWP_MATCH_TYPE.FWP_MATCH_RANGE, localRange.matchType);
        Assert.Equal(FWP_DATA_TYPE.FWP_RANGE_TYPE, localRange.conditionValue.type);
        Assert.Equal(FWP_DATA_TYPE.FWP_UINT16, localRange.conditionValue.rangeValue->valueLow.type);
        Assert.Equal(50000, localRange.conditionValue.rangeValue->valueLow.uint16);
        Assert.Equal(50100, localRange.conditionValue.rangeValue->valueHigh.uint16);

        var protocol = Build(new ProtocolCondition(FilterPlanBuilder.ProtocolUdp));
        Assert.Equal(PInvoke.FWPM_CONDITION_IP_PROTOCOL, protocol.fieldKey);
        Assert.Equal(FWP_MATCH_TYPE.FWP_MATCH_EQUAL, protocol.matchType);
        Assert.Equal(FWP_DATA_TYPE.FWP_UINT8, protocol.conditionValue.type);
        Assert.Equal(FilterPlanBuilder.ProtocolUdp, protocol.conditionValue.uint8);
        Assert.Equal(FWP_MATCH_TYPE.FWP_MATCH_NOT_EQUAL, Build(new ProtocolCondition(FilterPlanBuilder.ProtocolUdp, NotEqual: true)).matchType);

        var tunnel = Build(new LocalInterfaceCondition(0x1234_5678_9ABCUL, NotEqual: false));
        Assert.Equal(PInvoke.FWPM_CONDITION_IP_LOCAL_INTERFACE, tunnel.fieldKey);
        Assert.Equal(FWP_MATCH_TYPE.FWP_MATCH_EQUAL, tunnel.matchType);
        Assert.Equal(FWP_DATA_TYPE.FWP_UINT64, tunnel.conditionValue.type);
        Assert.Equal(0x1234_5678_9ABCUL, *tunnel.conditionValue.uint64);
        Assert.Equal(FWP_MATCH_TYPE.FWP_MATCH_NOT_EQUAL, Build(new LocalInterfaceCondition(1, NotEqual: true)).matchType);
    }

    private static void AssertRange32(FWPM_FILTER_CONDITION0 condition, uint low, uint high)
    {
        Assert.Equal(FWP_MATCH_TYPE.FWP_MATCH_RANGE, condition.matchType);
        Assert.Equal(FWP_DATA_TYPE.FWP_RANGE_TYPE, condition.conditionValue.type);
        Assert.Equal(FWP_DATA_TYPE.FWP_UINT32, condition.conditionValue.rangeValue->valueLow.type);
        Assert.Equal(low, condition.conditionValue.rangeValue->valueLow.uint32);
        Assert.Equal(FWP_DATA_TYPE.FWP_UINT32, condition.conditionValue.rangeValue->valueHigh.type);
        Assert.Equal(high, condition.conditionValue.rangeValue->valueHigh.uint32);
    }
}
