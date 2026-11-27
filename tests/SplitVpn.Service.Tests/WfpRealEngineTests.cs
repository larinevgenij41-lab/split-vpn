using System.Security.Principal;
using SplitVpn.Core.Protection;
using SplitVpn.Windows.Wfp;
using Xunit.Sdk;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Проверка на настоящей Windows Filtering Platform, без подмен. В 0.17.2 перечисление своих фильтров
/// перестало их находить, и ни один тест на подменах этого не заметил: служба не могла ни сверить,
/// ни снять блокировку трафика, «Восстановить сеть» и удаление программы не работали.
/// Объекты создаются в динамической сессии под случайными ключами: при любом исходе, включая аварийное
/// завершение теста, Windows удаляет их сама, а фильтры установленной программы не затрагиваются.
/// Нужны права администратора; без них тест пропускается, а выпуск без него скрипт не разрешает.
/// </summary>
public sealed class WfpRealEngineTests
{
    private static readonly FilterSpec Harmless = new(
        "[Тест] разрешение TCP на порт 9",
        FilterGroup.Runtime,
        FilterFamily.Both,
        1,
        FilterAction.Permit,
        [new ProtocolCondition(6), new RemotePortCondition(9)]);

    [Fact]
    public void OwnFilters_AreListedOnEveryLayer_AndDeletedCompletely()
    {
        RequireAdministrator();
        var identity = new WfpIdentity(Guid.NewGuid(), Guid.NewGuid(), "Раздельный VPN (тест)", "SplitVpnTestNoSuchService");
        using var engine = WfpEngine.Open(dynamicSession: true);
        WfpOps.EnsureProviderAndSubLayer(engine, identity, persistent: false);
        var added = WfpOps.AddFilters(engine, identity, [Harmless], persistent: false);

        // Два слоя IPv4 и два слоя IPv6: фильтр, не найденный хотя бы на одном, остался бы в системе.
        Assert.Equal(4, added.Count);
        var fast = WfpOps.ListFilters(engine, identity);
        var everywhere = WfpOps.ListFiltersEverywhere(engine, identity);
        Assert.Equal(added.Order(), fast.Select(f => f.Id).Order());
        Assert.Equal(added.Order(), everywhere.Select(f => f.Id).Order());
        Assert.Equal(4, fast.Select(f => f.Layer).Distinct().Count());

        Assert.Equal(4, WfpOps.DeleteAll(engine, identity));
        Assert.Empty(WfpOps.ListFilters(engine, identity));
        Assert.Empty(WfpOps.ListFiltersEverywhere(engine, identity));
        Assert.All(added, id => Assert.False(WfpOps.FilterExists(engine, id)));
    }

    [Fact]
    public void DeleteAll_IsRepeatable_WhenNothingIsInstalled()
    {
        RequireAdministrator();
        var identity = new WfpIdentity(Guid.NewGuid(), Guid.NewGuid(), "Раздельный VPN (тест)", "SplitVpnTestNoSuchService");
        using var engine = WfpEngine.Open(dynamicSession: true);

        Assert.Equal(0, WfpOps.DeleteAll(engine, identity));
        Assert.Equal(0, WfpOps.DeleteAll(engine, identity));
    }

    private static void RequireAdministrator()
    {
        using var current = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(current).IsInRole(WindowsBuiltInRole.Administrator))
        {
            throw SkipException.ForSkip("Проверка настоящих фильтров Windows требует прав администратора.");
        }
    }
}
