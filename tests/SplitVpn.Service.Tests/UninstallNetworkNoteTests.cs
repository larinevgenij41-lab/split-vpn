using SplitVpn.Core.Recovery;

namespace SplitVpn.Service.Tests;

/// <summary>
/// Удаление программы вернуло сеть не полностью: скрипт возврата сети и инструкция остаются в защищённом каталоге журнала
/// удаления — MSI удаляет и службу, и scripts\recover-network.*.
/// </summary>
public sealed class UninstallNetworkNoteTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "SplitVpn.Tests." + Guid.NewGuid().ToString("N"));

    public UninstallNetworkNoteTests()
    {
        Directory.CreateDirectory(Path.Combine(_root, "scripts"));
        File.WriteAllText(Path.Combine(_root, "scripts", "recover-network.ps1"), "# ps1 v1");
        File.WriteAllText(Path.Combine(_root, "scripts", "recover-network.cmd"), "@echo v1");
    }

    private string Scripts => Path.Combine(_root, "scripts");

    private string Target => Path.Combine(_root, "SplitVpn.Uninstall");

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private static IReadOnlyList<string> Secure(string directory)
    {
        Directory.CreateDirectory(directory);
        return [];
    }

    private static readonly EmergencyStepReport[] FailedDns =
    [
        new(EmergencySteps.Wfp, "Фильтры WFP", EmergencyStepOutcome.Done, null, 5),
        new(EmergencySteps.Dns, "DNS адаптеров", EmergencyStepOutcome.Failed, "адаптер Wi-Fi: отказано в доступе", 7),
    ];

    [Fact]
    public void IncompleteNetwork_CopiesScriptAndWritesInstruction()
    {
        var warnings = new List<string>();

        var note = ServiceRecovery.PreserveNetworkRecovery(Target, Scripts, FailedDns, Secure, _ => true, warnings.Add);

        Assert.NotNull(note);
        Assert.Empty(warnings);
        Assert.Equal(Target, Path.GetDirectoryName(note));
        Assert.Equal("# ps1 v1", File.ReadAllText(Path.Combine(Target, "recover-network.ps1")));
        Assert.Equal("@echo v1", File.ReadAllText(Path.Combine(Target, "recover-network.cmd")));
        var text = File.ReadAllText(note);
        Assert.Contains("DNS адаптеров: адаптер Wi-Fi: отказано в доступе", text, StringComparison.Ordinal);
        Assert.DoesNotContain("Фильтры WFP", text, StringComparison.Ordinal);
        Assert.Contains("-File \"" + Path.Combine(Target, "recover-network.ps1") + "\"", text, StringComparison.Ordinal);
        Assert.Contains("dns-backup.json", text, StringComparison.Ordinal);
    }

    /// <summary>Повторное неудачное удаление: копия скрипта заменяется новой, инструкция - новым файлом рядом с прежней.</summary>
    [Fact]
    public void RepeatedFailure_ReplacesScriptCopy()
    {
        var first = ServiceRecovery.PreserveNetworkRecovery(Target, Scripts, FailedDns, Secure, _ => true, _ => { });
        File.WriteAllText(Path.Combine(Scripts, "recover-network.ps1"), "# ps1 v2");

        var second = ServiceRecovery.PreserveNetworkRecovery(Target, Scripts, null, Secure, _ => true, _ => { });

        Assert.NotNull(first);
        Assert.NotNull(second);
        Assert.NotEqual(first, second);
        Assert.Equal("# ps1 v2", File.ReadAllText(Path.Combine(Target, "recover-network.ps1")));
        Assert.Contains("неизвестно", File.ReadAllText(second), StringComparison.Ordinal);
    }

    /// <summary>Скрипта нет (повреждённая установка): инструкция всё равно пишется - с ручным способом вернуть DNS.</summary>
    [Fact]
    public void MissingScript_InstructionDescribesManualWay()
    {
        File.Delete(Path.Combine(Scripts, "recover-network.ps1"));
        var warnings = new List<string>();

        var note = ServiceRecovery.PreserveNetworkRecovery(Target, Scripts, FailedDns, Secure, _ => true, warnings.Add);

        Assert.NotNull(note);
        Assert.Contains(warnings, w => w.Contains("recover-network.ps1", StringComparison.Ordinal));
        var text = File.ReadAllText(note);
        Assert.Contains("Автоматически (DHCP)", text, StringComparison.Ordinal);
        Assert.DoesNotContain("-File", text, StringComparison.Ordinal);
    }

    /// <summary>Каталог уже есть и принадлежит посторонней учётной записи: ни скрипта, ни инструкции в нём.</summary>
    [Fact]
    public void ForeignDirectory_IsNotUsed()
    {
        Directory.CreateDirectory(Target);
        var warnings = new List<string>();

        var note = ServiceRecovery.PreserveNetworkRecovery(Target, Scripts, FailedDns, Secure, _ => false, warnings.Add);

        Assert.Null(note);
        Assert.Empty(Directory.EnumerateFileSystemEntries(Target));
        Assert.NotEmpty(warnings);
    }

    /// <summary>
    /// Отметка с постоянным именем — только от этого удаления: ставится вместе с копией скрипта и снимается в начале
    /// следующего; в чужом каталоге не трогается.
    /// </summary>
    [Fact]
    public void PendingFlag_SetWithScriptCopy_ClearedNextTime()
    {
        var flag = Path.Combine(Target, ServiceRecovery.NetworkPendingFlagName);
        ServiceRecovery.PreserveNetworkRecovery(Target, Scripts, FailedDns, Secure, _ => true, _ => { });
        Assert.True(File.Exists(flag));

        ServiceRecovery.ClearNetworkPendingFlag(Target, _ => false, _ => { });
        Assert.True(File.Exists(flag));

        ServiceRecovery.ClearNetworkPendingFlag(Target, _ => true, _ => { });
        Assert.False(File.Exists(flag));
        Assert.True(File.Exists(Path.Combine(Target, "recover-network.ps1")));

        // Скрипт не скопирован - отметки нет: запускать было бы нечего.
        File.Delete(Path.Combine(Scripts, "recover-network.cmd"));
        ServiceRecovery.PreserveNetworkRecovery(Target, Scripts, FailedDns, Secure, _ => true, _ => { });
        Assert.False(File.Exists(flag));
    }

    [Fact]
    public void NetworkIncomplete_FollowsNetworkSteps()
    {
        Assert.True(ServiceRecovery.NetworkIncomplete(new EmergencyReport { NetworkClean = false, Steps = FailedDns }));
        Assert.True(ServiceRecovery.NetworkIncomplete(new EmergencyReport { NetworkClean = true, Steps = FailedDns }));

        // Все сетевые шаги выполнены (повторное снятие - тоже): сеть возвращена, скрипт и инструкция не нужны.
        string[] network =
        [
            EmergencySteps.Helpers, EmergencySteps.Wfp, EmergencySteps.Ras, EmergencySteps.Routes, EmergencySteps.Dns, EmergencySteps.Wcm,
            EmergencySteps.ServiceRecheck,
        ];
        var clean = network.Select(step => new EmergencyStepReport(step, step, EmergencyStepOutcome.Done, null, 1))
            .Append(new EmergencyStepReport(EmergencySteps.DnsAgain, "DNS ещё раз", EmergencyStepOutcome.Done, null, 1))
            .ToArray();
        Assert.False(ServiceRecovery.NetworkIncomplete(new EmergencyReport { NetworkClean = true, Steps = clean }));
        // Сама команда сочла сеть не возвращённой - этого достаточно, шаги не перевешивают.
        Assert.True(ServiceRecovery.NetworkIncomplete(new EmergencyReport { NetworkClean = false, Steps = clean }));
        // Нет одного сетевого шага в отчёте или не удалось повторное снятие - сеть не возвращена.
        Assert.True(ServiceRecovery.NetworkIncomplete(new EmergencyReport { NetworkClean = true, Steps = clean.Where(s => s.Step != EmergencySteps.Wcm).ToArray() }));
        Assert.True(ServiceRecovery.NetworkIncomplete(new EmergencyReport
        {
            NetworkClean = true,
            Steps = [.. clean.Where(s => s.Step != EmergencySteps.DnsAgain), new(EmergencySteps.DnsAgain, "DNS ещё раз", EmergencyStepOutcome.Failed, "отказано", 1)],
        }));
    }
}
