using SplitVpn.Core.Recovery;

namespace SplitVpn.Service.Tests;

/// <summary>Удаление программы без полной очистки сети: файлы паролей и ключей всё равно удаляются, остальное остаётся.</summary>
public sealed class UninstallSecretsTests
{
    [Theory]
    [InlineData("secrets.bin", true)]
    [InlineData("secrets.bin.ipsec", true)]
    [InlineData("secrets.bin.sshkey", true)]
    [InlineData("secrets.bin.v095", true)]
    [InlineData("secrets.bin.ipsec.v095", true)]
    [InlineData("secrets.bin.corrupt-20260101-000000", true)]
    [InlineData("secrets.bin.sshkey.undecryptable-20260101-000000-abc", true)]
    [InlineData("SECRETS.BIN", true)]
    [InlineData("secrets.binary", false)]
    [InlineData("dns-backup.json", false)]
    [InlineData("settings.json", false)]
    [InlineData("splitvpn.pbk", false)]
    public void Secret_file_names_are_recognised(string name, bool expected) =>
        Assert.Equal(expected, ServiceRecovery.IsSecretFileName(name));

    [Theory]
    [InlineData("pins.json", true)]
    [InlineData("PINS.JSON", true)]
    [InlineData("pins.json.1234-5.tmp", true)]
    [InlineData("pins.jsonx", false)]
    [InlineData("state.json", false)]
    public void Pin_file_names_are_recognised(string name, bool expected) =>
        Assert.Equal(expected, ServiceRecovery.IsPinFileName(name));

    [Fact]
    public void Deletes_only_secret_files_and_keeps_recovery_data()
    {
        var root = Path.Combine(Path.GetTempPath(), "splitvpn-uninstall-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            // pins.json - история открытых сайтов: удаляется вместе с паролями, и её недописанная копия тоже.
            foreach (var name in new[] { "secrets.bin", "secrets.bin.ipsec", "secrets.bin.sshkey", "secrets.bin.v095", "secrets.bin.corrupt-1", "secrets.bin.ipsec.undecryptable-2",
                "pins.json", "pins.json.1234-5.tmp" })
            {
                File.WriteAllText(Path.Combine(root, name), "x");
            }

            File.WriteAllText(Path.Combine(root, "dns-backup.json"), "{}");
            File.WriteAllText(Path.Combine(root, "state.json"), "{}");
            File.SetAttributes(Path.Combine(root, "secrets.bin.v095"), FileAttributes.ReadOnly);

            var detail = ServiceRecovery.DeleteSecretFiles(root, _ => true);

            Assert.Contains("8", detail, StringComparison.Ordinal);
            Assert.Equal(["dns-backup.json", "state.json"], Directory.EnumerateFiles(root).Select(Path.GetFileName).Order(StringComparer.Ordinal));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Foreign_data_directory_is_not_touched()
    {
        var root = Path.Combine(Path.GetTempPath(), "splitvpn-uninstall-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            File.WriteAllText(Path.Combine(root, "secrets.bin"), "x");

            Assert.Throws<IOException>(() => ServiceRecovery.DeleteSecretFiles(root, _ => false));
            Assert.True(File.Exists(Path.Combine(root, "secrets.bin")));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Missing_data_directory_is_not_an_error() =>
        Assert.Equal("каталога данных нет", ServiceRecovery.DeleteSecretFiles(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")), _ => true));

    private static readonly TimeSpan RasTimeout = TimeSpan.FromSeconds(5);

    private static EmergencyStepReport NetworkStep(string step, EmergencyStepOutcome outcome) => new(step, step, outcome, null, 0);

    private static (ServiceRecovery.UninstallActions Actions, List<string> Calls) Recorder(
        Action? purgeMark = null, Func<string>? secrets = null, Func<string>? ras = null)
    {
        List<string> calls = [];
        var actions = new ServiceRecovery.UninstallActions(
            () => { calls.Add("mark"); purgeMark?.Invoke(); },
            () => calls.Add("data"),
            () => calls.Add("registry"),
            () => { calls.Add("secrets"); return secrets?.Invoke() ?? "удалено файлов: 1"; },
            () => { lock (calls) { calls.Add("ras"); } return ras?.Invoke() ?? "удалено записей: 1"; });
        return (actions, calls);
    }

    /// <summary>
    /// Полная очистка разрешена: пароли и записи RAS не удаляются здесь — откаченное удаление вернёт программу целой,
    /// а после фиксации их уберёт установщик вместе с каталогом данных.
    /// </summary>
    [Fact]
    public void Clean_uninstall_keeps_secrets_and_ras_entries_for_rollback()
    {
        var (actions, calls) = Recorder();

        var finish = ServiceRecovery.FinishUninstall(RecoveryMode.UninstallNetwork, cleanable: true, [NetworkStep(EmergencySteps.Ras, EmergencyStepOutcome.Done)], actions, RasTimeout);

        Assert.True(finish.Cleaned);
        Assert.Equal(["mark"], calls);
        Assert.Equal(EmergencyStepOutcome.Skipped, finish.Secrets.Outcome);
        Assert.Equal(EmergencyStepOutcome.Skipped, finish.RasEntries.Outcome);
        Assert.Equal(ServiceRecovery.UninstallRasStep, finish.RasEntries.Step);
    }

    /// <summary>Сеть возвращена не полностью: отметки нет, пароли удаляются раньше записей RAS.</summary>
    [Fact]
    public void Incomplete_restore_deletes_secrets_before_ras_entries()
    {
        var (actions, calls) = Recorder();

        var finish = ServiceRecovery.FinishUninstall(RecoveryMode.UninstallNetwork, cleanable: false, [NetworkStep(EmergencySteps.Ras, EmergencyStepOutcome.Done)], actions, RasTimeout);

        Assert.False(finish.Cleaned);
        Assert.Equal(["secrets", "ras"], calls);
        Assert.Equal(EmergencyStepOutcome.Done, finish.Secrets.Outcome);
        Assert.Equal(EmergencyStepOutcome.Done, finish.RasEntries.Outcome);
    }

    /// <summary>Отметка не записалась из-за исключения не из списка ввода-вывода: пароли и записи RAS всё равно удаляются.</summary>
    [Fact]
    public void Purge_mark_failure_of_any_type_falls_back_to_deleting_secrets()
    {
        var (actions, calls) = Recorder(purgeMark: () => throw new InvalidOperationException("сбой"));

        var finish = ServiceRecovery.FinishUninstall(RecoveryMode.UninstallNetwork, cleanable: true, [], actions, RasTimeout);

        Assert.False(finish.Cleaned);
        Assert.Equal(["mark", "secrets", "ras"], calls);
    }

    /// <summary>Сбой удаления паролей исключением любого типа не отменяет удаление записей RAS.</summary>
    [Fact]
    public void Secrets_failure_of_any_type_does_not_skip_ras_entries()
    {
        var (actions, calls) = Recorder(secrets: () => throw new NullReferenceException("сбой"));

        var finish = ServiceRecovery.FinishUninstall(RecoveryMode.UninstallNetwork, cleanable: false, [], actions, RasTimeout);

        Assert.Equal(EmergencyStepOutcome.Failed, finish.Secrets.Outcome);
        Assert.Equal(EmergencyStepOutcome.Done, finish.RasEntries.Outcome);
        Assert.Equal(["secrets", "ras"], calls);
    }

    /// <summary>Зависший RasMan: удаление записей RAS ограничено своим сроком, отчёт получает «timeout».</summary>
    [Fact]
    public void Hung_ras_deletion_times_out()
    {
        using var hang = new ManualResetEventSlim();
        var (actions, _) = Recorder(ras: () => { hang.Wait(TestContext.Current.CancellationToken); return "-"; });
        try
        {
            var watch = System.Diagnostics.Stopwatch.StartNew();
            var finish = ServiceRecovery.FinishUninstall(RecoveryMode.UninstallNetwork, cleanable: false, [], actions, TimeSpan.FromMilliseconds(200));

            Assert.Equal(EmergencyStepOutcome.Done, finish.Secrets.Outcome);
            Assert.Equal(EmergencyStepOutcome.Timeout, finish.RasEntries.Outcome);
            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5));
        }
        finally
        {
            hang.Set();
        }
    }

    /// <summary>Служба RAS уже не ответила при восстановлении сети: записи RAS не трогаются вовсе, пароли удаляются.</summary>
    [Fact]
    public void Ras_entries_skipped_when_network_ras_step_timed_out()
    {
        var (actions, calls) = Recorder();

        var finish = ServiceRecovery.FinishUninstall(RecoveryMode.UninstallNetwork, cleanable: false, [NetworkStep(EmergencySteps.Ras, EmergencyStepOutcome.Timeout)], actions, RasTimeout);

        Assert.Equal(["secrets"], calls);
        Assert.Equal(EmergencyStepOutcome.Timeout, finish.RasEntries.Outcome);
        Assert.Equal(EmergencyStepOutcome.Done, finish.Secrets.Outcome);
    }
}
