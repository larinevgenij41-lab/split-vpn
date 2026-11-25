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

    [Fact]
    public void Deletes_only_secret_files_and_keeps_recovery_data()
    {
        var root = Path.Combine(Path.GetTempPath(), "splitvpn-uninstall-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            foreach (var name in new[] { "secrets.bin", "secrets.bin.ipsec", "secrets.bin.sshkey", "secrets.bin.v095", "secrets.bin.corrupt-1", "secrets.bin.ipsec.undecryptable-2" })
            {
                File.WriteAllText(Path.Combine(root, name), "x");
            }

            File.WriteAllText(Path.Combine(root, "dns-backup.json"), "{}");
            File.WriteAllText(Path.Combine(root, "state.json"), "{}");
            File.SetAttributes(Path.Combine(root, "secrets.bin.v095"), FileAttributes.ReadOnly);

            var detail = ServiceRecovery.DeleteSecretFiles(root, _ => true);

            Assert.Contains("6", detail, StringComparison.Ordinal);
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
}
