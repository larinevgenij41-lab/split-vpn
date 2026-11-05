using SplitVpn.Core.Diagnostics;

namespace SplitVpn.Core.Tests.Diagnostics;

public sealed class ProxyApplierTests : IDisposable
{
    private const string Pac = "https://nexus.example.org/proxy.pac";
    private readonly string _root = Path.Combine(Path.GetTempPath(), "splitvpn-proxy-tests", Guid.NewGuid().ToString("N"));
    private readonly FakeProxySettings _settings = new() { State = new ProxyState(1, null) };

    private string BackupPath => Path.Combine(_root, "proxy-backup.json");

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [Fact]
    public void AppliesPacAndRestoresOriginal()
    {
        var applier = new ProxyApplier(_settings, BackupPath);

        Assert.Equal(ProxyOutcome.Applied, applier.Sync(Pac));
        Assert.Equal(new ProxyState(1 | ProxyState.AutoProxyUrl, Pac), _settings.State);
        Assert.Equal(ProxyOutcome.Unchanged, applier.Sync(Pac));
        Assert.Equal(1, _settings.Writes);

        Assert.Equal(ProxyOutcome.Restored, applier.Sync(null));
        Assert.Equal(new ProxyState(1, null), _settings.State);
        Assert.False(File.Exists(BackupPath));
        Assert.Equal(ProxyOutcome.None, applier.Sync(null));
    }

    [Fact]
    public void BackupSurvivesRestartOfInterface()
    {
        new ProxyApplier(_settings, BackupPath).Sync(Pac);

        var restarted = new ProxyApplier(_settings, BackupPath);

        Assert.Equal(ProxyOutcome.Restored, restarted.Sync(null));
        Assert.Equal(new ProxyState(1, null), _settings.State);
    }

    [Fact]
    public void UserChangeIsNeitherOverwrittenNorRolledBack()
    {
        var applier = new ProxyApplier(_settings, BackupPath);
        applier.Sync(Pac);
        _settings.State = new ProxyState(2, null);

        Assert.Equal(ProxyOutcome.ChangedByUser, applier.Sync(Pac));
        Assert.Equal(ProxyOutcome.Unchanged, applier.Sync(Pac));
        Assert.Equal(ProxyOutcome.ChangedByUser, applier.Sync(null));
        Assert.Equal(new ProxyState(2, null), _settings.State);
        Assert.False(File.Exists(BackupPath));
    }

    [Fact]
    public void NewPacFromGatewayReplacesAppliedButKeepsOriginal()
    {
        var applier = new ProxyApplier(_settings, BackupPath);
        applier.Sync(Pac);

        Assert.Equal(ProxyOutcome.Applied, applier.Sync("https://other.example.org/p.pac"));
        Assert.Equal("https://other.example.org/p.pac", _settings.State.AutoConfigUrl);
        Assert.Equal(ProxyOutcome.Restored, applier.Sync(null));
        Assert.Equal(new ProxyState(1, null), _settings.State);
    }

    [Fact]
    public void CorruptedBackupLeavesProxyAlone()
    {
        Directory.CreateDirectory(_root);
        File.WriteAllText(BackupPath, "{не json");
        var applier = new ProxyApplier(_settings, BackupPath);

        Assert.Equal(ProxyOutcome.Unchanged, applier.Sync(Pac));
        Assert.Equal(0, _settings.Writes);
    }

    [Fact]
    public void FailedFirstWriteLeavesNoBackupThatClaimsPacApplied()
    {
        var applier = new ProxyApplier(_settings, BackupPath);
        _settings.Fail = true;

        Assert.Throws<IOException>(() => applier.Sync(Pac));

        Assert.False(File.Exists(BackupPath));
        _settings.Fail = false;
        Assert.Equal(ProxyOutcome.Applied, applier.Sync(Pac));
    }

    [Fact]
    public void FailedPacChangeKeepsBackupConsistentAndRestoresOriginal()
    {
        var applier = new ProxyApplier(_settings, BackupPath);
        applier.Sync(Pac);
        _settings.Fail = true;

        Assert.Throws<IOException>(() => applier.Sync("https://other.example.org/proxy.pac"));

        _settings.Fail = false;
        Assert.Equal(ProxyOutcome.Restored, applier.Sync(null));
        Assert.Equal(new ProxyState(1, null), _settings.State);
    }

    [Fact]
    public void ProxyBackupInArchiveHasNoUrlSecrets()
    {
        var json = "{ \"appliedUrl\": \"https://user:pass@nexus.example.org/p.pac?token=abc#x\" }";

        var text = LogText.StripUrls(json);

        Assert.DoesNotContain("pass", text, StringComparison.Ordinal);
        Assert.DoesNotContain("abc", text, StringComparison.Ordinal);
        Assert.Contains("nexus.example.org/p.pac", text, StringComparison.Ordinal);
    }

    [Fact]
    public void PhonebookSecretLinesAreDropped()
    {
        var text = "[SplitVpn]\r\nPhoneNumber=vpn.example.org\r\nPreSharedKey=abc\r\nPassword=zzz\r\nType=2\r\n";

        var stripped = LogText.StripPhonebookSecrets(text);

        Assert.DoesNotContain("abc", stripped, StringComparison.Ordinal);
        Assert.DoesNotContain("zzz", stripped, StringComparison.Ordinal);
        Assert.Contains("PhoneNumber=vpn.example.org", stripped, StringComparison.Ordinal);
        Assert.Contains("Type=2", stripped, StringComparison.Ordinal);
    }

    [Fact]
    public void RedactJsonKeepsStructureWhenSecretHasQuoteOrBackslash()
    {
        var json = System.Text.Json.JsonSerializer.Serialize(new { profile = "Corp \"A\"", user = "CORP\\ivanov", name = "x" });

        var redacted = Redactor.RedactJson(json, ["Corp \"A\"", "CORP\\ivanov", "x"]);

        using var doc = System.Text.Json.JsonDocument.Parse(redacted);
        Assert.Equal("<скрыто>", doc.RootElement.GetProperty("profile").GetString());
        Assert.Equal("<скрыто>", doc.RootElement.GetProperty("user").GetString());
        Assert.True(doc.RootElement.TryGetProperty("name", out _));
    }

    private sealed class FakeProxySettings : IProxySettings
    {
        public ProxyState State { get; set; } = new(1, null);

        public int Writes { get; private set; }

        public bool Fail { get; set; }

        public ProxyState Read() => State;

        public void Write(ProxyState state)
        {
            if (Fail)
            {
                throw new IOException("отказ записи");
            }

            State = state;
            Writes++;
        }
    }
}
