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

    private sealed class FakeProxySettings : IProxySettings
    {
        public ProxyState State { get; set; } = new(1, null);

        public int Writes { get; private set; }

        public ProxyState Read() => State;

        public void Write(ProxyState state)
        {
            State = state;
            Writes++;
        }
    }
}
