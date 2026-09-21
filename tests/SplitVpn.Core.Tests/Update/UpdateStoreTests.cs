using System.Text;
using SplitVpn.Core.Settings;
using SplitVpn.Core.Update;

namespace SplitVpn.Core.Tests.Update;

public sealed class UpdateStoreTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "splitvpn-update-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Временный каталог уберёт система.
        }
    }

    [Fact]
    public void State_SurvivesRoundTrip()
    {
        var store = new UpdateStore(_root);
        var state = new UpdateState
        {
            Phase = UpdatePhase.Ready,
            AvailableVersion = "0.8.1",
            PackageFileName = "SplitVpn-0.8.1.msi",
            PackageSha256 = new string('a', 64),
            PackageSize = 123,
            DownloadedBytes = 123,
            PackageUrls = ["https://example.org/a.msi"],
            HighestSeenVersion = "0.8.1",
            NextCheckUtc = DateTimeOffset.UnixEpoch.AddDays(1),
        };

        store.SaveState(state);
        var loaded = new UpdateStore(_root).LoadState();

        // Списки в записях сравниваются по ссылке, поэтому они проверяются отдельно от остальных полей.
        Assert.Equal(state.PackageUrls, loaded.PackageUrls);
        Assert.Equal(state with { PackageUrls = loaded.PackageUrls }, loaded);
    }

    [Fact]
    public void MissingState_IsDefault()
    {
        var state = new UpdateStore(_root).LoadState();

        Assert.Equal(UpdatePhase.Idle, state.Phase);
        Assert.Null(state.AvailableVersion);
    }

    /// <summary>Повреждённый файл откладывается в копию, а служба работает со значениями по умолчанию.</summary>
    [Fact]
    public void CorruptState_IsQuarantinedAndReported()
    {
        Directory.CreateDirectory(_root);
        File.WriteAllText(Path.Combine(_root, "state.json"), "{не json", Encoding.UTF8);
        var found = new List<CorruptFile>();
        var store = new UpdateStore(_root) { OnCorrupt = found.Add };

        var state = store.LoadState();

        Assert.Equal(UpdatePhase.Idle, state.Phase);
        Assert.Single(found);
        Assert.NotNull(found[0].CopyPath);
    }

    [Fact]
    public void Cleanup_KeepsCurrentPackageAndRemovesStrays()
    {
        var store = new UpdateStore(_root);
        var now = DateTimeOffset.UtcNow;
        File.WriteAllText(Path.Combine(_root, "SplitVpn-0.8.1.msi"), "новый");
        File.WriteAllText(Path.Combine(_root, "SplitVpn-0.8.1.msi.part"), "недокачка");
        File.WriteAllText(Path.Combine(_root, "SplitVpn-0.7.9.msi"), "старый");
        var freshLog = Path.Combine(_root, "install-0.8.1-20260101-000000.log");
        var oldLog = Path.Combine(_root, "install-0.1.0-20200101-000000.log");
        File.WriteAllText(freshLog, "свежий журнал");
        File.WriteAllText(oldLog, "старый журнал");
        File.SetLastWriteTimeUtc(oldLog, now.AddDays(-40).UtcDateTime);

        store.Cleanup(new UpdateState { PackageFileName = "SplitVpn-0.8.1.msi" }, now);

        Assert.True(File.Exists(Path.Combine(_root, "SplitVpn-0.8.1.msi")));
        Assert.True(File.Exists(Path.Combine(_root, "SplitVpn-0.8.1.msi.part")));
        Assert.False(File.Exists(Path.Combine(_root, "SplitVpn-0.7.9.msi")));
        Assert.True(File.Exists(freshLog));
        Assert.False(File.Exists(oldLog));
    }

    /// <summary>Без установщика в состоянии лишние файлы уходят сразу: десятки мегабайт хранить незачем.</summary>
    [Fact]
    public void Cleanup_WithoutCurrentPackage_RemovesEverythingButFreshLogs()
    {
        var store = new UpdateStore(_root);
        var now = DateTimeOffset.UtcNow;
        var stale = Path.Combine(_root, "SplitVpn-0.7.9.msi.part");
        var installed = Path.Combine(_root, "SplitVpn-0.7.9.msi");
        var log = Path.Combine(_root, "install-0.7.9-20260101-000000.log");
        File.WriteAllText(stale, "брошено");
        File.WriteAllText(installed, "уже установлено");
        File.WriteAllText(log, "журнал");

        store.Cleanup(new UpdateState(), now);

        Assert.False(File.Exists(stale));
        Assert.False(File.Exists(installed));
        Assert.True(File.Exists(log));
    }

    [Fact]
    public void InstallLogPath_IsInsideStore()
    {
        var path = new UpdateStore(_root).InstallLogPath("0.8.1", DateTimeOffset.UnixEpoch);

        Assert.StartsWith(_root, path, StringComparison.Ordinal);
        Assert.EndsWith(".log", path, StringComparison.Ordinal);
        Assert.Contains("0.8.1", path, StringComparison.Ordinal);
    }
}
