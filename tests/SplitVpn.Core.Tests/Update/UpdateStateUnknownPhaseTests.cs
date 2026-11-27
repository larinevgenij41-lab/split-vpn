using SplitVpn.Core.Settings;
using SplitVpn.Core.Update;

namespace SplitVpn.Core.Tests.Update;

/// <summary>
/// Фаза обновления, которой эта версия не знает (файл более новой версии после отката): состояние читается с фазой
/// «Idle», а самая новая виденная версия — защита от отката манифеста — не теряется.
/// </summary>
public sealed class UpdateStateUnknownPhaseTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "splitvpn-update-phase-" + Guid.NewGuid().ToString("N"));

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

    [Theory]
    [InlineData("\"Verifying\"")]
    [InlineData("42")]
    [InlineData("null")]
    public void UnknownPhase_BecomesIdle_AndKeepsHighestSeenVersion(string phase)
    {
        var corrupt = new List<CorruptFile>();
        var store = new UpdateStore(_root) { OnCorrupt = corrupt.Add };
        File.WriteAllText(Path.Combine(_root, "state.json"),
            $$"""{ "phase": {{phase}}, "highestSeenVersion": "1.4.2", "skippedVersion": "1.4.0" }""");

        var state = store.LoadState();

        Assert.Equal(UpdatePhase.Idle, state.Phase);
        Assert.Equal("1.4.2", state.HighestSeenVersion);
        Assert.Equal("1.4.0", state.SkippedVersion);
        Assert.Empty(corrupt);
    }

    [Fact]
    public void KnownPhase_IsReadAsIs_AndBrokenFileIsStillCorrupt()
    {
        var corrupt = new List<CorruptFile>();
        var store = new UpdateStore(_root) { OnCorrupt = corrupt.Add };
        var path = Path.Combine(_root, "state.json");
        File.WriteAllText(path, """{ "phase": "Ready", "highestSeenVersion": "1.4.2" }""");
        Assert.Equal(UpdatePhase.Ready, store.LoadState().Phase);

        File.WriteAllText(path, """{ "phase": "Verifying", """);
        Assert.Equal(new UpdateState(), store.LoadState());
        Assert.Single(corrupt);
    }
}
