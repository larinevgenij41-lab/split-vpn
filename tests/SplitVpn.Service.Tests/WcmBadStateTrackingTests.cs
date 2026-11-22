using Microsoft.Win32;
using SplitVpn.Windows.Net;

namespace SplitVpn.Service.Tests;

/// <summary>Настройка диспетчера подключений Windows: проверяется на временном разделе реестра пользователя.</summary>
public sealed class WcmBadStateTrackingTests : IDisposable
{
    private const string Wcm = "Wcm";
    private const string Own = "Own";
    private readonly string _path = @"Software\SplitVpn.Tests\" + Guid.NewGuid().ToString("N");
    private readonly RegistryKey _root;

    public WcmBadStateTrackingTests()
    {
        _root = Registry.CurrentUser.CreateSubKey(_path, writable: true);
    }

    public void Dispose()
    {
        _root.Dispose();
        Registry.CurrentUser.DeleteSubKeyTree(_path, throwOnMissingSubKey: false);
    }

    private object? Value()
    {
        using var key = _root.OpenSubKey(Wcm);
        return key?.GetValue(WcmBadStateTracking.ValueName);
    }

    private object? Remembered()
    {
        using var key = _root.OpenSubKey(Own);
        return key?.GetValue(WcmBadStateTracking.OriginalValueName);
    }

    private void Set(int value)
    {
        using var key = _root.CreateSubKey(Wcm, writable: true);
        key.SetValue(WcmBadStateTracking.ValueName, value, RegistryValueKind.DWord);
    }

    [Fact]
    public void Apply_ValueAbsent_WritesZeroAndRestoreRemovesIt()
    {
        Assert.Equal(WcmBadStateTrackingResult.Disabled, WcmBadStateTracking.Apply(_root, Wcm, Own));
        Assert.Equal(0, Value());
        Assert.Equal(WcmBadStateTracking.Absent, Remembered());

        // Второй запуск службы ничего не меняет и не сообщает об изменении.
        Assert.Equal(WcmBadStateTrackingResult.AlreadyDisabled, WcmBadStateTracking.Apply(_root, Wcm, Own));

        Assert.True(WcmBadStateTracking.Restore(_root, Wcm, Own));
        Assert.Null(Value());
        Assert.Null(Remembered());
    }

    [Fact]
    public void Apply_ValueEnabled_RestoreReturnsTheNumber()
    {
        Set(1);

        Assert.Equal(WcmBadStateTrackingResult.Disabled, WcmBadStateTracking.Apply(_root, Wcm, Own));
        Assert.Equal(0, Value());
        Assert.Equal("1", Remembered());

        Assert.True(WcmBadStateTracking.Restore(_root, Wcm, Own));
        Assert.Equal(1, Value());
    }

    [Fact]
    public void Apply_UserAlreadyDisabled_RestoreLeavesItAlone()
    {
        Set(0);

        Assert.Equal(WcmBadStateTrackingResult.AlreadyDisabled, WcmBadStateTracking.Apply(_root, Wcm, Own));
        Assert.Null(Remembered());

        Assert.False(WcmBadStateTracking.Restore(_root, Wcm, Own));
        Assert.Equal(0, Value());
    }

    [Fact]
    public void Apply_ValueResetBySomeoneElse_KeepsTheFirstRememberedValue()
    {
        WcmBadStateTracking.Apply(_root, Wcm, Own);
        Set(1);

        Assert.Equal(WcmBadStateTrackingResult.Disabled, WcmBadStateTracking.Apply(_root, Wcm, Own));
        Assert.Equal(WcmBadStateTracking.Absent, Remembered());
    }

    [Fact]
    public void Restore_ValueChangedAfterUs_IsNotTouched()
    {
        WcmBadStateTracking.Apply(_root, Wcm, Own);
        Set(1);

        Assert.False(WcmBadStateTracking.Restore(_root, Wcm, Own));
        Assert.Equal(1, Value());
        Assert.Null(Remembered());
    }
}
