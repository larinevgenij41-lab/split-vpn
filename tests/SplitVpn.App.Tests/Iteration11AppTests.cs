using SplitVpn.App.Services;
using SplitVpn.App.ViewModels;
using SplitVpn.Core.Ipc;

namespace SplitVpn.App.Tests;

/// <summary>Итерация 11: отказ службы на запрос состояния и сохранение компактного отчёта.</summary>
public sealed class Iteration11AppTests
{
    [Fact]
    public void FaultedStatus_IsNotDescribedAsVersionMismatch()
    {
        var (title, text, _) = MainViewModel.Describe(ServiceUnavailableReason.Faulted);
        Assert.DoesNotContain("Верси", title, StringComparison.Ordinal);
        Assert.DoesNotContain("разных версий", text, StringComparison.Ordinal);
        Assert.Equal(TimeSpan.FromSeconds(1.5), MainViewModel.Backoff(ServiceUnavailableReason.Faulted, 1));
    }

    [Fact]
    public void CommandException_KeepsServiceErrorCode()
    {
        Assert.Equal(IpcErrorCodes.Failed, new ServiceCommandException("текст", IpcErrorCodes.Failed).ErrorCode);
        Assert.Null(new ServiceCommandException("текст").ErrorCode);
    }

    [Fact]
    public void Report_IsSavedIndented_AndBrokenJsonAsIs()
    {
        var indented = DiagnosticsViewModel.IndentReport("{\"a\":1,\"b\":[1,2]}");
        Assert.Contains("\n", indented, StringComparison.Ordinal);
        Assert.Equal("не json", DiagnosticsViewModel.IndentReport("не json"));
    }
}
