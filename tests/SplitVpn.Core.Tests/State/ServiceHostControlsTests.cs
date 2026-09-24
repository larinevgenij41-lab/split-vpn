using SplitVpn.Core.State;

namespace SplitVpn.Core.Tests.State;

public sealed class ServiceHostControlsTests
{
    [Fact]
    public void Running_CanStopAndRestart()
    {
        var view = ServiceHostView.From(ServiceHostState.Running, notResponding: false, pending: null);

        Assert.Equal("Работает", view.Text);
        Assert.Equal(ServiceHostTone.Good, view.Tone);
        Assert.False(view.CanStart);
        Assert.True(view.CanStop);
        Assert.True(view.CanRestart);
    }

    [Fact]
    public void Stopped_CanOnlyStart()
    {
        var view = ServiceHostView.From(ServiceHostState.Stopped, notResponding: false, pending: null);

        Assert.Equal("Остановлена", view.Text);
        Assert.True(view.CanStart);
        Assert.False(view.CanStop);
        Assert.False(view.CanRestart);
    }

    [Fact]
    public void RunningButNotResponding_OffersRestart()
    {
        var view = ServiceHostView.From(ServiceHostState.Running, notResponding: true, pending: null);

        Assert.Equal("Не отвечает", view.Text);
        Assert.Equal(ServiceHostTone.Warning, view.Tone);
        Assert.False(view.CanStart);
        Assert.True(view.CanRestart);
    }

    [Fact]
    public void StoppedService_IsNotReportedAsNotResponding()
    {
        // Опрос помечает таймауты; у остановленной службы важнее, что её можно запустить.
        var view = ServiceHostView.From(ServiceHostState.Stopped, notResponding: true, pending: null);

        Assert.Equal("Остановлена", view.Text);
        Assert.True(view.CanStart);
    }

    [Theory]
    [InlineData(ServiceHostAction.Start, "Запускается…")]
    [InlineData(ServiceHostAction.Stop, "Останавливается…")]
    [InlineData(ServiceHostAction.Restart, "Перезапускается…")]
    public void PendingAction_BlocksAllButtons(ServiceHostAction action, string text)
    {
        foreach (var state in Enum.GetValues<ServiceHostState>())
        {
            var view = ServiceHostView.From(state, notResponding: false, pending: action);

            Assert.Equal(text, view.Text);
            Assert.False(view.CanStart || view.CanStop || view.CanRestart);
        }
    }

    [Theory]
    [InlineData(ServiceHostState.StartPending, "Запускается…")]
    [InlineData(ServiceHostState.StopPending, "Останавливается…")]
    [InlineData(ServiceHostState.NotInstalled, "Не установлена")]
    [InlineData(ServiceHostState.Unknown, "Неизвестно")]
    public void TransitionalAndMissing_HaveNoActions(ServiceHostState state, string text)
    {
        var view = ServiceHostView.From(state, notResponding: false, pending: null);

        Assert.Equal(text, view.Text);
        Assert.False(view.CanStart || view.CanStop || view.CanRestart);
    }

    [Fact]
    public void Commands_UseSingleElevatedProcess()
    {
        Assert.Equal(("sc.exe", "start SplitVpn"), ServiceHostCommands.For(ServiceHostAction.Start, "SplitVpn"));
        Assert.Equal(("sc.exe", "stop SplitVpn"), ServiceHostCommands.For(ServiceHostAction.Stop, "SplitVpn"));
        var (file, arguments) = ServiceHostCommands.For(ServiceHostAction.Restart, "SplitVpn");
        Assert.Equal("powershell.exe", file);
        Assert.Contains("Restart-Service -Name SplitVpn -Force", arguments, StringComparison.Ordinal);
    }

    [Fact]
    public void ExitCodes_AlreadyInTargetStateIsSuccess()
    {
        Assert.True(ServiceHostCommands.Succeeded(ServiceHostAction.Start, 0));
        Assert.True(ServiceHostCommands.Succeeded(ServiceHostAction.Start, ServiceHostCommands.AlreadyRunning));
        Assert.True(ServiceHostCommands.Succeeded(ServiceHostAction.Stop, ServiceHostCommands.NotActive));
        Assert.False(ServiceHostCommands.Succeeded(ServiceHostAction.Stop, ServiceHostCommands.AlreadyRunning));
        Assert.False(ServiceHostCommands.Succeeded(ServiceHostAction.Restart, 1));
        Assert.Equal(ServiceHostState.Stopped, ServiceHostCommands.Target(ServiceHostAction.Stop));
        Assert.Equal(ServiceHostState.Running, ServiceHostCommands.Target(ServiceHostAction.Restart));
    }
}
