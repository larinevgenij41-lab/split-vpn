using System.Diagnostics;
using System.Net.NetworkInformation;
using SplitVpn.Core.SshTunnel;
using SplitVpn.Windows.SshTunnel;

namespace SplitVpn.Service.Tests;

public sealed class SshEngineStartupTests
{
    [Fact]
    public void OccupiedAdapterNameIsRejectedBeforeConfiguration()
    {
        var adapter = NetworkInterface.GetAllNetworkInterfaces().First();
        Assert.Throws<IOException>(() => SystemSshTunnelOps.EnsureAliasAvailable(adapter.Name));
    }

    [Fact]
    public async Task HungPreparationHasOneWorkerAndDeadlinePreventsLateCleanup()
    {
        using var ops = new SystemSshTunnelOps(Environment.ProcessPath!, Path.GetTempPath());
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var finished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var starts = 0;
        var removed = false;
        async Task Prepare(string name, CancellationToken token)
        {
            Interlocked.Increment(ref starts);
            try
            {
                await release.Task;
                token.ThrowIfCancellationRequested();
                removed = true;
            }
            finally { finished.SetResult(); }
        }

        try
        {
            var timeout = TimeSpan.FromMilliseconds(100);
            await Assert.ThrowsAsync<IOException>(() => ops.PrepareInterfaceAsync("alias", timeout, Prepare));
            await Assert.ThrowsAsync<IOException>(() => ops.PrepareInterfaceAsync("alias", timeout, Prepare));
            Assert.Equal(1, starts);
        }
        finally { release.SetResult(); }
        await finished.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        Assert.False(removed);
    }

    [Fact]
    public async Task PreparationRejectsOccupiedNonWintunAndAcceptsFreeAlias()
    {
        using var ops = new SystemSshTunnelOps(Environment.ProcessPath!, Path.GetTempPath());
        var loopback = NetworkInterface.GetAllNetworkInterfaces().First(a => a.NetworkInterfaceType == NetworkInterfaceType.Loopback);
        await Assert.ThrowsAsync<IOException>(() => ops.PrepareInterfaceAsync(loopback.Name));
        await ops.PrepareInterfaceAsync("SplitVpn SSH " + Guid.NewGuid().ToString("N"));
    }

    [Fact]
    public async Task UnresponsiveChildIsStoppedAndConfigurationIsCleared()
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"))
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            ArgumentList = { "-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 60" },
        };
        using var process = Process.Start(start)!;
        var config = new byte[1024 * 1024];
        Array.Fill(config, (byte)1);
        var parameters = new SingBoxParameters
        {
            InterfaceName = Guid.NewGuid().ToString(), Server = 0, Port = 22, User = "test",
            HostKey = new SshHostKey("ssh-ed25519", ""),
        };
        using var session = new SystemSshTunnelOps.Session(process, parameters, _ => { }, config, config.Length, TimeSpan.FromMilliseconds(300));
        await session.Exited.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        Assert.False(config.AsSpan().ContainsAnyExcept((byte)0));
    }
}
